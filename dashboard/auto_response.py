from __future__ import annotations

import asyncio
import ipaddress
import json
import os
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from aiohttp import web

from . import runtime as core


VALID_MODES = {"off", "shadow", "challenge", "active"}
AUTO_ACTIONS = {"recommend_challenge", "recommend_block"}
LONG_BLOCK_ACTION = "recommend_long_block"


def _env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class AutoResponseConfig:
    default_mode: str = "off"
    cycle_seconds: float = 30.0
    max_actions_per_hour: int = 5
    max_actions_per_day: int = 20
    min_challenge_signals: int = 2
    min_block_signals: int = 3
    exclude_verified_bots: bool = True

    @classmethod
    def from_env(cls) -> "AutoResponseConfig":
        mode = os.getenv("HOTPOT_AUTO_RESPONSE_MODE", "off").strip().lower() or "off"
        if mode not in VALID_MODES:
            raise RuntimeError(
                "HOTPOT_AUTO_RESPONSE_MODE must be one of: off, shadow, challenge, active"
            )
        return cls(
            default_mode=mode,
            cycle_seconds=max(
                15.0, float(os.getenv("HOTPOT_AUTO_RESPONSE_CYCLE_SECONDS", "30"))
            ),
            max_actions_per_hour=max(
                1, int(os.getenv("HOTPOT_AUTO_RESPONSE_MAX_PER_HOUR", "5"))
            ),
            max_actions_per_day=max(
                1, int(os.getenv("HOTPOT_AUTO_RESPONSE_MAX_PER_DAY", "20"))
            ),
            min_challenge_signals=max(
                1,
                int(os.getenv("HOTPOT_AUTO_RESPONSE_MIN_CHALLENGE_SIGNALS", "2")),
            ),
            min_block_signals=max(
                1, int(os.getenv("HOTPOT_AUTO_RESPONSE_MIN_BLOCK_SIGNALS", "3"))
            ),
            exclude_verified_bots=_env_bool(
                "HOTPOT_AUTO_RESPONSE_EXCLUDE_VERIFIED_BOTS", True
            ),
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "default_mode": self.default_mode,
            "cycle_seconds": self.cycle_seconds,
            "max_actions_per_hour": self.max_actions_per_hour,
            "max_actions_per_day": self.max_actions_per_day,
            "min_challenge_signals": self.min_challenge_signals,
            "min_block_signals": self.min_block_signals,
            "exclude_verified_bots": self.exclude_verified_bots,
            "long_blocks_automatic": False,
        }


def _signal_names(evidence: dict[str, Any]) -> list[str]:
    signals: list[str] = []
    if int(evidence.get("observed_hits", 0) or 0) >= 10:
        signals.append("volume")
    if int(evidence.get("app_count", 0) or 0) >= 2:
        signals.append("multiple-apps")
    if int(evidence.get("category_count", 0) or 0) >= 3:
        signals.append("category-breadth")
    if (
        int(evidence.get("max_severity", 0) or 0) >= 4
        or int(evidence.get("high_severity_events", 0) or 0) >= 3
    ):
        signals.append("high-severity")
    if int(evidence.get("high_level_events", 0) or 0) >= 3:
        signals.append("repeat-high-level")
    return signals


def evaluate_candidate(
    recommendation: dict[str, Any],
    config: AutoResponseConfig,
    *,
    mode: str,
    verified_bot: bool = False,
    bot_check_available: bool = True,
    policy_suppressed: bool = False,
) -> dict[str, Any]:
    """Return a fail-closed automatic-response decision without performing writes."""

    action = str(recommendation.get("action") or "")
    evidence = recommendation.get("evidence")
    if not isinstance(evidence, dict):
        evidence = {}
    signals = _signal_names(evidence)
    result = {
        "eligible": False,
        "action": action,
        "signals": signals,
        "signal_count": len(signals),
        "reason": "not eligible",
    }

    if mode not in VALID_MODES:
        result["reason"] = "invalid automatic-response mode"
        return result
    if mode == "off":
        result["reason"] = "automatic response is disabled"
        return result
    if action == LONG_BLOCK_ACTION:
        result["reason"] = "7-day long blocks always require manual approval"
        return result
    if action not in AUTO_ACTIONS:
        result["reason"] = "recommendation action is not eligible for automation"
        return result
    if mode == "challenge" and action != "recommend_challenge":
        result["reason"] = "challenge-only mode keeps 24-hour blocks manual"
        return result
    if policy_suppressed:
        result["reason"] = "recommendation is suppressed by response policy"
        return result
    if str(recommendation.get("confidence") or "") != "high":
        result["reason"] = "automatic response requires high confidence"
        return result
    if str(recommendation.get("target_type") or "") != "ip":
        result["reason"] = "automatic response is limited to direct IP targets"
        return result
    if config.exclude_verified_bots and not bot_check_available:
        result["reason"] = "verified-bot safety check is unavailable"
        return result
    if config.exclude_verified_bots and verified_bot:
        result["reason"] = "verified bot infrastructure is excluded from automation"
        return result

    raw_ip = str(recommendation.get("target_value") or "").strip()
    try:
        address = ipaddress.ip_address(raw_ip)
    except ValueError:
        result["reason"] = "target is not a valid IP address"
        return result
    if not address.is_global:
        result["reason"] = "automatic response only targets globally routable IPs"
        return result

    source_type = str(evidence.get("source_type") or "ip")
    if source_type != "ip":
        result["reason"] = "automatic response excludes proxy/Worker identities"
        return result

    level = int(evidence.get("global_level", 1) or 1)
    required_signals = config.min_challenge_signals
    if action == "recommend_block":
        if level < 4:
            result["reason"] = "automatic block requires global level 4"
            return result
        required_signals = config.min_block_signals
    elif level < 3:
        result["reason"] = "automatic challenge requires global level 3 or higher"
        return result

    if len(signals) < required_signals:
        result["reason"] = (
            f"only {len(signals)} independent signal(s); {required_signals} required"
        )
        return result

    result["eligible"] = True
    result["reason"] = (
        "would automatically apply after guardrails"
        if mode == "shadow"
        else "eligible for guarded automatic response"
    )
    return result


class AutoResponseStateStore:
    """Small durable state extension stored in the dashboard SQLite database."""

    def __init__(self, path: Path):
        self.path = path
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        return conn

    def _initialize(self) -> None:
        conn = self._connect()
        try:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS auto_response_runtime (
                    key TEXT PRIMARY KEY,
                    value_json TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS auto_response_decisions (
                    recommendation_id TEXT PRIMARY KEY,
                    actor_key TEXT,
                    action TEXT,
                    mode TEXT NOT NULL,
                    decision TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    signals_json TEXT NOT NULL DEFAULT '[]',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_auto_response_decision_time
                    ON auto_response_decisions(decision, updated_at DESC);
                """
            )
            conn.commit()
        finally:
            conn.close()

    def mode_state(self, default_mode: str) -> dict[str, Any]:
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT value_json, updated_at FROM auto_response_runtime WHERE key = 'mode'"
            ).fetchone()
        finally:
            conn.close()
        if row is None:
            return {
                "mode": default_mode,
                "source": "environment-default",
                "changed_at": None,
            }
        try:
            payload = json.loads(str(row["value_json"]))
        except json.JSONDecodeError:
            payload = {}
        mode = str(payload.get("mode") or default_mode)
        if mode not in VALID_MODES:
            mode = "off"
        return {
            "mode": mode,
            "source": "dashboard-override",
            "changed_at": str(payload.get("changed_at") or row["updated_at"]),
        }

    def set_mode(self, mode: str) -> dict[str, Any]:
        if mode not in VALID_MODES:
            raise ValueError("mode must be one of: off, shadow, challenge, active")
        now = datetime.now(timezone.utc).isoformat()
        payload = json.dumps({"mode": mode, "changed_at": now}, separators=(",", ":"))
        conn = self._connect()
        try:
            conn.execute(
                """
                INSERT INTO auto_response_runtime(key, value_json, updated_at)
                VALUES ('mode', ?, ?)
                ON CONFLICT(key) DO UPDATE SET value_json=excluded.value_json,
                    updated_at=excluded.updated_at
                """,
                (payload, now),
            )
            conn.commit()
        finally:
            conn.close()
        return {"mode": mode, "source": "dashboard-override", "changed_at": now}

    def record_decision(
        self,
        recommendation: dict[str, Any],
        *,
        mode: str,
        decision: str,
        reason: str,
        signals: list[str],
    ) -> bool:
        recommendation_id = str(recommendation.get("recommendation_id") or "").strip()
        if not recommendation_id:
            return False
        actor_key = str(recommendation.get("actor_key") or "") or None
        action = str(recommendation.get("action") or "") or None
        now = datetime.now(timezone.utc).isoformat()
        conn = self._connect()
        try:
            previous = conn.execute(
                "SELECT mode, decision, reason, signals_json FROM auto_response_decisions WHERE recommendation_id = ?",
                (recommendation_id,),
            ).fetchone()
            encoded = json.dumps(signals, separators=(",", ":"))
            changed = previous is None or (
                str(previous["mode"]) != mode
                or str(previous["decision"]) != decision
                or str(previous["reason"]) != reason
                or str(previous["signals_json"]) != encoded
            )
            conn.execute(
                """
                INSERT INTO auto_response_decisions(
                    recommendation_id, actor_key, action, mode, decision,
                    reason, signals_json, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(recommendation_id) DO UPDATE SET
                    actor_key=excluded.actor_key,
                    action=excluded.action,
                    mode=excluded.mode,
                    decision=excluded.decision,
                    reason=excluded.reason,
                    signals_json=excluded.signals_json,
                    updated_at=excluded.updated_at
                """,
                (
                    recommendation_id,
                    actor_key,
                    action,
                    mode,
                    decision,
                    reason[:1000],
                    encoded,
                    now,
                    now,
                ),
            )
            conn.commit()
            return changed
        finally:
            conn.close()

    def action_counts(self) -> dict[str, int]:
        now = datetime.now(timezone.utc)
        hour = (now - timedelta(hours=1)).isoformat()
        day = (now - timedelta(hours=24)).isoformat()
        conn = self._connect()
        try:
            hour_count = conn.execute(
                """
                SELECT COUNT(*) AS count FROM auto_response_decisions
                WHERE decision IN ('applied', 'apply_failed') AND updated_at >= ?
                """,
                (hour,),
            ).fetchone()["count"]
            day_count = conn.execute(
                """
                SELECT COUNT(*) AS count FROM auto_response_decisions
                WHERE decision IN ('applied', 'apply_failed') AND updated_at >= ?
                """,
                (day,),
            ).fetchone()["count"]
            shadow = conn.execute(
                "SELECT COUNT(*) AS count FROM auto_response_decisions WHERE decision = 'shadow_would_apply'"
            ).fetchone()["count"]
            return {
                "last_hour": int(hour_count or 0),
                "last_24_hours": int(day_count or 0),
                "shadow_would_apply": int(shadow or 0),
            }
        finally:
            conn.close()

    def verified_bot_status(
        self, actor_key: str, *, active_window_hours: int
    ) -> dict[str, Any]:
        cutoff = (
            datetime.now(timezone.utc) - timedelta(hours=max(1, active_window_hours))
        ).isoformat()
        conn = self._connect()
        try:
            rows = conn.execute(
                """
                SELECT payload_json FROM events
                WHERE attacker_key = ? AND ts >= ?
                ORDER BY ts DESC LIMIT 250
                """,
                (actor_key, cutoff),
            ).fetchall()
        except sqlite3.Error as exc:
            return {"available": False, "verified": False, "error": str(exc)}
        finally:
            conn.close()

        identities: set[str] = set()
        for row in rows:
            try:
                payload = json.loads(str(row["payload_json"] or "{}"))
            except (TypeError, json.JSONDecodeError):
                continue
            if payload.get("bot_verified") is True:
                identity = str(payload.get("bot_identity") or "").strip()
                if identity:
                    identities.add(identity)
                return {
                    "available": True,
                    "verified": True,
                    "identities": sorted(identities),
                }
        return {"available": True, "verified": False, "identities": []}


class AutoResponseController:
    def __init__(self, dashboard: Any):
        self.dashboard = dashboard
        self.config = AutoResponseConfig.from_env()
        self.state = AutoResponseStateStore(Path(dashboard.store.path))
        self.task: asyncio.Task | None = None
        self.last_run_at: str | None = None
        self.last_error: str | None = None
        self.last_circuit: dict[str, Any] = {
            "status": "off",
            "reason": "automatic response is disabled",
        }
        self.last_mode_change_rejection: dict[str, Any] | None = None

    async def startup(self, app: web.Application) -> None:
        self.task = asyncio.create_task(self._loop(), name="hotpot-auto-response")

    async def shutdown(self, app: web.Application) -> None:
        if self.task is None:
            return
        self.task.cancel()
        await asyncio.gather(self.task, return_exceptions=True)
        self.task = None

    async def _loop(self) -> None:
        await asyncio.sleep(2)
        while True:
            try:
                await self.run_once()
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                self.last_error = f"{type(exc).__name__}: {exc}"
            await asyncio.sleep(self.config.cycle_seconds)

    async def _audit(
        self,
        *,
        event_type: str,
        message: str,
        recommendation: dict[str, Any] | None = None,
        status: str | None = None,
        details: dict[str, Any] | None = None,
        principal: str = "system",
    ) -> None:
        recorder = getattr(self.dashboard.store, "record_dashboard_action", None)
        if not callable(recorder):
            return
        recommendation_id = None
        if recommendation is not None:
            recommendation_id = str(recommendation.get("recommendation_id") or "") or None
        await recorder(
            event_type=event_type,
            message=message,
            principal=principal,
            session_id=None,
            recommendation_id=recommendation_id,
            status=status,
            details=details or {},
        )

    async def _policy_suppressed(self, recommendation: dict[str, Any]) -> bool:
        checker = getattr(self.dashboard, "_recommendation_is_policy_suppressed", None)
        if not callable(checker):
            return False
        return await checker(recommendation) is not None

    async def _circuit_check(self, *, force: bool) -> dict[str, Any]:
        if not self.dashboard.response_policy.enabled:
            return {"status": "open", "reason": "response recommendations are disabled"}
        if not self.dashboard.cloudflare.configured:
            return {"status": "open", "reason": "Cloudflare enforcement is not configured"}
        if not self.dashboard.cloudflare.can_remove:
            return {"status": "open", "reason": "Cloudflare removal permission is unavailable"}
        try:
            report = await self.dashboard._maybe_reconcile_cloudflare(force=force)
        except Exception as exc:
            return {
                "status": "open",
                "reason": f"Cloudflare reconciliation failed: {type(exc).__name__}: {exc}",
            }
        if str(report.get("status") or "") != "healthy":
            return {
                "status": "open",
                "reason": f"Cloudflare reconciliation is {report.get('status') or 'unknown'}",
                "reconciliation": report,
            }
        if int(report.get("rollback_cleanup_pending", 0) or 0) > 0:
            return {
                "status": "open",
                "reason": "rollback cleanup jobs are pending",
                "reconciliation": report,
            }
        if int(report.get("orphaned", 0) or 0) > 0:
            return {
                "status": "open",
                "reason": "orphaned Hotpot Cloudflare rules are present",
                "reconciliation": report,
            }
        return {
            "status": "closed",
            "reason": "Cloudflare reconciliation is healthy",
            "reconciliation": report,
        }

    async def set_mode(self, mode: str, *, principal: str) -> dict[str, Any]:
        mode = mode.strip().lower()
        if mode not in VALID_MODES:
            raise ValueError("mode must be one of: off, shadow, challenge, active")
        if mode in {"challenge", "active"}:
            circuit = await self._circuit_check(force=True)
            self.last_circuit = circuit
            if circuit["status"] != "closed":
                reason = "automatic enforcement cannot be enabled: " + str(circuit["reason"])
                self.last_mode_change_rejection = {
                    "attempted_mode": mode,
                    "reason": reason,
                    "checked_at": datetime.now(timezone.utc).isoformat(),
                }
                await self._audit(
                    event_type="auto_response_mode_rejected",
                    message=reason,
                    status="rejected",
                    details={
                        "attempted_mode": mode,
                        "circuit_status": circuit.get("status"),
                        "circuit_reason": circuit.get("reason"),
                    },
                    principal=principal,
                )
                raise ValueError(reason)
        state = await asyncio.to_thread(self.state.set_mode, mode)
        self.last_mode_change_rejection = None
        self.last_circuit = (
            {"status": "off", "reason": "dashboard kill switch is active"}
            if mode == "off"
            else self.last_circuit
        )
        await self._audit(
            event_type="auto_response_mode_changed",
            message=f"Automatic response mode changed to {mode}",
            status=mode,
            details={"mode": mode, "source": state["source"]},
            principal=principal,
        )
        return await self.status()

    async def status(self) -> dict[str, Any]:
        mode = await asyncio.to_thread(self.state.mode_state, self.config.default_mode)
        counts = await asyncio.to_thread(self.state.action_counts)
        changed_at = mode.get("changed_at")
        age_hours = None
        if changed_at:
            try:
                changed = datetime.fromisoformat(str(changed_at).replace("Z", "+00:00"))
                if changed.tzinfo is None:
                    changed = changed.replace(tzinfo=timezone.utc)
                age_hours = max(
                    0.0,
                    (datetime.now(timezone.utc) - changed.astimezone(timezone.utc)).total_seconds()
                    / 3600.0,
                )
            except ValueError:
                age_hours = None
        return {
            **mode,
            "config": self.config.as_dict(),
            "counts": counts,
            "last_run_at": self.last_run_at,
            "last_error": self.last_error,
            "circuit_breaker": self.last_circuit,
            "last_mode_change_rejection": self.last_mode_change_rejection,
            "shadow_age_hours": round(age_hours, 1)
            if mode["mode"] == "shadow" and age_hours is not None
            else None,
            "recommended_shadow_hours": 168,
            "kill_switch_active": mode["mode"] == "off",
            "stages": {
                "off": "manual approval only",
                "shadow": "record eligible actions without Cloudflare writes",
                "challenge": "automate high-confidence 6-hour managed challenges only",
                "active": "also automate high-confidence 24-hour L4 hostname-scoped blocks",
                "long_block": "always manual; zone-wide 7-day IP Access blocks are never automatic",
            },
        }

    async def run_once(self) -> None:
        self.last_run_at = datetime.now(timezone.utc).isoformat()
        self.last_error = None
        mode_state = await asyncio.to_thread(
            self.state.mode_state, self.config.default_mode
        )
        mode = str(mode_state["mode"])
        if mode == "off":
            self.last_circuit = {
                "status": "off",
                "reason": "dashboard kill switch is active",
            }
            return
        if not self.dashboard.response_policy.enabled:
            self.last_circuit = {
                "status": "open",
                "reason": "response recommendations are disabled",
            }
            return

        pending = await self.dashboard.store.recommendations(
            self.dashboard.response_policy, status="pending", limit=100
        )
        recommendations = list(pending.get("recommendations") or [])
        if not recommendations:
            self.last_circuit = {
                "status": "standby",
                "reason": "no pending recommendations",
            }
            return

        async with self.dashboard.cache_lock:
            apps = list(self.dashboard.cache.get("apps", []))

        candidates: list[tuple[dict[str, Any], dict[str, Any]]] = []
        for recommendation in recommendations:
            actor_key = str(recommendation.get("actor_key") or "")
            suppressed = await self._policy_suppressed(recommendation)
            bot_status = await asyncio.to_thread(
                self.state.verified_bot_status,
                actor_key,
                active_window_hours=self.dashboard.response_policy.active_window_hours,
            )
            evaluation = evaluate_candidate(
                recommendation,
                self.config,
                mode=mode,
                verified_bot=bool(bot_status.get("verified")),
                bot_check_available=bool(bot_status.get("available")),
                policy_suppressed=suppressed,
            )
            if mode == "shadow" and evaluation["eligible"]:
                decision = "shadow_would_apply"
            elif evaluation["eligible"]:
                decision = "eligible"
            else:
                decision = "manual_only"
            changed = await asyncio.to_thread(
                self.state.record_decision,
                recommendation,
                mode=mode,
                decision=decision,
                reason=str(evaluation["reason"]),
                signals=list(evaluation["signals"]),
            )
            if mode == "shadow" and evaluation["eligible"] and changed:
                await self._audit(
                    event_type="auto_response_shadow",
                    message=f"Shadow mode would apply {recommendation.get('action')}",
                    recommendation=recommendation,
                    status="shadow",
                    details={
                        "signals": evaluation["signals"],
                        "target": recommendation.get("target_value"),
                    },
                )
            if evaluation["eligible"] and mode != "shadow":
                candidates.append((recommendation, evaluation))

        if mode == "shadow":
            self.last_circuit = {
                "status": "shadow",
                "reason": "shadow mode records decisions but performs no Cloudflare writes",
            }
            return
        if not candidates:
            self.last_circuit = {
                "status": "standby",
                "reason": "no recommendations passed automatic-response guardrails",
            }
            return

        circuit = await self._circuit_check(force=True)
        self.last_circuit = circuit
        if circuit["status"] != "closed":
            for recommendation, evaluation in candidates:
                await asyncio.to_thread(
                    self.state.record_decision,
                    recommendation,
                    mode=mode,
                    decision="circuit_open",
                    reason=str(circuit["reason"]),
                    signals=list(evaluation["signals"]),
                )
            return

        for recommendation, evaluation in candidates:
            # Re-read the durable mode immediately before every write. The kill switch
            # therefore prevents the next automatic action even if a cycle is running.
            current = await asyncio.to_thread(
                self.state.mode_state, self.config.default_mode
            )
            current_mode = str(current["mode"])
            if current_mode == "off" or (
                current_mode == "challenge"
                and recommendation.get("action") != "recommend_challenge"
            ):
                self.last_circuit = {
                    "status": "off",
                    "reason": "automatic response mode changed during this cycle",
                }
                break

            counts = await asyncio.to_thread(self.state.action_counts)
            if counts["last_hour"] >= self.config.max_actions_per_hour:
                self.last_circuit = {
                    "status": "open",
                    "reason": "hourly automatic-action limit reached",
                }
                await asyncio.to_thread(
                    self.state.record_decision,
                    recommendation,
                    mode=current_mode,
                    decision="rate_limited",
                    reason=self.last_circuit["reason"],
                    signals=list(evaluation["signals"]),
                )
                break
            if counts["last_24_hours"] >= self.config.max_actions_per_day:
                self.last_circuit = {
                    "status": "open",
                    "reason": "daily automatic-action limit reached",
                }
                await asyncio.to_thread(
                    self.state.record_decision,
                    recommendation,
                    mode=current_mode,
                    decision="rate_limited",
                    reason=self.last_circuit["reason"],
                    signals=list(evaluation["signals"]),
                )
                break

            try:
                approved = await self.dashboard.store.approve_recommendation(
                    str(recommendation.get("recommendation_id") or ""),
                    self.dashboard.response_policy,
                    apps,
                )
            except ValueError as exc:
                await asyncio.to_thread(
                    self.state.record_decision,
                    recommendation,
                    mode=current_mode,
                    decision="guardrail_denied",
                    reason=str(exc),
                    signals=list(evaluation["signals"]),
                )
                continue
            if approved is None:
                continue

            await self._audit(
                event_type="auto_response_approved",
                message=f"Guarded automatic response approved {approved.get('action')}",
                recommendation=approved,
                status="approved",
                details={"signals": evaluation["signals"], "mode": current_mode},
            )
            result = await self.dashboard._apply_one(approved)
            if result.get("status") != "applied":
                await asyncio.to_thread(
                    self.state.record_decision,
                    recommendation,
                    mode=current_mode,
                    decision="apply_failed",
                    reason=str(result.get("enforcement_error") or "Cloudflare apply failed"),
                    signals=list(evaluation["signals"]),
                )
                self.last_circuit = {
                    "status": "open",
                    "reason": "automatic Cloudflare apply failed",
                }
                break

            await asyncio.to_thread(
                self.state.record_decision,
                recommendation,
                mode=current_mode,
                decision="applied",
                reason="automatic response applied and verified",
                signals=list(evaluation["signals"]),
            )
            await self._audit(
                event_type="auto_response_applied",
                message=f"Automatic response applied {result.get('action')}",
                recommendation=result,
                status="applied",
                details={"signals": evaluation["signals"], "mode": current_mode},
            )
            circuit = await self._circuit_check(force=True)
            self.last_circuit = circuit
            if circuit["status"] != "closed":
                break

        await self.dashboard._refresh_response_cache()


AUTO_RESPONSE_KEY = web.AppKey("hotpot_auto_response", AutoResponseController)


async def api_auto_response_status(request: web.Request) -> web.Response:
    dashboard = request.app[core.DASHBOARD_KEY]
    dashboard.require_auth(request)
    controller = request.app[AUTO_RESPONSE_KEY]
    return web.json_response(
        await controller.status(), headers={"Cache-Control": "no-store"}
    )


async def api_auto_response_mode(request: web.Request) -> web.Response:
    dashboard = request.app[core.DASHBOARD_KEY]
    context = dashboard.require_action(request, "auto-response-mode")
    try:
        payload = await request.json()
    except Exception as exc:
        raise web.HTTPBadRequest(text="JSON body is required") from exc
    if not isinstance(payload, dict):
        raise web.HTTPBadRequest(text="JSON body must be an object")
    mode = str(payload.get("mode") or "").strip().lower()
    controller = request.app[AUTO_RESPONSE_KEY]
    try:
        status = await controller.set_mode(mode, principal=context.username)
    except ValueError as exc:
        raise web.HTTPConflict(text=str(exc)) from exc
    return web.json_response(status, headers={"Cache-Control": "no-store"})


@web.middleware
async def auto_response_ui_middleware(request: web.Request, handler):
    response = await handler(request)
    if (
        request.method == "GET"
        and request.path == "/"
        and isinstance(response, web.Response)
        and response.content_type == "text/html"
        and response.text
        and "auto_response.js" not in response.text
    ):
        response.text = response.text.replace(
            "</body>", '<script src="/static/auto_response.js"></script>\n</body>'
        )
    return response


def install_auto_response(app: web.Application) -> AutoResponseController:
    dashboard = app[core.DASHBOARD_KEY]
    controller = AutoResponseController(dashboard)
    app[AUTO_RESPONSE_KEY] = controller
    app.middlewares.append(auto_response_ui_middleware)
    app.on_startup.append(controller.startup)
    app.on_cleanup.insert(0, controller.shutdown)
    app.router.add_get("/api/auto-response", api_auto_response_status)
    app.router.add_get("/api/v1/auto-response", api_auto_response_status)
    app.router.add_post("/api/auto-response/mode", api_auto_response_mode)
    app.router.add_post("/api/v1/auto-response/mode", api_auto_response_mode)
    return controller
