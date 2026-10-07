from __future__ import annotations

import asyncio
import ipaddress
import json
import sqlite3
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable

from .global_scoring import CLOUDFLARE_WORKER_SHARED_IP, LEGACY_WORKER_KEY, score_attacker
from .network_intelligence import NetworkIntelligenceStore


POLICY_VERSION = 1
ACTION_RANK = {
    "observe": 0,
    "watch": 1,
    "recommend_challenge": 2,
    "recommend_block": 3,
    "recommend_long_block": 4,
}


@dataclass(frozen=True)
class ResponsePolicy:
    enabled: bool = True
    active_window_hours: int = 24
    stale_minutes: int = 360
    recommendation_ttl_hours: int = 24
    dismiss_hours: int = 24

    def as_dict(self) -> dict[str, Any]:
        return {
            "version": POLICY_VERSION,
            "enabled": self.enabled,
            "active_window_hours": self.active_window_hours,
            "stale_minutes": self.stale_minutes,
            "recommendation_ttl_hours": self.recommendation_ttl_hours,
            "dismiss_hours": self.dismiss_hours,
            "enforcement": "recommendation-only",
            "levels": {
                "1": "observe",
                "2": "watch",
                "3": "recommend_challenge",
                "4": "recommend_block",
                "repeated_level4": "recommend_long_block",
            },
            "network_context_affects_decision": False,
        }


@dataclass(frozen=True)
class SafetyContext:
    allow_cidrs: tuple[str, ...] = ()
    trusted_proxy_cidrs: tuple[str, ...] = ()


def _parse_datetime(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _ip_in_cidrs(ip: str | None, cidrs: Iterable[str]) -> bool:
    if not ip:
        return False
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for raw in cidrs:
        try:
            if address in ipaddress.ip_network(str(raw).strip(), strict=False):
                return True
        except ValueError:
            continue
    return False


def _target_for(actor: dict[str, Any]) -> tuple[str, str | None]:
    source_type = str(actor.get("source_type") or "ip")
    worker_zone = str(actor.get("worker_zone") or "").strip()
    identity_key = str(actor.get("identity_key") or "")
    client_ip = str(actor.get("client_ip") or "").strip()
    if source_type == "cloudflare-worker" and worker_zone and identity_key != LEGACY_WORKER_KEY:
        return "cloudflare-worker-zone", worker_zone
    if client_ip:
        return "ip", client_ip
    return "none", None


def decide_response(
    actor: dict[str, Any],
    policy: ResponsePolicy,
    safety: SafetyContext,
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Return an explainable recommendation without performing enforcement."""

    current = now or datetime.now(timezone.utc)
    identity_key = str(actor.get("identity_key") or actor.get("ip") or "unknown")
    client_ip = str(actor.get("client_ip") or "").strip() or None
    source_type = str(actor.get("source_type") or "ip")
    worker_zone = str(actor.get("worker_zone") or "").strip() or None
    last_seen = _parse_datetime(actor.get("last_seen"))
    stale = last_seen is None or last_seen < current - timedelta(minutes=policy.stale_minutes)
    level = max(1, int(actor.get("global_level", 1) or 1))
    score = max(0, int(actor.get("global_score", 0) or 0))
    hits = max(0, int(actor.get("hits", 0) or 0))
    app_count = max(0, int(actor.get("app_count", 0) or 0))
    category_count = max(0, int(actor.get("category_count", 0) or 0))
    high_severity_events = max(0, int(actor.get("high_severity_events", 0) or 0))
    high_level_events = max(0, int(actor.get("high_level_events", 0) or 0))
    lifetime = actor.get("lifetime") if isinstance(actor.get("lifetime"), dict) else {}
    lifetime_hits = max(0, int((lifetime or {}).get("lifetime_hits", 0) or 0))
    lifetime_peak = max(1, int((lifetime or {}).get("max_global_level", 1) or 1))

    target_type, target_value = _target_for(actor)
    safety_reasons: list[str] = []
    excluded = False
    if _ip_in_cidrs(client_ip, safety.allow_cidrs):
        excluded = True
        safety_reasons.append("client IP matches a configured allowlist CIDR")
    if _ip_in_cidrs(client_ip, safety.trusted_proxy_cidrs):
        excluded = True
        safety_reasons.append("client IP matches a trusted proxy CIDR")
    if stale:
        excluded = True
        safety_reasons.append("actor is stale")

    shared_worker_without_zone = (
        client_ip == CLOUDFLARE_WORKER_SHARED_IP
        and (source_type != "cloudflare-worker" or not worker_zone or identity_key == LEGACY_WORKER_KEY)
    )

    action = "observe"
    confidence = "low"
    duration_hours = 0
    if not excluded:
        if level >= 4:
            repeated_l4 = lifetime_peak >= 4 and (
                lifetime_hits >= 100
                or (hits >= 30 and app_count >= 3)
                or high_severity_events >= 8
                or high_level_events >= 10
            )
            if repeated_l4:
                action = "recommend_long_block"
                confidence = "high"
                duration_hours = 168
            else:
                action = "recommend_block"
                confidence = "high"
                duration_hours = 24
        elif level == 3:
            action = "recommend_challenge"
            confidence = "high" if app_count >= 3 or category_count >= 4 or high_severity_events >= 5 else "medium"
            duration_hours = 6
        elif level == 2:
            action = "watch"
            confidence = "medium"

    # Cloudflare documents this IPv6 as a shared cross-zone Worker identity. When
    # the originating Worker zone is unavailable, an IP block would affect
    # unrelated Workers. Retain the intelligence but never recommend enforcement.
    if shared_worker_without_zone and ACTION_RANK[action] > ACTION_RANK["watch"]:
        action = "watch"
        confidence = "low"
        duration_hours = 0
        target_type = "none"
        target_value = None
        safety_reasons.append("shared Cloudflare Worker address has no trustworthy Worker zone")

    if action == "observe":
        summary = "Observe only"
    elif action == "watch":
        summary = "Watch for continued or broader probing"
    elif action == "recommend_challenge":
        summary = f"Recommend challenge for about {duration_hours} hours"
    elif action == "recommend_block":
        summary = f"Recommend temporary block for about {duration_hours} hours"
    else:
        summary = f"Recommend longer temporary block for about {duration_hours} hours"

    return {
        "actor_key": identity_key,
        "action": action,
        "action_rank": ACTION_RANK[action],
        "confidence": confidence,
        "duration_hours": duration_hours,
        "target_type": target_type,
        "target_value": target_value,
        "summary": summary,
        "safety_excluded": excluded,
        "safety_reasons": safety_reasons,
        "policy_version": POLICY_VERSION,
        "evidence": {
            "active_window_hours": policy.active_window_hours,
            "global_level": level,
            "global_score": score,
            "observed_hits": hits,
            "persisted_hits": max(0, int(actor.get("persisted_hits", 0) or 0)),
            "app_count": app_count,
            "category_count": category_count,
            "max_severity": max(0, int(actor.get("max_severity", 0) or 0)),
            "high_severity_events": high_severity_events,
            "high_level_events": high_level_events,
            "first_seen": actor.get("first_seen"),
            "last_seen": actor.get("last_seen"),
            "apps": list(actor.get("apps") or []),
            "categories": list(actor.get("categories") or []),
            "top_paths": list(actor.get("top_paths") or []),
            "source_type": source_type,
            "worker_zone": worker_zone,
            "client_ip": client_ip,
            "lifetime_hits": lifetime_hits,
            "lifetime_peak_level": lifetime_peak,
            "network": dict(actor.get("network") or {}),
        },
    }


class ThreatResponseStore(NetworkIntelligenceStore):
    """Network intelligence plus durable recommendation lifecycle state."""

    def _initialize(self) -> None:
        super()._initialize()
        conn = self._connect()
        try:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS response_recommendations (
                    recommendation_id TEXT PRIMARY KEY,
                    actor_key TEXT NOT NULL,
                    action TEXT NOT NULL,
                    confidence TEXT NOT NULL,
                    status TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    last_seen TEXT,
                    target_type TEXT NOT NULL DEFAULT 'none',
                    target_value TEXT,
                    duration_hours INTEGER NOT NULL DEFAULT 0,
                    summary TEXT NOT NULL,
                    evidence_json TEXT NOT NULL,
                    policy_version INTEGER NOT NULL DEFAULT 1
                );
                CREATE INDEX IF NOT EXISTS idx_response_recommendations_status
                    ON response_recommendations(status, updated_at DESC);
                CREATE INDEX IF NOT EXISTS idx_response_recommendations_actor
                    ON response_recommendations(actor_key, updated_at DESC);
                CREATE UNIQUE INDEX IF NOT EXISTS idx_response_recommendations_pending_actor
                    ON response_recommendations(actor_key) WHERE status = 'pending';
                """
            )
            conn.commit()
        finally:
            conn.close()

    @staticmethod
    def safety_context_from_apps(apps: list[dict[str, Any]]) -> SafetyContext:
        allow: set[str] = set()
        proxies: set[str] = set()
        for app in apps:
            for cidr in app.get("allowlist_cidrs") or []:
                value = str(cidr).strip()
                if value:
                    allow.add(value)
            for cidr in app.get("trusted_proxy_cidrs") or []:
                value = str(cidr).strip()
                if value:
                    proxies.add(value)
        return SafetyContext(tuple(sorted(allow)), tuple(sorted(proxies)))

    def _active_attackers_conn(
        self, conn: sqlite3.Connection, cutoff: str
    ) -> list[dict[str, Any]]:
        rows = conn.execute(
            """
            SELECT attacker_key AS identity_key,
                   MAX(client_ip) AS client_ip,
                   MAX(source_type) AS source_type,
                   MAX(worker_zone) AS worker_zone,
                   COUNT(*) AS persisted_hits,
                   COUNT(*) + COALESCE(SUM(suppressed_before), 0) AS hits,
                   COALESCE(SUM(severity), 0) AS severity_score,
                   COALESCE(MAX(severity), 0) AS max_severity,
                   COALESCE(MAX(escalation_level), 1) AS max_local_level,
                   SUM(CASE WHEN severity >= 4 THEN 1 ELSE 0 END) AS high_severity_events,
                   SUM(CASE WHEN escalation_level >= 3 THEN 1 ELSE 0 END) AS high_level_events,
                   COUNT(DISTINCT instance_id) AS app_count,
                   COUNT(DISTINCT category) AS category_count,
                   MIN(ts) AS first_seen,
                   MAX(ts) AS last_seen
            FROM events
            WHERE ts >= ?
              AND attacker_key IS NOT NULL
              AND attacker_key != ''
              AND attacker_key != 'unknown'
            GROUP BY attacker_key
            ORDER BY last_seen DESC
            """,
            (cutoff,),
        ).fetchall()

        result: list[dict[str, Any]] = []
        for raw in rows:
            item = dict(raw)
            score = score_attacker(
                severity_score=int(item.get("severity_score", 0) or 0),
                hits=int(item.get("hits", 0) or 0),
                app_count=int(item.get("app_count", 0) or 0),
                category_count=int(item.get("category_count", 0) or 0),
            )
            item["global_score"] = score.score
            item["global_level"] = score.level
            identity_key = str(item["identity_key"])
            apps = conn.execute(
                """
                SELECT instance_name, COUNT(*) + COALESCE(SUM(suppressed_before), 0) AS hits
                FROM events WHERE attacker_key = ? AND ts >= ?
                GROUP BY instance_id, instance_name ORDER BY hits DESC
                """,
                (identity_key, cutoff),
            ).fetchall()
            categories = conn.execute(
                """
                SELECT category, COUNT(*) + COALESCE(SUM(suppressed_before), 0) AS hits
                FROM events WHERE attacker_key = ? AND ts >= ?
                GROUP BY category ORDER BY hits DESC
                """,
                (identity_key, cutoff),
            ).fetchall()
            paths = conn.execute(
                """
                SELECT path, COUNT(*) + COALESCE(SUM(suppressed_before), 0) AS hits
                FROM events WHERE attacker_key = ? AND ts >= ?
                GROUP BY path ORDER BY hits DESC LIMIT 5
                """,
                (identity_key, cutoff),
            ).fetchall()
            item["apps"] = [str(row["instance_name"]) for row in apps]
            item["categories"] = [str(row["category"]) for row in categories]
            item["top_paths"] = [dict(row) for row in paths]
            lifetime = self._lifetime_attacker_conn(conn, identity_key)
            item["lifetime"] = lifetime or {}
            if lifetime and isinstance(lifetime.get("network"), dict):
                item["network"] = dict(lifetime["network"])
            result.append(item)
        return result

    @staticmethod
    def _recommendation_from_row(row: sqlite3.Row | dict[str, Any]) -> dict[str, Any]:
        item = dict(row)
        raw = item.pop("evidence_json", "{}")
        try:
            evidence = json.loads(raw)
        except (TypeError, json.JSONDecodeError):
            evidence = {}
        item["evidence"] = evidence if isinstance(evidence, dict) else {}
        return item

    async def sync_response_recommendations(
        self,
        policy: ResponsePolicy,
        apps: list[dict[str, Any]],
    ) -> dict[str, Any]:
        async with self.lock:
            return await asyncio.to_thread(
                self._sync_response_recommendations_sync, policy, apps
            )

    def _sync_response_recommendations_sync(
        self,
        policy: ResponsePolicy,
        apps: list[dict[str, Any]],
    ) -> dict[str, Any]:
        now = datetime.now(timezone.utc)
        now_iso = now.isoformat()
        cutoff = (now - timedelta(hours=policy.active_window_hours)).isoformat()
        safety = self.safety_context_from_apps(apps)
        conn = self._connect()
        try:
            conn.execute(
                "UPDATE response_recommendations SET status = 'expired', updated_at = ? "
                "WHERE status = 'pending' AND expires_at <= ?",
                (now_iso, now_iso),
            )
            if not policy.enabled:
                conn.commit()
                return self._response_snapshot_conn(conn, policy)

            actors = self._active_attackers_conn(conn, cutoff)
            desired: set[str] = set()
            for actor in actors:
                decision = decide_response(actor, policy, safety, now=now)
                if decision["action"] == "observe":
                    continue
                actor_key = str(decision["actor_key"])
                desired.add(actor_key)

                dismissed = conn.execute(
                    """
                    SELECT expires_at FROM response_recommendations
                    WHERE actor_key = ? AND status = 'dismissed'
                    ORDER BY updated_at DESC LIMIT 1
                    """,
                    (actor_key,),
                ).fetchone()
                if dismissed is not None and str(dismissed["expires_at"]) > now_iso:
                    continue

                pending = conn.execute(
                    "SELECT recommendation_id, created_at FROM response_recommendations "
                    "WHERE actor_key = ? AND status = 'pending' LIMIT 1",
                    (actor_key,),
                ).fetchone()
                expires_at = (
                    now + timedelta(hours=policy.recommendation_ttl_hours)
                ).isoformat()
                evidence_json = json.dumps(
                    decision["evidence"], separators=(",", ":"), sort_keys=True
                )
                if pending is None:
                    conn.execute(
                        """
                        INSERT INTO response_recommendations(
                            recommendation_id, actor_key, action, confidence, status,
                            created_at, updated_at, expires_at, last_seen,
                            target_type, target_value, duration_hours, summary,
                            evidence_json, policy_version
                        ) VALUES (?, ?, ?, ?, 'pending', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            uuid.uuid4().hex,
                            actor_key,
                            decision["action"],
                            decision["confidence"],
                            now_iso,
                            now_iso,
                            expires_at,
                            decision["evidence"].get("last_seen"),
                            decision["target_type"],
                            decision["target_value"],
                            decision["duration_hours"],
                            decision["summary"],
                            evidence_json,
                            POLICY_VERSION,
                        ),
                    )
                else:
                    conn.execute(
                        """
                        UPDATE response_recommendations
                        SET action = ?, confidence = ?, updated_at = ?, expires_at = ?,
                            last_seen = ?, target_type = ?, target_value = ?,
                            duration_hours = ?, summary = ?, evidence_json = ?,
                            policy_version = ?
                        WHERE recommendation_id = ?
                        """,
                        (
                            decision["action"],
                            decision["confidence"],
                            now_iso,
                            expires_at,
                            decision["evidence"].get("last_seen"),
                            decision["target_type"],
                            decision["target_value"],
                            decision["duration_hours"],
                            decision["summary"],
                            evidence_json,
                            POLICY_VERSION,
                            pending["recommendation_id"],
                        ),
                    )

            pending_rows = conn.execute(
                "SELECT recommendation_id, actor_key FROM response_recommendations "
                "WHERE status = 'pending'"
            ).fetchall()
            for row in pending_rows:
                if str(row["actor_key"]) not in desired:
                    conn.execute(
                        "UPDATE response_recommendations SET status = 'expired', updated_at = ? "
                        "WHERE recommendation_id = ?",
                        (now_iso, row["recommendation_id"]),
                    )
            conn.commit()
            return self._response_snapshot_conn(conn, policy)
        finally:
            conn.close()

    def _response_snapshot_conn(
        self, conn: sqlite3.Connection, policy: ResponsePolicy
    ) -> dict[str, Any]:
        rows = conn.execute(
            """
            SELECT * FROM response_recommendations
            WHERE status = 'pending'
            ORDER BY
                CASE action
                    WHEN 'recommend_long_block' THEN 4
                    WHEN 'recommend_block' THEN 3
                    WHEN 'recommend_challenge' THEN 2
                    WHEN 'watch' THEN 1
                    ELSE 0
                END DESC,
                CASE confidence WHEN 'high' THEN 3 WHEN 'medium' THEN 2 ELSE 1 END DESC,
                updated_at DESC
            LIMIT 100
            """
        ).fetchall()
        recommendations = [self._recommendation_from_row(row) for row in rows]
        by_action: dict[str, int] = {}
        by_confidence: dict[str, int] = {}
        for row in recommendations:
            by_action[row["action"]] = by_action.get(row["action"], 0) + 1
            by_confidence[row["confidence"]] = by_confidence.get(row["confidence"], 0) + 1
        return {
            "enabled": policy.enabled,
            "policy": policy.as_dict(),
            "summary": {
                "pending": len(recommendations),
                "high_priority": sum(
                    1
                    for row in recommendations
                    if row["action"] in {"recommend_block", "recommend_long_block"}
                    and row["confidence"] == "high"
                ),
                "by_action": by_action,
                "by_confidence": by_confidence,
            },
            "recommendations": recommendations,
        }

    async def recommendations(
        self, policy: ResponsePolicy, *, status: str = "pending", limit: int = 100
    ) -> dict[str, Any]:
        async with self.lock:
            return await asyncio.to_thread(
                self._recommendations_sync, policy, status, max(1, min(500, int(limit)))
            )

    def _recommendations_sync(
        self, policy: ResponsePolicy, status: str, limit: int
    ) -> dict[str, Any]:
        allowed = {"pending", "dismissed", "expired", "approved", "applied", "failed", "all"}
        if status not in allowed:
            raise ValueError("invalid recommendation status")
        conn = self._connect()
        try:
            if status == "all":
                rows = conn.execute(
                    "SELECT * FROM response_recommendations ORDER BY updated_at DESC LIMIT ?",
                    (limit,),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM response_recommendations WHERE status = ? "
                    "ORDER BY updated_at DESC LIMIT ?",
                    (status, limit),
                ).fetchall()
            values = [self._recommendation_from_row(row) for row in rows]
            return {
                "policy": policy.as_dict(),
                "status": status,
                "count": len(values),
                "recommendations": values,
            }
        finally:
            conn.close()

    async def recommendation(self, recommendation_id: str) -> dict[str, Any] | None:
        async with self.lock:
            return await asyncio.to_thread(self._recommendation_sync, recommendation_id)

    def _recommendation_sync(self, recommendation_id: str) -> dict[str, Any] | None:
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT * FROM response_recommendations WHERE recommendation_id = ?",
                (recommendation_id,),
            ).fetchone()
            return self._recommendation_from_row(row) if row is not None else None
        finally:
            conn.close()

    async def dismiss_recommendation(
        self, recommendation_id: str, dismiss_hours: int
    ) -> dict[str, Any] | None:
        async with self.lock:
            return await asyncio.to_thread(
                self._dismiss_recommendation_sync,
                recommendation_id,
                max(1, int(dismiss_hours)),
            )

    def _dismiss_recommendation_sync(
        self, recommendation_id: str, dismiss_hours: int
    ) -> dict[str, Any] | None:
        now = datetime.now(timezone.utc)
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT status FROM response_recommendations WHERE recommendation_id = ?",
                (recommendation_id,),
            ).fetchone()
            if row is None:
                return None
            if str(row["status"]) != "pending":
                return self._recommendation_from_row(
                    conn.execute(
                        "SELECT * FROM response_recommendations WHERE recommendation_id = ?",
                        (recommendation_id,),
                    ).fetchone()
                )
            conn.execute(
                """
                UPDATE response_recommendations
                SET status = 'dismissed', updated_at = ?, expires_at = ?
                WHERE recommendation_id = ?
                """,
                (
                    now.isoformat(),
                    (now + timedelta(hours=dismiss_hours)).isoformat(),
                    recommendation_id,
                ),
            )
            conn.commit()
            updated = conn.execute(
                "SELECT * FROM response_recommendations WHERE recommendation_id = ?",
                (recommendation_id,),
            ).fetchone()
            return self._recommendation_from_row(updated) if updated is not None else None
        finally:
            conn.close()
