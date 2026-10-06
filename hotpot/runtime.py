from __future__ import annotations

import asyncio
import json
import os
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from aiohttp import ClientTimeout, web

from .app import HOTPOT_APP_KEY, Hotpot
from .config import Settings
from .intelligence import classify, escalation_for
from .store import AttackerState


class HardenedHotpot(Hotpot):
    """Operational hardening layer kept separate from the core proxy implementation."""

    def __init__(self, settings: Settings):
        super().__init__(settings)
        self.health_interval = max(5, int(os.getenv("HOTPOT_HEALTHCHECK_INTERVAL_SECONDS", "30")))
        self.health_timeout = max(1.0, float(os.getenv("HOTPOT_HEALTHCHECK_TIMEOUT_SECONDS", "5")))
        self.health_task: asyncio.Task | None = None
        self.upstream_health: dict[str, Any] = {
            "healthy": False,
            "status": None,
            "latency_ms": None,
            "last_checked": None,
            "last_success": None,
            "last_failure": None,
            "consecutive_failures": 0,
            "error": "not_checked",
        }
        self.stats["tarpits_active"] = 0
        self.stats["tarpits_total"] = 0
        self.stats["tarpits_completed"] = 0
        self.stats["tarpits_disconnected"] = 0
        self.stats["telemetry_errors"] = 0

    async def startup(self, app: web.Application) -> None:
        await super().startup(app)
        await self.check_upstream()
        self.health_task = asyncio.create_task(self.health_loop(), name="hotpot-upstream-health")

    async def shutdown(self, app: web.Application) -> None:
        if self.health_task:
            self.health_task.cancel()
            await asyncio.gather(self.health_task, return_exceptions=True)
        await super().shutdown(app)

    async def health_loop(self) -> None:
        while True:
            try:
                await asyncio.sleep(self.health_interval)
                await self.check_upstream()
            except asyncio.CancelledError:
                raise
            except Exception:
                self.stats["healthcheck_errors"] += 1

    async def check_upstream(self) -> None:
        assert self.client is not None
        started = time.monotonic()
        now = datetime.now(timezone.utc).isoformat()
        previous = self.upstream_health
        try:
            timeout = ClientTimeout(total=self.health_timeout)
            async with self.client.get(self.settings.upstream + "/", allow_redirects=False, timeout=timeout) as response:
                # A 5xx response means the upstream itself says it is not ready. Any
                # other HTTP response proves the application is reachable.
                healthy = response.status < 500
                await response.release()
                latency = round((time.monotonic() - started) * 1000, 1)
                failures = 0 if healthy else int(previous.get("consecutive_failures", 0)) + 1
                self.upstream_health = {
                    "healthy": healthy,
                    "status": response.status,
                    "latency_ms": latency,
                    "last_checked": now,
                    "last_success": now if healthy else previous.get("last_success"),
                    "last_failure": previous.get("last_failure") if healthy else now,
                    "consecutive_failures": failures,
                    "error": None if healthy else f"HTTP {response.status}",
                }
        except Exception as exc:
            self.upstream_health = {
                "healthy": False,
                "status": None,
                "latency_ms": round((time.monotonic() - started) * 1000, 1),
                "last_checked": now,
                "last_success": previous.get("last_success"),
                "last_failure": now,
                "consecutive_failures": int(previous.get("consecutive_failures", 0)) + 1,
                "error": type(exc).__name__,
            }

    async def live(self, request: web.Request) -> web.Response:
        return web.json_response({"alive": True, "instance_id": self.settings.instance_id})

    async def health(self, request: web.Request) -> web.Response:
        payload = {
            "healthy": bool(self.upstream_health["healthy"]),
            "instance_id": self.settings.instance_id,
            "upstream": self.upstream_health,
        }
        return web.json_response(payload, status=200 if payload["healthy"] else 503)

    async def status(self, request: web.Request) -> web.Response:
        response = await super().status(request)
        payload = json.loads(response.text)
        payload["healthy"] = bool(self.upstream_health["healthy"])
        payload["instance_id"] = self.settings.instance_id
        payload["instance_name"] = self.settings.instance_name
        payload["upstream_health"] = self.upstream_health
        payload["stats"] = dict(self.stats)
        return web.json_response(payload, headers={"Cache-Control": "no-store"})

    async def events_api(self, request: web.Request) -> web.Response:
        if not self.authorized(request):
            raise web.HTTPUnauthorized()
        try:
            cursor = max(0, int(request.query.get("cursor", "0")))
            limit = max(1, min(500, int(request.query.get("limit", "250"))))
        except ValueError as exc:
            raise web.HTTPBadRequest(text="cursor and limit must be integers") from exc
        result = await asyncio.to_thread(self._events_since_sync, cursor, limit)
        result["instance_id"] = self.settings.instance_id
        result["instance_name"] = self.settings.instance_name
        return web.json_response(result, headers={"Cache-Control": "no-store"})

    def _events_since_sync(self, cursor: int, limit: int) -> dict[str, Any]:
        conn = sqlite3.connect(self.store.path, timeout=10)
        conn.row_factory = sqlite3.Row
        try:
            rows = conn.execute(
                """
                SELECT id, ts, ip, method, path, profile, rule, category, action,
                       scanner, scanner_family, fingerprint, severity,
                       escalation_level, details_json
                FROM events WHERE id > ? ORDER BY id ASC LIMIT ?
                """,
                (cursor, limit + 1),
            ).fetchall()
        finally:
            conn.close()
        has_more = len(rows) > limit
        rows = rows[:limit]
        events: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            details = item.pop("details_json", None)
            if details:
                try:
                    parsed = json.loads(details)
                    if isinstance(parsed, dict):
                        item.update(parsed)
                except (TypeError, json.JSONDecodeError):
                    pass
            item["client_ip"] = item.pop("ip")
            events.append(item)
        next_cursor = events[-1]["id"] if events else cursor
        return {"events": events, "next_cursor": next_cursor, "has_more": has_more}

    async def handler(self, request: web.Request) -> web.StreamResponse:
        if request.path == "/_hotpot/live":
            return await self.live(request)
        if request.path == "/_hotpot/health":
            return await self.health(request)
        if request.path == "/_hotpot/status":
            return await self.status(request)
        if request.path == "/_hotpot/api/events":
            return await self.events_api(request)
        return await super().handler(request)

    async def _safe_event_write(self, event: dict[str, Any]) -> None:
        try:
            await self.events.write(event)
        except Exception:
            self.stats["telemetry_errors"] += 1
            self.stats["jsonl_errors"] += 1

    async def deception(self, request: web.Request, rule) -> web.StreamResponse:
        identity = self.client_identity(request)
        ip = identity.client_ip
        user_agent = request.headers.get("User-Agent", "")
        classification = classify(user_agent, rule.category, request.method, request.path_qs)

        # Intelligence persistence is deliberately fail-open: telemetry failures must
        # never turn a deceptive request into a 500 or make Hotpot unavailable.
        prior = AttackerState(ip, 0, 0, None, None, None, None, 1)
        try:
            async with self.intelligence_lock:
                try:
                    prior = await self.store.state_for(ip)
                except Exception:
                    self.stats["telemetry_errors"] += 1
                    self.stats["sqlite_read_errors"] += 1
                escalation = escalation_for(
                    prior_hits=prior.hits,
                    prior_score=prior.score,
                    severity=classification.severity,
                    base_seconds=self.settings.tarpit_max_seconds,
                    max_escalated_seconds=self.settings.tarpit_escalated_max_seconds,
                )
                effective_action = rule.action
                if escalation.force_tarpit and self.settings.tarpit_enabled:
                    effective_action = "tarpit"
                event = {
                    "event": "deception",
                    "client_ip": ip,
                    "proxy_ip": identity.proxy_ip,
                    "client_ip_source": identity.source,
                    "trusted_proxy": identity.trusted_proxy,
                    "method": request.method,
                    "path": request.path_qs,
                    "host": request.host,
                    "user_agent": user_agent,
                    "referer": request.headers.get("Referer", ""),
                    "profile": rule.profile,
                    "rule": rule.name,
                    "category": rule.category,
                    "action": effective_action,
                    "rule_action": rule.action,
                    "scanner": classification.scanner,
                    "scanner_family": classification.scanner_family,
                    "fingerprint": classification.fingerprint,
                    "severity": classification.severity,
                    "escalation_level": escalation.level,
                    "attacker_score": escalation.score,
                    "prior_hits": prior.hits,
                }
                try:
                    await self.store.record(event, score=escalation.score, escalation_level=escalation.level)
                except Exception:
                    self.stats["telemetry_errors"] += 1
                    self.stats["sqlite_write_errors"] += 1
        except Exception:
            # A final safety net around scoring itself. The response still follows the
            # rule if any unexpected intelligence subsystem error occurs.
            effective_action = rule.action
            event = {
                "event": "deception", "client_ip": ip, "method": request.method,
                "path": request.path_qs, "profile": rule.profile, "rule": rule.name,
                "category": rule.category, "action": effective_action,
                "scanner": classification.scanner, "scanner_family": classification.scanner_family,
                "fingerprint": classification.fingerprint, "severity": classification.severity,
                "escalation_level": 1, "attacker_score": classification.severity, "prior_hits": 0,
            }
            self.stats["telemetry_errors"] += 1
            escalation = type("FallbackEscalation", (), {"level": 1, "tarpit_seconds": self.settings.tarpit_max_seconds})()

        self.stats["deceptions"] += 1
        self.stats[f"category:{rule.category}"] += 1
        self.stats[f"scanner:{classification.scanner}"] += 1
        self.stats[f"escalation:{event.get('escalation_level', 1)}"] += 1
        await self._safe_event_write(event)
        try:
            await self.maybe_notify(event)
        except Exception:
            self.stats["telemetry_errors"] += 1
            self.stats["notification_state_errors"] += 1

        if effective_action == "tarpit" and self.settings.tarpit_enabled:
            return await self.tarpit(request, rule, max_seconds=escalation.tarpit_seconds)
        return web.Response(status=rule.status, text=rule.response, content_type=rule.content_type.split(";", 1)[0])

    async def tarpit(self, request: web.Request, rule, *, max_seconds: float | None = None) -> web.StreamResponse:
        try:
            await asyncio.wait_for(self.tarpit_slots.acquire(), timeout=0.05)
        except TimeoutError:
            self.stats["tarpit_overflow"] += 1
            return web.Response(status=rule.status, text=rule.response,
                                content_type=rule.content_type.split(";", 1)[0])

        self.stats["tarpits_total"] += 1
        self.stats["tarpits_active"] += 1
        started = time.monotonic()
        disconnected = False
        try:
            await asyncio.sleep(self.settings.tarpit_initial_delay)
            resp = web.StreamResponse(status=rule.status)
            resp.headers["Content-Type"] = rule.content_type
            await resp.prepare(request)
            body = rule.response.encode("utf-8") or b" "
            pos = 0
            lifetime = max_seconds if max_seconds is not None else self.settings.tarpit_max_seconds
            while time.monotonic() - started < lifetime:
                chunk = body[pos:pos + 32]
                if not chunk:
                    pos = 0
                    chunk = b" "
                else:
                    pos += len(chunk)
                try:
                    await resp.write(chunk)
                except (ConnectionResetError, RuntimeError):
                    disconnected = True
                    break
                await asyncio.sleep(self.settings.tarpit_chunk_delay)
            try:
                await resp.write_eof()
            except (ConnectionResetError, RuntimeError):
                disconnected = True
            return resp
        finally:
            self.stats["tarpits_active"] = max(0, self.stats["tarpits_active"] - 1)
            if disconnected:
                self.stats["tarpits_disconnected"] += 1
            else:
                self.stats["tarpits_completed"] += 1
            self.tarpit_slots.release()


def build_app(settings: Settings | None = None) -> web.Application:
    settings = settings or Settings.from_env()
    hotpot = HardenedHotpot(settings)
    app = web.Application(client_max_size=settings.max_request_body)
    app[HOTPOT_APP_KEY] = hotpot
    app.on_startup.append(hotpot.startup)
    app.on_cleanup.append(hotpot.shutdown)
    app.router.add_route("*", "/{tail:.*}", hotpot.handler)
    return app


def main() -> None:
    settings = Settings.from_env()
    web.run_app(build_app(settings), host=settings.bind, port=settings.port, access_log=None)


if __name__ == "__main__":
    main()
