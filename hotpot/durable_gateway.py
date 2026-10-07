from __future__ import annotations

import json
import os
import sqlite3
import time

from aiohttp import web

from . import runtime as runtime_layer
from .app import HOTPOT_APP_KEY
from .config import Settings
from .durable_store import SourceIdentityStore
from .intelligence import classify, escalation_for
from .store import AttackerState
from .telemetry import BoundedTelemetryQueue, TelemetryWork

# ResilientStore resolves this runtime module global when each Hotpot instance is
# constructed, so production keeps telemetry fail-safety while gaining a stable
# SQLite-store generation identifier.
runtime_layer.RealIntelligenceStore = SourceIdentityStore

from .gateway import GatewayHotpot  # noqa: E402  (must follow runtime store override)


class DurableGatewayHotpot(GatewayHotpot):
    def __init__(self, settings: Settings):
        super().__init__(settings)
        self.telemetry_queue = BoundedTelemetryQueue(
            capacity=max(32, int(os.getenv("HOTPOT_TELEMETRY_QUEUE_MAX", "2048"))),
            drain_timeout=max(
                0.1,
                float(os.getenv("HOTPOT_TELEMETRY_DRAIN_TIMEOUT_SECONDS", "5")),
            ),
        )
        self.stats["telemetry_queue_dropped"] = 0
        self.stats["telemetry_queue_dropped_jsonl"] = 0
        self.stats["telemetry_queue_dropped_notify"] = 0

    async def startup(self, app: web.Application) -> None:
        await super().startup(app)
        await self.telemetry_queue.start(self._process_telemetry_work)

    async def shutdown(self, app: web.Application) -> None:
        # Drain auxiliary telemetry while the shared HTTP client is still available
        # to notification delivery, then let the inherited shutdown close clients.
        await self.telemetry_queue.stop()
        await super().shutdown(app)

    async def _process_telemetry_work(self, work: TelemetryWork) -> None:
        if work.kind == "jsonl":
            # Bypass this class's queueing override and use HardenedHotpot's
            # resilient direct JSONL writer from the background worker.
            await super()._safe_event_write(work.event)
            return
        if work.kind == "notify":
            try:
                await self._notify_direct(work.event)
            except Exception:
                self.stats["telemetry_errors"] += 1
                self.stats["notification_state_errors"] += 1
                raise
            return
        self.stats["telemetry_errors"] += 1
        raise RuntimeError(f"unknown telemetry work kind: {work.kind}")

    def _submit_telemetry(self, kind: str, event: dict) -> bool:
        accepted = self.telemetry_queue.submit(kind, event)
        if not accepted:
            self.stats["telemetry_queue_dropped"] += 1
            self.stats[f"telemetry_queue_dropped_{kind}"] += 1
        return accepted

    async def _safe_event_write(self, event: dict) -> None:
        if self.telemetry_queue.running:
            self._submit_telemetry("jsonl", event)
            return
        await super()._safe_event_write(event)

    @property
    def source_id(self) -> str | None:
        inner = getattr(self.store, "inner", None)
        value = getattr(inner, "source_id", None)
        return str(value) if value else None

    def _max_event_id_sync(self) -> int:
        path = getattr(self.store, "path", None)
        if path is None:
            return 0
        conn = sqlite3.connect(path, timeout=10)
        try:
            row = conn.execute("SELECT COALESCE(MAX(id), 0) FROM events").fetchone()
            return int(row[0] or 0) if row else 0
        finally:
            conn.close()

    async def events_api(self, request: web.Request) -> web.Response:
        if not self.authorized(request):
            raise web.HTTPUnauthorized()
        try:
            cursor = max(0, int(request.query.get("cursor", "0")))
            limit = max(1, min(500, int(request.query.get("limit", "250"))))
        except ValueError as exc:
            raise web.HTTPBadRequest(text="cursor and limit must be integers") from exc

        result = await runtime_layer.asyncio.to_thread(self._events_since_sync, cursor, limit)
        result["instance_id"] = self.settings.instance_id
        result["instance_name"] = self.settings.instance_name
        result["source_id"] = self.source_id
        result["event_cursor_max"] = await runtime_layer.asyncio.to_thread(
            self._max_event_id_sync
        )
        return web.json_response(result, headers={"Cache-Control": "no-store"})

    async def status(self, request: web.Request) -> web.Response:
        response = await super().status(request)
        payload = json.loads(response.text)
        payload["source_id"] = self.source_id
        payload["event_cursor_max"] = await runtime_layer.asyncio.to_thread(
            self._max_event_id_sync
        )
        payload["telemetry_queue"] = self.telemetry_queue.snapshot()
        return web.json_response(payload, headers={"Cache-Control": "no-store"})

    async def maybe_notify(self, event: dict) -> None:
        if not self.notifier.enabled:
            return
        level = int(event.get("escalation_level", 1))
        if level < self.settings.notify_min_level:
            return
        if self.telemetry_queue.running:
            self._submit_telemetry("notify", event)
            return
        await self._notify_direct(event)

    async def _notify_direct(self, event: dict) -> None:
        if not self.notifier.enabled:
            return
        level = int(event.get("escalation_level", 1))
        if level < self.settings.notify_min_level:
            return
        attacker_key = str(
            event.get("attacker_key") or event.get("client_ip", "unknown")
        )
        should_send = await self.store.claim_notification(
            attacker_key, level, self.settings.notify_cooldown_seconds
        )
        if not should_send:
            self.stats["notifications_suppressed"] += 1
            return
        assert self.client is not None
        try:
            channels = await self.notifier.send(self.client, event)
            self.stats["notifications_sent"] += 1
            await self.events.write(
                {
                    "event": "notification_sent",
                    "client_ip": event.get("client_ip", "unknown"),
                    "attacker_key": attacker_key,
                    "source_type": event.get("source_type", "ip"),
                    "worker_zone": event.get("worker_zone"),
                    "escalation_level": level,
                    "channels": channels,
                }
            )
        except Exception as exc:
            self.stats["notification_errors"] += 1
            await self.events.write(
                {
                    "event": "notification_error",
                    "client_ip": event.get("client_ip", "unknown"),
                    "attacker_key": attacker_key,
                    "source_type": event.get("source_type", "ip"),
                    "worker_zone": event.get("worker_zone"),
                    "escalation_level": level,
                    "error": type(exc).__name__,
                }
            )

    async def deception(self, request: web.Request, rule) -> web.StreamResponse:
        identity = self.client_identity(request)
        client_ip = identity.client_ip
        attacker_key = identity.actor_key
        user_agent = request.headers.get("User-Agent", "")
        classification = classify(user_agent, rule.category, request.method, request.path_qs)
        now = time.monotonic()

        persist_event = True
        suppressed_before = 0
        prior = AttackerState(attacker_key, 0, 0, None, None, None, None, 1)
        try:
            async with self.intelligence_lock:
                cached = self.runtime_attackers.get(attacker_key)
                if cached is None:
                    try:
                        prior = await self.store.state_for(attacker_key)
                    except Exception:
                        self.stats["telemetry_errors"] += 1
                        self.stats["sqlite_read_errors"] += 1
                    prior_hits = prior.hits
                    prior_score = prior.score
                else:
                    prior_hits, prior_score, _ = cached

                escalation = escalation_for(
                    prior_hits=prior_hits,
                    prior_score=prior_score,
                    severity=classification.severity,
                    base_seconds=self.settings.tarpit_max_seconds,
                    max_escalated_seconds=self.settings.tarpit_escalated_max_seconds,
                )
                observed_hits = prior_hits + 1
                self.runtime_attackers[attacker_key] = (
                    observed_hits,
                    escalation.score,
                    now,
                )

                effective_action = rule.action
                if escalation.force_tarpit and self.settings.tarpit_enabled:
                    effective_action = "tarpit"

                persist_event, suppressed_before = self.event_limiter.admit(
                    attacker_key, now=now
                )
                event = {
                    "event": "deception",
                    "client_ip": client_ip,
                    "attacker_key": attacker_key,
                    "source_type": identity.source_type,
                    "worker_zone": identity.worker_zone,
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
                    "prior_hits": prior_hits,
                    "observed_hits": observed_hits,
                }
                if suppressed_before:
                    event["suppressed_before"] = suppressed_before

                if persist_event:
                    try:
                        await self.store.record(
                            event,
                            score=escalation.score,
                            escalation_level=escalation.level,
                        )
                    except Exception:
                        self.stats["telemetry_errors"] += 1
                        self.stats["sqlite_write_errors"] += 1
                else:
                    self.stats["events_suppressed_total"] += 1
        except Exception:
            effective_action = rule.action
            event = {
                "event": "deception",
                "client_ip": client_ip,
                "attacker_key": attacker_key,
                "source_type": identity.source_type,
                "worker_zone": identity.worker_zone,
                "method": request.method,
                "path": request.path_qs,
                "profile": rule.profile,
                "rule": rule.name,
                "category": rule.category,
                "action": effective_action,
                "scanner": classification.scanner,
                "scanner_family": classification.scanner_family,
                "fingerprint": classification.fingerprint,
                "severity": classification.severity,
                "escalation_level": 1,
                "attacker_score": classification.severity,
                "prior_hits": 0,
                "observed_hits": 1,
            }
            self.stats["telemetry_errors"] += 1
            escalation = type(
                "FallbackEscalation",
                (),
                {"level": 1, "tarpit_seconds": self.settings.tarpit_max_seconds},
            )()
            persist_event = True

        self.stats["deceptions"] += 1
        self.stats[f"category:{rule.category}"] += 1
        self.stats[f"scanner:{classification.scanner}"] += 1
        self.stats[f"escalation:{event.get('escalation_level', 1)}"] += 1
        if identity.source_type == "cloudflare-worker":
            self.stats["cloudflare_worker_events"] += 1

        if persist_event:
            self.stats["events_persisted_total"] += 1
            await self._safe_event_write(event)
            try:
                await self.maybe_notify(event)
            except Exception:
                self.stats["telemetry_errors"] += 1
                self.stats["notification_state_errors"] += 1

        self.deceptions_since_prune += 1
        if self.deceptions_since_prune >= 1024:
            self._prune_runtime_attackers(now=now)
            self.deceptions_since_prune = 0

        if effective_action == "tarpit" and self.settings.tarpit_enabled:
            return await self.tarpit(request, rule, max_seconds=escalation.tarpit_seconds)
        return web.Response(
            status=rule.status,
            text=rule.response,
            content_type=rule.content_type.split(";", 1)[0],
        )


def build_app(settings: Settings | None = None) -> web.Application:
    settings = settings or Settings.from_env()
    hotpot = DurableGatewayHotpot(settings)
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
