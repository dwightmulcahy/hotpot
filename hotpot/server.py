from __future__ import annotations

import asyncio
import json
import os
import sqlite3
import time
from collections import Counter
from datetime import datetime, timezone
from typing import Any

from aiohttp import ClientSession, ClientTimeout, web
from multidict import CIMultiDict

from .app import HOTPOT_APP_KEY, Hotpot, clean_headers
from .config import Settings
from .intelligence import classify, escalation_for
from .network import Allowlist, ClientIPResolver
from .notification_spool import NotificationSpool
from .notifications import Notifier
from .rate_limit import EventRateLimiter
from .rules import RuleEngine
from .runtime_components import (
    ResilientEventLogger,
    ResilientSourceStore,
    ResourceBudget,
)
from .store import AttackerState
from .telemetry import BoundedTelemetryQueue, TelemetryWork


class HotpotServer(Hotpot):
    """Single production Hotpot runtime with explicitly composed subsystems."""

    HEALTHCHECK_FALLBACK_STATUSES = {405, 501}
    HEALTHCHECK_GET_BYTES = 1024

    def __init__(self, settings: Settings):
        self.settings = settings
        self.rules = RuleEngine.load(settings.profiles_dir, settings.enabled_profiles)
        self.events = ResilientEventLogger(settings.data_dir)
        self.store = ResilientSourceStore(settings.data_dir)
        self.allowlist = Allowlist(settings.allow_cidrs)
        self.client_ips = ClientIPResolver(
            settings.client_ip_mode, settings.trusted_proxy_cidrs
        )
        self.notifier = Notifier(settings)
        self.client: ClientSession | None = None
        self.housekeeping_task: asyncio.Task | None = None
        self.health_task: asyncio.Task | None = None
        self.notification_retry_task: asyncio.Task | None = None
        self.tarpit_slots = asyncio.Semaphore(settings.tarpit_max_concurrent)
        self.intelligence_lock = asyncio.Lock()
        self.stats = Counter()
        self.started = time.monotonic()

        self.health_interval = max(
            5, int(os.getenv("HOTPOT_HEALTHCHECK_INTERVAL_SECONDS", "30"))
        )
        self.health_timeout = max(
            1.0, float(os.getenv("HOTPOT_HEALTHCHECK_TIMEOUT_SECONDS", "5"))
        )
        self.upstream_health: dict[str, Any] = {
            "healthy": False,
            "status": None,
            "latency_ms": None,
            "last_checked": None,
            "last_success": None,
            "last_failure": None,
            "consecutive_failures": 0,
            "error": "not_checked",
            "probe_method": None,
            "body_read_limit": 0,
        }

        self.preserve_host = os.getenv("HOTPOT_PRESERVE_HOST", "true").strip().lower() in {
            "1",
            "true",
            "yes",
            "on",
        }
        self.event_rate_limit = max(
            0, int(os.getenv("HOTPOT_EVENT_RATE_LIMIT_PER_MINUTE", "120"))
        )
        self.event_burst = max(
            1, int(os.getenv("HOTPOT_EVENT_RATE_LIMIT_BURST", "30"))
        )
        self.event_state_ttl = max(
            60, int(os.getenv("HOTPOT_EVENT_STATE_TTL_SECONDS", "3600"))
        )
        self.event_max_sources = max(
            100, int(os.getenv("HOTPOT_EVENT_MAX_SOURCES", "10000"))
        )
        self.event_limiter = EventRateLimiter(
            self.event_rate_limit,
            self.event_burst,
            ttl_seconds=self.event_state_ttl,
            max_sources=self.event_max_sources,
        )
        self.runtime_attackers: dict[str, tuple[int, int, float]] = {}
        self.deceptions_since_prune = 0

        self.version = os.getenv("HOTPOT_VERSION", "dev").strip() or "dev"
        self.git_sha = os.getenv("HOTPOT_GIT_SHA", "unknown").strip() or "unknown"
        self.build_date = os.getenv("HOTPOT_BUILD_DATE", "unknown").strip() or "unknown"
        self.client_body_timeout = max(
            1.0, float(os.getenv("HOTPOT_CLIENT_BODY_TIMEOUT_SECONDS", "30"))
        )
        self.resources = ResourceBudget.from_env(
            max_request_body=settings.max_request_body
        )
        telemetry_capacity = max(
            32, int(os.getenv("HOTPOT_TELEMETRY_QUEUE_MAX", "2048"))
        )
        notify_reserve = max(
            1, int(os.getenv("HOTPOT_TELEMETRY_NOTIFY_RESERVE", "128"))
        )
        self.telemetry_queue = BoundedTelemetryQueue(
            capacity=telemetry_capacity,
            drain_timeout=max(
                0.1,
                float(os.getenv("HOTPOT_TELEMETRY_DRAIN_TIMEOUT_SECONDS", "5")),
            ),
            notify_reserve=notify_reserve,
        )
        self.notification_retry_seconds = max(
            10, int(os.getenv("HOTPOT_NOTIFICATION_RETRY_SECONDS", "60"))
        )
        self.notification_spool = NotificationSpool(
            settings.data_dir, retry_seconds=self.notification_retry_seconds
        )

        for key in (
            "tarpits_active",
            "tarpits_total",
            "tarpits_completed",
            "tarpits_disconnected",
            "telemetry_errors",
            "events_suppressed_total",
            "events_persisted_total",
            "request_body_rejected",
            "request_body_timeout",
            "resource_rejections_upstream",
            "resource_rejections_websocket",
            "resource_rejections_buffer",
            "telemetry_queue_dropped",
            "telemetry_queue_dropped_jsonl",
            "telemetry_queue_dropped_notify",
            "notification_spool_enqueued",
            "notification_spool_retry_sent",
            "notification_spool_retry_errors",
            "notification_spool_suppressed",
        ):
            self.stats[key] = 0
        if self.store.inner is None:
            self.stats["telemetry_errors"] += 1
            self.stats["sqlite_init_errors"] += 1
        if self.events.inner is None:
            self.stats["telemetry_errors"] += 1
            self.stats["jsonl_init_errors"] += 1

    async def startup(self, app: web.Application) -> None:
        try:
            await self.run_housekeeping()
        except Exception:
            self.stats["telemetry_errors"] += 1
            self.stats["housekeeping_errors"] += 1
        self.client = ClientSession(
            timeout=ClientTimeout(total=self.settings.upstream_timeout),
            auto_decompress=False,
        )
        self.housekeeping_task = asyncio.create_task(
            self.housekeeping_loop(), name="hotpot-housekeeping"
        )
        await self.check_upstream()
        self.health_task = asyncio.create_task(
            self.health_loop(), name="hotpot-upstream-health"
        )
        await self.telemetry_queue.start(self._process_telemetry_work)
        self.notification_retry_task = asyncio.create_task(
            self._notification_retry_loop(), name="hotpot-notification-retry"
        )

    async def shutdown(self, app: web.Application) -> None:
        if self.notification_retry_task:
            self.notification_retry_task.cancel()
            await asyncio.gather(
                self.notification_retry_task, return_exceptions=True
            )
        await self.telemetry_queue.stop()
        if self.health_task:
            self.health_task.cancel()
            await asyncio.gather(self.health_task, return_exceptions=True)
        if self.housekeeping_task:
            self.housekeeping_task.cancel()
            await asyncio.gather(self.housekeeping_task, return_exceptions=True)
        if self.client:
            await self.client.close()

    async def health_loop(self) -> None:
        while True:
            try:
                await asyncio.sleep(self.health_interval)
                await self.check_upstream()
            except asyncio.CancelledError:
                raise
            except Exception:
                self.stats["healthcheck_errors"] += 1

    async def _probe_upstream(self, method: str) -> int:
        assert self.client is not None
        headers = None
        if method == "GET":
            headers = {"Range": f"bytes=0-{self.HEALTHCHECK_GET_BYTES - 1}"}
        async with self.client.request(
            method,
            self.settings.upstream + "/",
            headers=headers,
            allow_redirects=False,
            timeout=ClientTimeout(total=self.health_timeout),
        ) as response:
            if method == "GET":
                await response.content.read(self.HEALTHCHECK_GET_BYTES)
            return int(response.status)

    async def check_upstream(self) -> None:
        started = time.monotonic()
        now = datetime.now(timezone.utc).isoformat()
        previous = self.upstream_health
        probe_method = "HEAD"
        try:
            status = await self._probe_upstream(probe_method)
            if status in self.HEALTHCHECK_FALLBACK_STATUSES:
                probe_method = "GET"
                status = await self._probe_upstream(probe_method)
            healthy = status < 500
            failures = 0 if healthy else int(previous.get("consecutive_failures", 0)) + 1
            self.upstream_health = {
                "healthy": healthy,
                "status": status,
                "latency_ms": round((time.monotonic() - started) * 1000, 1),
                "last_checked": now,
                "last_success": now if healthy else previous.get("last_success"),
                "last_failure": previous.get("last_failure") if healthy else now,
                "consecutive_failures": failures,
                "error": None if healthy else f"HTTP {status}",
                "probe_method": probe_method,
                "body_read_limit": self.HEALTHCHECK_GET_BYTES
                if probe_method == "GET"
                else 0,
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
                "probe_method": probe_method,
                "body_read_limit": self.HEALTHCHECK_GET_BYTES
                if probe_method == "GET"
                else 0,
            }

    def authorized(self, request: web.Request) -> bool:
        token = self.settings.admin_token
        if not token:
            return False
        from . import production as production_compat

        return production_compat.hmac.compare_digest(
            request.headers.get("Authorization", ""), f"Bearer {token}"
        )

    async def live(self, request: web.Request) -> web.Response:
        return web.json_response(
            {
                "alive": True,
                "instance_id": self.settings.instance_id,
                "version": self.version,
                "git_sha": self.git_sha,
            }
        )

    async def health(self, request: web.Request) -> web.Response:
        payload = {
            "healthy": bool(self.upstream_health["healthy"]),
            "instance_id": self.settings.instance_id,
            "upstream": self.upstream_health,
        }
        return web.json_response(payload, status=200 if payload["healthy"] else 503)

    @property
    def source_id(self) -> str | None:
        return self.store.source_id

    def _max_event_id_sync(self) -> int:
        if self.store.path is None:
            return 0
        conn = sqlite3.connect(self.store.path, timeout=10)
        try:
            row = conn.execute("SELECT COALESCE(MAX(id), 0) FROM events").fetchone()
            return int(row[0] or 0) if row else 0
        finally:
            conn.close()

    def _events_since_sync(self, cursor: int, limit: int) -> dict[str, Any]:
        if self.store.path is None:
            return {"events": [], "next_cursor": cursor, "has_more": False}
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

    async def events_api(self, request: web.Request) -> web.Response:
        if not self.authorized(request):
            raise web.HTTPUnauthorized()
        try:
            cursor = max(0, int(request.query.get("cursor", "0")))
            limit = max(1, min(500, int(request.query.get("limit", "250"))))
        except ValueError as exc:
            raise web.HTTPBadRequest(text="cursor and limit must be integers") from exc
        result = await asyncio.to_thread(self._events_since_sync, cursor, limit)
        result.update(
            instance_id=self.settings.instance_id,
            instance_name=self.settings.instance_name,
            source_id=self.source_id,
            event_cursor_max=await asyncio.to_thread(self._max_event_id_sync),
        )
        return web.json_response(result, headers={"Cache-Control": "no-store"})

    async def status(self, request: web.Request) -> web.Response:
        if not self.authorized(request):
            raise web.HTTPUnauthorized()
        try:
            snapshot = await self.store.dashboard_snapshot(limit=10)
        except Exception:
            self.stats["telemetry_errors"] += 1
            self.stats["sqlite_read_errors"] += 1
            snapshot = {
                "events": 0,
                "unique_ips": 0,
                "top_categories": [],
                "top_offenders": [],
            }
        payload = {
            "healthy": bool(self.upstream_health["healthy"]),
            "instance_id": self.settings.instance_id,
            "instance_name": self.settings.instance_name,
            "upstream": self.settings.upstream,
            "upstream_health": self.upstream_health,
            "profiles": self.settings.enabled_profiles,
            "rules": len(self.rules.rules),
            "version": self.version,
            "git_sha": self.git_sha,
            "build_date": self.build_date,
            "build": {
                "version": self.version,
                "git_sha": self.git_sha,
                "build_date": self.build_date,
            },
            "source_id": self.source_id,
            "event_cursor_max": await asyncio.to_thread(self._max_event_id_sync),
            "proxy": {
                "preserve_host": self.preserve_host,
                "max_request_body": self.settings.max_request_body,
                "client_body_timeout_seconds": self.client_body_timeout,
            },
            "resource_budget": {
                **self.resources.snapshot(),
                "tarpit_max_concurrent": self.settings.tarpit_max_concurrent,
                "tarpits_active": int(self.stats.get("tarpits_active", 0)),
            },
            "event_persistence": {
                "rate_limit_per_minute": self.event_rate_limit,
                "burst": self.event_burst,
                "state_ttl_seconds": self.event_state_ttl,
            },
            "tarpit": {
                "enabled": self.settings.tarpit_enabled,
                "max_concurrent": self.settings.tarpit_max_concurrent,
                "max_seconds": self.settings.tarpit_max_seconds,
                "escalated_max_seconds": self.settings.tarpit_escalated_max_seconds,
            },
            "client_ip": {
                "mode": self.settings.client_ip_mode,
                "trusted_proxy_cidrs": self.settings.trusted_proxy_cidrs,
            },
            "allowlist": {"cidrs": self.settings.allow_cidrs},
            "retention": {
                "events_days": self.settings.retention_days,
                "attackers_days": self.settings.attacker_retention_days,
                "housekeeping_interval_seconds": self.settings.housekeeping_interval_seconds,
            },
            "notifications": {
                "enabled": self.notifier.enabled,
                "min_level": self.settings.notify_min_level,
                "cooldown_seconds": self.settings.notify_cooldown_seconds,
                "webhook": bool(self.settings.notify_webhook_url),
                "email": bool(
                    self.settings.smtp_host
                    and self.settings.smtp_from
                    and self.settings.smtp_to
                ),
            },
            "notification_spool": await self.notification_spool.snapshot(),
            "telemetry_queue": self.telemetry_queue.snapshot(),
            "stats": dict(self.stats),
            "intelligence": {
                "events": snapshot.get("events", 0),
                "unique_ips": snapshot.get("unique_ips", 0),
                "top_categories": snapshot.get("top_categories", [])[:5],
                "top_offenders": snapshot.get("top_offenders", [])[:5],
            },
            "uptime_seconds": int(time.monotonic() - self.started),
        }
        return web.json_response(payload, headers={"Cache-Control": "no-store"})

    async def handler(self, request: web.Request) -> web.StreamResponse:
        if request.path == "/_hotpot/live":
            return await self.live(request)
        if request.path == "/_hotpot/api/events":
            return await self.events_api(request)
        return await super().handler(request)

    def _prune_runtime_attackers(self, *, now: float | None = None) -> None:
        current = time.monotonic() if now is None else now
        cutoff = current - self.event_state_ttl
        stale = [key for key, value in self.runtime_attackers.items() if value[2] < cutoff]
        for key in stale:
            self.runtime_attackers.pop(key, None)
        self.event_limiter.prune(now=current)
        if len(self.runtime_attackers) >= self.event_max_sources:
            remove = max(1, self.event_max_sources // 4)
            oldest = sorted(
                self.runtime_attackers.items(), key=lambda item: item[1][2]
            )[:remove]
            for key, _ in oldest:
                self.runtime_attackers.pop(key, None)

    def forwarding_headers(self, request: web.Request) -> CIMultiDict:
        headers = clean_headers(request.headers)
        identity = self.client_identity(request)
        forwarded_proto = request.scheme
        if identity.trusted_proxy:
            candidate = (
                request.headers.get("X-Forwarded-Proto", "")
                .split(",", 1)[0]
                .strip()
                .lower()
            )
            if candidate in {"http", "https"}:
                forwarded_proto = candidate
        headers["X-Forwarded-For"] = identity.client_ip
        headers["X-Real-IP"] = identity.client_ip
        headers["X-Forwarded-Proto"] = forwarded_proto
        headers["X-Forwarded-Host"] = request.host
        if self.preserve_host:
            headers["Host"] = request.host
        return headers

    async def _request_data(self, request: web.Request) -> tuple[Any, int]:
        if request.content_length is not None:
            if request.content_length > self.settings.max_request_body:
                self.stats["request_body_rejected"] += 1
                raise web.HTTPRequestEntityTooLarge(
                    max_size=self.settings.max_request_body,
                    actual_size=request.content_length,
                )
            return request.content.iter_chunked(64 * 1024), 0
        if not request.can_read_body:
            return None, 0

        body = bytearray()
        reserved = 0
        try:
            async with asyncio.timeout(self.client_body_timeout):
                async for chunk in request.content.iter_chunked(64 * 1024):
                    if len(body) + len(chunk) > self.settings.max_request_body:
                        self.stats["request_body_rejected"] += 1
                        raise web.HTTPRequestEntityTooLarge(
                            max_size=self.settings.max_request_body,
                            actual_size=len(body) + len(chunk),
                        )
                    if not await self.resources.reserve_buffer(len(chunk)):
                        self.stats["resource_rejections_buffer"] += 1
                        raise web.HTTPServiceUnavailable(
                            text="Hotpot buffered request budget is busy",
                            headers={"Retry-After": "1"},
                        )
                    reserved += len(chunk)
                    body.extend(chunk)
        except TimeoutError as exc:
            self.stats["request_body_timeout"] += 1
            if reserved:
                await self.resources.release_buffer(reserved)
            raise web.HTTPRequestTimeout(text="request body timed out") from exc
        except Exception:
            if reserved:
                await self.resources.release_buffer(reserved)
            raise
        return bytes(body), reserved

    async def proxy_http(self, request: web.Request) -> web.StreamResponse:
        assert self.client is not None
        reserved = 0
        acquired = False
        try:
            data, reserved = await self._request_data(request)
            if not await self.resources.acquire_upstream():
                self.stats["resource_rejections_upstream"] += 1
                raise web.HTTPServiceUnavailable(
                    text="Hotpot upstream concurrency budget is busy",
                    headers={"Retry-After": "1"},
                )
            acquired = True
            self.stats["proxied"] += 1
            async with self.client.request(
                request.method,
                self.upstream_url(request),
                headers=self.forwarding_headers(request),
                data=data,
                allow_redirects=False,
            ) as upstream:
                response = web.StreamResponse(
                    status=upstream.status,
                    reason=upstream.reason,
                    headers=clean_headers(upstream.headers, response=True),
                )
                await response.prepare(request)
                async for chunk in upstream.content.iter_chunked(64 * 1024):
                    await response.write(chunk)
                await response.write_eof()
                return response
        except (
            web.HTTPRequestEntityTooLarge,
            web.HTTPRequestTimeout,
            web.HTTPServiceUnavailable,
        ):
            raise
        except Exception as exc:
            self.stats["upstream_errors"] += 1
            await self._safe_event_write(
                {
                    "event": "upstream_error",
                    "method": request.method,
                    "path": request.path_qs,
                    "error": type(exc).__name__,
                }
            )
            raise web.HTTPBadGateway(text="Bad Gateway") from exc
        finally:
            if reserved:
                await self.resources.release_buffer(reserved)
            if acquired:
                self.resources.release_upstream()

    async def proxy_websocket(self, request: web.Request) -> web.WebSocketResponse:
        if not await self.resources.acquire_websocket():
            self.stats["resource_rejections_websocket"] += 1
            raise web.HTTPServiceUnavailable(
                text="Hotpot websocket concurrency budget is busy",
                headers={"Retry-After": "1"},
            )
        try:
            return await super().proxy_websocket(request)
        finally:
            self.resources.release_websocket()

    async def tarpit(
        self, request: web.Request, rule, *, max_seconds: float | None = None
    ) -> web.StreamResponse:
        try:
            await asyncio.wait_for(self.tarpit_slots.acquire(), timeout=0.05)
        except TimeoutError:
            self.stats["tarpit_overflow"] += 1
            return web.Response(
                status=rule.status,
                text=rule.response,
                content_type=rule.content_type.split(";", 1)[0],
            )
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
            lifetime = (
                max_seconds
                if max_seconds is not None
                else self.settings.tarpit_max_seconds
            )
            while time.monotonic() - started < lifetime:
                chunk = body[pos : pos + 32]
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
            self.stats["tarpits_active"] = max(
                0, self.stats["tarpits_active"] - 1
            )
            self.stats[
                "tarpits_disconnected" if disconnected else "tarpits_completed"
            ] += 1
            self.tarpit_slots.release()

    def _submit_telemetry(self, kind: str, event: dict) -> bool:
        accepted = self.telemetry_queue.submit(kind, event)
        if not accepted:
            self.stats["telemetry_queue_dropped"] += 1
            self.stats[f"telemetry_queue_dropped_{kind}"] += 1
        return accepted

    async def _write_event_direct(self, event: dict[str, Any]) -> None:
        try:
            await self.events.write(event)
        except Exception:
            self.stats["telemetry_errors"] += 1
            self.stats["jsonl_errors"] += 1

    async def _safe_event_write(self, event: dict[str, Any]) -> None:
        if self.telemetry_queue.running:
            self._submit_telemetry("jsonl", event)
            return
        await self._write_event_direct(event)

    async def _process_telemetry_work(self, work: TelemetryWork) -> None:
        if work.kind == "jsonl":
            await self._write_event_direct(work.event)
            return
        if work.kind == "notify":
            await self._notify_direct(work.event)
            return
        self.stats["telemetry_errors"] += 1
        raise RuntimeError(f"unknown telemetry work kind: {work.kind}")

    async def maybe_notify(self, event: dict) -> None:
        if not self.notifier.enabled:
            return
        level = int(event.get("escalation_level", 1))
        if level < self.settings.notify_min_level:
            return
        if self.telemetry_queue.running:
            if not self._submit_telemetry("notify", event):
                await self.notification_spool.enqueue(
                    event, claimed=False, error="telemetry notification queue full"
                )
                self.stats["notification_spool_enqueued"] += 1
            return
        await self._notify_direct(event)

    async def _send_notification(self, event: dict) -> None:
        assert self.client is not None
        channels = await self.notifier.send(self.client, event)
        self.stats["notifications_sent"] += 1
        await self._write_event_direct(
            {
                "event": "notification_sent",
                "client_ip": event.get("client_ip", "unknown"),
                "attacker_key": event.get("attacker_key")
                or event.get("client_ip", "unknown"),
                "source_type": event.get("source_type", "ip"),
                "worker_zone": event.get("worker_zone"),
                "escalation_level": int(event.get("escalation_level", 1)),
                "channels": channels,
            }
        )

    async def _notify_direct(self, event: dict) -> None:
        if not self.notifier.enabled:
            return
        level = int(event.get("escalation_level", 1))
        if level < self.settings.notify_min_level:
            return
        actor_key = str(
            event.get("attacker_key") or event.get("client_ip", "unknown")
        )
        claimed = False
        try:
            should_send = await self.store.claim_notification(
                actor_key, level, self.settings.notify_cooldown_seconds
            )
            if not should_send:
                self.stats["notifications_suppressed"] += 1
                return
            claimed = True
            await self._send_notification(event)
        except Exception as exc:
            self.stats["notification_errors"] += 1
            await self.notification_spool.enqueue(
                event,
                claimed=claimed,
                error=f"{type(exc).__name__}: {exc}",
            )
            self.stats["notification_spool_enqueued"] += 1
            await self._write_event_direct(
                {
                    "event": "notification_error",
                    "client_ip": event.get("client_ip", "unknown"),
                    "attacker_key": actor_key,
                    "source_type": event.get("source_type", "ip"),
                    "worker_zone": event.get("worker_zone"),
                    "escalation_level": level,
                    "error": type(exc).__name__,
                    "spooled": True,
                }
            )

    async def _notification_retry_loop(self) -> None:
        while True:
            try:
                await asyncio.sleep(self.notification_retry_seconds)
                await self._retry_spooled_notifications()
            except asyncio.CancelledError:
                raise
            except Exception:
                self.stats["notification_spool_retry_errors"] += 1

    async def _retry_spooled_notifications(self) -> None:
        if not self.notifier.enabled or self.client is None:
            return
        for job in await self.notification_spool.due(limit=25):
            job_id = int(job["id"])
            event = dict(job.get("event") or {})
            claimed = bool(job.get("claimed"))
            try:
                if not claimed:
                    actor_key = str(
                        event.get("attacker_key")
                        or event.get("client_ip", "unknown")
                    )
                    level = int(event.get("escalation_level", 1))
                    should_send = await self.store.claim_notification(
                        actor_key, level, self.settings.notify_cooldown_seconds
                    )
                    if not should_send:
                        await self.notification_spool.mark_done(
                            job_id, status="suppressed"
                        )
                        self.stats["notification_spool_suppressed"] += 1
                        continue
                    await self.notification_spool.mark_claimed(job_id)
                await self._send_notification(event)
                await self.notification_spool.mark_done(job_id, status="sent")
                self.stats["notification_spool_retry_sent"] += 1
            except Exception as exc:
                await self.notification_spool.mark_error(
                    job_id, f"{type(exc).__name__}: {exc}"
                )
                self.stats["notification_spool_retry_errors"] += 1

    async def deception(self, request: web.Request, rule) -> web.StreamResponse:
        identity = self.client_identity(request)
        client_ip = identity.client_ip
        actor_key = identity.actor_key
        user_agent = request.headers.get("User-Agent", "")
        classification = classify(
            user_agent, rule.category, request.method, request.path_qs
        )
        now = time.monotonic()
        persist_event = True
        suppressed_before = 0
        prior = AttackerState(actor_key, 0, 0, None, None, None, None, 1)
        try:
            async with self.intelligence_lock:
                cached = self.runtime_attackers.get(actor_key)
                if cached is None:
                    try:
                        prior = await self.store.state_for(actor_key)
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
                self.runtime_attackers[actor_key] = (
                    observed_hits,
                    escalation.score,
                    now,
                )
                effective_action = rule.action
                if escalation.force_tarpit and self.settings.tarpit_enabled:
                    effective_action = "tarpit"
                persist_event, suppressed_before = self.event_limiter.admit(
                    actor_key, now=now
                )
                event = {
                    "event": "deception",
                    "client_ip": client_ip,
                    "attacker_key": actor_key,
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
                "attacker_key": actor_key,
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
            await self.maybe_notify(event)
        self.deceptions_since_prune += 1
        if self.deceptions_since_prune >= 1024:
            self._prune_runtime_attackers(now=now)
            self.deceptions_since_prune = 0
        if effective_action == "tarpit" and self.settings.tarpit_enabled:
            return await self.tarpit(
                request, rule, max_seconds=escalation.tarpit_seconds
            )
        return web.Response(
            status=rule.status,
            text=rule.response,
            content_type=rule.content_type.split(";", 1)[0],
        )


def build_app(settings: Settings | None = None) -> web.Application:
    settings = settings or Settings.from_env()
    hotpot = HotpotServer(settings)
    app = web.Application(client_max_size=settings.max_request_body)
    app[HOTPOT_APP_KEY] = hotpot
    app.on_startup.append(hotpot.startup)
    app.on_cleanup.append(hotpot.shutdown)
    app.router.add_route("*", "/{tail:.*}", hotpot.handler)
    return app


def main() -> None:
    settings = Settings.from_env()
    web.run_app(
        build_app(settings),
        host=settings.bind,
        port=settings.port,
        access_log=None,
    )


if __name__ == "__main__":
    main()
