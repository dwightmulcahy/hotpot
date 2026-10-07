from __future__ import annotations

import asyncio
import hmac
import json
import os
import time
from datetime import datetime, timezone
from typing import AsyncIterator

from aiohttp import ClientTimeout, web
from multidict import CIMultiDict

from . import app as core_app
from .app import HOTPOT_APP_KEY
from .config import Settings
from .intelligence import classify, escalation_for
from .rate_limit import EventRateLimiter
from .runtime import HardenedHotpot
from .store import AttackerState


def _env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


class ProductionHotpot(HardenedHotpot):
    """Final production policy layer for proxy and telemetry hardening."""

    HEALTHCHECK_FALLBACK_STATUSES = {405, 501}
    HEALTHCHECK_GET_BYTES = 1024

    def __init__(self, settings: Settings):
        super().__init__(settings)
        self.preserve_host = _env_bool("HOTPOT_PRESERVE_HOST", True)
        self.event_rate_limit = max(0, int(os.getenv("HOTPOT_EVENT_RATE_LIMIT_PER_MINUTE", "120")))
        self.event_burst = max(1, int(os.getenv("HOTPOT_EVENT_RATE_LIMIT_BURST", "30")))
        self.event_state_ttl = max(60, int(os.getenv("HOTPOT_EVENT_STATE_TTL_SECONDS", "3600")))
        self.event_max_sources = max(100, int(os.getenv("HOTPOT_EVENT_MAX_SOURCES", "10000")))
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

        self.stats["events_suppressed_total"] = 0
        self.stats["events_persisted_total"] = 0
        self.stats["request_body_rejected"] = 0

    def authorized(self, request: web.Request) -> bool:
        """Authenticate admin endpoints without ordinary string equality."""

        token = self.settings.admin_token
        if not token:
            return False
        presented = request.headers.get("Authorization", "")
        expected = f"Bearer {token}"
        return hmac.compare_digest(presented, expected)

    async def _probe_upstream(self, method: str) -> int:
        assert self.client is not None
        timeout = ClientTimeout(total=self.health_timeout)
        headers = None
        if method == "GET":
            # Ask cooperative origins for only a byte range and, regardless of whether
            # they honor it, read only a tiny prefix before releasing the response.
            headers = {"Range": f"bytes=0-{self.HEALTHCHECK_GET_BYTES - 1}"}
        async with self.client.request(
            method,
            self.settings.upstream + "/",
            headers=headers,
            allow_redirects=False,
            timeout=timeout,
        ) as response:
            if method == "GET":
                await response.content.read(self.HEALTHCHECK_GET_BYTES)
            return int(response.status)

    async def check_upstream(self) -> None:
        """Probe readiness without downloading the protected application's homepage."""

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
            latency = round((time.monotonic() - started) * 1000, 1)
            failures = 0 if healthy else int(previous.get("consecutive_failures", 0)) + 1
            self.upstream_health = {
                "healthy": healthy,
                "status": status,
                "latency_ms": latency,
                "last_checked": now,
                "last_success": now if healthy else previous.get("last_success"),
                "last_failure": previous.get("last_failure") if healthy else now,
                "consecutive_failures": failures,
                "error": None if healthy else f"HTTP {status}",
                "probe_method": probe_method,
                "body_read_limit": self.HEALTHCHECK_GET_BYTES if probe_method == "GET" else 0,
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
                "body_read_limit": self.HEALTHCHECK_GET_BYTES if probe_method == "GET" else 0,
            }

    def _prune_runtime_attackers(self, *, now: float | None = None) -> None:
        current = time.monotonic() if now is None else now
        cutoff = current - self.event_state_ttl
        stale = [ip for ip, value in self.runtime_attackers.items() if value[2] < cutoff]
        for ip in stale:
            self.runtime_attackers.pop(ip, None)
        self.event_limiter.prune(now=current)

        if len(self.runtime_attackers) >= self.event_max_sources:
            remove = max(1, self.event_max_sources // 4)
            oldest = sorted(self.runtime_attackers.items(), key=lambda item: item[1][2])[:remove]
            for ip, _ in oldest:
                self.runtime_attackers.pop(ip, None)

    async def live(self, request: web.Request) -> web.Response:
        return web.json_response(
            {
                "alive": True,
                "instance_id": self.settings.instance_id,
                "version": self.version,
                "git_sha": self.git_sha,
            }
        )

    async def status(self, request: web.Request) -> web.Response:
        response = await super().status(request)
        payload = json.loads(response.text)
        payload.update(
            {
                "version": self.version,
                "git_sha": self.git_sha,
                "build_date": self.build_date,
                "build": {
                    "version": self.version,
                    "git_sha": self.git_sha,
                    "build_date": self.build_date,
                },
                "proxy": {
                    "preserve_host": self.preserve_host,
                    "max_request_body": self.settings.max_request_body,
                },
                "event_persistence": {
                    "rate_limit_per_minute": self.event_rate_limit,
                    "burst": self.event_burst,
                    "state_ttl_seconds": self.event_state_ttl,
                },
            }
        )
        payload["stats"] = dict(self.stats)
        return web.json_response(payload, headers={"Cache-Control": "no-store"})

    def forwarding_headers(self, request: web.Request) -> CIMultiDict:
        headers = core_app.clean_headers(request.headers)
        identity = self.client_identity(request)

        # Never accept forwarding metadata from an untrusted TCP peer. The same
        # trust boundary used for the client IP now also governs the original scheme.
        forwarded_proto = request.scheme
        if identity.trusted_proxy:
            candidate = request.headers.get("X-Forwarded-Proto", "").split(",", 1)[0].strip().lower()
            if candidate in {"http", "https"}:
                forwarded_proto = candidate

        headers["X-Forwarded-For"] = identity.client_ip
        headers["X-Real-IP"] = identity.client_ip
        headers["X-Forwarded-Proto"] = forwarded_proto
        headers["X-Forwarded-Host"] = request.host
        if self.preserve_host:
            headers["Host"] = request.host
        return headers

    async def _bounded_request_body(self, request: web.Request) -> AsyncIterator[bytes]:
        total = 0
        async for chunk in request.content.iter_chunked(64 * 1024):
            total += len(chunk)
            if total > self.settings.max_request_body:
                self.stats["request_body_rejected"] += 1
                raise web.HTTPRequestEntityTooLarge(
                    max_size=self.settings.max_request_body,
                    actual_size=total,
                )
            yield chunk

    async def proxy_http(self, request: web.Request) -> web.StreamResponse:
        assert self.client is not None
        if request.content_length is not None and request.content_length > self.settings.max_request_body:
            self.stats["request_body_rejected"] += 1
            raise web.HTTPRequestEntityTooLarge(
                max_size=self.settings.max_request_body,
                actual_size=request.content_length,
            )

        self.stats["proxied"] += 1
        try:
            async with self.client.request(
                request.method,
                self.upstream_url(request),
                headers=self.forwarding_headers(request),
                data=self._bounded_request_body(request),
                allow_redirects=False,
            ) as upstream:
                response = web.StreamResponse(
                    status=upstream.status,
                    reason=upstream.reason,
                    headers=core_app.clean_headers(upstream.headers, response=True),
                )
                await response.prepare(request)
                async for chunk in upstream.content.iter_chunked(64 * 1024):
                    await response.write(chunk)
                await response.write_eof()
                return response
        except web.HTTPRequestEntityTooLarge:
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

    async def deception(self, request: web.Request, rule) -> web.StreamResponse:
        identity = self.client_identity(request)
        ip = identity.client_ip
        user_agent = request.headers.get("User-Agent", "")
        classification = classify(user_agent, rule.category, request.method, request.path_qs)
        now = time.monotonic()

        persist_event = True
        suppressed_before = 0
        prior = AttackerState(ip, 0, 0, None, None, None, None, 1)
        try:
            async with self.intelligence_lock:
                cached = self.runtime_attackers.get(ip)
                if cached is None:
                    try:
                        prior = await self.store.state_for(ip)
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
                self.runtime_attackers[ip] = (observed_hits, escalation.score, now)

                effective_action = rule.action
                if escalation.force_tarpit and self.settings.tarpit_enabled:
                    effective_action = "tarpit"

                persist_event, suppressed_before = self.event_limiter.admit(ip, now=now)
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
                "client_ip": ip,
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
    hotpot = ProductionHotpot(settings)
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
