from __future__ import annotations

import asyncio
import os
import time
from pathlib import Path
from typing import Any

from aiohttp import web

from . import runtime as core
from .geoip_enrichment import GeoIPEnricher
from .response_recommendations import ResponsePolicy, ThreatResponseStore
from .template import PRODUCTION_HTML


def _env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


class ProductionDashboard(core.Dashboard):
    def __init__(self) -> None:
        super().__init__()
        self.retention_days = max(
            1, int(os.getenv("HOTPOT_DASHBOARD_EVENT_RETENTION_DAYS", "90"))
        )
        self.housekeeping_interval_seconds = max(
            900.0,
            float(os.getenv("HOTPOT_DASHBOARD_HOUSEKEEPING_INTERVAL_HOURS", "6"))
            * 3600.0,
        )
        self.geoip_enrich_batch = max(
            1,
            min(
                5000,
                int(os.getenv("HOTPOT_DASHBOARD_GEOIP_ENRICH_BATCH", "500")),
            ),
        )
        self.response_policy = ResponsePolicy(
            enabled=_env_bool("HOTPOT_RESPONSE_ENABLED", True),
            active_window_hours=max(
                1, int(os.getenv("HOTPOT_RESPONSE_ACTIVE_WINDOW_HOURS", "24"))
            ),
            stale_minutes=max(
                15, int(os.getenv("HOTPOT_RESPONSE_STALE_MINUTES", "360"))
            ),
            recommendation_ttl_hours=max(
                1, int(os.getenv("HOTPOT_RESPONSE_RECOMMENDATION_TTL_HOURS", "24"))
            ),
            dismiss_hours=max(
                1, int(os.getenv("HOTPOT_RESPONSE_DISMISS_HOURS", "24"))
            ),
        )
        self._last_housekeeping = 0.0
        self.maintenance_errors = 0
        self.store = ThreatResponseStore(
            Path(os.getenv("HOTPOT_DASHBOARD_DATA_DIR", "/data")),
            retention_days=self.retention_days,
        )
        self.geoip = GeoIPEnricher()

    async def shutdown(self, app: web.Application) -> None:
        self.geoip.close()
        await super().shutdown(app)

    @staticmethod
    def _status_error(instance, error: str) -> dict[str, Any]:
        return {
            "id": instance.instance_id,
            "name": instance.name,
            "healthy": False,
            "error": error,
            "uptime_seconds": 0,
            "upstream": None,
            "upstream_health": {},
            "tarpits_active": 0,
            "tarpits_total": 0,
            "proxied": 0,
            "telemetry_errors": 0,
            "events_suppressed": 0,
            "events_persisted": 0,
            "version": "unknown",
            "git_sha": "unknown",
            "build_date": "unknown",
            "source_id": None,
            "event_cursor_max": 0,
            "allowlist_cidrs": [],
            "trusted_proxy_cidrs": [],
        }

    async def collect_status(self, instance) -> dict[str, Any]:
        """Fetch each Hotpot status document exactly once per refresh."""

        try:
            status = await self.fetch_json(f"{instance.url}/_hotpot/status")
        except Exception as exc:
            return self._status_error(instance, type(exc).__name__)

        stats = status.get("stats", {}) if isinstance(status, dict) else {}
        upstream_health = (
            status.get("upstream_health", {}) if isinstance(status, dict) else {}
        )
        client_ip = status.get("client_ip", {}) if isinstance(status, dict) else {}
        allowlist = status.get("allowlist", {}) if isinstance(status, dict) else {}
        return {
            "id": instance.instance_id,
            "name": instance.name,
            "healthy": bool(status.get("healthy", False)),
            "error": None,
            "uptime_seconds": int(status.get("uptime_seconds", 0) or 0),
            "upstream": status.get("upstream"),
            "upstream_health": upstream_health,
            "tarpits_active": int(stats.get("tarpits_active", 0) or 0),
            "tarpits_total": int(stats.get("tarpits_total", 0) or 0),
            "proxied": int(stats.get("proxied", 0) or 0),
            "telemetry_errors": int(stats.get("telemetry_errors", 0) or 0),
            "events_suppressed": int(
                stats.get("events_suppressed_total", 0) or 0
            ),
            "events_persisted": int(stats.get("events_persisted_total", 0) or 0),
            "version": str(status.get("version", "unknown")),
            "git_sha": str(status.get("git_sha", "unknown")),
            "build_date": str(status.get("build_date", "unknown")),
            "source_id": status.get("source_id"),
            "event_cursor_max": int(status.get("event_cursor_max", 0) or 0),
            "allowlist_cidrs": list(allowlist.get("cidrs") or []),
            "trusted_proxy_cidrs": list(client_ip.get("trusted_proxy_cidrs") or []),
        }

    async def collect_events(self, instance) -> None:
        state = await self.store.cursor_state(instance.instance_id)
        cursor = int(state.get("cursor", 0) or 0)
        known_source = str(state.get("source_id") or "") or None
        pages = 0

        while pages < self.max_pages:
            try:
                payload = await self.fetch_json(
                    f"{instance.url}/_hotpot/api/events?cursor={cursor}&limit=250"
                )
            except Exception:
                return

            remote_source = str(payload.get("source_id") or "") or None
            remote_max = int(payload.get("event_cursor_max", 0) or 0)
            if remote_source:
                if known_source and remote_source != known_source:
                    await self.store.reset_source(instance.instance_id, remote_source)
                    cursor = 0
                    known_source = remote_source
                    pages = 0
                    continue
                if not known_source:
                    if "event_cursor_max" in payload and cursor > remote_max:
                        await self.store.reset_source(instance.instance_id, remote_source)
                        cursor = 0
                        known_source = remote_source
                        pages = 0
                        continue
                    await self.store.register_source(instance.instance_id, remote_source)
                    known_source = remote_source

            events = payload.get("events", [])
            if not isinstance(events, list):
                return
            next_cursor = int(payload.get("next_cursor", cursor) or cursor)
            await self.store.ingest(instance, events, next_cursor)
            cursor = next_cursor
            pages += 1
            if not payload.get("has_more") or not events:
                return

    def enrich_attacker(self, row: dict[str, Any]) -> dict[str, Any]:
        enriched = dict(row)
        network_ip = str(row.get("client_ip") or row.get("ip") or "")
        current = self.geoip.lookup(network_ip)
        persisted = row.get("network")
        if not isinstance(persisted, dict):
            lifetime = row.get("lifetime")
            if isinstance(lifetime, dict):
                persisted = lifetime.get("network")
        if current.get("enriched"):
            enriched["network"] = current
        elif isinstance(persisted, dict) and persisted.get("enriched"):
            enriched["network"] = dict(persisted)
        else:
            enriched["network"] = current
        return enriched

    async def _persist_network_attribution(self) -> dict[str, Any]:
        revision = self.geoip.revision()
        if not self.geoip.enabled:
            return {
                "enabled": False,
                "revision": revision,
                "batch_limit": self.geoip_enrich_batch,
                "candidates": 0,
                "updated": 0,
                "backlog_remaining": 0,
                "backlog_is_lower_bound": False,
            }

        backlog_scan = await self.store.network_enrichment_candidates(revision, 5000)
        candidates = backlog_scan[: self.geoip_enrich_batch]
        records = [
            {
                "identity_key": row["identity_key"],
                "client_ip": row["client_ip"],
                "revision": revision,
                "network": self.geoip.lookup(row["client_ip"]),
            }
            for row in candidates
        ]
        updated = await self.store.update_network_attributions(records)
        remaining = await self.store.network_enrichment_candidates(revision, 5000)
        return {
            "enabled": True,
            "revision": revision,
            "batch_limit": self.geoip_enrich_batch,
            "candidates": len(candidates),
            "updated": updated,
            "backlog_before": len(backlog_scan),
            "backlog_remaining": len(remaining),
            "backlog_is_lower_bound": len(remaining) >= 5000,
        }

    async def _maybe_housekeep(self) -> None:
        now = time.monotonic()
        if self._last_housekeeping and (
            now - self._last_housekeeping < self.housekeeping_interval_seconds
        ):
            return
        self._last_housekeeping = now
        try:
            await self.store.housekeeping(self.retention_days)
        except Exception:
            self.maintenance_errors += 1

    async def refresh(self) -> None:
        await asyncio.gather(
            *(self.collect_events(instance) for instance in self.instances)
        )
        apps = await asyncio.gather(
            *(self.collect_status(instance) for instance in self.instances)
        )
        await self._maybe_housekeep()
        self.geoip.reload_if_changed()
        attribution = await self._persist_network_attribution()
        response = await self.store.sync_response_recommendations(
            self.response_policy, list(apps)
        )
        snapshot = await self.store.snapshot(list(apps))
        snapshot["summary"]["suppressed_events"] = sum(
            int(app.get("events_suppressed", 0) or 0) for app in apps
        )
        snapshot["summary"]["response_pending"] = int(
            response.get("summary", {}).get("pending", 0) or 0
        )
        snapshot["summary"]["response_high_priority"] = int(
            response.get("summary", {}).get("high_priority", 0) or 0
        )
        snapshot["top_offenders"] = [
            self.enrich_attacker(row) for row in snapshot.get("top_offenders", [])
        ]
        snapshot["top_lifetime_offenders"] = [
            self.enrich_attacker(row)
            for row in snapshot.get("top_lifetime_offenders", [])
        ]

        network_intelligence = snapshot.get("network_intelligence") or {}
        attribution["lifetime_attackers"] = int(
            snapshot.get("summary", {}).get("lifetime_attackers", 0) or 0
        )
        attribution["attributed_attackers"] = int(
            network_intelligence.get("attributed_attackers", 0) or 0
        )
        geoip_status = self.geoip.status()
        geoip_status["attribution"] = attribution
        snapshot["geoip"] = geoip_status
        snapshot["network_attribution"] = attribution
        snapshot["response"] = response
        snapshot.setdefault("database", {})[
            "maintenance_errors"
        ] = self.maintenance_errors
        async with self.cache_lock:
            self.cache = snapshot

    async def _refresh_response_cache(self) -> None:
        async with self.cache_lock:
            apps = list(self.cache.get("apps", []))
        response = await self.store.sync_response_recommendations(
            self.response_policy, apps
        )
        async with self.cache_lock:
            self.cache["response"] = response
            summary = self.cache.setdefault("summary", {})
            summary["response_pending"] = int(
                response.get("summary", {}).get("pending", 0) or 0
            )
            summary["response_high_priority"] = int(
                response.get("summary", {}).get("high_priority", 0) or 0
            )

    async def api_attacker(self, request: web.Request) -> web.Response:
        self.require_auth(request)
        identity_key = request.query.get("key", "").strip() or request.query.get(
            "ip", ""
        ).strip()
        if not identity_key:
            raise web.HTTPBadRequest(
                text="key (or legacy ip) query parameter is required"
            )
        result = await self.store.attacker_snapshot(identity_key)
        if result is None:
            raise web.HTTPNotFound(text="attacker not found")
        self.geoip.reload_if_changed()
        result = self.enrich_attacker(result)
        return web.json_response(result, headers={"Cache-Control": "no-store"})

    async def api_network(self, request: web.Request) -> web.Response:
        self.require_auth(request)
        raw_asn = request.query.get("asn", "").strip()
        provider = request.query.get("provider", "").strip() or None
        country_code = request.query.get("country", "").strip().upper() or None
        asn: int | None = None
        if raw_asn:
            try:
                asn = int(raw_asn)
            except ValueError as exc:
                raise web.HTTPBadRequest(text="asn must be an integer") from exc
        if asn is None and provider is None and country_code is None:
            raise web.HTTPBadRequest(
                text="asn, provider, or country query parameter is required"
            )
        result = await self.store.network_snapshot(
            asn=asn,
            provider=provider,
            country_code=country_code,
        )
        if result is None:
            raise web.HTTPNotFound(text="network intelligence not found")
        return web.json_response(result, headers={"Cache-Control": "no-store"})

    async def api_recommendations(self, request: web.Request) -> web.Response:
        self.require_auth(request)
        status = request.query.get("status", "pending").strip().lower() or "pending"
        try:
            limit = max(1, min(500, int(request.query.get("limit", "100"))))
            result = await self.store.recommendations(
                self.response_policy, status=status, limit=limit
            )
        except ValueError as exc:
            raise web.HTTPBadRequest(text=str(exc)) from exc
        return web.json_response(result, headers={"Cache-Control": "no-store"})

    async def api_recommendation(self, request: web.Request) -> web.Response:
        self.require_auth(request)
        recommendation_id = request.query.get("id", "").strip()
        if not recommendation_id:
            raise web.HTTPBadRequest(text="id query parameter is required")
        result = await self.store.recommendation(recommendation_id)
        if result is None:
            raise web.HTTPNotFound(text="recommendation not found")
        return web.json_response(result, headers={"Cache-Control": "no-store"})

    async def api_dismiss_recommendation(self, request: web.Request) -> web.Response:
        self.require_auth(request)
        if request.headers.get("X-Hotpot-Action", "") != "dismiss":
            raise web.HTTPBadRequest(text="X-Hotpot-Action: dismiss header is required")
        recommendation_id = request.match_info.get("recommendation_id", "").strip()
        if not recommendation_id:
            raise web.HTTPBadRequest(text="recommendation id is required")
        result = await self.store.dismiss_recommendation(
            recommendation_id, self.response_policy.dismiss_hours
        )
        if result is None:
            raise web.HTTPNotFound(text="recommendation not found")
        await self._refresh_response_cache()
        return web.json_response(result, headers={"Cache-Control": "no-store"})

    async def index(self, request: web.Request) -> web.Response:
        self.require_auth(request)
        return web.Response(
            text=PRODUCTION_HTML,
            content_type="text/html",
            charset="utf-8",
            headers={
                "Cache-Control": "no-store",
                "X-Robots-Tag": "noindex, nofollow",
                "Content-Security-Policy": "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'",
                "X-Frame-Options": "DENY",
                "X-Content-Type-Options": "nosniff",
                "Referrer-Policy": "no-referrer",
            },
        )


def build_app() -> web.Application:
    dashboard = ProductionDashboard()
    app = web.Application()
    app[core.DASHBOARD_KEY] = dashboard
    app.on_startup.append(dashboard.startup)
    app.on_cleanup.append(dashboard.shutdown)
    app.router.add_get("/", dashboard.index)
    app.router.add_get("/health", dashboard.health)
    app.router.add_get("/api/overview", dashboard.api_overview)
    app.router.add_get("/api/attacker", dashboard.api_attacker)
    app.router.add_get("/api/network", dashboard.api_network)
    app.router.add_get("/api/recommendations", dashboard.api_recommendations)
    app.router.add_get("/api/recommendation", dashboard.api_recommendation)
    app.router.add_post(
        "/api/recommendation/{recommendation_id}/dismiss",
        dashboard.api_dismiss_recommendation,
    )
    return app


def main() -> None:
    bind = os.getenv("HOTPOT_DASHBOARD_BIND", "127.0.0.1")
    port = int(os.getenv("HOTPOT_DASHBOARD_PORT", "19090"))
    web.run_app(build_app(), host=bind, port=port, access_log=None)


if __name__ == "__main__":
    main()
