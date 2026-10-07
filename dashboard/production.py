from __future__ import annotations

import asyncio
import os
import time
from pathlib import Path
from typing import Any

from aiohttp import web

from . import runtime as core
from .geoip_enrichment import GeoIPEnricher
from .network_intelligence import NetworkIntelligenceStore
from .template import PRODUCTION_HTML


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
        self._last_housekeeping = 0.0
        self.maintenance_errors = 0
        self.store = NetworkIntelligenceStore(
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

        # The store intentionally caps candidate scans at 5000. If that cap is
        # reached, report the backlog as a lower bound rather than pretending it is
        # an exact count. Normal installations will quickly fall below the cap.
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
        snapshot = await self.store.snapshot(list(apps))
        snapshot["summary"]["suppressed_events"] = sum(
            int(app.get("events_suppressed", 0) or 0) for app in apps
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
        snapshot.setdefault("database", {})[
            "maintenance_errors"
        ] = self.maintenance_errors
        async with self.cache_lock:
            self.cache = snapshot

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
    return app


def main() -> None:
    bind = os.getenv("HOTPOT_DASHBOARD_BIND", "127.0.0.1")
    port = int(os.getenv("HOTPOT_DASHBOARD_PORT", "19090"))
    web.run_app(build_app(), host=bind, port=port, access_log=None)


if __name__ == "__main__":
    main()
