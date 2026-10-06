from __future__ import annotations

import asyncio
import os
from pathlib import Path
from typing import Any

from aiohttp import web

from . import runtime as core
from .geoip_enrichment import GeoIPEnricher
from .global_scoring import GlobalCentralStore


class ProductionDashboard(core.Dashboard):
    def __init__(self) -> None:
        super().__init__()
        self.store = GlobalCentralStore(Path(os.getenv("HOTPOT_DASHBOARD_DATA_DIR", "/data")))
        self.geoip = GeoIPEnricher()

    async def shutdown(self, app: web.Application) -> None:
        self.geoip.close()
        await super().shutdown(app)

    async def collect_status(self, instance) -> dict[str, Any]:
        row = await super().collect_status(instance)
        if row.get("error"):
            row.update(events_suppressed=0, events_persisted=0, version="unknown", git_sha="unknown", build_date="unknown")
            return row
        try:
            status = await self.fetch_json(f"{instance.url}/_hotpot/status")
            stats = status.get("stats", {}) if isinstance(status, dict) else {}
            row.update(
                events_suppressed=int(stats.get("events_suppressed_total", 0) or 0),
                events_persisted=int(stats.get("events_persisted_total", 0) or 0),
                version=str(status.get("version", "unknown")),
                git_sha=str(status.get("git_sha", "unknown")),
                build_date=str(status.get("build_date", "unknown")),
            )
        except Exception:
            row.update(events_suppressed=0, events_persisted=0, version="unknown", git_sha="unknown", build_date="unknown")
        return row

    def enrich_attacker(self, row: dict[str, Any]) -> dict[str, Any]:
        enriched = dict(row)
        enriched["network"] = self.geoip.lookup(str(row.get("ip", "")))
        return enriched

    async def refresh(self) -> None:
        await asyncio.gather(*(self.collect_events(instance) for instance in self.instances))
        apps = await asyncio.gather(*(self.collect_status(instance) for instance in self.instances))
        snapshot = await self.store.snapshot(list(apps))
        snapshot["summary"]["suppressed_events"] = sum(int(app.get("events_suppressed", 0) or 0) for app in apps)
        snapshot["top_offenders"] = [self.enrich_attacker(row) for row in snapshot.get("top_offenders", [])]
        snapshot["geoip"] = self.geoip.status()
        async with self.cache_lock:
            self.cache = snapshot

    async def api_attacker(self, request: web.Request) -> web.Response:
        self.require_auth(request)
        ip = request.query.get("ip", "").strip()
        if not ip:
            raise web.HTTPBadRequest(text="ip query parameter is required")
        result = await self.store.attacker_snapshot(ip)
        if result is None:
            raise web.HTTPNotFound(text="attacker not found")
        result = self.enrich_attacker(result)
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


PRODUCTION_HTML = core.HTML
PRODUCTION_HTML = PRODUCTION_HTML.replace(
    ".cards{display:grid;grid-template-columns:repeat(5,1fr);",
    ".cards{display:grid;grid-template-columns:repeat(7,1fr);",
)
PRODUCTION_HTML = PRODUCTION_HTML.replace(
    "['Active tarpits',s.active_tarpits]",
    "['Active tarpits',s.active_tarpits],['Suppressed',s.suppressed_events||0],['Global L3+',s.level3_plus||0]",
)
PRODUCTION_HTML = PRODUCTION_HTML.replace(
    "${fmt(a.proxied)} proxied · ${fmt(a.telemetry_errors)} telemetry errors",
    "${fmt(a.proxied)} proxied · ${fmt(a.events_suppressed||0)} suppressed · ${fmt(a.telemetry_errors)} telemetry errors</div><div class=\"muted\">${esc(a.version||'unknown')} · ${esc((a.git_sha||'unknown').slice(0,7))}",
)
PRODUCTION_HTML = PRODUCTION_HTML.replace(
    "<strong>${esc(o.ip)}</strong> · score ${fmt(o.score)} · ${fmt(o.hits)} hits · ${o.app_count} apps<div class=\"muted\">${esc(o.apps.join(', '))}</div>",
    "<strong>${esc(o.ip)}</strong> · <strong>Global L${fmt(o.global_level||o.level)}</strong> · score ${fmt(o.global_score||o.score)} · ${fmt(o.hits)} hits<div class=\"muted\">${fmt(o.app_count)} apps · ${fmt(o.category_count)} categories · ${esc((o.apps||[]).join(', '))}</div><div class=\"muted\">${o.network?.asn?'AS'+esc(o.network.asn)+' · ':''}${esc(o.network?.provider||'Unknown provider')}${o.network?.country?' · '+esc(o.network.country):''}${o.network?.city?' · '+esc(o.network.city):''}</div>",
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
    return app


def main() -> None:
    bind = os.getenv("HOTPOT_DASHBOARD_BIND", "127.0.0.1")
    port = int(os.getenv("HOTPOT_DASHBOARD_PORT", "19090"))
    web.run_app(build_app(), host=bind, port=port, access_log=None)


if __name__ == "__main__":
    main()
