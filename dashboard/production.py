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


class ProductionDashboard(core.Dashboard):
    def __init__(self) -> None:
        super().__init__()
        self.retention_days = max(
            1, int(os.getenv("HOTPOT_DASHBOARD_EVENT_RETENTION_DAYS", "90"))
        )
        self.housekeeping_interval_seconds = max(
            900.0,
            float(os.getenv("HOTPOT_DASHBOARD_HOUSEKEEPING_INTERVAL_HOURS", "6")) * 3600.0,
        )
        self.geoip_enrich_batch = max(
            1, min(5000, int(os.getenv("HOTPOT_DASHBOARD_GEOIP_ENRICH_BATCH", "500")))
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

    async def collect_status(self, instance) -> dict[str, Any]:
        row = await super().collect_status(instance)
        if row.get("error"):
            row.update(
                events_suppressed=0,
                events_persisted=0,
                version="unknown",
                git_sha="unknown",
                build_date="unknown",
                source_id=None,
            )
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
                source_id=status.get("source_id"),
            )
        except Exception:
            row.update(
                events_suppressed=0,
                events_persisted=0,
                version="unknown",
                git_sha="unknown",
                build_date="unknown",
                source_id=None,
            )
        return row

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

    def _geoip_revision(self) -> str:
        status = self.geoip.status()
        databases = status.get("databases") or {}
        parts: list[str] = []
        for name in sorted(databases):
            info = databases.get(name) or {}
            parts.append(
                f"{name}:{1 if info.get('present') else 0}:"
                f"{int(info.get('mtime_ns', 0) or 0)}:{int(info.get('size', 0) or 0)}"
            )
        return "|".join(parts) or "geoip-unconfigured"

    async def _persist_network_attribution(self) -> dict[str, Any]:
        revision = self._geoip_revision()
        if not self.geoip.enabled:
            return {
                "enabled": False,
                "revision": revision,
                "batch_limit": self.geoip_enrich_batch,
                "candidates": 0,
                "updated": 0,
            }
        candidates = await self.store.network_enrichment_candidates(
            revision, self.geoip_enrich_batch
        )
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
        return {
            "enabled": True,
            "revision": revision,
            "batch_limit": self.geoip_enrich_batch,
            "candidates": len(candidates),
            "updated": updated,
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
        await asyncio.gather(*(self.collect_events(instance) for instance in self.instances))
        apps = await asyncio.gather(*(self.collect_status(instance) for instance in self.instances))
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
        snapshot["geoip"] = self.geoip.status()
        snapshot["network_attribution"] = attribution
        snapshot.setdefault("database", {})["maintenance_errors"] = self.maintenance_errors
        async with self.cache_lock:
            self.cache = snapshot

    async def api_attacker(self, request: web.Request) -> web.Response:
        self.require_auth(request)
        identity_key = (
            request.query.get("key", "").strip()
            or request.query.get("ip", "").strip()
        )
        if not identity_key:
            raise web.HTTPBadRequest(text="key (or legacy ip) query parameter is required")
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


PRODUCTION_HTML = core.HTML
PRODUCTION_HTML = PRODUCTION_HTML.replace(
    ".cards{display:grid;grid-template-columns:repeat(5,1fr);",
    ".cards{display:grid;grid-template-columns:repeat(9,1fr);",
)
PRODUCTION_HTML = PRODUCTION_HTML.replace(
    "['Active tarpits',s.active_tarpits]",
    "['Active tarpits',s.active_tarpits],['Suppressed',s.suppressed_events||0],['Global L3+',s.level3_plus||0],['Lifetime attackers',s.lifetime_attackers||0],['DB MB',s.database_size_mb||0]",
)
PRODUCTION_HTML = PRODUCTION_HTML.replace(
    "${fmt(a.proxied)} proxied · ${fmt(a.telemetry_errors)} telemetry errors",
    "${fmt(a.proxied)} proxied · ${fmt(a.events_suppressed||0)} suppressed · ${fmt(a.telemetry_errors)} telemetry errors</div><div class=\"muted\">${esc(a.version||'unknown')} · ${esc((a.git_sha||'unknown').slice(0,7))}",
)
PRODUCTION_HTML = PRODUCTION_HTML.replace(
    "<strong>${esc(o.ip)}</strong> · score ${fmt(o.score)} · ${fmt(o.hits)} hits · ${o.app_count} apps<div class=\"muted\">${esc(o.apps.join(', '))}</div>",
    "<strong>${o.source_type==='cloudflare-worker'?'Cloudflare Worker · '+esc(o.worker_zone||'legacy/unknown zone'):esc(o.identity_key||o.ip)}</strong> · <strong>Global L${fmt(o.global_level||o.level)}</strong> · score ${fmt(o.global_score||o.score)} · ${fmt(o.hits)} hits<div class=\"muted\">${fmt(o.app_count)} apps · ${fmt(o.category_count)} categories · ${esc((o.apps||[]).join(', '))}</div>${o.network?.enriched?'<div class=\"muted\">'+(o.source_type==='cloudflare-worker'?'Observed via '+esc(o.client_ip||'Cloudflare shared address')+' · ':'')+(o.network.asn?'AS'+esc(o.network.asn)+' · ':'')+esc(o.network.provider||'')+(o.network.country?' · '+esc(o.network.country):'')+(o.network.city?' · '+esc(o.network.city):'')+'</div>':''}<div class=\"muted\">Lifetime ${fmt(o.lifetime?.lifetime_hits||o.hits)} hits${o.lifetime?.first_seen?' · first '+esc(new Date(o.lifetime.first_seen).toLocaleDateString()):''}</div>",
)
PRODUCTION_HTML = PRODUCTION_HTML.replace(
    '</section></div><div class="grid"><section class="panel"><h3>Recent activity',
    '</section></div><div class="grid"><section class="panel"><h3>Top networks / ASNs</h3><div id="networks"></div></section><section class="panel"><h3>Top countries</h3><div id="countries"></div></section></div><div class="grid"><section class="panel"><h3>Recent activity',
)
PRODUCTION_HTML = PRODUCTION_HTML.replace(
    "document.getElementById('recent').innerHTML=",
    "document.getElementById('networks').innerHTML=(d.network_intelligence?.top_networks||[]).map(n=>{const detail=n.asn!=null?'/api/network?asn='+encodeURIComponent(n.asn):'/api/network?provider='+encodeURIComponent(n.provider||'');const apps=(n.top_apps||[]).slice(0,3).map(x=>x.instance_name).join(', ');const cats=(n.top_categories||[]).slice(0,3).map(x=>x.category).join(', ');return `<div style=\"padding:7px 0;border-bottom:1px solid #202b40\"><strong>${n.asn!=null?'AS'+esc(n.asn)+' · ':''}${esc(n.provider||'Unknown provider')}</strong> · ${fmt(n.hits)} hits · ${fmt(n.attackers)} attackers <a class=\"muted\" href=\"${esc(detail)}\">details</a><div class=\"muted\">${fmt(n.level3_plus)} L3+ · ${fmt(n.level4)} L4${apps?' · Targets: '+esc(apps):''}</div>${cats?'<div class=\"muted\">Top probes: '+esc(cats)+'</div>':''}</div>`}).join('')||'<span class=\"muted\">No attributed networks yet</span>';document.getElementById('countries').innerHTML=(d.network_intelligence?.top_countries||[]).map(c=>{const detail='/api/network?country='+encodeURIComponent(c.country_code||'');const apps=(c.top_apps||[]).slice(0,2).map(x=>x.instance_name).join(', ');return `<div style=\"padding:7px 0;border-bottom:1px solid #202b40\"><strong>${esc(c.country||c.country_code||'Unknown')}</strong> · ${fmt(c.hits)} hits · ${fmt(c.attackers)} attackers <a class=\"muted\" href=\"${esc(detail)}\">details</a><div class=\"muted\">${fmt(c.level3_plus)} L3+ · ${fmt(c.level4)} L4${apps?' · Targets: '+esc(apps):''}</div></div>`}).join('')||'<span class=\"muted\">No attributed countries yet</span>';document.getElementById('recent').innerHTML=",
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
