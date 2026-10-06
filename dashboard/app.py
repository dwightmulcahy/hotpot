from __future__ import annotations

import asyncio
import json
import os
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from aiohttp import ClientSession, ClientTimeout, web


@dataclass(frozen=True)
class Instance:
    instance_id: str
    name: str
    url: str


def _instances_from_env() -> list[Instance]:
    raw = os.getenv("HOTPOT_DASHBOARD_INSTANCES", "").strip()
    if not raw:
        raise RuntimeError("HOTPOT_DASHBOARD_INSTANCES is required")
    try:
        values = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError("HOTPOT_DASHBOARD_INSTANCES must be valid JSON") from exc
    if not isinstance(values, list) or not values:
        raise RuntimeError("HOTPOT_DASHBOARD_INSTANCES must be a non-empty JSON list")

    result: list[Instance] = []
    seen: set[str] = set()
    for value in values:
        if not isinstance(value, dict):
            raise RuntimeError("Each dashboard instance must be a JSON object")
        instance_id = str(value.get("id", "")).strip()
        name = str(value.get("name", instance_id)).strip()
        url = str(value.get("url", "")).strip().rstrip("/")
        if not instance_id or not name or not url:
            raise RuntimeError("Each dashboard instance requires id, name, and url")
        if instance_id in seen:
            raise RuntimeError(f"Duplicate dashboard instance id: {instance_id}")
        seen.add(instance_id)
        result.append(Instance(instance_id, name, url))
    return result


class Dashboard:
    def __init__(self) -> None:
        self.instances = _instances_from_env()
        self.token = os.getenv("HOTPOT_ADMIN_TOKEN", "").strip()
        if not self.token:
            raise RuntimeError("HOTPOT_ADMIN_TOKEN is required for dashboard collection")
        self.refresh_seconds = max(5, int(os.getenv("HOTPOT_DASHBOARD_REFRESH_SECONDS", "15")))
        self.timeout = max(2.0, float(os.getenv("HOTPOT_DASHBOARD_TIMEOUT", "5")))
        self.client: ClientSession | None = None
        self.cache: dict[str, Any] = self.empty_snapshot()
        self.cache_lock = asyncio.Lock()
        self.refresh_task: asyncio.Task | None = None

    @staticmethod
    def empty_snapshot() -> dict[str, Any]:
        return {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "apps": [],
            "summary": {
                "protected_apps": 0,
                "healthy_apps": 0,
                "events": 0,
                "instance_unique_ips": 0,
                "active_tarpits": 0,
                "level3_plus": 0,
            },
            "recent": [],
            "top_paths": [],
            "top_categories": [],
            "top_scanners": [],
            "top_offenders": [],
        }

    async def startup(self, app: web.Application) -> None:
        self.client = ClientSession(timeout=ClientTimeout(total=self.timeout))
        await self.refresh()
        self.refresh_task = asyncio.create_task(self.refresh_loop(), name="hotpot-dashboard-refresh")

    async def shutdown(self, app: web.Application) -> None:
        if self.refresh_task:
            self.refresh_task.cancel()
            await asyncio.gather(self.refresh_task, return_exceptions=True)
        if self.client:
            await self.client.close()

    async def refresh_loop(self) -> None:
        while True:
            try:
                await asyncio.sleep(self.refresh_seconds)
                await self.refresh()
            except asyncio.CancelledError:
                raise
            except Exception:
                # Keep serving the previous snapshot if a collection cycle fails.
                pass

    async def fetch_json(self, url: str) -> dict[str, Any]:
        assert self.client is not None
        headers = {"Authorization": f"Bearer {self.token}"}
        async with self.client.get(url, headers=headers) as response:
            response.raise_for_status()
            data = await response.json()
            if not isinstance(data, dict):
                raise RuntimeError("Hotpot API returned a non-object JSON response")
            return data

    async def collect_instance(self, instance: Instance) -> dict[str, Any]:
        try:
            status, intel = await asyncio.gather(
                self.fetch_json(f"{instance.url}/_hotpot/status"),
                self.fetch_json(f"{instance.url}/_hotpot/api/intelligence"),
            )
            return {
                "id": instance.instance_id,
                "name": instance.name,
                "url": instance.url,
                "healthy": bool(status.get("healthy", False)),
                "status": status,
                "intel": intel,
                "error": None,
            }
        except Exception as exc:
            return {
                "id": instance.instance_id,
                "name": instance.name,
                "url": instance.url,
                "healthy": False,
                "status": {},
                "intel": {},
                "error": type(exc).__name__,
            }

    async def refresh(self) -> None:
        rows = await asyncio.gather(*(self.collect_instance(instance) for instance in self.instances))
        snapshot = self.aggregate(rows)
        async with self.cache_lock:
            self.cache = snapshot

    def aggregate(self, rows: list[dict[str, Any]]) -> dict[str, Any]:
        summary = {
            "protected_apps": len(rows),
            "healthy_apps": 0,
            "events": 0,
            "instance_unique_ips": 0,
            "active_tarpits": 0,
            "level3_plus": 0,
        }
        recent: list[dict[str, Any]] = []
        paths: Counter[str] = Counter()
        categories: Counter[str] = Counter()
        scanners: Counter[str] = Counter()
        offenders: dict[str, dict[str, Any]] = defaultdict(
            lambda: {"hits": 0, "score": 0, "level": 1, "apps": set(), "last_seen": None}
        )
        apps: list[dict[str, Any]] = []

        for row in rows:
            status = row["status"]
            intel = row["intel"]
            stats = status.get("stats", {}) if isinstance(status, dict) else {}
            if row["healthy"]:
                summary["healthy_apps"] += 1
            event_count = int(intel.get("events", 0) or 0)
            unique_ips = int(intel.get("unique_ips", 0) or 0)
            summary["events"] += event_count
            summary["instance_unique_ips"] += unique_ips
            summary["active_tarpits"] += int(stats.get("tarpits", 0) or 0)

            app_level3 = 0
            for offender in intel.get("top_offenders", []) or []:
                ip = str(offender.get("ip", "")).strip()
                if not ip:
                    continue
                level = int(offender.get("escalation_level", 1) or 1)
                if level >= 3:
                    app_level3 += 1
                item = offenders[ip]
                item["hits"] += int(offender.get("hits", 0) or 0)
                item["score"] += int(offender.get("score", 0) or 0)
                item["level"] = max(item["level"], level)
                item["apps"].add(row["name"])
                last_seen = offender.get("last_seen")
                if last_seen and (item["last_seen"] is None or last_seen > item["last_seen"]):
                    item["last_seen"] = last_seen
            summary["level3_plus"] += app_level3

            for item in intel.get("top_paths", []) or []:
                paths[str(item.get("path", ""))] += int(item.get("hits", 0) or 0)
            for item in intel.get("top_categories", []) or []:
                categories[str(item.get("category", "unknown"))] += int(item.get("hits", 0) or 0)
            for item in intel.get("top_scanners", []) or []:
                scanners[str(item.get("scanner", "unknown"))] += int(item.get("hits", 0) or 0)
            for event in intel.get("recent", []) or []:
                copy = dict(event)
                copy["instance_id"] = row["id"]
                copy["instance_name"] = row["name"]
                recent.append(copy)

            apps.append({
                "id": row["id"],
                "name": row["name"],
                "healthy": row["healthy"],
                "error": row["error"],
                "events": event_count,
                "unique_ips": unique_ips,
                "tarpits": int(stats.get("tarpits", 0) or 0),
                "proxied": int(stats.get("proxied", 0) or 0),
                "uptime_seconds": int(status.get("uptime_seconds", 0) or 0),
                "upstream": status.get("upstream"),
            })

        recent.sort(key=lambda item: str(item.get("ts", "")), reverse=True)
        offender_rows = [
            {
                "ip": ip,
                "hits": data["hits"],
                "score": data["score"],
                "level": data["level"],
                "apps": sorted(data["apps"]),
                "app_count": len(data["apps"]),
                "last_seen": data["last_seen"],
            }
            for ip, data in offenders.items()
        ]
        offender_rows.sort(key=lambda item: (item["score"], item["hits"], item["app_count"]), reverse=True)

        def top(counter: Counter[str], key: str) -> list[dict[str, Any]]:
            return [{key: value, "hits": hits} for value, hits in counter.most_common(10) if value]

        return {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "apps": apps,
            "summary": summary,
            "recent": recent[:50],
            "top_paths": top(paths, "path"),
            "top_categories": top(categories, "category"),
            "top_scanners": top(scanners, "scanner"),
            "top_offenders": offender_rows[:20],
        }

    async def health(self, request: web.Request) -> web.Response:
        async with self.cache_lock:
            cache = self.cache
        healthy = bool(cache["apps"]) and all(app["healthy"] for app in cache["apps"])
        return web.json_response({"healthy": healthy, "apps": len(cache["apps"])}, status=200 if healthy else 503)

    async def api_overview(self, request: web.Request) -> web.Response:
        async with self.cache_lock:
            return web.json_response(self.cache, headers={"Cache-Control": "no-store"})

    async def index(self, request: web.Request) -> web.Response:
        return web.Response(text=HTML, content_type="text/html", charset="utf-8",
                            headers={"Cache-Control": "no-store", "X-Robots-Tag": "noindex, nofollow"})


HTML = r'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Hotpot Dashboard</title>
<style>
:root{color-scheme:dark;--bg:#0b1020;--panel:#121a2d;--line:#26324a;--muted:#93a4bd;--text:#edf4ff;--good:#38d996;--warn:#f2c14e;--bad:#ff6b6b;--accent:#6ea8fe}
*{box-sizing:border-box}body{margin:0;font-family:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:linear-gradient(180deg,#09101d,#0d1322 35%,#0b1020);color:var(--text)}
main{max-width:1500px;margin:auto;padding:28px}.header{display:flex;justify-content:space-between;align-items:end;gap:20px;margin-bottom:22px}.title{font-size:30px;font-weight:800}.subtitle,.muted{color:var(--muted)}
.cards{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:12px}.card,.panel{background:rgba(18,26,45,.94);border:1px solid var(--line);border-radius:16px;box-shadow:0 18px 45px rgba(0,0,0,.15)}.card{padding:16px}.metric{font-size:30px;font-weight:800;margin-top:5px}.label{font-size:12px;text-transform:uppercase;letter-spacing:.08em;color:var(--muted)}
.grid{display:grid;grid-template-columns:1.25fr .75fr;gap:14px;margin-top:14px}.panel{padding:18px}.panel h2{font-size:16px;margin:0 0 14px}.appgrid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px}.app{padding:13px;border:1px solid var(--line);border-radius:12px;background:#0e1627}.apphead{display:flex;justify-content:space-between;gap:8px}.dot{display:inline-block;width:9px;height:9px;border-radius:50%;margin-right:7px}.ok{background:var(--good)}.down{background:var(--bad)}
table{width:100%;border-collapse:collapse;font-size:13px}th,td{text-align:left;padding:9px 8px;border-bottom:1px solid #202b40;vertical-align:top}th{color:var(--muted);font-weight:600}.pill{display:inline-block;border:1px solid var(--line);border-radius:999px;padding:2px 7px;font-size:11px;margin:1px}.level3,.level4{border-color:#8a5b25;color:#ffd486}.level4{border-color:#8b3440;color:#ff99a5}.bars{display:grid;gap:9px}.barrow{display:grid;grid-template-columns:minmax(100px,1fr) 2fr 48px;align-items:center;gap:9px;font-size:12px}.bar{height:8px;background:#202b40;border-radius:999px;overflow:hidden}.bar span{display:block;height:100%;background:linear-gradient(90deg,#5f8eff,#8b6dff)}
@media(max-width:1000px){.cards{grid-template-columns:repeat(2,1fr)}.grid{grid-template-columns:1fr}.appgrid{grid-template-columns:1fr}}@media(max-width:600px){main{padding:16px}.cards{grid-template-columns:1fr}.header{display:block}}
</style></head><body><main>
<div class="header"><div><div class="title">🔥 Hotpot</div><div class="subtitle">Central deception & attack intelligence</div></div><div id="updated" class="muted">Loading…</div></div>
<div class="cards" id="metrics"></div>
<div class="grid"><section class="panel"><h2>Protected applications</h2><div class="appgrid" id="apps"></div></section><section class="panel"><h2>Cross-app offenders</h2><div id="offenders"></div></section></div>
<div class="grid"><section class="panel"><h2>Recent attack activity</h2><div style="overflow:auto"><table><thead><tr><th>Time</th><th>Application</th><th>Source</th><th>Category</th><th>Path</th><th>Action</th><th>Level</th></tr></thead><tbody id="recent"></tbody></table></div></section><section class="panel"><h2>Top attack paths</h2><div class="bars" id="paths"></div><h2 style="margin-top:22px">Top categories</h2><div class="bars" id="categories"></div><h2 style="margin-top:22px">Scanner identification</h2><div class="bars" id="scanners"></div></section></div>
<script>
const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const fmt=n=>new Intl.NumberFormat().format(n||0); const ago=s=>{if(!s)return'—';const d=new Date(s);return isNaN(d)?esc(s):d.toLocaleString()};
function bars(id,rows,key){const el=document.getElementById(id),m=Math.max(1,...rows.map(x=>x.hits||0));el.innerHTML=rows.map(x=>`<div class="barrow"><div title="${esc(x[key])}">${esc(x[key])}</div><div class="bar"><span style="width:${Math.max(3,(x.hits/m)*100)}%"></span></div><div>${fmt(x.hits)}</div></div>`).join('')||'<div class="muted">No data yet</div>'}
async function load(){try{const r=await fetch('/api/overview',{cache:'no-store'});const d=await r.json();document.getElementById('updated').textContent='Updated '+new Date(d.generated_at).toLocaleTimeString();const s=d.summary;const metrics=[['Protected apps',s.protected_apps],['Healthy',s.healthy_apps+'/'+s.protected_apps],['Events',s.events],['Instance unique IPs',s.instance_unique_ips],['Tarpits started',s.active_tarpits]];document.getElementById('metrics').innerHTML=metrics.map(x=>`<div class="card"><div class="label">${esc(x[0])}</div><div class="metric">${esc(x[1])}</div></div>`).join('');document.getElementById('apps').innerHTML=d.apps.map(a=>`<div class="app"><div class="apphead"><strong><span class="dot ${a.healthy?'ok':'down'}"></span>${esc(a.name)}</strong><span class="muted">${a.healthy?'Healthy':esc(a.error||'Unavailable')}</span></div><div style="margin-top:10px" class="muted">${fmt(a.events)} events · ${fmt(a.unique_ips)} unique IPs · ${fmt(a.tarpits)} tarpits</div><div style="margin-top:5px" class="muted">${fmt(a.proxied)} proxied requests</div></div>`).join('');document.getElementById('offenders').innerHTML=d.top_offenders.slice(0,10).map(o=>`<div style="padding:9px 0;border-bottom:1px solid #202b40"><div><strong>${esc(o.ip)}</strong> <span class="pill level${o.level}">L${o.level}</span> ${o.app_count>1?`<span class="pill">${o.app_count} apps</span>`:''}</div><div class="muted">score ${fmt(o.score)} · hits ${fmt(o.hits)} · ${esc(o.apps.join(', '))}</div></div>`).join('')||'<div class="muted">No offenders yet</div>';document.getElementById('recent').innerHTML=d.recent.slice(0,35).map(e=>`<tr><td>${ago(e.ts)}</td><td>${esc(e.instance_name)}</td><td>${esc(e.client_ip)}</td><td>${esc(e.category||'unknown')}</td><td><code>${esc(e.path)}</code></td><td>${esc(e.action)}</td><td>L${esc(e.escalation_level||1)}</td></tr>`).join('');bars('paths',d.top_paths,'path');bars('categories',d.top_categories,'category');bars('scanners',d.top_scanners,'scanner')}catch(e){document.getElementById('updated').textContent='Dashboard refresh failed'}}
load();setInterval(load,15000);
</script></main></body></html>'''


DASHBOARD_KEY = web.AppKey("dashboard", Dashboard)


def build_app() -> web.Application:
    dashboard = Dashboard()
    app = web.Application()
    app[DASHBOARD_KEY] = dashboard
    app.on_startup.append(dashboard.startup)
    app.on_cleanup.append(dashboard.shutdown)
    app.router.add_get("/", dashboard.index)
    app.router.add_get("/health", dashboard.health)
    app.router.add_get("/api/overview", dashboard.api_overview)
    return app


def main() -> None:
    bind = os.getenv("HOTPOT_DASHBOARD_BIND", "127.0.0.1")
    port = int(os.getenv("HOTPOT_DASHBOARD_PORT", "19090"))
    web.run_app(build_app(), host=bind, port=port, access_log=None)


if __name__ == "__main__":
    main()
