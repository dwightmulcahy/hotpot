from __future__ import annotations

import asyncio
import base64
import hmac
import json
import os
import sqlite3
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from aiohttp import ClientSession, ClientTimeout, web


@dataclass(frozen=True)
class Instance:
    instance_id: str
    name: str
    url: str


def instances_from_env() -> list[Instance]:
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


class CentralStore:
    def __init__(self, data_dir: Path):
        data_dir.mkdir(parents=True, exist_ok=True)
        self.path = data_dir / "dashboard.sqlite3"
        self.lock = asyncio.Lock()
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        return conn

    def _initialize(self) -> None:
        conn = self._connect()
        try:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS events (
                    instance_id TEXT NOT NULL,
                    instance_name TEXT NOT NULL,
                    event_id INTEGER NOT NULL,
                    ts TEXT NOT NULL,
                    client_ip TEXT NOT NULL,
                    method TEXT,
                    path TEXT,
                    category TEXT,
                    action TEXT,
                    scanner TEXT,
                    severity INTEGER NOT NULL DEFAULT 1,
                    escalation_level INTEGER NOT NULL DEFAULT 1,
                    attacker_score INTEGER NOT NULL DEFAULT 0,
                    payload_json TEXT NOT NULL,
                    PRIMARY KEY(instance_id, event_id)
                );
                CREATE INDEX IF NOT EXISTS idx_dashboard_events_ts ON events(ts DESC);
                CREATE INDEX IF NOT EXISTS idx_dashboard_events_ip ON events(client_ip, ts DESC);
                CREATE INDEX IF NOT EXISTS idx_dashboard_events_path ON events(path);
                CREATE INDEX IF NOT EXISTS idx_dashboard_events_category ON events(category);
                CREATE TABLE IF NOT EXISTS cursors (
                    instance_id TEXT PRIMARY KEY,
                    cursor INTEGER NOT NULL DEFAULT 0,
                    updated_at TEXT NOT NULL
                );
                """
            )
            conn.commit()
        finally:
            conn.close()

    async def cursor_for(self, instance_id: str) -> int:
        async with self.lock:
            return await asyncio.to_thread(self._cursor_for_sync, instance_id)

    def _cursor_for_sync(self, instance_id: str) -> int:
        conn = self._connect()
        try:
            row = conn.execute("SELECT cursor FROM cursors WHERE instance_id = ?", (instance_id,)).fetchone()
            return int(row["cursor"]) if row else 0
        finally:
            conn.close()

    async def ingest(self, instance: Instance, events: list[dict[str, Any]], next_cursor: int) -> int:
        async with self.lock:
            return await asyncio.to_thread(self._ingest_sync, instance, events, next_cursor)

    def _ingest_sync(self, instance: Instance, events: list[dict[str, Any]], next_cursor: int) -> int:
        conn = self._connect()
        inserted = 0
        try:
            for event in events:
                event_id = int(event.get("id", 0) or 0)
                if event_id <= 0:
                    continue
                cur = conn.execute(
                    """
                    INSERT OR IGNORE INTO events (
                        instance_id, instance_name, event_id, ts, client_ip, method,
                        path, category, action, scanner, severity, escalation_level,
                        attacker_score, payload_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        instance.instance_id,
                        instance.name,
                        event_id,
                        str(event.get("ts") or event.get("timestamp") or datetime.now(timezone.utc).isoformat()),
                        str(event.get("client_ip", "unknown")),
                        str(event.get("method", "")),
                        str(event.get("path", "")),
                        str(event.get("category", "unknown")),
                        str(event.get("action", "")),
                        str(event.get("scanner", "unknown")),
                        int(event.get("severity", 1) or 1),
                        int(event.get("escalation_level", 1) or 1),
                        int(event.get("attacker_score", 0) or 0),
                        json.dumps(event, separators=(",", ":")),
                    ),
                )
                inserted += cur.rowcount
            conn.execute(
                """
                INSERT INTO cursors(instance_id, cursor, updated_at) VALUES (?, ?, ?)
                ON CONFLICT(instance_id) DO UPDATE SET cursor=excluded.cursor, updated_at=excluded.updated_at
                """,
                (instance.instance_id, int(next_cursor), datetime.now(timezone.utc).isoformat()),
            )
            conn.commit()
            return inserted
        finally:
            conn.close()

    async def snapshot(self, apps: list[dict[str, Any]]) -> dict[str, Any]:
        async with self.lock:
            return await asyncio.to_thread(self._snapshot_sync, apps)

    def _snapshot_sync(self, apps: list[dict[str, Any]]) -> dict[str, Any]:
        conn = self._connect()
        try:
            totals = conn.execute(
                "SELECT COUNT(*) events, COUNT(DISTINCT client_ip) unique_ips FROM events"
            ).fetchone()
            recent = conn.execute(
                """
                SELECT instance_id, instance_name, ts, client_ip, method, path, category,
                       action, scanner, severity, escalation_level, attacker_score
                FROM events ORDER BY ts DESC LIMIT 50
                """
            ).fetchall()
            top_paths = conn.execute(
                "SELECT path, COUNT(*) hits FROM events GROUP BY path ORDER BY hits DESC LIMIT 10"
            ).fetchall()
            top_categories = conn.execute(
                "SELECT category, COUNT(*) hits FROM events GROUP BY category ORDER BY hits DESC LIMIT 10"
            ).fetchall()
            top_scanners = conn.execute(
                "SELECT scanner, COUNT(*) hits FROM events GROUP BY scanner ORDER BY hits DESC LIMIT 10"
            ).fetchall()
            offenders = conn.execute(
                """
                SELECT client_ip AS ip, COUNT(*) hits, SUM(severity) score,
                       MAX(escalation_level) level, COUNT(DISTINCT instance_id) app_count,
                       MAX(ts) last_seen
                FROM events GROUP BY client_ip
                ORDER BY score DESC, hits DESC, app_count DESC LIMIT 20
                """
            ).fetchall()
            offender_rows: list[dict[str, Any]] = []
            for row in offenders:
                item = dict(row)
                app_rows = conn.execute(
                    "SELECT DISTINCT instance_name FROM events WHERE client_ip = ? ORDER BY instance_name",
                    (row["ip"],),
                ).fetchall()
                item["apps"] = [app["instance_name"] for app in app_rows]
                offender_rows.append(item)
            per_app = {
                row["instance_id"]: dict(row)
                for row in conn.execute(
                    """
                    SELECT instance_id, COUNT(*) events, COUNT(DISTINCT client_ip) unique_ips
                    FROM events GROUP BY instance_id
                    """
                ).fetchall()
            }
        finally:
            conn.close()

        normalized_apps: list[dict[str, Any]] = []
        for app in apps:
            counts = per_app.get(app["id"], {"events": 0, "unique_ips": 0})
            merged = dict(app)
            merged["events"] = int(counts.get("events", 0) or 0)
            merged["unique_ips"] = int(counts.get("unique_ips", 0) or 0)
            normalized_apps.append(merged)

        return {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "apps": normalized_apps,
            "summary": {
                "protected_apps": len(normalized_apps),
                "healthy_apps": sum(1 for app in normalized_apps if app.get("healthy")),
                "events": int(totals["events"] or 0),
                "unique_ips": int(totals["unique_ips"] or 0),
                "active_tarpits": sum(int(app.get("tarpits_active", 0) or 0) for app in normalized_apps),
                "level3_plus": sum(1 for row in offender_rows if int(row.get("level", 1) or 1) >= 3),
            },
            "recent": [dict(row) for row in recent],
            "top_paths": [dict(row) for row in top_paths],
            "top_categories": [dict(row) for row in top_categories],
            "top_scanners": [dict(row) for row in top_scanners],
            "top_offenders": offender_rows,
        }


class Dashboard:
    def __init__(self) -> None:
        self.instances = instances_from_env()
        self.hotpot_token = os.getenv("HOTPOT_ADMIN_TOKEN", "").strip()
        if not self.hotpot_token:
            raise RuntimeError("HOTPOT_ADMIN_TOKEN is required for dashboard collection")
        self.dashboard_token = os.getenv("HOTPOT_DASHBOARD_TOKEN", "").strip()
        if not self.dashboard_token:
            raise RuntimeError("HOTPOT_DASHBOARD_TOKEN is required")
        self.refresh_seconds = max(5, int(os.getenv("HOTPOT_DASHBOARD_REFRESH_SECONDS", "15")))
        self.timeout = max(2.0, float(os.getenv("HOTPOT_DASHBOARD_TIMEOUT", "5")))
        self.max_pages = max(1, int(os.getenv("HOTPOT_DASHBOARD_MAX_EVENT_PAGES", "20")))
        self.store = CentralStore(Path(os.getenv("HOTPOT_DASHBOARD_DATA_DIR", "/data")))
        self.client: ClientSession | None = None
        self.cache: dict[str, Any] = {}
        self.cache_lock = asyncio.Lock()
        self.refresh_task: asyncio.Task | None = None

    def authorized(self, request: web.Request) -> bool:
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Basic "):
            return False
        try:
            decoded = base64.b64decode(auth[6:], validate=True).decode("utf-8")
            _, password = decoded.split(":", 1)
        except (ValueError, UnicodeDecodeError):
            return False
        return hmac.compare_digest(password, self.dashboard_token)

    def require_auth(self, request: web.Request) -> None:
        if not self.authorized(request):
            raise web.HTTPUnauthorized(headers={"WWW-Authenticate": 'Basic realm="Hotpot Dashboard"'})

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
                pass

    async def fetch_json(self, url: str) -> dict[str, Any]:
        assert self.client is not None
        headers = {"Authorization": f"Bearer {self.hotpot_token}"}
        async with self.client.get(url, headers=headers) as response:
            response.raise_for_status()
            data = await response.json()
            if not isinstance(data, dict):
                raise RuntimeError("Hotpot API returned non-object JSON")
            return data

    async def collect_status(self, instance: Instance) -> dict[str, Any]:
        try:
            status = await self.fetch_json(f"{instance.url}/_hotpot/status")
            stats = status.get("stats", {}) if isinstance(status, dict) else {}
            upstream_health = status.get("upstream_health", {}) if isinstance(status, dict) else {}
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
            }
        except Exception as exc:
            return {
                "id": instance.instance_id,
                "name": instance.name,
                "healthy": False,
                "error": type(exc).__name__,
                "uptime_seconds": 0,
                "upstream": None,
                "upstream_health": {},
                "tarpits_active": 0,
                "tarpits_total": 0,
                "proxied": 0,
                "telemetry_errors": 0,
            }

    async def collect_events(self, instance: Instance) -> None:
        cursor = await self.store.cursor_for(instance.instance_id)
        for _ in range(self.max_pages):
            try:
                payload = await self.fetch_json(
                    f"{instance.url}/_hotpot/api/events?cursor={cursor}&limit=250"
                )
            except Exception:
                return
            events = payload.get("events", [])
            if not isinstance(events, list):
                return
            next_cursor = int(payload.get("next_cursor", cursor) or cursor)
            await self.store.ingest(instance, events, next_cursor)
            cursor = next_cursor
            if not payload.get("has_more") or not events:
                return

    async def refresh(self) -> None:
        await asyncio.gather(*(self.collect_events(instance) for instance in self.instances))
        apps = await asyncio.gather(*(self.collect_status(instance) for instance in self.instances))
        snapshot = await self.store.snapshot(list(apps))
        async with self.cache_lock:
            self.cache = snapshot

    async def health(self, request: web.Request) -> web.Response:
        async with self.cache_lock:
            apps = self.cache.get("apps", [])
        healthy = bool(apps) and all(app.get("healthy") for app in apps)
        return web.json_response({"healthy": healthy, "apps": len(apps)}, status=200 if healthy else 503)

    async def api_overview(self, request: web.Request) -> web.Response:
        self.require_auth(request)
        async with self.cache_lock:
            return web.json_response(self.cache, headers={"Cache-Control": "no-store"})

    async def index(self, request: web.Request) -> web.Response:
        self.require_auth(request)
        return web.Response(
            text=HTML,
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


HTML = r'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Hotpot Dashboard</title>
<style>:root{color-scheme:dark;--bg:#0b1020;--panel:#121a2d;--line:#26324a;--muted:#93a4bd;--text:#edf4ff;--good:#38d996;--bad:#ff6b6b}*{box-sizing:border-box}body{margin:0;font-family:system-ui,-apple-system,"Segoe UI",sans-serif;background:#0b1020;color:var(--text)}main{max-width:1500px;margin:auto;padding:28px}.header{display:flex;justify-content:space-between;align-items:end;margin-bottom:20px}.title{font-size:30px;font-weight:800}.muted{color:var(--muted)}.cards{display:grid;grid-template-columns:repeat(5,1fr);gap:12px}.card,.panel{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:16px}.metric{font-size:28px;font-weight:800}.label{font-size:12px;text-transform:uppercase;color:var(--muted)}.grid{display:grid;grid-template-columns:1.2fr .8fr;gap:14px;margin-top:14px}.appgrid{display:grid;grid-template-columns:repeat(2,1fr);gap:10px}.app{padding:12px;border:1px solid var(--line);border-radius:10px}.dot{display:inline-block;width:9px;height:9px;border-radius:50%;margin-right:7px}.ok{background:var(--good)}.down{background:var(--bad)}table{width:100%;border-collapse:collapse;font-size:13px}th,td{text-align:left;padding:8px;border-bottom:1px solid #202b40}code{color:#dbe8ff}@media(max-width:900px){.cards{grid-template-columns:repeat(2,1fr)}.grid{grid-template-columns:1fr}.appgrid{grid-template-columns:1fr}}</style></head>
<body><main><div class="header"><div><div class="title">🔥 Hotpot</div><div class="muted">Persistent cross-app attack intelligence</div></div><div id="updated" class="muted">Loading…</div></div><div id="metrics" class="cards"></div><div class="grid"><section class="panel"><h3>Protected applications</h3><div id="apps" class="appgrid"></div></section><section class="panel"><h3>Top offenders</h3><div id="offenders"></div></section></div><div class="grid"><section class="panel"><h3>Recent activity</h3><div style="overflow:auto"><table><thead><tr><th>Time</th><th>App</th><th>Source</th><th>Category</th><th>Path</th><th>Action</th></tr></thead><tbody id="recent"></tbody></table></div></section><section class="panel"><h3>Top paths</h3><div id="paths"></div><h3>Categories</h3><div id="categories"></div><h3>Scanners</h3><div id="scanners"></div></section></div>
<script>const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));const fmt=n=>new Intl.NumberFormat().format(n||0);function list(id,rows,key){document.getElementById(id).innerHTML=rows.map(x=>`<div style="padding:5px 0;border-bottom:1px solid #202b40">${esc(x[key])} <span class="muted">${fmt(x.hits)}</span></div>`).join('')||'<span class="muted">No data yet</span>'}async function load(){try{const r=await fetch('/api/overview',{cache:'no-store'});const d=await r.json();const s=d.summary;document.getElementById('updated').textContent='Updated '+new Date(d.generated_at).toLocaleTimeString();document.getElementById('metrics').innerHTML=[['Apps',s.protected_apps],['Healthy',s.healthy_apps+'/'+s.protected_apps],['Events',s.events],['Unique attackers',s.unique_ips],['Active tarpits',s.active_tarpits]].map(x=>`<div class="card"><div class="label">${esc(x[0])}</div><div class="metric">${esc(x[1])}</div></div>`).join('');document.getElementById('apps').innerHTML=d.apps.map(a=>`<div class="app"><strong><span class="dot ${a.healthy?'ok':'down'}"></span>${esc(a.name)}</strong><div class="muted">${a.healthy?'Ready':esc(a.error||a.upstream_health?.error||'Unavailable')}</div><div>${fmt(a.events)} events · ${fmt(a.unique_ips)} attackers · ${fmt(a.tarpits_active)} active tarpits</div><div class="muted">${fmt(a.proxied)} proxied · ${fmt(a.telemetry_errors)} telemetry errors</div></div>`).join('');document.getElementById('offenders').innerHTML=d.top_offenders.slice(0,10).map(o=>`<div style="padding:7px 0;border-bottom:1px solid #202b40"><strong>${esc(o.ip)}</strong> · score ${fmt(o.score)} · ${fmt(o.hits)} hits · ${o.app_count} apps<div class="muted">${esc(o.apps.join(', '))}</div></div>`).join('')||'<span class="muted">No offenders yet</span>';document.getElementById('recent').innerHTML=d.recent.map(e=>`<tr><td>${esc(new Date(e.ts).toLocaleString())}</td><td>${esc(e.instance_name)}</td><td>${esc(e.client_ip)}</td><td>${esc(e.category)}</td><td><code>${esc(e.path)}</code></td><td>${esc(e.action)}</td></tr>`).join('');list('paths',d.top_paths,'path');list('categories',d.top_categories,'category');list('scanners',d.top_scanners,'scanner')}catch(e){document.getElementById('updated').textContent='Refresh failed'}}load();setInterval(load,15000);</script></main></body></html>'''


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
