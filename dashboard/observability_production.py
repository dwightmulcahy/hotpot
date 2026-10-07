from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from aiohttp import web

from . import runtime as core
from .investigation_store import InvestigationStore
from .notifications import NotificationCenter, NotificationConfig
from .secure_production import SecureProductionDashboard


EXTRA_CSS = r'''
.timeline{position:relative;margin-top:4px;padding-left:18px}.timeline:before{content:"";position:absolute;left:5px;top:5px;bottom:5px;width:1px;background:var(--line)}.timeline-item{position:relative;padding:0 0 14px 12px}.timeline-item:last-child{padding-bottom:0}.timeline-dot{position:absolute;left:-17px;top:5px;width:9px;height:9px;border:2px solid var(--surface);border-radius:50%;background:var(--muted)}.timeline-item.probe .timeline-dot{background:var(--info)}.timeline-item.escalation .timeline-dot{background:var(--warn)}.timeline-item.approval .timeline-dot,.timeline-item.enforcement .timeline-dot{background:var(--good)}.timeline-item.audit .timeline-dot{background:var(--muted)}.timeline-time{font-size:10px;color:var(--faint);text-transform:uppercase;letter-spacing:.04em}.timeline-title{font-weight:680;margin-top:2px}.timeline-detail{font-size:11px;color:var(--muted);margin-top:2px;overflow-wrap:anywhere}.timeline-principal{font-size:10px;color:var(--faint);margin-top:3px}.notify-row{display:grid;grid-template-columns:92px minmax(180px,.75fr) minmax(260px,1.4fr) 120px;gap:10px;padding:9px 0;border-bottom:1px solid var(--line-soft);font-size:12px}.notify-row:last-child{border-bottom:0}.notify-subject{font-weight:650;overflow-wrap:anywhere}.notify-message{color:var(--muted);overflow-wrap:anywhere}.badge.critical{color:var(--bad);border-color:#66353b;background:var(--bad-bg)}.badge.info{color:var(--info);border-color:#365272;background:var(--info-bg)}.badge.sent{color:var(--good);border-color:#2e5547;background:var(--good-bg)}.badge.recorded{color:var(--muted)}.badge.failed{color:var(--bad);border-color:#66353b;background:var(--bad-bg)}@media(max-width:720px){.notify-row{grid-template-columns:90px 1fr}.notify-row>:nth-child(3),.notify-row>:nth-child(4){display:none}}
'''


EXTRA_JS = r'''
<script>
(()=>{
  const baseThreatDrawer=renderThreatDrawer;
  renderThreatDrawer=function(d){
    baseThreatDrawer(d);
    const body=document.getElementById('drawerBody');
    const rows=d.timeline||[];
    const section=document.createElement('div');section.className='drawer-section';
    const items=rows.map(x=>{
      const principal=x.principal?`<div class="timeline-principal">${esc(x.source||'dashboard')} · ${esc(x.principal)}</div>`:'';
      const level=x.level?` ${levelBadge(x.level)}`:'';
      const app=x.instance_name?` · ${esc(x.instance_name)}`:'';
      return `<div class="timeline-item ${esc(x.kind||'audit')}"><span class="timeline-dot"></span><div class="timeline-time">${esc(shortWhen(x.ts))}${app}</div><div class="timeline-title">${esc(x.title||x.event_type||'Activity')}${level}</div><div class="timeline-detail">${esc(x.detail||'')}</div>${principal}</div>`;
    }).join('');
    section.innerHTML=`<h4>Investigation timeline</h4><div class="timeline">${items||'<div class="empty">No retained timeline activity</div>'}</div>`;
    const responseSection=[...body.querySelectorAll('.drawer-section')].find(el=>el.querySelector('h4')?.textContent==='Response');
    if(responseSection)responseSection.insertAdjacentElement('afterend',section);else body.appendChild(section);
  };

  let notificationLoadedAt=0,notificationLoading=false;
  function ensureNotificationPanel(){
    if(document.getElementById('notificationCenter'))return;
    const anchor=document.getElementById('systemCheck')?.closest('section.panel');if(!anchor)return;
    const panel=document.createElement('section');panel.className='panel';panel.style.marginTop='12px';
    panel.innerHTML='<div class="panel-head"><div><div class="section-kicker">Meaningful alerts</div><h2>Notification center</h2></div><button id="refreshNotifications" class="panel-link" type="button">Refresh</button></div><div id="notificationCenter"><div class="empty">Loading notification state…</div></div>';
    anchor.insertAdjacentElement('afterend',panel);
    document.getElementById('refreshNotifications').addEventListener('click',()=>loadNotificationCenter(true));
  }
  async function loadNotificationCenter(force=false){
    ensureNotificationPanel();const target=document.getElementById('notificationCenter');if(!target||notificationLoading)return;
    const now=Date.now();if(!force&&notificationLoadedAt&&now-notificationLoadedAt<12000)return;notificationLoading=true;
    try{
      const r=await fetch('/api/notifications?limit=30',{cache:'no-store'});if(!r.ok)throw new Error('notifications '+r.status);const d=await r.json();notificationLoadedAt=Date.now();
      const c=d.config||{},channels=c.channels||[],rows=d.notifications||[];
      const mode=c.enabled?(channels.length?`Delivery active · ${channels.join(' + ')}`:'Enabled, but no delivery channel configured'):'External delivery off · recording important events locally';
      const header=`<div class="reconcile-summary"><span class="badge ${c.enabled&&channels.length?'pass':'neutral'}">${c.enabled&&channels.length?'active':'local only'}</span><span class="muted">${esc(mode)} · retry ${esc(age(c.retry_seconds||0))}${d.processing_errors?' · '+fmt(d.processing_errors)+' processing error(s)':''}</span></div>`;
      const policy='<div class="meta-line" style="margin-bottom:9px">Alerts: L4 recommendations, high-confidence L3 challenges, Cloudflare apply/removal failures, drift/missing/orphan rules, unhealthy instances, and failed system checks. Routine L1/L2 probes are ignored.</div>';
      const list=rows.map(x=>`<div class="notify-row"><div><span class="badge ${esc(x.severity||'info')}">${esc(x.severity||'info')}</span><div style="margin-top:4px"><span class="badge ${esc(x.status||'recorded')}">${esc(x.status||'recorded')}</span></div></div><div><div class="notify-subject">${esc(x.subject)}</div><div class="cell-sub">${esc(shortWhen(x.created_at))}${x.actor_key?' · '+esc(x.actor_key):''}</div></div><div class="notify-message">${esc(x.message||'')}${x.last_error?'<div class="danger" style="margin-top:3px">'+esc(x.last_error)+'</div>':''}</div><div class="muted">${esc((x.channels||[]).join(', ')||'local')}</div></div>`).join('')||'<div class="empty">No meaningful alert events have been recorded yet.</div>';
      target.innerHTML=header+policy+list;
    }catch(e){target.innerHTML='<div class="empty danger">Could not load notification center.</div>';notificationLoadedAt=0}finally{notificationLoading=false}
  }
  const baseRenderOperations=renderOperations;
  renderOperations=function(d){baseRenderOperations(d);ensureNotificationPanel();loadNotificationCenter(false)};
  ensureNotificationPanel();loadNotificationCenter(true);setInterval(()=>loadNotificationCenter(false),30000);
})();
</script>
'''


class ObservabilityDashboard(SecureProductionDashboard):
    """Secure production dashboard with timelines and meaningful alert delivery."""

    def __init__(self) -> None:
        super().__init__()
        self.store = InvestigationStore(
            Path(os.getenv("HOTPOT_DASHBOARD_DATA_DIR", "/data")),
            retention_days=self.retention_days,
        )
        self.notification_config = NotificationConfig.from_env()
        self.notifications = NotificationCenter(self.notification_config, self.store)
        self.notification_processing_errors = 0

    async def refresh(self) -> None:
        await super().refresh()
        if self.client is None:
            return
        async with self.cache_lock:
            apps = list(self.cache.get("apps", []))
        try:
            await self.notifications.process_instance_health(apps, self.client)
        except Exception:
            self.notification_processing_errors += 1
        try:
            await self.notifications.sync_audit_events(self.client)
        except Exception:
            self.notification_processing_errors += 1

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
        result["timeline"] = await self.store.attacker_timeline(identity_key)
        return web.json_response(result, headers={"Cache-Control": "no-store"})

    async def api_notifications(self, request: web.Request) -> web.Response:
        self.require_auth(request)
        try:
            limit = max(1, min(200, int(request.query.get("limit", "50"))))
        except ValueError as exc:
            raise web.HTTPBadRequest(text="limit must be an integer") from exc
        rows = await self.store.recent_notifications(limit=limit)
        return web.json_response(
            {
                "config": self.notification_config.public_status(),
                "count": len(rows),
                "notifications": rows,
                "processing_errors": self.notification_processing_errors,
            },
            headers={"Cache-Control": "no-store"},
        )

    async def api_system_check(self, request: web.Request) -> web.Response:
        response = await super().api_system_check(request)
        if self.client is not None:
            try:
                payload = json.loads(response.text)
                if isinstance(payload, dict):
                    await self.notifications.record_system_check_failure(
                        payload, self.client
                    )
            except Exception:
                self.notification_processing_errors += 1
        return response

    async def index(self, request: web.Request) -> web.Response:
        response = await super().index(request)
        text = response.text
        text = text.replace("</style>", EXTRA_CSS + "</style>", 1)
        text = text.replace("</body>", EXTRA_JS + "</body>", 1)
        response.text = text
        return response


def build_app() -> web.Application:
    dashboard = ObservabilityDashboard()
    app = web.Application()
    app[core.DASHBOARD_KEY] = dashboard
    app.on_startup.append(dashboard.startup)
    app.on_cleanup.append(dashboard.shutdown)
    app.router.add_get("/", dashboard.index)
    app.router.add_get("/health", dashboard.health)
    app.router.add_get("/api/session", dashboard.api_session)
    app.router.add_get("/api/overview", dashboard.api_overview)
    app.router.add_get("/api/attacker", dashboard.api_attacker)
    app.router.add_get("/api/network", dashboard.api_network)
    app.router.add_get("/api/recommendations", dashboard.api_recommendations)
    app.router.add_get("/api/recommendation", dashboard.api_recommendation)
    app.router.add_get("/api/audit", dashboard.api_audit)
    app.router.add_get("/api/notifications", dashboard.api_notifications)
    app.router.add_post(
        "/api/recommendation/{recommendation_id}/dismiss",
        dashboard.api_dismiss_recommendation,
    )
    app.router.add_post(
        "/api/recommendation/{recommendation_id}/approve",
        dashboard.api_approve_recommendation,
    )
    app.router.add_post(
        "/api/recommendation/{recommendation_id}/remove",
        dashboard.api_remove_enforcement,
    )
    app.router.add_post(
        "/api/enforcement/reconcile", dashboard.api_reconcile_enforcement
    )
    app.router.add_post("/api/system-check", dashboard.api_system_check)
    return app


def main() -> None:
    bind = os.getenv("HOTPOT_DASHBOARD_BIND", "127.0.0.1")
    port = int(os.getenv("HOTPOT_DASHBOARD_PORT", "19090"))
    web.run_app(build_app(), host=bind, port=port, access_log=None)


if __name__ == "__main__":
    main()
