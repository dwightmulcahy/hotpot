from __future__ import annotations

import json
import os
import uuid
from pathlib import Path

from aiohttp import web

from . import runtime as core
from .notification_routing import NotificationRoutingPolicy, RoutedInvestigationStore
from .notifications import NotificationCenter
from .observability_production import ObservabilityDashboard


TEST_UI_JS = r'''
<script>
(()=>{
  async function addNotificationControls(){
    const center=document.getElementById('notificationCenter');
    if(!center)return;
    const panel=center.closest('section.panel');
    const head=panel?.querySelector('.panel-head');
    if(!head)return;
    if(!document.getElementById('sendTestNotification')){
      const button=document.createElement('button');
      button.id='sendTestNotification';button.className='btn ghost';button.type='button';button.textContent='Send test';
      head.appendChild(button);
      button.addEventListener('click',async()=>{
        if(!confirm('Send a test notification through every configured external channel?'))return;
        button.disabled=true;button.textContent='Sending…';
        try{
          const r=await fetch('/api/notifications/test',{method:'POST',headers:{'X-Hotpot-Action':'notification-test'}});
          let body={};try{body=await r.json()}catch(e){}
          if(!r.ok)throw new Error(body.error||body.message||('HTTP '+r.status));
          alert('Test notification delivered through: '+((body.channels||[]).join(', ')||'none'));
          document.getElementById('refreshNotifications')?.click();
        }catch(e){alert('Test notification failed: '+e.message)}
        finally{button.disabled=false;button.textContent='Send test'}
      });
    }
    if(!document.getElementById('notificationRoutingSummary')){
      const summary=document.createElement('div');summary.id='notificationRoutingSummary';summary.className='meta-line';summary.style.marginBottom='9px';
      center.insertAdjacentElement('beforebegin',summary);
    }
    try{
      const r=await fetch('/api/notifications?limit=1',{cache:'no-store'});if(!r.ok)return;
      const d=await r.json();const route=d.routing||{};const health=d.delivery_health||{};
      const fmtRoute=k=>((route[k]||{}).active||[]).join('+')||'dashboard only';
      document.getElementById('notificationRoutingSummary').textContent='Routing: critical → '+fmtRoute('critical')+' · warning → '+fmtRoute('warning')+' · info → '+fmtRoute('info')+(health.last_success_at?' · last delivery '+shortWhen(health.last_success_at):'');
    }catch(e){}
  }
  addNotificationControls();setInterval(addNotificationControls,15000);
})();
</script>
'''


class RoutedObservabilityDashboard(ObservabilityDashboard):
    """Observability dashboard with severity routing and delivery self-test."""

    def __init__(self) -> None:
        super().__init__()
        self.notification_routing = NotificationRoutingPolicy.from_env()
        self.store = RoutedInvestigationStore(
            Path(os.getenv("HOTPOT_DASHBOARD_DATA_DIR", "/data")),
            retention_days=self.retention_days,
            routing=self.notification_routing,
            configured_channels=self.notification_config.channels,
            delivery_enabled=self.notification_config.enabled,
        )
        self.notifications = NotificationCenter(self.notification_config, self.store)

    async def api_notifications(self, request: web.Request) -> web.Response:
        response = await super().api_notifications(request)
        payload = json.loads(response.text)
        payload["routing"] = self.notification_routing.as_dict(
            configured_channels=self.notification_config.channels,
            enabled=self.notification_config.enabled,
        )
        payload["delivery_health"] = await self.store.notification_delivery_summary()
        return web.json_response(payload, headers={"Cache-Control": "no-store"})

    async def api_notification_test(self, request: web.Request) -> web.Response:
        context = self.require_action(request, "notification-test")
        if not self.notification_config.enabled:
            return web.json_response(
                {"error": "external notification delivery is disabled"}, status=409
            )
        channels = list(self.notification_config.channels)
        if not channels:
            return web.json_response(
                {"error": "no external notification channels are configured"}, status=409
            )
        if self.client is None:
            return web.json_response({"error": "dashboard HTTP client is not ready"}, status=503)

        event_key = f"notification-test:{uuid.uuid4().hex}"
        notification, _ = await self.store.queue_notification(
            event_key=event_key,
            event_type="notification_test",
            severity="critical",
            subject="Hotpot notification test",
            message="This is a test notification sent from the Hotpot dashboard.",
            channels=channels,
            payload={"requested_by": context.username},
        )
        await self.notifications.deliver_due(self.client)
        rows = await self.store.recent_notifications(limit=20)
        updated = next((row for row in rows if row.get("event_key") == event_key), notification)
        await self._record_action(
            context,
            event_type="dashboard_notification_test",
            message="Dashboard user sent a notification delivery test",
            details={"channels": channels, "status": updated.get("status")},
        )
        status = 200 if updated.get("status") == "sent" else 502
        return web.json_response(
            {
                "ok": status == 200,
                "channels": channels,
                "notification": updated,
            },
            status=status,
            headers={"Cache-Control": "no-store"},
        )

    async def index(self, request: web.Request) -> web.Response:
        response = await super().index(request)
        response.text = response.text.replace("</body>", TEST_UI_JS + "</body>", 1)
        return response


def build_app() -> web.Application:
    dashboard = RoutedObservabilityDashboard()
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
    app.router.add_post("/api/notifications/test", dashboard.api_notification_test)
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
