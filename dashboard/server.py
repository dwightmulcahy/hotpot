from __future__ import annotations

import base64
import hmac
import json
import os
import uuid
from pathlib import Path
from typing import Any

from aiohttp import web

from . import runtime as core
from .api_v1 import register_api_routes
from .notification_routing import NotificationRoutingPolicy, RoutedInvestigationStore
from .notifications import NotificationCenter, NotificationConfig
from .production import PRODUCTION_HTML
from .security import (
    ACTION_HEADER,
    CSRF_HEADER,
    SESSION_COOKIE,
    ActionRateLimiter,
    AuthContext,
    SessionManager,
    secret_from_env,
)
from .transactional_production import TransactionalProductionDashboard


_SECRET_NAMES = (
    "HOTPOT_ADMIN_TOKEN",
    "HOTPOT_DASHBOARD_TOKEN",
    "HOTPOT_CLOUDFLARE_API_TOKEN",
)
STATIC_DIR = Path(__file__).with_name("static")


def _restore_environment(previous: dict[str, str | None]) -> None:
    for name, value in previous.items():
        if value is None:
            os.environ.pop(name, None)
        else:
            os.environ[name] = value


def dashboard_page() -> str:
    """Attach static dashboard enhancements without runtime HTML string replacement."""

    head, head_marker, remainder = PRODUCTION_HTML.partition("</head>")
    if not head_marker:
        raise RuntimeError("dashboard template is missing </head>")
    body, body_marker, tail = remainder.rpartition("</body>")
    if not body_marker:
        raise RuntimeError("dashboard template is missing </body>")
    assets = (
        '<link rel="stylesheet" href="/static/observability.css">\n'
        '<script src="/static/security.js"></script>\n'
    )
    scripts = (
        '<script src="/static/observability.js"></script>\n'
        '<script src="/static/campaigns.js"></script>\n'
    )
    return head + assets + head_marker + body + scripts + body_marker + tail


DASHBOARD_HTML = dashboard_page()


class DashboardApplication(TransactionalProductionDashboard):
    """Single production dashboard application.

    Security, investigation timelines, notifications, routing and Cloudflare response
    all terminate in this class. Supporting modules hold reusable stores/policies only;
    there is no production -> secure -> observability subclass chain at runtime.
    """

    def __init__(self) -> None:
        previous = {name: os.environ.get(name) for name in _SECRET_NAMES}
        resolved = {
            "HOTPOT_ADMIN_TOKEN": secret_from_env("HOTPOT_ADMIN_TOKEN", required=True),
            "HOTPOT_DASHBOARD_TOKEN": secret_from_env(
                "HOTPOT_DASHBOARD_TOKEN", required=True
            ),
            "HOTPOT_CLOUDFLARE_API_TOKEN": secret_from_env(
                "HOTPOT_CLOUDFLARE_API_TOKEN"
            ),
        }
        try:
            for name, value in resolved.items():
                if value:
                    os.environ[name] = value
                else:
                    os.environ.pop(name, None)
            super().__init__()
        finally:
            _restore_environment(previous)

        self.sessions = SessionManager(self.dashboard_token)
        self.action_limiter = ActionRateLimiter()
        self.notification_config = NotificationConfig.from_env()
        self.notification_routing = NotificationRoutingPolicy.from_env()
        self.store = RoutedInvestigationStore(
            Path(os.getenv("HOTPOT_DASHBOARD_DATA_DIR", "/data")),
            retention_days=self.retention_days,
            routing=self.notification_routing,
            configured_channels=self.notification_config.channels,
            delivery_enabled=self.notification_config.enabled,
        )
        self.notifications = NotificationCenter(self.notification_config, self.store)
        self.notification_processing_errors = 0

    def _basic_context(self, request: web.Request) -> AuthContext | None:
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Basic "):
            return None
        try:
            decoded = base64.b64decode(auth[6:], validate=True).decode("utf-8")
            username, password = decoded.split(":", 1)
        except (ValueError, UnicodeDecodeError):
            return None
        if not hmac.compare_digest(password, self.dashboard_token):
            return None
        return AuthContext(username or "hotpot", None, None, "basic")

    def auth_context(self, request: web.Request) -> AuthContext | None:
        session = self.sessions.verify(request.cookies.get(SESSION_COOKIE))
        if session is not None:
            return session
        return self._basic_context(request)

    def authorized(self, request: web.Request) -> bool:
        return self.auth_context(request) is not None

    def require_auth(self, request: web.Request) -> None:
        if self.auth_context(request) is None:
            raise web.HTTPUnauthorized(
                headers={"WWW-Authenticate": 'Basic realm="Hotpot Dashboard"'}
            )

    def require_action(self, request: web.Request, action: str) -> AuthContext:
        if request.headers.get(ACTION_HEADER, "") != action:
            raise web.HTTPBadRequest(text=f"{ACTION_HEADER}: {action} header is required")
        context = self.sessions.verify(request.cookies.get(SESSION_COOKIE))
        if context is None:
            raise web.HTTPUnauthorized(
                text="A current dashboard session is required; reload the dashboard to renew it"
            )
        if not self.sessions.verify_csrf(context, request.headers.get(CSRF_HEADER)):
            raise web.HTTPForbidden(text="Invalid or missing dashboard CSRF token")
        allowed, retry_after = self.action_limiter.check(context.session_id or "")
        if not allowed:
            raise web.HTTPTooManyRequests(
                text="Dashboard action rate limit exceeded",
                headers={"Retry-After": str(retry_after)},
            )
        return context

    async def _record_action(
        self,
        context: AuthContext,
        *,
        event_type: str,
        message: str,
        recommendation_id: str | None = None,
        status: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        await self.store.record_dashboard_action(
            event_type=event_type,
            message=message,
            principal=context.username,
            session_id=context.session_id,
            recommendation_id=recommendation_id,
            status=status,
            details=details,
        )

    async def api_session(self, request: web.Request) -> web.Response:
        context = self.auth_context(request)
        if context is None:
            raise web.HTTPUnauthorized(
                headers={"WWW-Authenticate": 'Basic realm="Hotpot Dashboard"'}
            )
        token, fresh, csrf = self.sessions.issue(context.username)
        response = web.json_response(
            self.sessions.public_session(fresh, csrf),
            headers={"Cache-Control": "no-store"},
        )
        self.sessions.set_cookie(response, token)
        return response

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
                "routing": self.notification_routing.as_dict(
                    configured_channels=self.notification_config.channels,
                    enabled=self.notification_config.enabled,
                ),
                "delivery_health": await self.store.notification_delivery_summary(),
                "count": len(rows),
                "notifications": rows,
                "processing_errors": self.notification_processing_errors,
            },
            headers={"Cache-Control": "no-store"},
        )

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
            return web.json_response(
                {"error": "dashboard HTTP client is not ready"}, status=503
            )

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
        updated = next(
            (row for row in rows if row.get("event_key") == event_key), notification
        )
        await self._record_action(
            context,
            event_type="dashboard_notification_test",
            message="Dashboard user sent a notification delivery test",
            details={"channels": channels, "status": updated.get("status")},
        )
        status = 200 if updated.get("status") == "sent" else 502
        return web.json_response(
            {"ok": status == 200, "channels": channels, "notification": updated},
            status=status,
            headers={"Cache-Control": "no-store"},
        )

    async def api_dismiss_recommendation(self, request: web.Request) -> web.Response:
        context = self.require_action(request, "dismiss")
        recommendation_id = request.match_info.get("recommendation_id", "").strip()
        response = await super().api_dismiss_recommendation(request)
        await self._record_action(
            context,
            event_type="dashboard_dismiss",
            message="Dashboard user dismissed recommendation",
            recommendation_id=recommendation_id or None,
            details={"http_status": response.status},
        )
        return response

    async def api_approve_recommendation(self, request: web.Request) -> web.Response:
        context = self.require_action(request, "approve")
        recommendation_id = request.match_info.get("recommendation_id", "").strip()
        response = await super().api_approve_recommendation(request)
        await self._record_action(
            context,
            event_type="dashboard_approve",
            message=(
                "Dashboard user approved Cloudflare enforcement"
                if response.status < 400
                else "Dashboard approval reached Cloudflare but did not apply cleanly"
            ),
            recommendation_id=recommendation_id or None,
            details={"http_status": response.status},
        )
        return response

    async def api_remove_enforcement(self, request: web.Request) -> web.Response:
        context = self.require_action(request, "remove")
        recommendation_id = request.match_info.get("recommendation_id", "").strip()
        response = await super().api_remove_enforcement(request)
        await self._record_action(
            context,
            event_type="dashboard_remove",
            message="Dashboard user requested immediate Cloudflare rule removal",
            recommendation_id=recommendation_id or None,
            details={"http_status": response.status},
        )
        return response

    async def api_repair_enforcement(self, request: web.Request) -> web.Response:
        context = self.require_action(request, "repair")
        recommendation_id = request.match_info.get("recommendation_id", "").strip()
        response = await super().api_repair_enforcement(request)
        await self._record_action(
            context,
            event_type="dashboard_repair",
            message="Dashboard user requested verified Cloudflare rule repair",
            recommendation_id=recommendation_id or None,
            details={"http_status": response.status},
        )
        return response

    async def api_remove_orphan(self, request: web.Request) -> web.Response:
        context = self.require_action(request, "remove-orphan")
        response = await super().api_remove_orphan(request)
        await self._record_action(
            context,
            event_type="dashboard_remove_orphan",
            message="Dashboard user requested verified orphan-rule removal",
            details={"http_status": response.status},
        )
        return response

    async def api_reconcile_enforcement(self, request: web.Request) -> web.Response:
        context = self.require_action(request, "reconcile")
        response = await super().api_reconcile_enforcement(request)
        await self._record_action(
            context,
            event_type="dashboard_reconcile",
            message="Dashboard user ran Cloudflare reconciliation",
            details={"http_status": response.status},
        )
        return response

    async def api_system_check(self, request: web.Request) -> web.Response:
        context = self.require_action(request, "system-check")
        response = await super().api_system_check(request)
        await self._record_action(
            context,
            event_type="dashboard_system_check",
            message="Dashboard user ran the non-destructive system self-test",
            details={"http_status": response.status},
        )
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
        context = self.auth_context(request)
        if context is None:
            raise web.HTTPUnauthorized(
                headers={"WWW-Authenticate": 'Basic realm="Hotpot Dashboard"'}
            )
        token, _, _ = self.sessions.issue(context.username)
        response = web.Response(
            text=DASHBOARD_HTML,
            content_type="text/html",
            charset="utf-8",
            headers={
                "Cache-Control": "no-store",
                "X-Robots-Tag": "noindex, nofollow",
                "Content-Security-Policy": "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'",
                "X-Frame-Options": "DENY",
                "X-Content-Type-Options": "nosniff",
                "Referrer-Policy": "no-referrer",
            },
        )
        self.sessions.set_cookie(response, token)
        return response


def build_app() -> web.Application:
    dashboard = DashboardApplication()
    app = web.Application()
    app[core.DASHBOARD_KEY] = dashboard
    app.on_startup.append(dashboard.startup)
    app.on_cleanup.append(dashboard.shutdown)
    app.router.add_static("/static/", STATIC_DIR, show_index=False)
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
    app.router.add_get("/api/enforcement/cleanup-jobs", dashboard.api_cleanup_jobs)
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
        "/api/recommendation/{recommendation_id}/repair",
        dashboard.api_repair_enforcement,
    )
    app.router.add_post(
        "/api/enforcement/orphan/remove", dashboard.api_remove_orphan
    )
    app.router.add_post(
        "/api/enforcement/reconcile", dashboard.api_reconcile_enforcement
    )
    app.router.add_post("/api/system-check", dashboard.api_system_check)
    register_api_routes(app, dashboard)
    return app


def main() -> None:
    bind = os.getenv("HOTPOT_DASHBOARD_BIND", "127.0.0.1")
    port = int(os.getenv("HOTPOT_DASHBOARD_PORT", "19090"))
    web.run_app(build_app(), host=bind, port=port, access_log=None)


if __name__ == "__main__":
    main()
