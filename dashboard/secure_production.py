from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from aiohttp import web

from . import runtime as core
from .production import PRODUCTION_HTML, ProductionDashboard
from .security import (
    ACTION_HEADER,
    CSRF_HEADER,
    SESSION_COOKIE,
    ActionRateLimiter,
    AuthContext,
    SessionManager,
    secret_from_env,
)
from .security_store import SecureEnforcementStore


_SECRET_NAMES = (
    "HOTPOT_ADMIN_TOKEN",
    "HOTPOT_DASHBOARD_TOKEN",
    "HOTPOT_CLOUDFLARE_API_TOKEN",
)


def _restore_environment(previous: dict[str, str | None]) -> None:
    for name, value in previous.items():
        if value is None:
            os.environ.pop(name, None)
        else:
            os.environ[name] = value


class SecureProductionDashboard(ProductionDashboard):
    """Production dashboard with signed sessions and CSRF-protected actions."""

    def __init__(self) -> None:
        # The existing dashboard constructors consume env vars. Resolve optional
        # *_FILE secrets just for construction, then restore the process environment
        # so file-backed credentials do not remain in os.environ.
        previous = {name: os.environ.get(name) for name in _SECRET_NAMES}
        resolved = {
            "HOTPOT_ADMIN_TOKEN": secret_from_env(
                "HOTPOT_ADMIN_TOKEN", required=True
            ),
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

        # Replace the base store with the additive security-aware store. Both use
        # the same SQLite file and migrations are safe to run repeatedly.
        self.store = SecureEnforcementStore(
            Path(os.getenv("HOTPOT_DASHBOARD_DATA_DIR", "/data")),
            retention_days=self.retention_days,
        )
        self.sessions = SessionManager(self.dashboard_token)
        self.action_limiter = ActionRateLimiter()

    def _basic_context(self, request: web.Request) -> AuthContext | None:
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Basic "):
            return None
        import base64
        import hmac

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
            raise web.HTTPBadRequest(
                text=f"{ACTION_HEADER}: {action} header is required"
            )
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
        return response

    @staticmethod
    def _bootstrap_script(csrf: str, username: str, expires_at: str | None) -> str:
        config = json.dumps(
            {
                "csrfToken": csrf,
                "user": username,
                "expiresAt": expires_at,
            },
            separators=(",", ":"),
        )
        return f"""<script>
window.HOTPOT_SECURITY={config};
(()=>{{
  const originalFetch=window.fetch.bind(window);
  window.fetch=(input,init={{}})=>{{
    const method=String(init.method||(input instanceof Request?input.method:'GET')).toUpperCase();
    const raw=typeof input==='string'?input:input.url;
    const url=new URL(raw,window.location.href);
    if(url.origin===window.location.origin&&!['GET','HEAD','OPTIONS'].includes(method)){{
      const headers=new Headers(init.headers||(input instanceof Request?input.headers:undefined));
      headers.set('{CSRF_HEADER}',window.HOTPOT_SECURITY.csrfToken);
      init={{...init,headers}};
    }}
    return originalFetch(input,init);
  }};
}})();
</script>
"""

    async def index(self, request: web.Request) -> web.Response:
        context = self.auth_context(request)
        if context is None:
            raise web.HTTPUnauthorized(
                headers={"WWW-Authenticate": 'Basic realm="Hotpot Dashboard"'}
            )
        token, fresh, csrf = self.sessions.issue(context.username)
        public = self.sessions.public_session(fresh, csrf)
        bootstrap = self._bootstrap_script(
            csrf, fresh.username, public.get("expires_at")
        )
        html = PRODUCTION_HTML.replace("<script>\nconst esc", bootstrap + "<script>\nconst esc", 1)
        response = web.Response(
            text=html,
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
        self.sessions.set_cookie(response, token)
        return response


def build_app() -> web.Application:
    dashboard = SecureProductionDashboard()
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
