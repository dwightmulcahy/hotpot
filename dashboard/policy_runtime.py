from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from aiohttp import web

from . import runtime as core
from .api_v1 import register_api_routes
from .deployment import collect_deployment_report
from .policy import PolicyManager
from .server import (
    DASHBOARD_HTML as BASE_DASHBOARD_HTML,
    DashboardApplication,
    STATIC_DIR,
)


def policy_dashboard_page() -> str:
    """Attach policy and deployment assets to the composed production dashboard."""

    head, head_marker, remainder = BASE_DASHBOARD_HTML.partition("</head>")
    if not head_marker:
        raise RuntimeError("dashboard template is missing </head>")
    body, body_marker, tail = remainder.rpartition("</body>")
    if not body_marker:
        raise RuntimeError("dashboard template is missing </body>")
    return (
        head
        + '<link rel="stylesheet" href="/static/policy.css">\n'
        + '<link rel="stylesheet" href="/static/deployment.css">\n'
        + head_marker
        + body
        + '<script src="/static/policy.js"></script>\n'
        + '<script src="/static/deployment.js"></script>\n'
        + body_marker
        + tail
    )


POLICY_DASHBOARD_HTML = policy_dashboard_page()


class PolicyDashboardApplication(DashboardApplication):
    """Dashboard application with policy and deployment visibility."""

    def __init__(self) -> None:
        super().__init__()
        self.policy_manager = PolicyManager(
            Path(os.getenv("HOTPOT_DASHBOARD_DATA_DIR", "/data")), self.instances
        )

    async def collect_status(self, instance) -> dict[str, Any]:
        row = await super().collect_status(instance)
        dynamic = await self.policy_manager.effective_allow_cidrs(instance.instance_id)
        row["allowlist_cidrs"] = sorted(
            set(row.get("allowlist_cidrs") or []) | set(dynamic)
        )
        row["policy_desired_allow_cidrs"] = dynamic
        return row

    async def refresh(self) -> None:
        if self.client is not None:
            try:
                await self.policy_manager.reconcile(
                    self.client, token=self.hotpot_token, force=False
                )
            except Exception:
                # Each core keeps its last-known-good snapshot when central sync is
                # unavailable; policy drift is visible without taking down dashboard.
                pass
        await super().refresh()

    async def _recommendation_is_policy_suppressed(
        self, recommendation: dict[str, Any]
    ) -> dict[str, Any] | None:
        actor_key = str(recommendation.get("actor_key") or "")
        actor_policy = await self.policy_manager.suppression_for_actor(actor_key)
        if actor_policy is not None:
            return actor_policy
        evidence = recommendation.get("evidence") or {}
        for category in evidence.get("categories") or []:
            preview = await self.policy_manager.preview(
                {"actor_key": actor_key, "category": str(category)}
            )
            match = next(
                (
                    item
                    for item in preview.get("matches", [])
                    if item.get("kind") == "exclude_category"
                ),
                None,
            )
            if match is not None:
                return match
        return None

    async def _response_payload(
        self, apps: list[dict[str, Any]], *, sync: bool = True
    ) -> dict[str, Any]:
        response = await super()._response_payload(apps, sync=sync)
        visible = []
        suppressed = 0
        for recommendation in response.get("recommendations") or []:
            if await self._recommendation_is_policy_suppressed(recommendation):
                suppressed += 1
                continue
            visible.append(recommendation)
        response["recommendations"] = visible
        response.setdefault("summary", {})["pending"] = len(visible)
        response["summary"]["policy_suppressed"] = suppressed
        response["summary"]["high_priority"] = sum(
            1
            for row in visible
            if row.get("action") in {"recommend_block", "recommend_long_block"}
            and row.get("confidence") == "high"
        )
        return response

    async def api_approve_recommendation(self, request: web.Request) -> web.Response:
        recommendation_id = request.match_info.get("recommendation_id", "").strip()
        recommendation = await self.store.recommendation(recommendation_id)
        if recommendation is not None:
            policy = await self._recommendation_is_policy_suppressed(recommendation)
            if policy is not None:
                raise web.HTTPConflict(
                    text=(
                        "response approval is suppressed by policy "
                        f"{policy.get('policy_id')}: "
                        f"{policy.get('reason') or policy.get('kind')}"
                    )
                )
        return await super().api_approve_recommendation(request)

    async def api_deployment(self, request: web.Request) -> web.Response:
        self.require_auth(request)
        report = await collect_deployment_report(self)
        return web.json_response(report, headers={"Cache-Control": "no-store"})

    async def api_policies(self, request: web.Request) -> web.Response:
        self.require_auth(request)
        try:
            limit = max(1, min(500, int(request.query.get("audit_limit", "100"))))
        except ValueError as exc:
            raise web.HTTPBadRequest(text="audit_limit must be an integer") from exc
        policies = await self.policy_manager.list(include_inactive=True)
        now = datetime.now(timezone.utc)
        active = 0
        for item in policies:
            expires_at = item.get("expires_at")
            try:
                expires = (
                    datetime.fromisoformat(str(expires_at).replace("Z", "+00:00"))
                    if expires_at
                    else None
                )
            except ValueError:
                expires = now
            if expires is not None and expires.tzinfo is None:
                expires = expires.replace(tzinfo=timezone.utc)
            if item.get("enabled") and (expires is None or expires > now):
                active += 1
        return web.json_response(
            {
                "policies": policies,
                "active": active,
                "sync": await self.policy_manager.sync_status(),
                "audit": await self.policy_manager.audit(limit),
                "kinds": [
                    "allow_cidr",
                    "suppress_actor",
                    "suppress_scanner",
                    "exclude_category",
                ],
                "applications": [
                    {"id": instance.instance_id, "name": instance.name}
                    for instance in self.instances
                ],
            },
            headers={"Cache-Control": "no-store"},
        )

    async def api_policy_create(self, request: web.Request) -> web.Response:
        context = self.require_action(request, "policy-create")
        try:
            payload = await request.json()
            policy = await self.policy_manager.create(payload, principal=context.username)
        except ValueError as exc:
            raise web.HTTPBadRequest(text=str(exc)) from exc
        if self.client is None:
            raise web.HTTPServiceUnavailable(text="dashboard HTTP client is not ready")
        sync = await self.policy_manager.reconcile(
            self.client, token=self.hotpot_token, force=True
        )
        await self._record_action(
            context,
            event_type="policy_created",
            message=f"Dashboard user created {policy['kind']} policy",
            details={"policy": policy, "sync": sync},
        )
        await self._refresh_response_cache()
        return web.json_response(
            {"policy": policy, "sync": sync},
            status=201,
            headers={"Cache-Control": "no-store"},
        )

    async def api_policy_disable(self, request: web.Request) -> web.Response:
        context = self.require_action(request, "policy-disable")
        policy_id = request.match_info.get("policy_id", "").strip()
        if not policy_id:
            raise web.HTTPBadRequest(text="policy id is required")
        policy = await self.policy_manager.disable(policy_id, principal=context.username)
        if policy is None:
            raise web.HTTPNotFound(text="policy not found")
        if self.client is None:
            raise web.HTTPServiceUnavailable(text="dashboard HTTP client is not ready")
        sync = await self.policy_manager.reconcile(
            self.client, token=self.hotpot_token, force=True
        )
        await self._record_action(
            context,
            event_type="policy_disabled",
            message="Dashboard user disabled security policy",
            details={"policy": policy, "sync": sync},
        )
        await self._refresh_response_cache()
        return web.json_response(
            {"policy": policy, "sync": sync}, headers={"Cache-Control": "no-store"}
        )

    async def api_policy_reconcile(self, request: web.Request) -> web.Response:
        context = self.require_action(request, "policy-reconcile")
        if self.client is None:
            raise web.HTTPServiceUnavailable(text="dashboard HTTP client is not ready")
        sync = await self.policy_manager.reconcile(
            self.client, token=self.hotpot_token, force=True
        )
        await self._record_action(
            context,
            event_type="policy_reconcile",
            message="Dashboard user forced policy reconciliation",
            details={"sync": sync},
        )
        return web.json_response(sync, headers={"Cache-Control": "no-store"})

    async def api_policy_preview(self, request: web.Request) -> web.Response:
        self.require_auth(request)
        try:
            payload = await request.json()
            if isinstance(payload, dict) and "candidate" in payload:
                candidate = self.policy_manager.validate_policy(payload["candidate"])
                scoped = candidate.get("app_ids") or [
                    instance.instance_id for instance in self.instances
                ]
                app_names = [
                    instance.name
                    for instance in self.instances
                    if instance.instance_id in scoped
                ]
                if candidate["kind"] == "allow_cidr":
                    impacts = [
                        "bypass_deception",
                        "exclude_from_response_enforcement",
                    ]
                else:
                    impacts = [
                        "suppress_notifications",
                        "suppress_response_approval",
                    ]
                result = {
                    "candidate": candidate,
                    "applications": app_names,
                    "impacts": impacts,
                    "writes": False,
                    "note": "Preview only. No policy has been persisted or synchronized.",
                }
            else:
                result = await self.policy_manager.preview(payload)
        except ValueError as exc:
            raise web.HTTPBadRequest(text=str(exc)) from exc
        return web.json_response(result, headers={"Cache-Control": "no-store"})

    async def index(self, request: web.Request) -> web.Response:
        context = self.auth_context(request)
        if context is None:
            raise web.HTTPUnauthorized(
                headers={"WWW-Authenticate": 'Basic realm="Hotpot Dashboard"'}
            )
        token, _, _ = self.sessions.issue(context.username)
        response = web.Response(
            text=POLICY_DASHBOARD_HTML,
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
    dashboard = PolicyDashboardApplication()
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
    app.router.add_get("/api/deployment", dashboard.api_deployment)
    app.router.add_get("/api/v1/deployment", dashboard.api_deployment)
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

    app.router.add_get("/api/policies", dashboard.api_policies)
    app.router.add_post("/api/policies", dashboard.api_policy_create)
    app.router.add_post(
        "/api/policies/{policy_id}/disable", dashboard.api_policy_disable
    )
    app.router.add_post("/api/policies/reconcile", dashboard.api_policy_reconcile)
    app.router.add_post("/api/policies/preview", dashboard.api_policy_preview)
    app.router.add_get("/api/v1/policies", dashboard.api_policies)
    app.router.add_post("/api/v1/policies", dashboard.api_policy_create)
    app.router.add_post(
        "/api/v1/policies/{policy_id}/disable", dashboard.api_policy_disable
    )
    app.router.add_post(
        "/api/v1/policies/reconcile", dashboard.api_policy_reconcile
    )
    app.router.add_post("/api/v1/policies/preview", dashboard.api_policy_preview)

    register_api_routes(app, dashboard)
    return app
