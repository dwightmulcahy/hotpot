from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from aiohttp import web

from . import runtime as core
from .api_v1 import register_api_routes
from .policy import PolicyManager
from .server import DashboardApplication, STATIC_DIR


class PolicyDashboardApplication(DashboardApplication):
    """Dashboard application with a durable, reconciled security-policy control plane."""

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
                # The last-known-good snapshot remains active at each Hotpot. Policy
                # sync health is surfaced separately and must not take the dashboard down.
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
                        f"{policy.get('policy_id')}: {policy.get('reason') or policy.get('kind')}"
                    )
                )
        return await super().api_approve_recommendation(request)

    async def api_policies(self, request: web.Request) -> web.Response:
        self.require_auth(request)
        try:
            limit = max(1, min(500, int(request.query.get("audit_limit", "100"))))
        except ValueError as exc:
            raise web.HTTPBadRequest(text="audit_limit must be an integer") from exc
        policies = await self.policy_manager.list(include_inactive=True)
        return web.json_response(
            {
                "policies": policies,
                "active": sum(
                    1
                    for item in policies
                    if item.get("enabled")
                    and (
                        not item.get("expires_at")
                        or str(item.get("expires_at")) > __import__("datetime").datetime.now(
                            __import__("datetime").timezone.utc
                        ).isoformat()
                    )
                ),
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
            result = await self.policy_manager.preview(payload)
        except ValueError as exc:
            raise web.HTTPBadRequest(text=str(exc)) from exc
        return web.json_response(result, headers={"Cache-Control": "no-store"})


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
