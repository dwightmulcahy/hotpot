from __future__ import annotations

import json
import os
import sys
from pathlib import Path

from aiohttp import web

from . import runtime as core
from .backups import DashboardBackupManager
from .enforcement_plan import build_enforcement_plan
from .manual_response import ManualResponseService
from .metrics import DashboardMetricsCollector, MetricHistory
from .policy_runtime import build_app as build_dashboard_app
from .preflight import run_preflight


METRICS_KEY = web.AppKey("dashboard_metrics", DashboardMetricsCollector)
BACKUPS_KEY = web.AppKey("dashboard_backups", DashboardBackupManager)


async def _metrics_startup(app: web.Application) -> None:
    dashboard = app[core.DASHBOARD_KEY]
    history = MetricHistory(Path(os.getenv("HOTPOT_DASHBOARD_DATA_DIR", "/data")))
    collector = DashboardMetricsCollector(dashboard, history)
    app[METRICS_KEY] = collector
    await collector.start()


async def _metrics_shutdown(app: web.Application) -> None:
    collector = app.get(METRICS_KEY)
    if collector is not None:
        await collector.stop()


async def _backup_startup(app: web.Application) -> None:
    manager = DashboardBackupManager(Path(os.getenv("HOTPOT_DASHBOARD_DATA_DIR", "/data")))
    app[BACKUPS_KEY] = manager
    await manager.start()


async def _backup_shutdown(app: web.Application) -> None:
    manager = app.get(BACKUPS_KEY)
    if manager is not None:
        await manager.stop()


async def api_metrics_trends(request: web.Request) -> web.Response:
    dashboard = request.app[core.DASHBOARD_KEY]
    dashboard.require_auth(request)
    collector = request.app.get(METRICS_KEY)
    if collector is None:
        raise web.HTTPServiceUnavailable(text="metrics collector is not ready")
    payload = await collector.history.trends()
    payload["collector_errors"] = collector.errors
    return web.json_response(payload, headers={"Cache-Control": "no-store"})


async def api_preflight(request: web.Request) -> web.Response:
    dashboard = request.app[core.DASHBOARD_KEY]
    dashboard.require_auth(request)
    report = run_preflight(check_bind=False)
    return web.json_response(
        report,
        status=200 if report["ok"] else 503,
        headers={"Cache-Control": "no-store"},
    )


async def api_backups(request: web.Request) -> web.Response:
    dashboard = request.app[core.DASHBOARD_KEY]
    dashboard.require_auth(request)
    manager = request.app.get(BACKUPS_KEY)
    if manager is None:
        raise web.HTTPServiceUnavailable(text="backup manager is not ready")
    return web.json_response(await manager.status(), headers={"Cache-Control": "no-store"})


async def api_backup_run(request: web.Request) -> web.Response:
    dashboard = request.app[core.DASHBOARD_KEY]
    context = dashboard.require_action(request, "backup-now")
    manager = request.app.get(BACKUPS_KEY)
    if manager is None:
        raise web.HTTPServiceUnavailable(text="backup manager is not ready")
    result = await manager.backup(label="manual")
    record = getattr(dashboard, "_record_action", None)
    if callable(record):
        await record(
            context,
            event_type="dashboard_backup",
            message="Dashboard user created and restore-verified a manual backup",
            details={"backup": result.get("backup"), "sha256": result.get("sha256")},
        )
    return web.json_response(result, headers={"Cache-Control": "no-store"})


async def api_enforcement_plan(request: web.Request) -> web.Response:
    dashboard = request.app[core.DASHBOARD_KEY]
    dashboard.require_auth(request)
    recommendation_id = request.match_info.get("recommendation_id", "").strip()
    if not recommendation_id:
        raise web.HTTPBadRequest(text="recommendation id is required")
    recommendation = await dashboard.store.recommendation(recommendation_id)
    if recommendation is None:
        raise web.HTTPNotFound(text="recommendation not found")
    try:
        plan = build_enforcement_plan(recommendation, dashboard.cloudflare)
    except ValueError as exc:
        raise web.HTTPConflict(text=str(exc)) from exc
    return web.json_response(plan, headers={"Cache-Control": "no-store"})


async def _manual_payload(request: web.Request) -> dict:
    try:
        payload = await request.json()
    except Exception as exc:
        raise web.HTTPBadRequest(text="JSON body is required") from exc
    if not isinstance(payload, dict):
        raise web.HTTPBadRequest(text="JSON body must be an object")
    return payload


async def _ensure_manual_not_suppressed(dashboard, actor_key: str) -> None:
    policy_manager = getattr(dashboard, "policy_manager", None)
    if policy_manager is None:
        return
    policy = await policy_manager.suppression_for_actor(actor_key)
    if policy is not None:
        raise web.HTTPConflict(
            text=(
                "manual response is suppressed by policy "
                f"{policy.get('policy_id')}: {policy.get('reason') or policy.get('kind')}"
            )
        )


async def api_manual_response_preview(request: web.Request) -> web.Response:
    dashboard = request.app[core.DASHBOARD_KEY]
    dashboard.require_auth(request)
    payload = await _manual_payload(request)
    actor_key = str(payload.get("actor_key") or "").strip()
    action = str(payload.get("action") or "").strip()
    await _ensure_manual_not_suppressed(dashboard, actor_key)
    async with dashboard.cache_lock:
        apps = list(dashboard.cache.get("apps", []))
    service = ManualResponseService(dashboard.store)
    try:
        recommendation = await service.prepare(
            actor_key=actor_key,
            action_key=action,
            apps=apps,
        )
        plan = build_enforcement_plan(recommendation, dashboard.cloudflare)
    except ValueError as exc:
        raise web.HTTPConflict(text=str(exc)) from exc
    return web.json_response(
        {"recommendation": recommendation, "plan": plan, "writes": False},
        headers={"Cache-Control": "no-store"},
    )


async def api_manual_response_apply(request: web.Request) -> web.Response:
    dashboard = request.app[core.DASHBOARD_KEY]
    context = dashboard.require_action(request, "manual-response")
    if not dashboard.cloudflare.configured:
        raise web.HTTPServiceUnavailable(
            text="Cloudflare enforcement is disabled or incomplete"
        )
    payload = await _manual_payload(request)
    actor_key = str(payload.get("actor_key") or "").strip()
    action = str(payload.get("action") or "").strip()
    await _ensure_manual_not_suppressed(dashboard, actor_key)
    async with dashboard.cache_lock:
        apps = list(dashboard.cache.get("apps", []))
    service = ManualResponseService(dashboard.store)
    try:
        recommendation = await service.prepare(
            actor_key=actor_key,
            action_key=action,
            apps=apps,
        )
        plan = build_enforcement_plan(recommendation, dashboard.cloudflare)
        persisted = await service.persist(recommendation, principal=context.username)
    except ValueError as exc:
        raise web.HTTPConflict(text=str(exc)) from exc

    result = await dashboard._apply_one(persisted)
    if result.get("status") == "applied":
        await dashboard._maybe_reconcile_cloudflare(force=True)
    await dashboard._record_action(
        context,
        event_type="manual_response",
        message=f"Dashboard user applied manual response {action}",
        recommendation_id=str(persisted.get("recommendation_id") or "") or None,
        status=str(result.get("status") or "unknown"),
        details={"actor_key": actor_key, "action": action, "plan": plan},
    )
    await dashboard._refresh_response_cache()
    status = 200 if result.get("status") == "applied" else 502
    return web.json_response(
        {"recommendation": result, "plan": plan},
        status=status,
        headers={"Cache-Control": "no-store"},
    )


def build_app() -> web.Application:
    app = build_dashboard_app()
    app.on_startup.append(_metrics_startup)
    app.on_startup.append(_backup_startup)
    app.on_cleanup.insert(0, _backup_shutdown)
    app.on_cleanup.insert(0, _metrics_shutdown)
    app.router.add_get("/api/metrics/trends", api_metrics_trends)
    app.router.add_get("/api/v1/metrics/trends", api_metrics_trends)
    app.router.add_get("/api/preflight", api_preflight)
    app.router.add_get("/api/v1/preflight", api_preflight)
    app.router.add_get("/api/backups", api_backups)
    app.router.add_get("/api/v1/backups", api_backups)
    app.router.add_post("/api/backups/run", api_backup_run)
    app.router.add_post("/api/v1/backups/run", api_backup_run)
    app.router.add_get(
        "/api/recommendation/{recommendation_id}/plan", api_enforcement_plan
    )
    app.router.add_get(
        "/api/v1/recommendations/{recommendation_id}/plan", api_enforcement_plan
    )
    app.router.add_post("/api/manual-response/preview", api_manual_response_preview)
    app.router.add_post("/api/v1/manual-response/preview", api_manual_response_preview)
    app.router.add_post("/api/manual-response/apply", api_manual_response_apply)
    app.router.add_post("/api/v1/manual-response/apply", api_manual_response_apply)
    return app


def main() -> None:
    report = run_preflight()
    if "--check-config" in sys.argv[1:]:
        print(json.dumps(report, indent=2, sort_keys=True))
        raise SystemExit(0 if report["ok"] else 2)
    if not report["ok"]:
        raise RuntimeError("Hotpot dashboard configuration preflight failed: " + json.dumps(report))

    bind = os.getenv("HOTPOT_DASHBOARD_BIND", "127.0.0.1")
    port = int(os.getenv("HOTPOT_DASHBOARD_PORT", "19090"))
    web.run_app(build_app(), host=bind, port=port, access_log=None)


if __name__ == "__main__":
    main()
