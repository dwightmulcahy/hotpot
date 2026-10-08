from __future__ import annotations

import json
import os
import sys
from pathlib import Path

from aiohttp import web

from . import runtime as core
from .backups import DashboardBackupManager
from .metrics import DashboardMetricsCollector, MetricHistory
from .preflight import run_preflight
from .server import build_app as build_dashboard_app


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
