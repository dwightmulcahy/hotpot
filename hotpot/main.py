from __future__ import annotations

import json
import sys

from aiohttp import web

from .app import HOTPOT_APP_KEY
from .config import Settings
from .metrics import PROMETHEUS_CONTENT_TYPE, render_prometheus
from .preflight import run_preflight
from .server import build_app as build_server_app


@web.middleware
async def metrics_middleware(
    request: web.Request, handler: web.RequestHandler
) -> web.StreamResponse:
    if request.path != "/_hotpot/metrics":
        return await handler(request)

    hotpot = request.app[HOTPOT_APP_KEY]
    if not hotpot.authorized(request):
        raise web.HTTPUnauthorized()
    body = (await render_prometheus(hotpot)).encode("utf-8")
    return web.Response(
        body=body,
        headers={
            "Content-Type": PROMETHEUS_CONTENT_TYPE,
            "Cache-Control": "no-store",
        },
    )


def build_app(settings: Settings | None = None) -> web.Application:
    app = build_server_app(settings)
    app.middlewares.insert(0, metrics_middleware)
    return app


def main() -> None:
    report = run_preflight()
    if "--check-config" in sys.argv[1:]:
        print(json.dumps(report, indent=2, sort_keys=True))
        raise SystemExit(0 if report["ok"] else 2)
    if not report["ok"]:
        raise RuntimeError("Hotpot configuration preflight failed: " + json.dumps(report))

    settings = Settings.from_env()
    web.run_app(
        build_app(settings),
        host=settings.bind,
        port=settings.port,
        access_log=None,
    )


if __name__ == "__main__":
    main()
