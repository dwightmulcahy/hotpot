from __future__ import annotations

import json

from aiohttp import web

from . import runtime as runtime_layer
from .app import HOTPOT_APP_KEY
from .config import Settings
from .durable_store import SourceIdentityStore

# ResilientStore resolves this runtime module global when each Hotpot instance is
# constructed, so production keeps telemetry fail-safety while gaining a stable
# SQLite-store generation identifier.
runtime_layer.RealIntelligenceStore = SourceIdentityStore

from .gateway import GatewayHotpot  # noqa: E402  (must follow runtime store override)


class DurableGatewayHotpot(GatewayHotpot):
    @property
    def source_id(self) -> str | None:
        inner = getattr(self.store, "inner", None)
        value = getattr(inner, "source_id", None)
        return str(value) if value else None

    async def events_api(self, request: web.Request) -> web.Response:
        if not self.authorized(request):
            raise web.HTTPUnauthorized()
        try:
            cursor = max(0, int(request.query.get("cursor", "0")))
            limit = max(1, min(500, int(request.query.get("limit", "250"))))
        except ValueError as exc:
            raise web.HTTPBadRequest(text="cursor and limit must be integers") from exc

        result = await runtime_layer.asyncio.to_thread(self._events_since_sync, cursor, limit)
        result["instance_id"] = self.settings.instance_id
        result["instance_name"] = self.settings.instance_name
        result["source_id"] = self.source_id
        return web.json_response(result, headers={"Cache-Control": "no-store"})

    async def status(self, request: web.Request) -> web.Response:
        response = await super().status(request)
        payload = json.loads(response.text)
        payload["source_id"] = self.source_id
        return web.json_response(payload, headers={"Cache-Control": "no-store"})


def build_app(settings: Settings | None = None) -> web.Application:
    settings = settings or Settings.from_env()
    hotpot = DurableGatewayHotpot(settings)
    app = web.Application(client_max_size=settings.max_request_body)
    app[HOTPOT_APP_KEY] = hotpot
    app.on_startup.append(hotpot.startup)
    app.on_cleanup.append(hotpot.shutdown)
    app.router.add_route("*", "/{tail:.*}", hotpot.handler)
    return app


def main() -> None:
    settings = Settings.from_env()
    web.run_app(build_app(settings), host=settings.bind, port=settings.port, access_log=None)


if __name__ == "__main__":
    main()
