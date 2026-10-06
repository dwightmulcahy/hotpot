from __future__ import annotations

from aiohttp import web

from . import app as core_app
from .app import HOTPOT_APP_KEY
from .config import Settings
from .production import ProductionHotpot


class GatewayHotpot(ProductionHotpot):
    """Production entrypoint with deterministic unknown-length body enforcement."""

    async def _request_data(self, request: web.Request):
        if request.content_length is not None:
            if request.content_length > self.settings.max_request_body:
                self.stats["request_body_rejected"] += 1
                raise web.HTTPRequestEntityTooLarge(
                    max_size=self.settings.max_request_body,
                    actual_size=request.content_length,
                )
            return request.content.iter_chunked(64 * 1024)

        if not request.can_read_body:
            return None

        # For chunked/unknown-length requests there is no trustworthy size to
        # check before opening the upstream connection. Read the incoming stream
        # incrementally into a strictly bounded buffer first, then forward only
        # after it has proven to be within policy. This prevents partial oversized
        # uploads from reaching the protected application and guarantees a 413.
        body = bytearray()
        async for chunk in request.content.iter_chunked(64 * 1024):
            body.extend(chunk)
            if len(body) > self.settings.max_request_body:
                self.stats["request_body_rejected"] += 1
                raise web.HTTPRequestEntityTooLarge(
                    max_size=self.settings.max_request_body,
                    actual_size=len(body),
                )
        return bytes(body)

    async def proxy_http(self, request: web.Request) -> web.StreamResponse:
        assert self.client is not None
        data = await self._request_data(request)
        self.stats["proxied"] += 1
        try:
            async with self.client.request(
                request.method,
                self.upstream_url(request),
                headers=self.forwarding_headers(request),
                data=data,
                allow_redirects=False,
            ) as upstream:
                response = web.StreamResponse(
                    status=upstream.status,
                    reason=upstream.reason,
                    headers=core_app.clean_headers(upstream.headers, response=True),
                )
                await response.prepare(request)
                async for chunk in upstream.content.iter_chunked(64 * 1024):
                    await response.write(chunk)
                await response.write_eof()
                return response
        except web.HTTPRequestEntityTooLarge:
            raise
        except Exception as exc:
            self.stats["upstream_errors"] += 1
            await self._safe_event_write(
                {
                    "event": "upstream_error",
                    "method": request.method,
                    "path": request.path_qs,
                    "error": type(exc).__name__,
                }
            )
            raise web.HTTPBadGateway(text="Bad Gateway") from exc


def build_app(settings: Settings | None = None) -> web.Application:
    settings = settings or Settings.from_env()
    hotpot = GatewayHotpot(settings)
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
