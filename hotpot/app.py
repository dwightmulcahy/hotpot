from __future__ import annotations

import asyncio
import json
import time
from collections import Counter
from urllib.parse import urlsplit

from aiohttp import ClientSession, ClientTimeout, WSMsgType, web
from multidict import CIMultiDict

from .config import Settings
from .dashboard import render_dashboard
from .intelligence import classify, escalation_for
from .logging import EventLogger
from .network import Allowlist
from .notifications import Notifier
from .rules import Rule, RuleEngine
from .store import IntelligenceStore

HOP_BY_HOP = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade",
}


def clean_headers(headers, *, response: bool = False) -> CIMultiDict:
    out = CIMultiDict()
    connection_tokens = {
        token.strip().lower()
        for token in headers.get("Connection", "").split(",") if token.strip()
    }
    blocked = HOP_BY_HOP | connection_tokens
    for key, value in headers.items():
        if key.lower() in blocked:
            continue
        if not response and key.lower() == "host":
            continue
        out.add(key, value)
    return out


def peer_ip(request: web.Request, trust_forwarded_for: bool) -> str:
    if trust_forwarded_for:
        xff = request.headers.get("X-Forwarded-For")
        if xff:
            return xff.split(",", 1)[0].strip()
    peer = request.transport.get_extra_info("peername") if request.transport else None
    return peer[0] if peer else "unknown"


class Hotpot:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.rules = RuleEngine.load(settings.profiles_dir, settings.enabled_profiles)
        self.events = EventLogger(settings.data_dir)
        self.store = IntelligenceStore(settings.data_dir)
        self.allowlist = Allowlist(settings.allow_cidrs)
        self.notifier = Notifier(settings)
        self.client: ClientSession | None = None
        self.housekeeping_task: asyncio.Task | None = None
        self.tarpit_slots = asyncio.Semaphore(settings.tarpit_max_concurrent)
        self.intelligence_lock = asyncio.Lock()
        self.stats = Counter()
        self.started = time.monotonic()

    async def startup(self, app: web.Application) -> None:
        # Run cleanup before opening the outbound client so a startup cleanup failure
        # cannot leak a ClientSession.
        await self.run_housekeeping()
        timeout = ClientTimeout(total=self.settings.upstream_timeout)
        self.client = ClientSession(timeout=timeout, auto_decompress=False)
        self.housekeeping_task = asyncio.create_task(self.housekeeping_loop(), name="hotpot-housekeeping")

    async def shutdown(self, app: web.Application) -> None:
        if self.housekeeping_task:
            self.housekeeping_task.cancel()
            await asyncio.gather(self.housekeeping_task, return_exceptions=True)
        if self.client:
            await self.client.close()

    async def run_housekeeping(self) -> None:
        db = await self.store.cleanup(
            self.settings.retention_days, self.settings.attacker_retention_days
        )
        jsonl_deleted = await self.events.cleanup(self.settings.retention_days)
        self.stats["housekeeping_runs"] += 1
        self.stats["housekeeping_events_deleted"] += db["events_deleted"]
        self.stats["housekeeping_attackers_deleted"] += db["attackers_deleted"]
        self.stats["housekeeping_jsonl_deleted"] += jsonl_deleted

    async def housekeeping_loop(self) -> None:
        while True:
            try:
                await asyncio.sleep(self.settings.housekeeping_interval_seconds)
                await self.run_housekeeping()
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                self.stats["housekeeping_errors"] += 1
                await self.events.write({
                    "event": "housekeeping_error",
                    "error": type(exc).__name__,
                })

    def authorized(self, request: web.Request) -> bool:
        token = self.settings.admin_token
        if not token:
            return False
        auth = request.headers.get("Authorization", "")
        return auth == f"Bearer {token}"

    async def health(self, request: web.Request) -> web.Response:
        return web.json_response({"healthy": True})

    async def status(self, request: web.Request) -> web.Response:
        if not self.authorized(request):
            raise web.HTTPUnauthorized()
        snapshot = await self.store.dashboard_snapshot(limit=10)
        return web.json_response({
            "healthy": True,
            "upstream": self.settings.upstream,
            "profiles": self.settings.enabled_profiles,
            "rules": len(self.rules.rules),
            "tarpit": {
                "enabled": self.settings.tarpit_enabled,
                "max_concurrent": self.settings.tarpit_max_concurrent,
                "max_seconds": self.settings.tarpit_max_seconds,
                "escalated_max_seconds": self.settings.tarpit_escalated_max_seconds,
            },
            "allowlist": {"cidrs": self.settings.allow_cidrs},
            "retention": {
                "events_days": self.settings.retention_days,
                "attackers_days": self.settings.attacker_retention_days,
                "housekeeping_interval_seconds": self.settings.housekeeping_interval_seconds,
            },
            "notifications": {
                "enabled": self.notifier.enabled,
                "min_level": self.settings.notify_min_level,
                "cooldown_seconds": self.settings.notify_cooldown_seconds,
                "webhook": bool(self.settings.notify_webhook_url),
                "email": bool(self.settings.smtp_host and self.settings.smtp_from and self.settings.smtp_to),
            },
            "stats": dict(self.stats),
            "intelligence": {
                "events": snapshot["events"],
                "unique_ips": snapshot["unique_ips"],
                "top_categories": snapshot["top_categories"][:5],
                "top_offenders": snapshot["top_offenders"][:5],
            },
            "uptime_seconds": int(time.monotonic() - self.started),
        })

    async def dashboard(self, request: web.Request) -> web.Response:
        if not self.authorized(request):
            raise web.HTTPUnauthorized()
        snapshot = await self.store.dashboard_snapshot(limit=30)
        return web.Response(
            text=render_dashboard(snapshot, dict(self.stats)),
            content_type="text/html",
            charset="utf-8",
            headers={"Cache-Control": "no-store", "X-Robots-Tag": "noindex, nofollow"},
        )

    async def intelligence_api(self, request: web.Request) -> web.Response:
        if not self.authorized(request):
            raise web.HTTPUnauthorized()
        return web.json_response(await self.store.dashboard_snapshot(limit=50))

    async def attacker_api(self, request: web.Request) -> web.Response:
        if not self.authorized(request):
            raise web.HTTPUnauthorized()
        ip = request.query.get("ip", "").strip()
        if not ip:
            raise web.HTTPBadRequest(text="ip query parameter is required")
        return web.json_response(await self.store.attacker_history(ip, limit=100))

    async def handler(self, request: web.Request) -> web.StreamResponse:
        # Reserve these before the catch-all route/proxy path.
        if request.path == "/_hotpot/health":
            return await self.health(request)
        if request.path == "/_hotpot/status":
            return await self.status(request)
        if request.path in {"/_hotpot", "/_hotpot/", "/_hotpot/dashboard"}:
            return await self.dashboard(request)
        if request.path == "/_hotpot/api/intelligence":
            return await self.intelligence_api(request)
        if request.path == "/_hotpot/api/attacker":
            return await self.attacker_api(request)

        client_ip = peer_ip(request, self.settings.trust_forwarded_for)
        if self.allowlist.contains(client_ip):
            self.stats["allowlisted"] += 1
            if request.headers.get("Upgrade", "").lower() == "websocket":
                return await self.proxy_websocket(request)
            return await self.proxy_http(request)

        rule = self.rules.match(request.path, request.method)
        if rule:
            return await self.deception(request, rule)

        if request.headers.get("Upgrade", "").lower() == "websocket":
            return await self.proxy_websocket(request)
        return await self.proxy_http(request)

    async def deception(self, request: web.Request, rule: Rule) -> web.StreamResponse:
        ip = peer_ip(request, self.settings.trust_forwarded_for)
        user_agent = request.headers.get("User-Agent", "")
        classification = classify(user_agent, rule.category, request.method, request.path_qs)

        # Serialize the small state read/update section so simultaneous probes from one source
        # cannot lose score increments. Tarpit/proxy work happens outside this lock.
        async with self.intelligence_lock:
            prior = await self.store.state_for(ip)
            escalation = escalation_for(
                prior_hits=prior.hits, prior_score=prior.score, severity=classification.severity,
                base_seconds=self.settings.tarpit_max_seconds,
                max_escalated_seconds=self.settings.tarpit_escalated_max_seconds,
            )
            effective_action = rule.action
            if escalation.force_tarpit and self.settings.tarpit_enabled:
                effective_action = "tarpit"

            event = {
                "event": "deception",
                "client_ip": ip,
                "method": request.method,
                "path": request.path_qs,
                "host": request.host,
                "user_agent": user_agent,
                "referer": request.headers.get("Referer", ""),
                "profile": rule.profile,
                "rule": rule.name,
                "category": rule.category,
                "action": effective_action,
                "rule_action": rule.action,
                "scanner": classification.scanner,
                "scanner_family": classification.scanner_family,
                "fingerprint": classification.fingerprint,
                "severity": classification.severity,
                "escalation_level": escalation.level,
                "attacker_score": escalation.score,
                "prior_hits": prior.hits,
            }
            await self.store.record(event, score=escalation.score, escalation_level=escalation.level)

        self.stats["deceptions"] += 1
        self.stats[f"category:{rule.category}"] += 1
        self.stats[f"scanner:{classification.scanner}"] += 1
        self.stats[f"escalation:{escalation.level}"] += 1
        await self.events.write(event)
        await self.maybe_notify(event)

        if effective_action == "tarpit" and self.settings.tarpit_enabled:
            return await self.tarpit(request, rule, max_seconds=escalation.tarpit_seconds)
        return web.Response(status=rule.status, text=rule.response, content_type=rule.content_type.split(";", 1)[0])

    async def maybe_notify(self, event: dict) -> None:
        if not self.notifier.enabled:
            return
        level = int(event.get("escalation_level", 1))
        if level < self.settings.notify_min_level:
            return
        ip = str(event.get("client_ip", "unknown"))
        should_send = await self.store.claim_notification(
            ip, level, self.settings.notify_cooldown_seconds
        )
        if not should_send:
            self.stats["notifications_suppressed"] += 1
            return
        assert self.client is not None
        try:
            channels = await self.notifier.send(self.client, event)
            self.stats["notifications_sent"] += 1
            await self.events.write({
                "event": "notification_sent",
                "client_ip": ip,
                "escalation_level": level,
                "channels": channels,
            })
        except Exception as exc:
            self.stats["notification_errors"] += 1
            await self.events.write({
                "event": "notification_error",
                "client_ip": ip,
                "escalation_level": level,
                "error": type(exc).__name__,
            })

    async def tarpit(self, request: web.Request, rule: Rule, *, max_seconds: float | None = None) -> web.StreamResponse:
        # Do not queue attackers forever if all tarpit slots are occupied.
        try:
            await asyncio.wait_for(self.tarpit_slots.acquire(), timeout=0.05)
        except TimeoutError:
            self.stats["tarpit_overflow"] += 1
            return web.Response(status=rule.status, text=rule.response,
                                content_type=rule.content_type.split(";", 1)[0])

        self.stats["tarpits"] += 1
        started = time.monotonic()
        try:
            await asyncio.sleep(self.settings.tarpit_initial_delay)
            resp = web.StreamResponse(status=rule.status)
            resp.headers["Content-Type"] = rule.content_type
            # Deliberately omit Content-Length so the scanner must wait on the stream.
            await resp.prepare(request)
            body = rule.response.encode("utf-8") or b" "
            pos = 0
            lifetime = max_seconds if max_seconds is not None else self.settings.tarpit_max_seconds
            while time.monotonic() - started < lifetime:
                chunk = body[pos:pos + 32]
                if not chunk:
                    pos = 0
                    chunk = b" "
                else:
                    pos += len(chunk)
                try:
                    await resp.write(chunk)
                except (ConnectionResetError, RuntimeError):
                    break
                await asyncio.sleep(self.settings.tarpit_chunk_delay)
            try:
                await resp.write_eof()
            except (ConnectionResetError, RuntimeError):
                pass
            return resp
        finally:
            self.tarpit_slots.release()

    def upstream_url(self, request: web.Request) -> str:
        return f"{self.settings.upstream}{request.rel_url}"

    def forwarding_headers(self, request: web.Request) -> CIMultiDict:
        headers = clean_headers(request.headers)
        ip = peer_ip(request, self.settings.trust_forwarded_for)
        prior = request.headers.get("X-Forwarded-For") if self.settings.trust_forwarded_for else None
        headers["X-Forwarded-For"] = f"{prior}, {ip}" if prior else ip
        headers["X-Real-IP"] = ip
        headers["X-Forwarded-Proto"] = request.headers.get("X-Forwarded-Proto", request.scheme)
        headers["X-Forwarded-Host"] = request.host
        return headers

    async def proxy_http(self, request: web.Request) -> web.StreamResponse:
        assert self.client is not None
        if request.content_length and request.content_length > self.settings.max_request_body:
            raise web.HTTPRequestEntityTooLarge(
                max_size=self.settings.max_request_body,
                actual_size=request.content_length,
            )
        self.stats["proxied"] += 1
        try:
            async with self.client.request(
                request.method,
                self.upstream_url(request),
                headers=self.forwarding_headers(request),
                data=request.content.iter_chunked(64 * 1024),
                allow_redirects=False,
            ) as upstream:
                response = web.StreamResponse(
                    status=upstream.status,
                    reason=upstream.reason,
                    headers=clean_headers(upstream.headers, response=True),
                )
                await response.prepare(request)
                async for chunk in upstream.content.iter_chunked(64 * 1024):
                    await response.write(chunk)
                await response.write_eof()
                return response
        except Exception as exc:
            self.stats["upstream_errors"] += 1
            await self.events.write({
                "event": "upstream_error",
                "method": request.method,
                "path": request.path_qs,
                "error": type(exc).__name__,
            })
            raise web.HTTPBadGateway(text="Bad Gateway") from exc

    async def proxy_websocket(self, request: web.Request) -> web.WebSocketResponse:
        assert self.client is not None
        self.stats["websockets"] += 1
        ws_server = web.WebSocketResponse(
            protocols=request.headers.getall("Sec-WebSocket-Protocol", []),
            autoclose=True,
            autoping=True,
        )
        await ws_server.prepare(request)

        scheme = "wss" if self.settings.upstream.startswith("https://") else "ws"
        parsed = urlsplit(self.settings.upstream)
        target = f"{scheme}://{parsed.netloc}{parsed.path.rstrip('/')}{request.rel_url}"
        headers = self.forwarding_headers(request)
        # aiohttp creates websocket-specific headers itself.
        for name in list(headers):
            if name.lower().startswith("sec-websocket-"):
                del headers[name]

        try:
            async with self.client.ws_connect(target, headers=headers, autoclose=True, autoping=True) as ws_upstream:
                async def client_to_upstream() -> None:
                    async for msg in ws_server:
                        if msg.type == WSMsgType.TEXT:
                            await ws_upstream.send_str(msg.data)
                        elif msg.type == WSMsgType.BINARY:
                            await ws_upstream.send_bytes(msg.data)
                        elif msg.type == WSMsgType.CLOSE:
                            await ws_upstream.close()
                            return

                async def upstream_to_client() -> None:
                    async for msg in ws_upstream:
                        if msg.type == WSMsgType.TEXT:
                            await ws_server.send_str(msg.data)
                        elif msg.type == WSMsgType.BINARY:
                            await ws_server.send_bytes(msg.data)
                        elif msg.type == WSMsgType.CLOSE:
                            await ws_server.close()
                            return

                tasks = [asyncio.create_task(client_to_upstream()), asyncio.create_task(upstream_to_client())]
                done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
                for task in pending:
                    task.cancel()
                await asyncio.gather(*pending, return_exceptions=True)
        except Exception as exc:
            await self.events.write({"event": "websocket_error", "path": request.path_qs,
                                     "error": type(exc).__name__})
            await ws_server.close(code=1011, message=b"upstream websocket error")
        return ws_server


HOTPOT_APP_KEY = web.AppKey("hotpot", Hotpot)


def build_app(settings: Settings | None = None) -> web.Application:
    settings = settings or Settings.from_env()
    hotpot = Hotpot(settings)
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
