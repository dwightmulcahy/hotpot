from __future__ import annotations

from typing import Any

from aiohttp import web

from .app import HOTPOT_APP_KEY
from .config import Settings
from .deployment import deployment_snapshot
from .policy import RuntimePolicyStore
from .server import HotpotServer


class PolicyHotpotServer(HotpotServer):
    """Hotpot runtime with durable dashboard-managed policy layered over env policy."""

    def __init__(self, settings: Settings):
        super().__init__(settings)
        self.policy = RuntimePolicyStore(
            settings.data_dir,
            instance_id=settings.instance_id,
            bootstrap_allow_cidrs=settings.allow_cidrs,
        )
        self.stats["policy_allow_bypasses"] = 0
        self.stats["policy_notification_suppressed"] = 0
        self.stats["policy_syncs"] = 0
        self.stats["policy_sync_errors"] = 0

    async def policy_status(self, request: web.Request) -> web.Response:
        if not self.authorized(request):
            raise web.HTTPUnauthorized()
        return web.json_response(
            self.policy.status(), headers={"Cache-Control": "no-store"}
        )

    async def policy_update(self, request: web.Request) -> web.Response:
        if not self.authorized(request):
            raise web.HTTPUnauthorized()
        if request.headers.get("X-Hotpot-Action", "") != "policy-sync":
            raise web.HTTPBadRequest(
                text="X-Hotpot-Action: policy-sync header is required"
            )
        try:
            payload = await request.json()
            result = self.policy.apply_snapshot(payload)
        except Exception as exc:
            self.stats["policy_sync_errors"] += 1
            return web.json_response(
                {"ok": False, "error": f"{type(exc).__name__}: {exc}"},
                status=400,
                headers={"Cache-Control": "no-store"},
            )
        self.stats["policy_syncs"] += 1
        return web.json_response(
            {"ok": True, "policy": result}, headers={"Cache-Control": "no-store"}
        )

    async def status(self, request: web.Request) -> web.Response:
        response = await super().status(request)
        payload: dict[str, Any] = response.body and __import__("json").loads(
            response.body.decode("utf-8")
        ) or {}
        payload["policy"] = self.policy.status()
        payload.setdefault("allowlist", {})["dynamic_cidrs"] = [
            entry["value"]
            for entry in self.policy.active_entries()
            if entry.get("kind") == "allow_cidr"
        ]
        deployment = deployment_snapshot(
            self.settings,
            version=self.version,
            git_sha=self.git_sha,
            build_date=self.build_date,
        )
        deployment["policy_revision"] = self.policy.revision
        deployment["policy_updated_at"] = self.policy.updated_at
        payload["deployment"] = deployment
        payload["config_fingerprint"] = deployment["config_fingerprint"]
        payload["shared_config_fingerprint"] = deployment[
            "shared_config_fingerprint"
        ]
        return web.json_response(payload, headers={"Cache-Control": "no-store"})

    async def handler(self, request: web.Request) -> web.StreamResponse:
        if request.path == "/_hotpot/api/policy":
            if request.method == "GET":
                return await self.policy_status(request)
            if request.method == "PUT":
                return await self.policy_update(request)
            raise web.HTTPMethodNotAllowed(request.method, ["GET", "PUT"])

        # Dashboard policy is evaluated before the legacy env allowlist. An allow
        # policy only bypasses deception; it never changes forwarding-header trust.
        if not request.path.startswith("/_hotpot/"):
            identity = self.client_identity(request)
            matched = self.policy.allow_match(identity.client_ip)
            if matched is not None:
                self.stats["policy_allow_bypasses"] += 1
                rule = self.rules.match(request.path, request.method)
                if rule is not None:
                    await self._safe_event_write(
                        {
                            "event": "policy_bypass",
                            "client_ip": identity.client_ip,
                            "attacker_key": identity.actor_key,
                            "path": request.path_qs,
                            "method": request.method,
                            "rule": rule.name,
                            "category": rule.category,
                            "policy_id": matched.get("policy_id"),
                            "policy_reason": matched.get("reason"),
                        }
                    )
                if request.headers.get("Upgrade", "").lower() == "websocket":
                    return await self.proxy_websocket(request)
                return await self.proxy_http(request)
        return await super().handler(request)

    async def maybe_notify(self, event: dict) -> None:
        matched = self.policy.suppression_match(
            actor_key=str(event.get("attacker_key") or event.get("client_ip") or ""),
            scanner_family=str(event.get("scanner_family") or ""),
            category=str(event.get("category") or ""),
        )
        if matched is not None:
            self.stats["policy_notification_suppressed"] += 1
            return
        await super().maybe_notify(event)


def build_app(settings: Settings | None = None) -> web.Application:
    settings = settings or Settings.from_env()
    hotpot = PolicyHotpotServer(settings)
    app = web.Application(client_max_size=settings.max_request_body)
    app[HOTPOT_APP_KEY] = hotpot
    app.on_startup.append(hotpot.startup)
    app.on_cleanup.append(hotpot.shutdown)
    app.router.add_route("*", "/{tail:.*}", hotpot.handler)
    return app
