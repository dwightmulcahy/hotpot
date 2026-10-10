from __future__ import annotations

import tempfile
import time
import unittest
from pathlib import Path

from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

from hotpot.app import HOTPOT_APP_KEY
from hotpot.config import Settings
from hotpot.policy_runtime import build_app


class BotRuntimeIntegrationTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.upstream_hits: list[str] = []

        async def upstream_handler(request: web.Request) -> web.Response:
            self.upstream_hits.append(request.path_qs)
            return web.Response(text="upstream")

        upstream_app = web.Application()
        upstream_app.router.add_route("*", "/{tail:.*}", upstream_handler)
        self.upstream_server = TestServer(upstream_app)
        await self.upstream_server.start_server()

        root = Path(__file__).resolve().parents[1]
        settings = Settings(
            bind="127.0.0.1",
            port=8080,
            upstream=str(self.upstream_server.make_url("/")).rstrip("/"),
            data_dir=Path(self.tmp.name),
            profiles_dir=root / "profiles",
            enabled_profiles=("wordpress", "secrets", "git", "php", "generic"),
            max_request_body=8 * 1024 * 1024,
            upstream_timeout=10,
            client_ip_mode="direct",
            trusted_proxy_cidrs=(),
            tarpit_enabled=False,
            tarpit_max_concurrent=2,
            tarpit_initial_delay=0,
            tarpit_chunk_delay=0.001,
            tarpit_max_seconds=0.02,
            tarpit_escalated_max_seconds=0.03,
            admin_token="test-secret",
            allow_cidrs=(),
            retention_days=30,
            attacker_retention_days=90,
            housekeeping_interval_seconds=21600,
            notify_min_level=4,
            notify_cooldown_seconds=3600,
            notify_webhook_url=None,
            notify_webhook_bearer=None,
            smtp_host=None,
            smtp_port=587,
            smtp_starttls=True,
            smtp_username=None,
            smtp_password=None,
            smtp_from=None,
            smtp_to=(),
            instance_id="bot-runtime-test",
            instance_name="Bot Runtime Test",
        )
        app = build_app(settings)
        hotpot = app[HOTPOT_APP_KEY]
        # Prevent live network refresh in the test; inject a deterministic feed below.
        hotpot.bot_intelligence.enabled = False
        self.server = TestServer(app)
        self.client = TestClient(self.server)
        await self.client.start_server()
        self.upstream_hits.clear()

        hotpot.bot_intelligence.enabled = True
        hotpot.bot_intelligence._apply_payload(
            {
                "fetched_at": time.time(),
                "feeds": {
                    "crawler": {
                        "services": {
                            "Googlebot": {
                                "user_agent_patterns": ["*Googlebot*"],
                                "ip_list_authoritative": True,
                                "ipv4": ["127.0.0.0/8"],
                                "ipv6": [],
                            },
                            "ClaudeBot": {
                                "user_agent_patterns": ["*ClaudeBot*"],
                                "ip_list_authoritative": True,
                                "ipv4": ["192.0.2.0/24"],
                                "ipv6": [],
                            },
                        }
                    },
                    "monitor": {"services": {}},
                },
            }
        )

    async def asyncTearDown(self) -> None:
        await self.client.close()
        await self.upstream_server.close()
        self.tmp.cleanup()

    async def test_verified_and_spoofed_bot_identity_is_persisted(self) -> None:
        verified = await self.client.get(
            "/wp-json/", headers={"User-Agent": "Googlebot/2.1"}
        )
        self.assertEqual(verified.status, 200)
        await verified.read()

        spoofed = await self.client.get(
            "/readme.html", headers={"User-Agent": "ClaudeBot/1.0"}
        )
        self.assertEqual(spoofed.status, 200)
        await spoofed.read()
        self.assertEqual(self.upstream_hits, [])

        hotpot = self.server.app[HOTPOT_APP_KEY]
        events = await __import__("asyncio").to_thread(hotpot._events_since_sync, 0, 20)
        deception = [event for event in events["events"] if event.get("event") == "deception"]
        self.assertEqual(len(deception), 2)

        first, second = deception
        self.assertEqual(first.get("bot_source"), "ipverse")
        self.assertEqual(first.get("bot_identity"), "Googlebot")
        self.assertEqual(first.get("bot_claimed_identity"), "Googlebot")
        self.assertTrue(first.get("bot_verified"))
        self.assertTrue(first.get("bot_claim_verified"))
        self.assertFalse(first.get("bot_spoofed"))

        self.assertEqual(second.get("bot_ip_identity"), "Googlebot")
        self.assertEqual(second.get("bot_claimed_identity"), "ClaudeBot")
        self.assertTrue(second.get("bot_verified"))
        self.assertFalse(second.get("bot_claim_verified"))
        self.assertTrue(second.get("bot_spoofed"))
        self.assertEqual(second.get("severity"), min(5, second.get("base_severity") + 1))

        self.assertEqual(hotpot.stats["bot_verified"], 2)
        self.assertEqual(hotpot.stats["bot_claimed"], 2)
        self.assertEqual(hotpot.stats["bot_spoofed"], 1)


if __name__ == "__main__":
    unittest.main()
