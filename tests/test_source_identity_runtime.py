from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

from hotpot.config import Settings
from hotpot.durable_gateway import build_app


class SourceIdentityRuntimeTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp = tempfile.TemporaryDirectory()

        async def upstream(request):
            return web.Response(text="ok")

        upstream_app = web.Application()
        upstream_app.router.add_route("*", "/{tail:.*}", upstream)
        self.upstream_server = TestServer(upstream_app)
        await self.upstream_server.start_server()

        root = Path(__file__).resolve().parents[1]
        self.settings = Settings(
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
            tarpit_chunk_delay=0.01,
            tarpit_max_seconds=0.02,
            tarpit_escalated_max_seconds=0.05,
            admin_token="test-secret",
            allow_cidrs=(),
            retention_days=30,
            attacker_retention_days=90,
            housekeeping_interval_seconds=21600,
            notify_min_level=3,
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
            instance_id="test",
            instance_name="Test Hotpot",
        )
        self.server = TestServer(build_app(self.settings))
        self.client = TestClient(self.server)
        await self.client.start_server()

    async def asyncTearDown(self):
        await self.client.close()
        await self.upstream_server.close()
        self.tmp.cleanup()

    async def test_event_feed_and_status_expose_same_source_id(self):
        await self.client.get("/.env")
        headers = {"Authorization": "Bearer test-secret"}
        feed = await self.client.get("/_hotpot/api/events?cursor=0&limit=10", headers=headers)
        self.assertEqual(feed.status, 200)
        feed_payload = await feed.json()
        self.assertTrue(feed_payload["source_id"])

        status = await self.client.get("/_hotpot/status", headers=headers)
        self.assertEqual(status.status, 200)
        status_payload = await status.json()
        self.assertEqual(status_payload["source_id"], feed_payload["source_id"])


if __name__ == "__main__":
    unittest.main()
