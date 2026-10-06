import tempfile
import unittest
from pathlib import Path

from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

from hotpot.app import HOTPOT_APP_KEY
from hotpot.config import Settings
from hotpot.runtime import build_app


class RuntimeHardeningTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp = tempfile.TemporaryDirectory()

        async def upstream(request):
            return web.Response(text="ok")

        upstream_app = web.Application()
        upstream_app.router.add_route("*", "/{tail:.*}", upstream)
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
        self.server = TestServer(build_app(settings))
        self.client = TestClient(self.server)
        await self.client.start_server()

    async def asyncTearDown(self):
        await self.client.close()
        await self.upstream_server.close()
        self.tmp.cleanup()

    async def test_live_and_readiness_are_distinct(self):
        live = await self.client.get("/_hotpot/live")
        self.assertEqual(live.status, 200)
        self.assertTrue((await live.json())["alive"])

        ready = await self.client.get("/_hotpot/health")
        self.assertEqual(ready.status, 200)
        payload = await ready.json()
        self.assertTrue(payload["healthy"])
        self.assertEqual(payload["instance_id"], "test")
        self.assertIsNotNone(payload["upstream"]["latency_ms"])

    async def test_event_feed_uses_monotonic_cursor(self):
        response = await self.client.get("/.env")
        self.assertEqual(response.status, 403)
        feed = await self.client.get(
            "/_hotpot/api/events?cursor=0&limit=10",
            headers={"Authorization": "Bearer test-secret"},
        )
        self.assertEqual(feed.status, 200)
        payload = await feed.json()
        self.assertEqual(len(payload["events"]), 1)
        self.assertGreater(payload["next_cursor"], 0)
        self.assertEqual(payload["instance_id"], "test")

    async def test_sqlite_write_failure_does_not_break_deception(self):
        hotpot = self.server.app[HOTPOT_APP_KEY]

        async def broken_record(*args, **kwargs):
            raise OSError("disk full")

        hotpot.store.record = broken_record
        response = await self.client.get("/wp-admin/install.php")
        self.assertEqual(response.status, 200)
        self.assertIn("WordPress", await response.text())
        self.assertGreaterEqual(hotpot.stats["telemetry_errors"], 1)
        self.assertGreaterEqual(hotpot.stats["sqlite_write_errors"], 1)

    async def test_status_exposes_readiness_and_correct_tarpit_counters(self):
        status = await self.client.get(
            "/_hotpot/status", headers={"Authorization": "Bearer test-secret"}
        )
        self.assertEqual(status.status, 200)
        payload = await status.json()
        self.assertIn("upstream_health", payload)
        self.assertEqual(payload["stats"]["tarpits_active"], 0)
        self.assertEqual(payload["stats"]["tarpits_total"], 0)


if __name__ == "__main__":
    unittest.main()
