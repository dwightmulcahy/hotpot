import tempfile
import unittest
from pathlib import Path

from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

from hotpot.app import HOTPOT_APP_KEY, build_app
from hotpot.config import Settings


class AppIntegrationTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.upstream_hits = []

        async def upstream_handler(request):
            self.upstream_hits.append(request.path_qs)
            return web.Response(text=f"upstream:{request.path_qs}")

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
            trust_forwarded_for=False,
            tarpit_enabled=False,
            tarpit_max_concurrent=2,
            tarpit_initial_delay=0,
            tarpit_chunk_delay=0.01,
            tarpit_max_seconds=0.05,
            tarpit_escalated_max_seconds=0.1,
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
        )
        self.server = TestServer(build_app(settings))
        self.client = TestClient(self.server)
        await self.client.start_server()

    async def asyncTearDown(self):
        await self.client.close()
        await self.upstream_server.close()
        self.tmp.cleanup()

    async def test_normal_request_proxies(self):
        response = await self.client.get("/hello?x=1")
        self.assertEqual(response.status, 200)
        self.assertEqual(await response.text(), "upstream:/hello?x=1")
        self.assertEqual(self.upstream_hits, ["/hello?x=1"])

    async def test_probe_never_reaches_upstream(self):
        response = await self.client.get("/wp-admin/install.php", headers={"User-Agent": "WPScan v3.8.27"})
        self.assertEqual(response.status, 200)
        self.assertIn("WordPress", await response.text())
        self.assertEqual(self.upstream_hits, [])
        hotpot = self.server.app[HOTPOT_APP_KEY]
        snapshot = await hotpot.store.dashboard_snapshot()
        self.assertEqual(snapshot["events"], 1)
        self.assertEqual(snapshot["top_scanners"][0]["scanner"], "WPScan")

    async def test_admin_endpoints_require_token(self):
        response = await self.client.get("/_hotpot/dashboard")
        self.assertEqual(response.status, 401)
        response = await self.client.get(
            "/_hotpot/dashboard", headers={"Authorization": "Bearer test-secret"}
        )
        self.assertEqual(response.status, 200)
        self.assertIn("Hotpot Attack Intelligence", await response.text())

    async def test_health_remains_public(self):
        response = await self.client.get("/_hotpot/health")
        self.assertEqual(response.status, 200)
        self.assertEqual(await response.json(), {"healthy": True})


if __name__ == "__main__":
    unittest.main()
