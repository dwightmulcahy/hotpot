import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

from hotpot.app import HOTPOT_APP_KEY
from hotpot.config import Settings
from hotpot.production import build_app


class ProductionHardeningTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.upstream_requests = []

        async def upstream(request):
            body = await request.read()
            self.upstream_requests.append(
                {
                    "path": request.path_qs,
                    "host": request.headers.get("Host"),
                    "xff": request.headers.get("X-Forwarded-For"),
                    "xfp": request.headers.get("X-Forwarded-Proto"),
                    "body": body,
                }
            )
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
            max_request_body=32,
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
            instance_id="prod-test",
            instance_name="Production Test",
        )
        self.env = patch.dict(
            "os.environ",
            {
                "HOTPOT_PRESERVE_HOST": "true",
                "HOTPOT_EVENT_RATE_LIMIT_PER_MINUTE": "1",
                "HOTPOT_EVENT_RATE_LIMIT_BURST": "1",
                "HOTPOT_VERSION": "v9.9.9",
                "HOTPOT_GIT_SHA": "0123456789abcdef",
                "HOTPOT_BUILD_DATE": "2026-10-06T16:00:00Z",
            },
        )
        self.env.start()
        self.server = TestServer(build_app(self.settings))
        self.client = TestClient(self.server)
        await self.client.start_server()
        self.upstream_requests.clear()  # discard the startup readiness probe

    async def asyncTearDown(self):
        await self.client.close()
        await self.upstream_server.close()
        self.env.stop()
        self.tmp.cleanup()

    async def test_untrusted_forwarded_proto_is_ignored_and_host_is_preserved(self):
        response = await self.client.get(
            "/hello",
            headers={"Host": "example.test", "X-Forwarded-Proto": "https"},
        )
        self.assertEqual(response.status, 200)
        self.assertEqual(len(self.upstream_requests), 1)
        upstream = self.upstream_requests[0]
        self.assertEqual(upstream["host"], "example.test")
        self.assertEqual(upstream["xfp"], "http")
        self.assertEqual(upstream["xff"], "127.0.0.1")

    async def test_chunked_unknown_length_body_is_rejected_at_streaming_limit(self):
        async def body():
            yield b"a" * 20
            yield b"b" * 20

        response = await self.client.post("/upload", data=body(), chunked=True)
        self.assertEqual(response.status, 413)
        hotpot = self.server.app[HOTPOT_APP_KEY]
        self.assertEqual(hotpot.stats["request_body_rejected"], 1)

    async def test_event_flood_is_suppressed_without_changing_response(self):
        first = await self.client.get("/.env")
        second = await self.client.get("/.env")
        self.assertEqual(first.status, 403)
        self.assertEqual(second.status, 403)

        hotpot = self.server.app[HOTPOT_APP_KEY]
        snapshot = await hotpot.store.dashboard_snapshot()
        self.assertEqual(snapshot["events"], 1)
        self.assertEqual(hotpot.stats["events_persisted_total"], 1)
        self.assertEqual(hotpot.stats["events_suppressed_total"], 1)

    async def test_status_exposes_build_identity_and_hardening_policy(self):
        response = await self.client.get(
            "/_hotpot/status",
            headers={"Authorization": "Bearer test-secret"},
        )
        self.assertEqual(response.status, 200)
        payload = await response.json()
        self.assertEqual(payload["version"], "v9.9.9")
        self.assertEqual(payload["git_sha"], "0123456789abcdef")
        self.assertTrue(payload["proxy"]["preserve_host"])
        self.assertEqual(payload["proxy"]["max_request_body"], 32)
        self.assertEqual(payload["event_persistence"]["burst"], 1)


if __name__ == "__main__":
    unittest.main()
