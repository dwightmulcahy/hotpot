from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

from hotpot.app import HOTPOT_APP_KEY
from hotpot.config import Settings
from hotpot.policy_runtime import build_app


class ProductionDeceptionJourneyTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.upstream_hits: list[str] = []

        async def upstream_handler(request: web.Request) -> web.Response:
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
            client_ip_mode="direct",
            trusted_proxy_cidrs=(),
            tarpit_enabled=True,
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
            instance_id="journey-test",
            instance_name="Journey Test",
        )
        self.server = TestServer(build_app(settings))
        self.client = TestClient(self.server)
        await self.client.start_server()
        # Startup performs an upstream readiness check; journey assertions start here.
        self.upstream_hits.clear()

    async def asyncTearDown(self) -> None:
        await self.client.close()
        await self.upstream_server.close()
        self.tmp.cleanup()

    async def test_wordpress_journey_stays_correlated_and_never_hits_upstream(self) -> None:
        headers = {
            "User-Agent": "WPScan v3.8.27",
            "Accept": "application/json,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
        }

        rest = await self.client.get("/wp-json/", headers=headers)
        self.assertEqual(rest.status, 200)
        rest_payload = await rest.json()
        self.assertIn("wp/v2", rest_payload["namespaces"])

        lure = await self.client.get(
            "/wp-content/plugins/wp-file-manager/readme.txt", headers=headers
        )
        self.assertEqual(lure.status, 200)
        self.assertIn("Stable tag: 6.8", await lure.text())

        exploit = await self.client.get(
            "/wp-content/plugins/wp-file-manager/lib/php/connector.minimal.php",
            headers=headers,
        )
        self.assertEqual(exploit.status, 200)
        await exploit.read()

        canary = await self.client.get(
            "/wp-content/uploads/.cache/wp-maintenance.json", headers=headers
        )
        self.assertEqual(canary.status, 200)
        await canary.read()

        self.assertEqual(self.upstream_hits, [])

        hotpot = self.server.app[HOTPOT_APP_KEY]
        events = await __import__("asyncio").to_thread(hotpot._events_since_sync, 0, 20)
        journey = [
            event
            for event in events["events"]
            if event.get("profile") == "wordpress"
        ]
        self.assertEqual(len(journey), 4)

        session_ids = {event.get("session_id") for event in journey}
        actor_fingerprints = {event.get("actor_fingerprint") for event in journey}
        request_fingerprints = {event.get("fingerprint") for event in journey}
        self.assertEqual(len(session_ids), 1)
        self.assertEqual(len(actor_fingerprints), 1)
        self.assertGreater(len(request_fingerprints), 1)
        self.assertEqual(
            [event.get("session_step") for event in journey],
            [1, 2, 3, 4],
        )

        self.assertEqual(journey[1].get("bait_stage"), "discovered")
        self.assertEqual(journey[2].get("bait_stage"), "exploit-attempt")
        self.assertTrue(journey[2].get("bait_followed"))
        self.assertEqual(journey[2].get("tarpit_style"), "burst-then-stall")
        self.assertEqual(journey[3].get("bait_stage"), "canary-followed")
        self.assertTrue(journey[3].get("bait_followed"))
        self.assertGreater(journey[3].get("severity"), journey[3].get("base_severity"))

    async def test_same_network_address_with_different_clients_gets_distinct_actor_ids(self) -> None:
        first = await self.client.get(
            "/wp-json/",
            headers={"User-Agent": "WPScan v3.8.27", "Accept": "*/*"},
        )
        self.assertEqual(first.status, 200)
        second = await self.client.get(
            "/readme.html",
            headers={"User-Agent": "curl/8.5.0", "Accept": "*/*"},
        )
        self.assertEqual(second.status, 200)

        hotpot = self.server.app[HOTPOT_APP_KEY]
        events = await __import__("asyncio").to_thread(hotpot._events_since_sync, 0, 20)
        journey = [event for event in events["events"] if event.get("profile") == "wordpress"]
        self.assertEqual(len(journey), 2)
        self.assertEqual(journey[0]["client_ip"], journey[1]["client_ip"])
        self.assertNotEqual(
            journey[0].get("actor_fingerprint"),
            journey[1].get("actor_fingerprint"),
        )
        self.assertNotEqual(journey[0].get("session_id"), journey[1].get("session_id"))


if __name__ == "__main__":
    unittest.main()
