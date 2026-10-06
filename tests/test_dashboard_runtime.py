from __future__ import annotations

import asyncio
import base64
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from aiohttp.test_utils import make_mocked_request

from dashboard.runtime import CentralStore, Dashboard, Instance


class CentralStoreTests(unittest.IsolatedAsyncioTestCase):
    async def test_exact_global_unique_attackers_and_cross_app_correlation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = CentralStore(Path(tmp))
            one = Instance("one", "One", "http://one")
            two = Instance("two", "Two", "http://two")
            await store.ingest(
                one,
                [
                    {"id": 1, "ts": "2026-01-01T00:00:00+00:00", "client_ip": "203.0.113.1", "path": "/.env", "category": "secret", "scanner": "Nuclei", "action": "tarpit", "severity": 5, "escalation_level": 2},
                    {"id": 2, "ts": "2026-01-01T00:01:00+00:00", "client_ip": "203.0.113.2", "path": "/wp-login.php", "category": "wordpress", "scanner": "WPScan", "action": "deceive", "severity": 3, "escalation_level": 1},
                ],
                2,
            )
            await store.ingest(
                two,
                [
                    {"id": 1, "ts": "2026-01-01T00:02:00+00:00", "client_ip": "203.0.113.1", "path": "/.git/config", "category": "git", "scanner": "Nuclei", "action": "tarpit", "severity": 5, "escalation_level": 3},
                ],
                1,
            )
            snapshot = await store.snapshot([
                {"id": "one", "name": "One", "healthy": True, "tarpits_active": 1},
                {"id": "two", "name": "Two", "healthy": True, "tarpits_active": 0},
            ])
            self.assertEqual(snapshot["summary"]["events"], 3)
            self.assertEqual(snapshot["summary"]["unique_ips"], 2)
            self.assertEqual(snapshot["summary"]["active_tarpits"], 1)
            offender = snapshot["top_offenders"][0]
            self.assertEqual(offender["ip"], "203.0.113.1")
            self.assertEqual(offender["app_count"], 2)
            self.assertEqual(offender["apps"], ["One", "Two"])


class DashboardAuthTests(unittest.TestCase):
    def make_dashboard(self) -> Dashboard:
        instances = [{"id": "one", "name": "One", "url": "http://127.0.0.1:18001"}]
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        with patch.dict(
            os.environ,
            {
                "HOTPOT_DASHBOARD_INSTANCES": json.dumps(instances),
                "HOTPOT_ADMIN_TOKEN": "collector-token",
                "HOTPOT_DASHBOARD_TOKEN": "viewer-token",
                "HOTPOT_DASHBOARD_DATA_DIR": self.tmp.name,
            },
            clear=False,
        ):
            return Dashboard()

    def test_dashboard_requires_separate_viewer_token(self) -> None:
        dashboard = self.make_dashboard()
        missing = make_mocked_request("GET", "/")
        self.assertFalse(dashboard.authorized(missing))

        encoded = base64.b64encode(b"hotpot:viewer-token").decode("ascii")
        allowed = make_mocked_request("GET", "/", headers={"Authorization": f"Basic {encoded}"})
        self.assertTrue(dashboard.authorized(allowed))

        wrong = base64.b64encode(b"hotpot:wrong").decode("ascii")
        denied = make_mocked_request("GET", "/", headers={"Authorization": f"Basic {wrong}"})
        self.assertFalse(dashboard.authorized(denied))

    def test_dashboard_refuses_to_start_without_viewer_token(self) -> None:
        instances = [{"id": "one", "name": "One", "url": "http://127.0.0.1:18001"}]
        with tempfile.TemporaryDirectory() as tmp, patch.dict(
            os.environ,
            {
                "HOTPOT_DASHBOARD_INSTANCES": json.dumps(instances),
                "HOTPOT_ADMIN_TOKEN": "collector-token",
                "HOTPOT_DASHBOARD_TOKEN": "",
                "HOTPOT_DASHBOARD_DATA_DIR": tmp,
            },
            clear=False,
        ):
            with self.assertRaises(RuntimeError):
                Dashboard()


if __name__ == "__main__":
    unittest.main()
