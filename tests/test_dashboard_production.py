from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from dashboard.production import PRODUCTION_HTML, ProductionDashboard
from dashboard.runtime import Instance


class DashboardProductionTests(unittest.IsolatedAsyncioTestCase):
    def make_dashboard(self) -> ProductionDashboard:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        instances = [{"id": "one", "name": "One", "url": "http://127.0.0.1:18001"}]
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
            return ProductionDashboard()

    async def test_collect_status_exposes_build_and_suppression(self) -> None:
        dashboard = self.make_dashboard()

        async def fetch_json(url: str):
            return {
                "healthy": True,
                "uptime_seconds": 10,
                "upstream": "http://example",
                "upstream_health": {"healthy": True},
                "version": "v1.2.3",
                "git_sha": "abcdef0123456789",
                "build_date": "2026-10-06T16:00:00Z",
                "stats": {
                    "tarpits_active": 1,
                    "tarpits_total": 4,
                    "proxied": 20,
                    "telemetry_errors": 0,
                    "events_suppressed_total": 7,
                    "events_persisted_total": 11,
                },
            }

        dashboard.fetch_json = fetch_json
        row = await dashboard.collect_status(Instance("one", "One", "http://127.0.0.1:18001"))
        self.assertEqual(row["version"], "v1.2.3")
        self.assertEqual(row["git_sha"], "abcdef0123456789")
        self.assertEqual(row["events_suppressed"], 7)
        self.assertEqual(row["events_persisted"], 11)

    def test_dashboard_html_surfaces_suppression_and_version(self) -> None:
        self.assertIn("Suppressed", PRODUCTION_HTML)
        self.assertIn("events_suppressed", PRODUCTION_HTML)
        self.assertIn("a.version", PRODUCTION_HTML)

    def test_dashboard_image_copies_server_header_hardening(self) -> None:
        root = Path(__file__).resolve().parents[1]
        dockerfile = (root / "Dockerfile.dashboard").read_text(encoding="utf-8")
        self.assertIn("COPY sitecustomize.py ./sitecustomize.py", dockerfile)
        self.assertIn('CMD ["python", "-m", "dashboard.production"]', dockerfile)


if __name__ == "__main__":
    unittest.main()
