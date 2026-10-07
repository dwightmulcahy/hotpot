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
        instances = [
            {"id": "one", "name": "One", "url": "http://127.0.0.1:18001"}
        ]
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

    async def test_collect_status_exposes_build_suppression_and_safety_with_one_fetch(self) -> None:
        dashboard = self.make_dashboard()
        calls = []

        async def fetch_json(url: str):
            calls.append(url)
            return {
                "healthy": True,
                "uptime_seconds": 10,
                "upstream": "http://example",
                "upstream_health": {"healthy": True, "probe_method": "HEAD"},
                "version": "v1.2.3",
                "git_sha": "abcdef0123456789",
                "build_date": "2026-10-06T16:00:00Z",
                "source_id": "source-one",
                "event_cursor_max": 44,
                "allowlist": {"cidrs": ["10.0.0.0/8"]},
                "client_ip": {"trusted_proxy_cidrs": ["127.0.0.1/32"]},
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
        row = await dashboard.collect_status(
            Instance("one", "One", "http://127.0.0.1:18001")
        )
        self.assertEqual(len(calls), 1)
        self.assertTrue(calls[0].endswith("/_hotpot/status"))
        self.assertEqual(row["version"], "v1.2.3")
        self.assertEqual(row["git_sha"], "abcdef0123456789")
        self.assertEqual(row["events_suppressed"], 7)
        self.assertEqual(row["events_persisted"], 11)
        self.assertEqual(row["source_id"], "source-one")
        self.assertEqual(row["event_cursor_max"], 44)
        self.assertEqual(row["upstream_health"]["probe_method"], "HEAD")
        self.assertEqual(row["allowlist_cidrs"], ["10.0.0.0/8"])
        self.assertEqual(row["trusted_proxy_cidrs"], ["127.0.0.1/32"])

    def test_dashboard_html_surfaces_operations_and_response_without_string_rewrite(self) -> None:
        self.assertIn("Suppressed", PRODUCTION_HTML)
        self.assertIn("Top networks / ASNs", PRODUCTION_HTML)
        self.assertIn("Operational health", PRODUCTION_HTML)
        self.assertIn("GeoIP / attribution", PRODUCTION_HTML)
        self.assertIn("Response recommendations", PRODUCTION_HTML)
        self.assertIn("Pending response", PRODUCTION_HTML)
        self.assertIn("/api/recommendation/", PRODUCTION_HTML)
        self.assertIn("Backlog", PRODUCTION_HTML)
        root = Path(__file__).resolve().parents[1]
        production = (root / "dashboard" / "production.py").read_text(encoding="utf-8")
        self.assertNotIn("PRODUCTION_HTML.replace", production)
        self.assertIn("from .template import PRODUCTION_HTML", production)

    def test_dashboard_image_copies_server_header_hardening(self) -> None:
        root = Path(__file__).resolve().parents[1]
        dockerfile = (root / "Dockerfile.dashboard").read_text(encoding="utf-8")
        self.assertIn("COPY sitecustomize.py ./sitecustomize.py", dockerfile)
        self.assertIn('CMD ["python", "-m", "dashboard.production"]', dockerfile)

    def test_core_and_dashboard_dependency_sets_are_split(self) -> None:
        root = Path(__file__).resolve().parents[1]
        core = (root / "requirements-core.txt").read_text(encoding="utf-8")
        dashboard = (root / "requirements-dashboard.txt").read_text(encoding="utf-8")
        core_dockerfile = (root / "Dockerfile").read_text(encoding="utf-8")
        dashboard_dockerfile = (root / "Dockerfile.dashboard").read_text(
            encoding="utf-8"
        )
        self.assertIn("aiohttp", core)
        self.assertNotIn("geoip2", core)
        self.assertIn("geoip2", dashboard)
        self.assertIn("requirements-core.txt", core_dockerfile)
        self.assertNotIn("requirements-dashboard.txt", core_dockerfile)
        self.assertIn("requirements-dashboard.txt", dashboard_dockerfile)


if __name__ == "__main__":
    unittest.main()
