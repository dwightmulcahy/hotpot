from __future__ import annotations

import json
import os
import unittest
from unittest.mock import patch

from dashboard.app import Dashboard


class DashboardTests(unittest.TestCase):
    def make_dashboard(self) -> Dashboard:
        instances = [
            {"id": "one", "name": "One", "url": "http://127.0.0.1:18001"},
            {"id": "two", "name": "Two", "url": "http://127.0.0.1:18002"},
        ]
        with patch.dict(
            os.environ,
            {
                "HOTPOT_DASHBOARD_INSTANCES": json.dumps(instances),
                "HOTPOT_ADMIN_TOKEN": "test-token",
            },
            clear=False,
        ):
            return Dashboard()

    def test_requires_instances(self) -> None:
        with patch.dict(os.environ, {"HOTPOT_DASHBOARD_INSTANCES": "", "HOTPOT_ADMIN_TOKEN": "x"}, clear=False):
            with self.assertRaises(RuntimeError):
                Dashboard()

    def test_aggregates_apps_events_and_cross_app_offenders(self) -> None:
        dashboard = self.make_dashboard()
        rows = [
            {
                "id": "one",
                "name": "One",
                "url": "http://127.0.0.1:18001",
                "healthy": True,
                "error": None,
                "status": {"healthy": True, "uptime_seconds": 60, "upstream": "http://a", "stats": {"tarpits": 2, "proxied": 20}},
                "intel": {
                    "events": 4,
                    "unique_ips": 2,
                    "top_paths": [{"path": "/.env", "hits": 3}],
                    "top_categories": [{"category": "secret-discovery", "hits": 3}],
                    "top_scanners": [{"scanner": "Nuclei", "hits": 2}],
                    "top_offenders": [{"ip": "203.0.113.1", "hits": 3, "score": 8, "escalation_level": 2, "last_seen": "2026-01-01T00:00:00+00:00"}],
                    "recent": [{"ts": "2026-01-01T00:00:00+00:00", "client_ip": "203.0.113.1", "path": "/.env"}],
                },
            },
            {
                "id": "two",
                "name": "Two",
                "url": "http://127.0.0.1:18002",
                "healthy": True,
                "error": None,
                "status": {"healthy": True, "uptime_seconds": 120, "upstream": "http://b", "stats": {"tarpits": 1, "proxied": 10}},
                "intel": {
                    "events": 5,
                    "unique_ips": 3,
                    "top_paths": [{"path": "/.env", "hits": 2}],
                    "top_categories": [{"category": "secret-discovery", "hits": 2}],
                    "top_scanners": [{"scanner": "Nuclei", "hits": 1}],
                    "top_offenders": [{"ip": "203.0.113.1", "hits": 2, "score": 5, "escalation_level": 3, "last_seen": "2026-01-02T00:00:00+00:00"}],
                    "recent": [{"ts": "2026-01-02T00:00:00+00:00", "client_ip": "203.0.113.1", "path": "/.git/config"}],
                },
            },
        ]

        result = dashboard.aggregate(rows)
        self.assertEqual(result["summary"]["protected_apps"], 2)
        self.assertEqual(result["summary"]["healthy_apps"], 2)
        self.assertEqual(result["summary"]["events"], 9)
        self.assertEqual(result["summary"]["active_tarpits"], 3)
        self.assertEqual(result["top_paths"][0], {"path": "/.env", "hits": 5})
        offender = result["top_offenders"][0]
        self.assertEqual(offender["ip"], "203.0.113.1")
        self.assertEqual(offender["app_count"], 2)
        self.assertEqual(offender["score"], 13)
        self.assertEqual(offender["level"], 3)
        self.assertEqual(result["recent"][0]["instance_name"], "Two")


if __name__ == "__main__":
    unittest.main()
