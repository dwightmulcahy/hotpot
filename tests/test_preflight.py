from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from dashboard.preflight import run_preflight as run_dashboard_preflight
from hotpot.preflight import run_preflight as run_hotpot_preflight


class PreflightTests(unittest.TestCase):
    def test_core_preflight_validates_config_without_network_calls(self) -> None:
        root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as directory, patch.dict(
            "os.environ",
            {
                "HOTPOT_UPSTREAM": "http://127.0.0.1:9999",
                "HOTPOT_DATA_DIR": directory,
                "HOTPOT_PROFILES_DIR": str(root / "profiles"),
                "HOTPOT_ADMIN_TOKEN": "test-token",
                "HOTPOT_CLIENT_IP_MODE": "direct",
            },
            clear=False,
        ):
            report = run_hotpot_preflight(check_bind=False)
        self.assertTrue(report["ok"], report)
        self.assertFalse(report["network_calls_performed"])
        self.assertIn("profiles", {row["id"] for row in report["checks"]})

    def test_core_preflight_rejects_invalid_upstream_url(self) -> None:
        root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as directory, patch.dict(
            "os.environ",
            {
                "HOTPOT_UPSTREAM": "not-a-url",
                "HOTPOT_DATA_DIR": directory,
                "HOTPOT_PROFILES_DIR": str(root / "profiles"),
            },
            clear=False,
        ):
            report = run_hotpot_preflight(check_bind=False)
        self.assertFalse(report["ok"])
        upstream = next(row for row in report["checks"] if row["id"] == "upstream")
        self.assertEqual(upstream["status"], "fail")

    def test_dashboard_preflight_accepts_coherent_local_configuration(self) -> None:
        with tempfile.TemporaryDirectory() as directory, patch.dict(
            "os.environ",
            {
                "HOTPOT_ADMIN_TOKEN": "collector-token",
                "HOTPOT_DASHBOARD_TOKEN": "viewer-token",
                "HOTPOT_DASHBOARD_DATA_DIR": directory,
                "HOTPOT_DASHBOARD_INSTANCES": json.dumps(
                    [{"id": "one", "name": "One", "url": "http://127.0.0.1:18088"}]
                ),
                "HOTPOT_CLOUDFLARE_ENFORCEMENT_ENABLED": "false",
                "HOTPOT_DASHBOARD_NOTIFICATIONS_ENABLED": "false",
                "HOTPOT_GEOIP_ASN_DB": "",
                "HOTPOT_GEOIP_COUNTRY_DB": "",
                "HOTPOT_GEOIP_CITY_DB": "",
            },
            clear=False,
        ):
            report = run_dashboard_preflight(check_bind=False)
        self.assertTrue(report["ok"], report)
        self.assertFalse(report["network_calls_performed"])

    def test_dashboard_preflight_fails_when_enforcement_has_no_targets(self) -> None:
        with tempfile.TemporaryDirectory() as directory, patch.dict(
            "os.environ",
            {
                "HOTPOT_ADMIN_TOKEN": "collector-token",
                "HOTPOT_DASHBOARD_TOKEN": "viewer-token",
                "HOTPOT_DASHBOARD_DATA_DIR": directory,
                "HOTPOT_DASHBOARD_INSTANCES": json.dumps(
                    [{"id": "one", "name": "One", "url": "http://127.0.0.1:18088"}]
                ),
                "HOTPOT_CLOUDFLARE_ENFORCEMENT_ENABLED": "true",
                "HOTPOT_CLOUDFLARE_API_TOKEN": "cf-token",
                "HOTPOT_CLOUDFLARE_TARGETS": "",
                "HOTPOT_DASHBOARD_NOTIFICATIONS_ENABLED": "false",
            },
            clear=False,
        ):
            report = run_dashboard_preflight(check_bind=False)
        self.assertFalse(report["ok"])
        cloudflare = next(row for row in report["checks"] if row["id"] == "cloudflare")
        self.assertEqual(cloudflare["status"], "fail")


if __name__ == "__main__":
    unittest.main()
