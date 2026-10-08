from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from dashboard.deployment import collect_deployment_report
from dashboard.runtime import Instance


class _PolicyManager:
    reconcile_seconds = 60

    def __init__(self, instance_ids: list[str]) -> None:
        self.instance_ids = instance_ids

    async def sync_status(self) -> dict:
        return {
            "instances": [
                {
                    "instance_id": instance_id,
                    "desired_revision": "policy-one",
                    "applied_revision": "policy-one",
                    "last_attempt_at": "2026-10-08T17:00:00+00:00",
                    "last_success_at": "2026-10-08T17:00:00+00:00",
                    "last_error": None,
                    "in_sync": True,
                }
                for instance_id in self.instance_ids
            ],
            "in_sync": True,
        }


class _Dashboard:
    refresh_seconds = 15
    timeout = 5.0
    max_pages = 20

    def __init__(self, statuses: dict[str, dict]) -> None:
        self.instances = [
            Instance(instance_id, instance_id.title(), f"http://127.0.0.1:{port}")
            for instance_id, port in (
                ("monkeyhead", 18088),
                ("watersolver", 12120),
                ("hvac", 18080),
                ("tapmenu", 18111),
            )
        ]
        self.statuses = statuses
        self.policy_manager = _PolicyManager([item.instance_id for item in self.instances])
        self.cloudflare = SimpleNamespace(enabled=False)
        self.notification_config = SimpleNamespace(enabled=False)

    async def fetch_json(self, url: str) -> dict:
        for instance in self.instances:
            if url.startswith(instance.url):
                return dict(self.statuses[instance.instance_id])
        raise RuntimeError("unexpected URL")


def _status(instance_id: str, *, sha: str = "same-sha", shared: str = "shared-one") -> dict:
    return {
        "healthy": True,
        "instance_id": instance_id,
        "instance_name": instance_id.title(),
        "upstream_health": {"healthy": True},
        "version": "v1.2.3",
        "git_sha": sha,
        "build_date": "2026-10-08T17:00:00Z",
        "deployment": {
            "instance_id": instance_id,
            "instance_name": instance_id.title(),
            "version": "v1.2.3",
            "git_sha": sha,
            "build_date": "2026-10-08T17:00:00Z",
            "config_fingerprint": f"full-{instance_id}",
            "shared_config_fingerprint": shared,
            "policy_revision": "policy-one",
            "policy_updated_at": "2026-10-08T17:00:00+00:00",
            "secret_sources": {"admin_token": "file"},
            "config": {"client_ip_mode": "cloudflare"},
        },
        "policy": {"revision": "policy-one"},
    }


class DeploymentUxTests(unittest.IsolatedAsyncioTestCase):
    async def test_ready_report_requires_health_identity_build_config_policy_and_backup_gate(self) -> None:
        statuses = {key: _status(key) for key in ("monkeyhead", "watersolver", "hvac", "tapmenu")}
        dashboard = _Dashboard(statuses)
        with tempfile.TemporaryDirectory() as directory, patch.dict(
            "os.environ",
            {
                "HOTPOT_ADMIN_TOKEN": "collector-token",
                "HOTPOT_DASHBOARD_TOKEN": "viewer-token",
                "HOTPOT_DASHBOARD_DATA_DIR": directory,
                "HOTPOT_DASHBOARD_INSTANCES": json.dumps(
                    [
                        {"id": item.instance_id, "name": item.name, "url": item.url}
                        for item in dashboard.instances
                    ]
                ),
                "HOTPOT_CLOUDFLARE_ENFORCEMENT_ENABLED": "false",
                "HOTPOT_DASHBOARD_NOTIFICATIONS_ENABLED": "false",
                "HOTPOT_DASHBOARD_BACKUPS_ENABLED": "false",
                "HOTPOT_GEOIP_ASN_DB": "",
                "HOTPOT_GEOIP_COUNTRY_DB": "",
                "HOTPOT_GEOIP_CITY_DB": "",
                "HOTPOT_VERSION": "v1.2.3",
                "HOTPOT_GIT_SHA": "same-sha",
                "HOTPOT_BUILD_DATE": "2026-10-08T17:00:00Z",
            },
            clear=True,
        ):
            report = await collect_deployment_report(dashboard)
        self.assertTrue(report["ready"], report)
        self.assertEqual(report["summary"]["healthy"], 4)
        self.assertTrue(report["summary"]["release_consistent"])
        self.assertTrue(report["summary"]["dashboard_matches_cores"])
        self.assertTrue(report["summary"]["shared_config_consistent"])
        self.assertTrue(report["summary"]["policy_in_sync"])
        self.assertTrue(all(row["admin_token_source"] == "file" for row in report["instances"]))
        self.assertTrue(all(check["status"] == "pass" for check in report["checks"]))
        self.assertEqual(report["upgrade_plan"]["target_tag"], "latest")
        self.assertTrue(report["upgrade_plan"]["mutable_tag"])

    async def test_release_and_config_skew_are_visible_and_block_ready_state(self) -> None:
        statuses = {key: _status(key) for key in ("monkeyhead", "watersolver", "hvac", "tapmenu")}
        statuses["hvac"] = _status("hvac", sha="different-sha", shared="different-shared")
        dashboard = _Dashboard(statuses)
        with tempfile.TemporaryDirectory() as directory, patch.dict(
            "os.environ",
            {
                "HOTPOT_ADMIN_TOKEN": "collector-token",
                "HOTPOT_DASHBOARD_TOKEN": "viewer-token",
                "HOTPOT_DASHBOARD_DATA_DIR": directory,
                "HOTPOT_DASHBOARD_INSTANCES": json.dumps(
                    [
                        {"id": item.instance_id, "name": item.name, "url": item.url}
                        for item in dashboard.instances
                    ]
                ),
                "HOTPOT_CLOUDFLARE_ENFORCEMENT_ENABLED": "false",
                "HOTPOT_DASHBOARD_NOTIFICATIONS_ENABLED": "false",
                "HOTPOT_DASHBOARD_BACKUPS_ENABLED": "false",
                "HOTPOT_VERSION": "v1.2.3",
                "HOTPOT_GIT_SHA": "same-sha",
                "HOTPOT_BUILD_DATE": "2026-10-08T17:00:00Z",
            },
            clear=True,
        ):
            report = await collect_deployment_report(dashboard)
        checks = {item["id"]: item["status"] for item in report["checks"]}
        self.assertFalse(report["ready"])
        self.assertEqual(checks["core-release"], "fail")
        self.assertEqual(checks["shared-config"], "fail")

    def test_static_deployment_ui_is_read_only_except_existing_verified_backup_action(self) -> None:
        root = Path(__file__).resolve().parents[1]
        runtime = (root / "dashboard" / "policy_runtime.py").read_text(encoding="utf-8")
        script = (root / "dashboard" / "static" / "deployment.js").read_text(encoding="utf-8")
        self.assertIn('/static/deployment.js', runtime)
        self.assertIn('/api/deployment', runtime)
        self.assertIn('/api/v1/deployment', runtime)
        self.assertIn('Deployment & upgrades', script)
        self.assertIn("fetch('/api/deployment'", script)
        self.assertIn("fetch('/api/backups/run'", script)
        self.assertIn("'X-Hotpot-Action':'backup-now'", script)
        self.assertNotIn('/var/run/docker.sock', script)
        self.assertNotIn('docker compose up', script)


if __name__ == "__main__":
    unittest.main()
