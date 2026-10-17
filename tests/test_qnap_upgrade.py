from __future__ import annotations

import unittest
from pathlib import Path


class QnapUpgradeTests(unittest.TestCase):
    def test_upgrade_helper_is_sequential_health_gated_and_never_tears_down_stack(self) -> None:
        root = Path(__file__).resolve().parents[1]
        script = (root / "scripts" / "qnap-upgrade.sh").read_text(encoding="utf-8")
        self.assertIn("set -eu", script)
        self.assertIn("config -q", script)
        self.assertIn("--force-recreate", script)
        self.assertIn("wait_for_health", script)
        self.assertIn('DASHBOARD_SERVICE="${HOTPOT_QNAP_DASHBOARD_SERVICE:-hotpot-dashboard}"', script)
        self.assertIn("config --services", script)
        self.assertIn("for service in $CORE_SERVICES", script)
        self.assertIn(".State.Health.Status", script)
        self.assertIn('compose up -d --no-deps --force-recreate "$DASHBOARD_SERVICE"', script)
        self.assertNotIn("\ndocker compose down", script)
        self.assertNotIn("\ncompose down", script)
        self.assertNotIn("cloudflared geoipupdate", script)
        self.assertNotIn("docker inspect -f '{{json .Config.Env}}'", script)

    def test_qnap_example_supports_immutable_hotpot_image_tag(self) -> None:
        root = Path(__file__).resolve().parents[1]
        compose = (root / "compose.qnap.example.yml").read_text(encoding="utf-8")
        self.assertGreaterEqual(compose.count("${HOTPOT_IMAGE_TAG:-latest}"), 3)
        self.assertIn("immutable release tag", compose)

    def test_upgrade_documentation_calls_out_dry_run_and_rollback(self) -> None:
        root = Path(__file__).resolve().parents[1]
        doc = (root / "docs" / "QNAP_UPGRADES.md").read_text(encoding="utf-8")
        self.assertIn("--dry-run", doc)
        self.assertIn("## Rollback", doc)
        self.assertIn("immutable release tag", doc)
        self.assertIn("never mounts the Docker socket", doc)

    def test_dashboard_example_documents_deployment_plan_inputs(self) -> None:
        root = Path(__file__).resolve().parents[1]
        env = (root / "dashboard.env.example").read_text(encoding="utf-8")
        self.assertIn("HOTPOT_DASHBOARD_COMPOSE_FILE=", env)
        self.assertIn("HOTPOT_DASHBOARD_DEPLOY_TAG=", env)
        self.assertIn("HOTPOT_DASHBOARD_DEPLOY_SERVICES=", env)


    def test_public_deployment_examples_do_not_embed_private_instance_names(self) -> None:
        root = Path(__file__).resolve().parents[1]
        paths = (
            root / "dashboard" / "deployment.py",
            root / "scripts" / "qnap-upgrade.sh",
            root / "compose.qnap.example.yml",
            root / "dashboard.env.example",
            root / "docs" / "QNAP_UPGRADES.md",
        )
        combined = "\n".join(path.read_text(encoding="utf-8").lower() for path in paths)
        for private_value in (
            "monkeyhead",
            "watersolver",
            "brewwatersolver.com",
            "monkeyheadbrewing.com",
            "bytemeloser.com",
            "passwordlab.dwights.dev",
            "hotpot-hvac",
            "hotpot-tapmenu",
        ):
            self.assertNotIn(private_value, combined)


if __name__ == "__main__":
    unittest.main()
