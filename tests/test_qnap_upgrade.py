from __future__ import annotations

import os
import subprocess
import tempfile
import textwrap
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
        self.assertIn("discover_labeled_services", script)
        self.assertIn('io.hotpot.managed', script)
        self.assertIn('io.hotpot.role', script)
        self.assertIn("for service in $CORE_SERVICES", script)
        self.assertIn(".State.Health.Status", script)
        self.assertIn('compose up -d --no-deps --force-recreate "$DASHBOARD_SERVICE"', script)
        self.assertNotIn("\ndocker compose down", script)
        self.assertNotIn("\ncompose down", script)
        self.assertNotIn("cloudflared geoipupdate", script)
        self.assertNotIn("docker inspect -f '{{json .Config.Env}}'", script)

    def test_label_discovery_supports_nonstandard_service_names(self) -> None:
        root = Path(__file__).resolve().parents[1]
        script = root / "scripts" / "qnap-upgrade.sh"
        with tempfile.TemporaryDirectory() as directory:
            temp = Path(directory)
            compose = temp / "compose.yml"
            compose.write_text("services: {}\n", encoding="utf-8")
            docker = temp / "docker"
            docker.write_text(
                textwrap.dedent(
                    """\
                    #!/bin/sh
                    if [ "$1" = "compose" ]; then
                      shift
                      while [ "$#" -gt 0 ]; do
                        case "$1" in
                          -f) shift 2 ;;
                          config)
                            shift
                            if [ "${1:-}" = "-q" ]; then exit 0; fi
                            if [ "${1:-}" = "--services" ]; then
                              printf '%s\n' edge-alpha edge-beta command-center cloudflared
                              exit 0
                            fi
                            ;;
                          ps)
                            shift
                            [ "${1:-}" = "-q" ] && shift
                            case "${1:-}" in
                              edge-alpha) echo cid-alpha ;;
                              edge-beta) echo cid-beta ;;
                              command-center) echo cid-dashboard ;;
                              cloudflared) echo cid-cloudflared ;;
                            esac
                            exit 0
                            ;;
                        esac
                      done
                    fi
                    if [ "$1" = "inspect" ]; then
                      shift
                      [ "$1" = "--format" ] || exit 1
                      format=$2
                      id=$3
                      case "$format" in
                        *io.hotpot.managed*)
                          case "$id" in cid-alpha|cid-beta|cid-dashboard) echo true ;; *) echo "" ;; esac
                          ;;
                        *io.hotpot.role*)
                          case "$id" in cid-alpha|cid-beta) echo core ;; cid-dashboard) echo dashboard ;; *) echo "" ;; esac
                          ;;
                      esac
                      exit 0
                    fi
                    exit 1
                    """
                ),
                encoding="utf-8",
            )
            docker.chmod(0o755)
            env = {
                **os.environ,
                "PATH": f"{temp}:{os.environ.get('PATH', '')}",
                "HOTPOT_QNAP_COMPOSE_FILE": str(compose),
                "HOTPOT_QNAP_CORE_SERVICES": "",
                "HOTPOT_QNAP_DASHBOARD_SERVICE": "",
            }
            result = subprocess.run(
                ["/bin/sh", str(script), "--dry-run", "--skip-pull"],
                env=env,
                text=True,
                capture_output=True,
                check=False,
            )
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertIn("edge-alpha", result.stdout)
        self.assertIn("edge-beta", result.stdout)
        self.assertIn("dashboard: command-center", result.stdout)
        self.assertNotIn("legacy hotpot-* naming fallback", result.stdout)

    def test_qnap_example_uses_registry_scoped_secrets_and_role_labels(self) -> None:
        root = Path(__file__).resolve().parents[1]
        compose = (root / "compose.qnap.example.yml").read_text(encoding="utf-8")
        registry = (root / "hotpot-apps.example.toml").read_text(encoding="utf-8")

        self.assertGreaterEqual(compose.count("${HOTPOT_IMAGE_TAG:-latest}"), 3)
        self.assertIn("immutable release tag", compose)
        self.assertEqual(
            compose.count(
                "/share/Data/config/cloudflared/hotpot-apps.toml:/config/apps.toml:ro"
            ),
            3,
        )
        self.assertEqual(compose.count("HOTPOT_APP_REGISTRY: /config/apps.toml"), 3)
        self.assertEqual(compose.count('"io.hotpot.role=core"'), 2)
        self.assertEqual(compose.count('"io.hotpot.role=dashboard"'), 1)
        self.assertEqual(compose.count('"io.hotpot.managed=true"'), 3)
        self.assertNotIn("HOTPOT_INSTANCE_NAME:", compose)
        self.assertIn(
            "/share/Data/config/cloudflared/secrets/app-one:/run/secrets/app-one:ro",
            compose,
        )
        self.assertIn(
            "/share/Data/config/cloudflared/secrets/app-two:/run/secrets/app-two:ro",
            compose,
        )
        self.assertIn(
            'collector_token_file = "/run/secrets/app-one/collector_token"',
            registry,
        )
        self.assertIn(
            'policy_token_file = "/run/secrets/app-two/policy_token"',
            registry,
        )

    def test_dashboard_example_uses_registry_without_duplicate_app_maps(self) -> None:
        root = Path(__file__).resolve().parents[1]
        env = (root / "dashboard.env.example").read_text(encoding="utf-8")
        qnap_env = (root / "hotpot.qnap.env.example").read_text(encoding="utf-8")
        registry = (root / "hotpot-apps.example.toml").read_text(encoding="utf-8")

        self.assertIn("HOTPOT_APP_REGISTRY=/config/apps.toml", env)
        self.assertIn("HOTPOT_DASHBOARD_COMPOSE_FILE=", env)
        self.assertIn("HOTPOT_DASHBOARD_DEPLOY_TAG=", env)
        self.assertIn("HOTPOT_DASHBOARD_DEPLOY_SERVICES=", env)
        self.assertNotIn("\nHOTPOT_DASHBOARD_INSTANCES=[", env)
        self.assertNotIn("\nHOTPOT_CLOUDFLARE_TARGETS={", env)
        self.assertNotIn("\nHOTPOT_ADMIN_TOKEN=", env)
        self.assertNotIn("HOTPOT_PROFILES=", qnap_env)
        self.assertNotIn("\nHOTPOT_ADMIN_TOKEN=", qnap_env)
        self.assertIn('id = "app-one"', registry)
        self.assertIn('id = "app-two"', registry)
        self.assertIn("[apps.deployment]", registry)
        self.assertIn("[apps.cloudflare]", registry)

    def test_app_registry_runbook_documents_isolation_migration_and_fallback(self) -> None:
        root = Path(__file__).resolve().parents[1]
        doc = (root / "docs" / "app-registry.md").read_text(encoding="utf-8")
        self.assertIn("Separate traffic plane, centralized intelligence", doc)
        self.assertIn("collector token", doc)
        self.assertIn("policy token", doc)
        self.assertIn("only its own", doc)
        self.assertIn("qnap-upgrade.sh", doc)
        self.assertIn("--dry-run", doc)
        self.assertIn("legacy", doc)
        self.assertIn("HOTPOT_APP_REGISTRY", doc)
        self.assertIn("migrate_qnap_registry.py", doc)
        self.assertIn("--retire-legacy", doc)
        self.assertIn("does not restart anything", doc)
        self.assertIn("automatically restores", doc)

    def test_qnap_upgrade_runbook_documents_two_stage_migration(self) -> None:
        root = Path(__file__).resolve().parents[1]
        doc = (root / "docs" / "QNAP_UPGRADES.md").read_text(encoding="utf-8")
        readme = (root / "README.md").read_text(encoding="utf-8")
        migration = root / "scripts" / "migrate_qnap_registry.py"

        self.assertTrue(migration.is_file())
        self.assertTrue(os.access(migration, os.X_OK))
        self.assertIn("migrate_qnap_registry.py --apply", doc)
        self.assertIn("migrate_qnap_registry.py --retire-legacy", doc)
        self.assertIn("--retire-legacy --apply", doc)
        self.assertIn("keeps the legacy shared admin", doc)
        self.assertIn("migrate_qnap_registry.py", readme)
        self.assertIn("preview only", readme)

    def test_snapshot_runbook_documents_offline_review_safety(self) -> None:
        root = Path(__file__).resolve().parents[1]
        app_registry = (root / "docs" / "app-registry.md").read_text(
            encoding="utf-8"
        )
        qnap = (root / "docs" / "QNAP_UPGRADES.md").read_text(
            encoding="utf-8"
        )
        readme = (root / "README.md").read_text(encoding="utf-8")

        self.assertIn("--snapshot-root", app_registry)
        self.assertIn("hotpot-qnap-original", app_registry)
        self.assertIn("hotpot-qnap-migrated", app_registry)
        self.assertIn("keeps the real QNAP paths", app_registry)
        self.assertIn("output path outside the snapshot is rejected", app_registry)
        self.assertIn("Do not blindly `git add .`", app_registry)
        self.assertIn("never starts/stops/restarts containers", qnap)
        self.assertIn("--snapshot-root", readme)

    def test_public_deployment_examples_use_generic_placeholders(self) -> None:
        root = Path(__file__).resolve().parents[1]
        compose = (root / "compose.qnap.example.yml").read_text(encoding="utf-8")
        registry = (root / "hotpot-apps.example.toml").read_text(encoding="utf-8")
        deployment = (root / "dashboard" / "deployment.py").read_text(encoding="utf-8")

        self.assertIn("hotpot-app-one:", compose)
        self.assertIn("hotpot-app-two:", compose)
        self.assertIn("app-one.example.com", registry)
        self.assertIn('id = "app-one"', registry)
        self.assertIn('id = "app-two"', registry)
        self.assertIn("app.service or", deployment)
        self.assertNotIn("DEFAULT_SERVICES =", deployment)


if __name__ == "__main__":
    unittest.main()
