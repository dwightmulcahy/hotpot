from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path


class QnapRegistryMigrationTests(unittest.TestCase):
    def _fixture(self, root: Path, *, missing_smtp_secret: bool = False):
        compose = root / "docker-compose.yml"
        hotpot_env = root / "hotpot.env"
        dashboard_env = root / "dashboard.env"
        secrets_dir = root / "secrets"
        secrets_dir.mkdir()
        smtp = secrets_dir / "smtp_password"
        if not missing_smtp_secret:
            smtp.write_text("smtp-super-secret\n", encoding="utf-8")

        container_user = f"{os.getuid()}:{os.getgid()}"
        compose.write_text(
            textwrap.dedent(
                f"""\
                services:
                  edge-alpha:
                    image: dwightmulcahy/hotpot:latest
                    network_mode: host
                    user: "{container_user}"
                    env_file:
                      - {hotpot_env}
                    environment:
                      HOTPOT_INSTANCE_ID: app-one
                      HOTPOT_INSTANCE_NAME: Legacy One
                      HOTPOT_PORT: "18081"
                      HOTPOT_UPSTREAM: http://127.0.0.1:8081
                    volumes:
                      - {root / 'data-one'}:/data
                      - {secrets_dir}:/run/secrets:ro
                    labels:
                      - "com.centurylinklabs.watchtower.enable=true"

                  edge-beta:
                    image: dwightmulcahy/hotpot:latest
                    network_mode: host
                    user: "{container_user}"
                    env_file:
                      - {hotpot_env}
                    environment:
                      HOTPOT_INSTANCE_ID: app-two
                      HOTPOT_PORT: "18082"
                      HOTPOT_UPSTREAM: http://127.0.0.1:8082
                      HOTPOT_PROFILES: secrets,git,generic
                    volumes:
                      - {root / 'data-two'}:/data
                      - {secrets_dir}:/run/secrets:ro

                  command-center:
                    image: dwightmulcahy/hotpot-dashboard:latest
                    network_mode: host
                    user: "{container_user}"
                    env_file:
                      - {dashboard_env}
                    volumes:
                      - {root / 'dashboard-data'}:/data
                      - {secrets_dir}:/run/secrets:ro
                """
            ),
            encoding="utf-8",
        )
        hotpot_env.write_text(
            textwrap.dedent(
                """\
                HOTPOT_BIND=127.0.0.1
                HOTPOT_PROFILES=wordpress,secrets,git,php,generic
                HOTPOT_ADMIN_TOKEN=legacy-admin-super-secret
                HOTPOT_SMTP_PASSWORD_FILE=/run/secrets/smtp_password
                HOTPOT_TARPIT_ENABLED=true
                """
            ),
            encoding="utf-8",
        )
        dashboard_env.write_text(
            textwrap.dedent(
                """\
                HOTPOT_ADMIN_TOKEN=legacy-admin-super-secret
                HOTPOT_DASHBOARD_TOKEN=viewer-super-secret
                HOTPOT_DASHBOARD_DATA_DIR=/data
                HOTPOT_DASHBOARD_INSTANCES=[{"id":"app-one","name":"Dashboard One","url":"http://127.0.0.1:18081"},{"id":"app-two","name":"Dashboard Two","url":"http://127.0.0.1:18082"}]
                HOTPOT_CLOUDFLARE_TARGETS={"app-one":{"zone_id":"zone-one","hosts":["WWW.ONE.EXAMPLE"]},"app-two":{"zone_id":"zone-two","hosts":["two.example"]}}
                """
            ),
            encoding="utf-8",
        )
        return compose, hotpot_env, dashboard_env, secrets_dir

    def _docker(self, root: Path, compose: Path, hotpot_env: Path, dashboard_env: Path, secrets_dir: Path) -> Path:
        docker = root / "docker"
        container_user = f"{os.getuid()}:{os.getgid()}"
        payload = {
            "services": {
                "edge-alpha": {
                    "image": "dwightmulcahy/hotpot:latest",
                    "user": container_user,
                    "environment": {
                        "HOTPOT_BIND": "127.0.0.1",
                        "HOTPOT_PROFILES": "wordpress,secrets,git,php,generic",
                        "HOTPOT_ADMIN_TOKEN": "legacy-admin-super-secret",
                        "HOTPOT_SMTP_PASSWORD_FILE": "/run/secrets/smtp_password",
                        "HOTPOT_INSTANCE_ID": "app-one",
                        "HOTPOT_INSTANCE_NAME": "Legacy One",
                        "HOTPOT_PORT": "18081",
                        "HOTPOT_UPSTREAM": "http://127.0.0.1:8081",
                    },
                    "volumes": [
                        {"type": "bind", "source": str(root / "data-one"), "target": "/data"},
                        {"type": "bind", "source": str(secrets_dir), "target": "/run/secrets", "read_only": True},
                    ],
                },
                "edge-beta": {
                    "image": "dwightmulcahy/hotpot:latest",
                    "user": container_user,
                    "environment": {
                        "HOTPOT_BIND": "127.0.0.1",
                        "HOTPOT_PROFILES": "secrets,git,generic",
                        "HOTPOT_ADMIN_TOKEN": "legacy-admin-super-secret",
                        "HOTPOT_SMTP_PASSWORD_FILE": "/run/secrets/smtp_password",
                        "HOTPOT_INSTANCE_ID": "app-two",
                        "HOTPOT_PORT": "18082",
                        "HOTPOT_UPSTREAM": "http://127.0.0.1:8082",
                    },
                    "volumes": [
                        {"type": "bind", "source": str(root / "data-two"), "target": "/data"},
                        {"type": "bind", "source": str(secrets_dir), "target": "/run/secrets", "read_only": True},
                    ],
                },
                "command-center": {
                    "image": "dwightmulcahy/hotpot-dashboard:latest",
                    "user": container_user,
                    "environment": {
                        "HOTPOT_ADMIN_TOKEN": "legacy-admin-super-secret",
                        "HOTPOT_DASHBOARD_TOKEN": "viewer-super-secret",
                        "HOTPOT_DASHBOARD_DATA_DIR": "/data",
                        "HOTPOT_DASHBOARD_INSTANCES": '[{"id":"app-one","name":"Dashboard One","url":"http://127.0.0.1:18081"},{"id":"app-two","name":"Dashboard Two","url":"http://127.0.0.1:18082"}]',
                        "HOTPOT_CLOUDFLARE_TARGETS": '{"app-one":{"zone_id":"zone-one","hosts":["WWW.ONE.EXAMPLE"]},"app-two":{"zone_id":"zone-two","hosts":["two.example"]}}',
                    },
                    "volumes": [
                        {"type": "bind", "source": str(root / "dashboard-data"), "target": "/data"},
                        {"type": "bind", "source": str(secrets_dir), "target": "/run/secrets", "read_only": True},
                    ],
                },
            }
        }
        encoded = json.dumps(payload)
        docker.write_text(
            textwrap.dedent(
                f"""\
                #!{sys.executable}
                import json
                import pathlib
                import sys

                args = sys.argv[1:]
                if args[:1] != ["compose"]:
                    raise SystemExit(2)
                if "--format" in args and "json" in args:
                    print({encoded!r})
                    raise SystemExit(0)
                if "config" in args and "-q" in args:
                    candidate = pathlib.Path(args[args.index("-f") + 1])
                    text = candidate.read_text(encoding="utf-8")
                    if "services:" not in text:
                        raise SystemExit(4)
                    raise SystemExit(0)
                raise SystemExit(3)
                """
            ),
            encoding="utf-8",
        )
        docker.chmod(0o755)
        return docker

    def _run(self, script: Path, args: list[str]) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(script), *args],
            text=True,
            capture_output=True,
            check=False,
        )

    def test_plan_is_read_only_redacted_and_captures_all_apps(self) -> None:
        root_repo = Path(__file__).resolve().parents[1]
        script = root_repo / "scripts" / "migrate_qnap_registry.py"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            compose, hotpot_env, dashboard_env, secrets_dir = self._fixture(root)
            docker = self._docker(root, compose, hotpot_env, dashboard_env, secrets_dir)
            before = {
                compose: compose.read_bytes(),
                hotpot_env: hotpot_env.read_bytes(),
                dashboard_env: dashboard_env.read_bytes(),
            }
            result = self._run(
                script,
                [
                    "--compose", str(compose),
                    "--hotpot-env", str(hotpot_env),
                    "--dashboard-env", str(dashboard_env),
                    "--docker-bin", str(docker),
                ],
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("PLAN ONLY", result.stdout)
            self.assertIn("app-one: service=edge-alpha", result.stdout)
            self.assertIn("app-two: service=edge-beta", result.stdout)
            self.assertIn('service = "edge-alpha"', result.stdout)
            self.assertIn('hosts = ["www.one.example"]', result.stdout)
            self.assertNotIn("legacy-admin-super-secret", result.stdout)
            self.assertNotIn("viewer-super-secret", result.stdout)
            self.assertNotIn("smtp-super-secret", result.stdout)
            for path, content in before.items():
                self.assertEqual(path.read_bytes(), content)
            self.assertFalse((root / "hotpot-apps.toml").exists())

    def test_apply_creates_registry_scoped_secrets_backups_and_idempotent_config(self) -> None:
        root_repo = Path(__file__).resolve().parents[1]
        script = root_repo / "scripts" / "migrate_qnap_registry.py"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            compose, hotpot_env, dashboard_env, secrets_dir = self._fixture(root)
            docker = self._docker(root, compose, hotpot_env, dashboard_env, secrets_dir)
            args = [
                "--compose", str(compose),
                "--hotpot-env", str(hotpot_env),
                "--dashboard-env", str(dashboard_env),
                "--docker-bin", str(docker),
                "--apply",
            ]
            result = self._run(script, args)
            self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
            self.assertIn("App-registry migration staged", result.stdout)
            self.assertIn("containers were NOT restarted", result.stdout)

            registry = root / "hotpot-apps.toml"
            registry_text = registry.read_text(encoding="utf-8")
            self.assertIn('id = "app-one"', registry_text)
            self.assertIn('service = "edge-alpha"', registry_text)
            self.assertIn('profiles = ["wordpress", "secrets", "git", "php", "generic"]', registry_text)
            self.assertIn('profiles = ["secrets", "git", "generic"]', registry_text)
            self.assertIn('zone_id = "zone-one"', registry_text)
            self.assertNotIn("legacy-admin-super-secret", registry_text)

            compose_text = compose.read_text(encoding="utf-8")
            self.assertEqual(compose_text.count("HOTPOT_APP_REGISTRY"), 3)
            self.assertIn('"io.hotpot.role=core"', compose_text)
            self.assertIn('"io.hotpot.role=dashboard"', compose_text)
            self.assertIn(
                f"{secrets_dir / 'app-one'}:/run/secrets/app-one:ro",
                compose_text,
            )
            self.assertNotIn(f"{secrets_dir}:/run/secrets:ro\n    read_only", compose_text)

            hotpot_text = hotpot_env.read_text(encoding="utf-8")
            self.assertIn("HOTPOT_PROFILES=", hotpot_text)
            self.assertIn("HOTPOT_ADMIN_TOKEN=legacy-admin-super-secret", hotpot_text)
            self.assertIn(
                "HOTPOT_SMTP_PASSWORD_FILE=/run/secrets/smtp_password",
                hotpot_text,
            )

            dashboard_text = dashboard_env.read_text(encoding="utf-8")
            self.assertIn("HOTPOT_APP_REGISTRY=/config/apps.toml", dashboard_text)
            self.assertIn("HOTPOT_DASHBOARD_INSTANCES=", dashboard_text)
            self.assertIn("HOTPOT_CLOUDFLARE_TARGETS=", dashboard_text)
            self.assertIn(
                "HOTPOT_ADMIN_TOKEN=legacy-admin-super-secret", dashboard_text
            )
            self.assertIn("HOTPOT_DASHBOARD_TOKEN=viewer-super-secret", dashboard_text)

            tokens = []
            for app in ("app-one", "app-two"):
                app_dir = secrets_dir / app
                collector = app_dir / "collector_token"
                policy = app_dir / "policy_token"
                smtp = app_dir / "smtp_password"
                for path in (collector, policy, smtp):
                    self.assertTrue(path.is_file(), path)
                    self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
                self.assertEqual(smtp.read_text(encoding="utf-8").strip(), "smtp-super-secret")
                self.assertNotEqual(
                    collector.read_text(encoding="utf-8").strip(),
                    policy.read_text(encoding="utf-8").strip(),
                )
                tokens.extend(
                    [
                        collector.read_text(encoding="utf-8").strip(),
                        policy.read_text(encoding="utf-8").strip(),
                    ]
                )
            self.assertEqual(len(set(tokens)), 4)

            backups = list((root / "hotpot-migration-backups").glob("*/migration-manifest.json"))
            self.assertEqual(len(backups), 1)

            # The fake compose output still represents the old running deployment,
            # so exercise idempotence using a second config that reports registry env.
            fake = docker.read_text(encoding="utf-8")
            fake = fake.replace(
                '"HOTPOT_INSTANCE_ID": "app-one",',
                '"HOTPOT_APP_REGISTRY": "/config/apps.toml", "HOTPOT_INSTANCE_ID": "app-one",',
            ).replace(
                '"HOTPOT_INSTANCE_ID": "app-two",',
                '"HOTPOT_APP_REGISTRY": "/config/apps.toml", "HOTPOT_INSTANCE_ID": "app-two",',
            ).replace(
                '"HOTPOT_DASHBOARD_DATA_DIR": "/data",',
                '"HOTPOT_APP_REGISTRY": "/config/apps.toml", "HOTPOT_DASHBOARD_DATA_DIR": "/data",',
            )
            docker.write_text(fake, encoding="utf-8")
            second = self._run(script, args)
            self.assertEqual(second.returncode, 0, second.stderr)
            self.assertIn("already appears to use HOTPOT_APP_REGISTRY", second.stdout)
            self.assertIn("--retire-legacy", second.stdout)

            retire_plan = self._run(
                script,
                [*args[:-1], "--retire-legacy"],
            )
            self.assertEqual(retire_plan.returncode, 0, retire_plan.stderr)
            self.assertIn("legacy-retirement plan", retire_plan.stdout)
            self.assertIn("PLAN ONLY", retire_plan.stdout)
            self.assertNotIn("legacy-admin-super-secret", retire_plan.stdout)

            retire = self._run(
                script,
                [*args[:-1], "--retire-legacy", "--apply"],
            )
            self.assertEqual(retire.returncode, 0, retire.stderr + retire.stdout)
            self.assertIn("Legacy fallback retirement completed", retire.stdout)

            retired_hotpot = hotpot_env.read_text(encoding="utf-8")
            self.assertNotIn("HOTPOT_PROFILES=", retired_hotpot)
            self.assertNotIn("HOTPOT_ADMIN_TOKEN=", retired_hotpot)
            self.assertNotIn("HOTPOT_SMTP_PASSWORD_FILE=", retired_hotpot)

            retired_dashboard = dashboard_env.read_text(encoding="utf-8")
            self.assertIn(
                "HOTPOT_APP_REGISTRY=/config/apps.toml", retired_dashboard
            )
            self.assertNotIn("HOTPOT_DASHBOARD_INSTANCES=", retired_dashboard)
            self.assertNotIn("HOTPOT_CLOUDFLARE_TARGETS=", retired_dashboard)
            self.assertNotIn("HOTPOT_ADMIN_TOKEN=", retired_dashboard)
            self.assertIn(
                "HOTPOT_DASHBOARD_TOKEN=viewer-super-secret",
                retired_dashboard,
            )
            retired_compose = compose.read_text(encoding="utf-8")
            self.assertNotIn("HOTPOT_INSTANCE_NAME:", retired_compose)
            self.assertNotIn("HOTPOT_PROFILES:", retired_compose)

            backups = list(
                (root / "hotpot-migration-backups").glob(
                    "*/migration-manifest.json"
                )
            )
            self.assertEqual(len(backups), 2)

    def test_retirement_refuses_to_run_before_registry_is_staged(self) -> None:
        root_repo = Path(__file__).resolve().parents[1]
        script = root_repo / "scripts" / "migrate_qnap_registry.py"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            compose, hotpot_env, dashboard_env, secrets_dir = self._fixture(root)
            docker = self._docker(root, compose, hotpot_env, dashboard_env, secrets_dir)
            result = self._run(
                script,
                [
                    "--compose", str(compose),
                    "--hotpot-env", str(hotpot_env),
                    "--dashboard-env", str(dashboard_env),
                    "--docker-bin", str(docker),
                    "--retire-legacy",
                    "--apply",
                ],
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(
                "requires an already staged app-registry deployment",
                result.stderr,
            )
            self.assertFalse((root / "hotpot-apps.toml").exists())

    def test_missing_referenced_shared_secret_fails_before_writes(self) -> None:
        root_repo = Path(__file__).resolve().parents[1]
        script = root_repo / "scripts" / "migrate_qnap_registry.py"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            compose, hotpot_env, dashboard_env, secrets_dir = self._fixture(
                root, missing_smtp_secret=True
            )
            docker = self._docker(root, compose, hotpot_env, dashboard_env, secrets_dir)
            before = compose.read_bytes()
            result = self._run(
                script,
                [
                    "--compose", str(compose),
                    "--hotpot-env", str(hotpot_env),
                    "--dashboard-env", str(dashboard_env),
                    "--docker-bin", str(docker),
                    "--apply",
                ],
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("Could not read legacy shared secret", result.stderr)
            self.assertEqual(compose.read_bytes(), before)
            self.assertFalse((root / "hotpot-apps.toml").exists())
            self.assertFalse((root / "hotpot-migration-backups").exists())


if __name__ == "__main__":
    unittest.main()
