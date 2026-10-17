from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from hotpot.config import Settings, env_secret


class CoreSecretFileTests(unittest.TestCase):
    def test_file_value_takes_precedence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            secret = Path(tmp) / "token"
            secret.write_text("from-file\n", encoding="utf-8")
            with patch.dict(
                os.environ,
                {"EXAMPLE_SECRET": "from-env", "EXAMPLE_SECRET_FILE": str(secret)},
                clear=False,
            ):
                self.assertEqual(env_secret("EXAMPLE_SECRET"), "from-file")

    def test_settings_load_core_secrets_from_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            values = {
                "HOTPOT_ADMIN_TOKEN": "admin-file",
                "HOTPOT_COLLECTOR_TOKEN": "collector-file",
                "HOTPOT_POLICY_TOKEN": "policy-file",
                "HOTPOT_NOTIFY_WEBHOOK_BEARER": "webhook-file",
                "HOTPOT_SMTP_PASSWORD": "smtp-file",
            }
            env = {"HOTPOT_UPSTREAM": "http://example:8080"}
            for name, value in values.items():
                path = root / name.lower()
                path.write_text(value + "\n", encoding="utf-8")
                env[name] = "should-not-win"
                env[name + "_FILE"] = str(path)
            with patch.dict(os.environ, env, clear=False):
                settings = Settings.from_env()
            self.assertEqual(settings.admin_token, "admin-file")
            self.assertEqual(settings.collector_token, "collector-file")
            self.assertEqual(settings.policy_token, "policy-file")
            self.assertEqual(settings.notify_webhook_bearer, "webhook-file")
            self.assertEqual(settings.smtp_password, "smtp-file")

    def test_registry_controls_core_name_profiles_and_scoped_secret_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            collector = root / "collector"
            policy = root / "policy"
            collector.write_text("registry-read\n", encoding="utf-8")
            policy.write_text("registry-write\n", encoding="utf-8")
            registry = root / "apps.toml"
            registry.write_text(
                f"""
[[apps]]
id = "one"
name = "Registry One"
profiles = ["generic", "password_lab"]
[apps.dashboard]
url = "http://127.0.0.1:18001"
[apps.credentials]
collector_token_file = "{collector}"
policy_token_file = "{policy}"
""",
                encoding="utf-8",
            )
            with patch.dict(
                os.environ,
                {
                    "HOTPOT_UPSTREAM": "http://example:8080",
                    "HOTPOT_INSTANCE_ID": "one",
                    "HOTPOT_APP_REGISTRY": str(registry),
                    "HOTPOT_PROFILES": "wordpress",
                    "HOTPOT_INSTANCE_NAME": "",
                    "HOTPOT_COLLECTOR_TOKEN": "",
                    "HOTPOT_POLICY_TOKEN": "",
                },
                clear=True,
            ):
                settings = Settings.from_env()
        self.assertEqual(settings.instance_name, "Registry One")
        self.assertEqual(settings.enabled_profiles, ("generic", "password_lab"))
        self.assertEqual(settings.collector_token, "registry-read")
        self.assertEqual(settings.policy_token, "registry-write")

    def test_registry_mode_fails_when_core_instance_is_missing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            registry = Path(tmp) / "apps.toml"
            registry.write_text(
                """
[[apps]]
id = "one"
profiles = ["generic"]
[apps.dashboard]
url = "http://127.0.0.1:18001"
""",
                encoding="utf-8",
            )
            with patch.dict(
                os.environ,
                {
                    "HOTPOT_UPSTREAM": "http://example:8080",
                    "HOTPOT_INSTANCE_ID": "missing",
                    "HOTPOT_APP_REGISTRY": str(registry),
                },
                clear=True,
            ):
                with self.assertRaisesRegex(RuntimeError, "not present"):
                    Settings.from_env()

    def test_explicit_scoped_env_secret_overrides_registry_secret_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            registry_collector = root / "registry-collector"
            registry_policy = root / "registry-policy"
            registry_collector.write_text("registry-read\n", encoding="utf-8")
            registry_policy.write_text("registry-write\n", encoding="utf-8")
            registry = root / "apps.toml"
            registry.write_text(
                f"""
[[apps]]
id = "one"
profiles = ["generic"]
[apps.dashboard]
url = "http://127.0.0.1:18001"
[apps.credentials]
collector_token_file = "{registry_collector}"
policy_token_file = "{registry_policy}"
""",
                encoding="utf-8",
            )
            with patch.dict(
                os.environ,
                {
                    "HOTPOT_UPSTREAM": "http://example:8080",
                    "HOTPOT_INSTANCE_ID": "one",
                    "HOTPOT_APP_REGISTRY": str(registry),
                    "HOTPOT_COLLECTOR_TOKEN": "env-read",
                    "HOTPOT_POLICY_TOKEN": "env-write",
                },
                clear=True,
            ):
                settings = Settings.from_env()
        self.assertEqual(settings.collector_token, "env-read")
        self.assertEqual(settings.policy_token, "env-write")

    def test_unreadable_secret_file_fails_closed(self) -> None:
        with patch.dict(
            os.environ,
            {"BROKEN_SECRET_FILE": "/definitely/not/here"},
            clear=False,
        ):
            with self.assertRaises(RuntimeError):
                env_secret("BROKEN_SECRET")


if __name__ == "__main__":
    unittest.main()
