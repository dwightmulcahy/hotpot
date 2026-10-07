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
            self.assertEqual(settings.notify_webhook_bearer, "webhook-file")
            self.assertEqual(settings.smtp_password, "smtp-file")

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
