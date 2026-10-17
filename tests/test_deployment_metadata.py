from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from hotpot.config import Settings
from hotpot.deployment import deployment_snapshot


class DeploymentMetadataTests(unittest.TestCase):
    def _snapshot(self, env: dict[str, str]) -> dict:
        with patch.dict("os.environ", env, clear=True):
            settings = Settings.from_env()
            return deployment_snapshot(
                settings,
                version="v1.2.3",
                git_sha="abc123",
                build_date="2026-10-08T17:00:00Z",
            )

    def test_secret_values_are_never_emitted_and_sources_are_visible(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            secret = Path(directory) / "admin-token"
            secret.write_text("very-secret-admin-token\n", encoding="utf-8")
            snapshot = self._snapshot(
                {
                    "HOTPOT_UPSTREAM": "http://127.0.0.1:8088",
                    "HOTPOT_INSTANCE_ID": "monkeyhead",
                    "HOTPOT_INSTANCE_NAME": "Monkey Head Brewing",
                    "HOTPOT_ADMIN_TOKEN_FILE": str(secret),
                    "HOTPOT_SMTP_PASSWORD": "very-secret-smtp-password",
                }
            )
        encoded = json.dumps(snapshot, sort_keys=True)
        self.assertNotIn("very-secret-admin-token", encoded)
        self.assertNotIn("very-secret-smtp-password", encoded)
        self.assertEqual(snapshot["secret_sources"]["admin_token"], "file")
        self.assertEqual(snapshot["secret_sources"]["smtp_password"], "environment")
        self.assertEqual(snapshot["secret_sources"]["webhook_bearer"], "unset")

    def test_shared_fingerprint_ignores_instance_specific_wiring(self) -> None:
        first = self._snapshot(
            {
                "HOTPOT_UPSTREAM": "http://127.0.0.1:8088",
                "HOTPOT_INSTANCE_ID": "monkeyhead",
                "HOTPOT_INSTANCE_NAME": "Monkey Head Brewing",
                "HOTPOT_BIND": "127.0.0.1",
                "HOTPOT_PORT": "18088",
            }
        )
        second = self._snapshot(
            {
                "HOTPOT_UPSTREAM": "http://127.0.0.1:8080",
                "HOTPOT_INSTANCE_ID": "hvac",
                "HOTPOT_INSTANCE_NAME": "HVAC Dashboard",
                "HOTPOT_BIND": "127.0.0.1",
                "HOTPOT_PORT": "18080",
            }
        )
        self.assertNotEqual(first["config_fingerprint"], second["config_fingerprint"])
        self.assertEqual(
            first["shared_config_fingerprint"], second["shared_config_fingerprint"]
        )

    def test_global_policy_fingerprint_allows_instance_specific_security_to_differ(self) -> None:
        baseline = self._snapshot(
            {
                "HOTPOT_UPSTREAM": "http://127.0.0.1:8088",
                "HOTPOT_INSTANCE_ID": "one",
                "HOTPOT_PROFILES": "wordpress,secrets,generic",
                "HOTPOT_ALLOW_CIDRS": "10.0.0.0/8",
                "HOTPOT_CLIENT_IP_MODE": "direct",
            }
        )
        specialized = self._snapshot(
            {
                "HOTPOT_UPSTREAM": "http://127.0.0.1:9099",
                "HOTPOT_INSTANCE_ID": "two",
                "HOTPOT_PROFILES": "generic,password_lab,containers",
                "HOTPOT_ALLOW_CIDRS": "192.168.0.0/16",
                "HOTPOT_CLIENT_IP_MODE": "cloudflare",
                "HOTPOT_TRUSTED_PROXY_CIDRS": "127.0.0.1/32",
            }
        )
        self.assertEqual(
            baseline["global_policy_fingerprint"],
            specialized["global_policy_fingerprint"],
        )
        self.assertEqual(
            baseline["shared_config_fingerprint"],
            specialized["shared_config_fingerprint"],
        )
        self.assertNotEqual(
            baseline["runtime_fingerprint"], specialized["runtime_fingerprint"]
        )
        self.assertNotEqual(
            baseline["instance_fingerprint"], specialized["instance_fingerprint"]
        )

    def test_runtime_fingerprint_tracks_source_identity_configuration(self) -> None:
        direct = self._snapshot(
            {
                "HOTPOT_UPSTREAM": "http://127.0.0.1:8088",
                "HOTPOT_CLIENT_IP_MODE": "direct",
            }
        )
        cloudflare = self._snapshot(
            {
                "HOTPOT_UPSTREAM": "http://127.0.0.1:8088",
                "HOTPOT_CLIENT_IP_MODE": "cloudflare",
                "HOTPOT_TRUSTED_PROXY_CIDRS": "127.0.0.1/32",
            }
        )
        self.assertNotEqual(
            direct["runtime_fingerprint"], cloudflare["runtime_fingerprint"]
        )
        self.assertEqual(
            direct["global_policy_fingerprint"],
            cloudflare["global_policy_fingerprint"],
        )

    def test_compatibility_aliases_match_new_fingerprint_scopes(self) -> None:
        snapshot = self._snapshot(
            {
                "HOTPOT_UPSTREAM": "http://127.0.0.1:8088",
                "HOTPOT_INSTANCE_ID": "one",
            }
        )
        self.assertEqual(
            snapshot["config_fingerprint"], snapshot["instance_fingerprint"]
        )
        self.assertEqual(
            snapshot["shared_config_fingerprint"],
            snapshot["global_policy_fingerprint"],
        )
        self.assertEqual(snapshot["schema_version"], 2)

    def test_shared_fingerprint_detects_common_policy_drift(self) -> None:
        baseline = self._snapshot(
            {
                "HOTPOT_UPSTREAM": "http://127.0.0.1:8088",
                "HOTPOT_INSTANCE_ID": "one",
                "HOTPOT_TARPIT_MAX_CONCURRENT": "10",
            }
        )
        drifted = self._snapshot(
            {
                "HOTPOT_UPSTREAM": "http://127.0.0.1:8088",
                "HOTPOT_INSTANCE_ID": "one",
                "HOTPOT_TARPIT_MAX_CONCURRENT": "11",
            }
        )
        self.assertNotEqual(
            baseline["shared_config_fingerprint"],
            drifted["shared_config_fingerprint"],
        )


if __name__ == "__main__":
    unittest.main()
