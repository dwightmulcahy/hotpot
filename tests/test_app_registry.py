from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from dashboard.app_registry import (
    load_app_registry,
    parse_app_registry,
    registry_from_environment,
)


VALID = """
[[apps]]
id = "app-one"
name = "App One"
profiles = ["wordpress", "generic", "generic"]

[apps.dashboard]
url = "http://127.0.0.1:18081/"

[apps.deployment]
service = "security-gateway-one"

[apps.cloudflare]
zone_id = "zone-one"
hosts = ["WWW.Example.COM.", "api.example.com", "www.example.com"]

[apps.credentials]
collector_token_file = "/run/secrets/app-one/collector_token"
policy_token_file = "/run/secrets/app-one/policy_token"

[[apps]]
id = "password-lab"
profiles = ["generic", "password_lab"]

[apps.dashboard]
url = "https://password.internal:18443"
"""


class AppRegistryTests(unittest.TestCase):
    def test_registry_normalizes_and_preserves_per_app_configuration(self) -> None:
        registry = parse_app_registry(VALID, source="test.toml")
        self.assertEqual(registry.source, "test.toml")
        self.assertEqual(len(registry.apps), 2)

        one = registry.by_id()["app-one"]
        self.assertEqual(one.name, "App One")
        self.assertEqual(one.url, "http://127.0.0.1:18081")
        self.assertEqual(one.profiles, ("wordpress", "generic"))
        self.assertEqual(one.service, "security-gateway-one")
        self.assertEqual(one.cloudflare.zone_id, "zone-one")
        self.assertEqual(
            one.cloudflare.hosts,
            ("api.example.com", "www.example.com"),
        )
        self.assertEqual(
            one.credentials.collector_token_file,
            "/run/secrets/app-one/collector_token",
        )
        self.assertEqual(
            one.credentials.policy_token_file,
            "/run/secrets/app-one/policy_token",
        )

        password = registry.by_id()["password-lab"]
        self.assertEqual(password.name, "password-lab")
        self.assertEqual(password.profiles, ("generic", "password_lab"))
        self.assertIsNone(password.service)
        self.assertIsNone(password.cloudflare)

    def test_registry_can_load_from_explicit_path_or_environment(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "apps.toml"
            path.write_text(VALID, encoding="utf-8")
            self.assertEqual(load_app_registry(path).apps[0].instance_id, "app-one")
            with patch.dict(os.environ, {"HOTPOT_APP_REGISTRY": str(path)}, clear=False):
                loaded = load_app_registry()
            self.assertEqual(loaded.source, str(path))
            self.assertEqual([app.instance_id for app in loaded.apps], ["app-one", "password-lab"])

    def test_registry_rejects_invalid_toml_and_missing_apps(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "not valid TOML"):
            parse_app_registry("[[apps]")
        with self.assertRaisesRegex(RuntimeError, "at least one"):
            parse_app_registry("title = 'empty'")

    def test_registry_rejects_duplicate_or_invalid_ids(self) -> None:
        duplicate = """
[[apps]]
id = "same"
[apps.dashboard]
url = "http://one"

[[apps]]
id = "same"
[apps.dashboard]
url = "http://two"
"""
        with self.assertRaisesRegex(RuntimeError, "Duplicate app id"):
            parse_app_registry(duplicate)

        invalid = """
[[apps]]
id = "Not Valid"
[apps.dashboard]
url = "http://one"
"""
        with self.assertRaisesRegex(RuntimeError, "Invalid app id"):
            parse_app_registry(invalid)

    def test_registry_rejects_unsafe_or_incomplete_dashboard_urls(self) -> None:
        for url in ("localhost:8080", "ftp://example.com", "http://user:pass@example.com"):
            raw = f"""
[[apps]]
id = "one"
[apps.dashboard]
url = "{url}"
"""
            with self.subTest(url=url), self.assertRaises(RuntimeError):
                parse_app_registry(raw)

    def test_registry_rejects_incomplete_cloudflare_configuration(self) -> None:
        missing_zone = """
[[apps]]
id = "one"
[apps.dashboard]
url = "http://one"
[apps.cloudflare]
hosts = ["one.example.com"]
"""
        with self.assertRaisesRegex(RuntimeError, "zone_id"):
            parse_app_registry(missing_zone)

        missing_hosts = """
[[apps]]
id = "one"
[apps.dashboard]
url = "http://one"
[apps.cloudflare]
zone_id = "zone-one"
"""
        with self.assertRaisesRegex(RuntimeError, "hosts"):
            parse_app_registry(missing_hosts)

    def test_registry_rejects_hostname_urls_paths_and_blank_profiles(self) -> None:
        bad_host = """
[[apps]]
id = "one"
[apps.dashboard]
url = "http://one"
[apps.cloudflare]
zone_id = "zone-one"
hosts = ["https://one.example.com/path"]
"""
        with self.assertRaisesRegex(RuntimeError, "invalid Cloudflare hostname"):
            parse_app_registry(bad_host)

        bad_profile = """
[[apps]]
id = "one"
profiles = ["generic", ""]
[apps.dashboard]
url = "http://one"
"""
        with self.assertRaisesRegex(RuntimeError, "profiles"):
            parse_app_registry(bad_profile)

    def test_registry_rejects_incomplete_relative_or_reused_credentials(self) -> None:
        cases = (
            (
                """
[[apps]]
id = "one"
[apps.dashboard]
url = "http://one"
[apps.credentials]
collector_token_file = "/run/secrets/collector"
""",
                "policy_token_file",
            ),
            (
                """
[[apps]]
id = "one"
[apps.dashboard]
url = "http://one"
[apps.credentials]
collector_token_file = "relative/collector"
policy_token_file = "/run/secrets/policy"
""",
                "absolute path",
            ),
            (
                """
[[apps]]
id = "one"
[apps.dashboard]
url = "http://one"
[apps.credentials]
collector_token_file = "/run/secrets/same"
policy_token_file = "/run/secrets/same"
""",
                "must differ",
            ),
        )
        for raw, message in cases:
            with self.subTest(message=message), self.assertRaisesRegex(
                RuntimeError, message
            ):
                parse_app_registry(raw)

    def test_missing_registry_file_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            missing = Path(directory) / "missing.toml"
            with self.assertRaisesRegex(RuntimeError, "Could not read app registry"):
                load_app_registry(missing)

    def test_environment_loader_preserves_legacy_configuration(self) -> None:
        legacy_instances = '[{"id":"one","name":"One","url":"http://127.0.0.1:18001"}]'
        legacy_targets = '{"one":{"zone_id":"zone-one","hosts":["WWW.Example.COM"]}}'
        with patch.dict(
            os.environ,
            {
                "HOTPOT_APP_REGISTRY": "",
                "HOTPOT_DASHBOARD_INSTANCES": legacy_instances,
                "HOTPOT_CLOUDFLARE_TARGETS": legacy_targets,
            },
            clear=False,
        ):
            registry = registry_from_environment()
        self.assertEqual(registry.source, "legacy-environment")
        app = registry.apps[0]
        self.assertEqual(app.instance_id, "one")
        self.assertEqual(app.cloudflare.zone_id, "zone-one")
        self.assertEqual(app.cloudflare.hosts, ("www.example.com",))

    def test_explicit_registry_takes_precedence_over_legacy_environment(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "apps.toml"
            path.write_text(VALID, encoding="utf-8")
            with patch.dict(
                os.environ,
                {
                    "HOTPOT_APP_REGISTRY": str(path),
                    "HOTPOT_DASHBOARD_INSTANCES": "not-json",
                    "HOTPOT_CLOUDFLARE_TARGETS": "not-json",
                },
                clear=False,
            ):
                registry = registry_from_environment()
        self.assertEqual(registry.source, str(path))
        self.assertEqual(registry.apps[0].instance_id, "app-one")


if __name__ == "__main__":
    unittest.main()
