from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from dashboard.secure_production import SecureProductionDashboard
from dashboard.security import ActionRateLimiter, SessionManager, secret_from_env
from dashboard.security_store import SecureEnforcementStore


class SecretFileTests(unittest.TestCase):
    def test_file_secret_takes_precedence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            secret_path = Path(tmp) / "secret"
            secret_path.write_text("from-file\n", encoding="utf-8")
            with patch.dict(
                os.environ,
                {
                    "TEST_HOTPOT_SECRET": "from-env",
                    "TEST_HOTPOT_SECRET_FILE": str(secret_path),
                },
                clear=False,
            ):
                self.assertEqual(
                    secret_from_env("TEST_HOTPOT_SECRET", required=True),
                    "from-file",
                )

    def test_secure_dashboard_loads_all_supported_file_secrets(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            admin = root / "admin"
            viewer = root / "viewer"
            cloudflare = root / "cloudflare"
            admin.write_text("collector-file\n", encoding="utf-8")
            viewer.write_text("viewer-file\n", encoding="utf-8")
            cloudflare.write_text("cf-file\n", encoding="utf-8")
            instances = [
                {"id": "one", "name": "One", "url": "http://127.0.0.1:18001"}
            ]
            targets = {
                "one": {"zone_id": "zone-one", "hosts": ["www.example.com"]}
            }
            with patch.dict(
                os.environ,
                {
                    "HOTPOT_DASHBOARD_INSTANCES": json.dumps(instances),
                    "HOTPOT_DASHBOARD_DATA_DIR": tmp,
                    "HOTPOT_ADMIN_TOKEN": "wrong-env-admin",
                    "HOTPOT_ADMIN_TOKEN_FILE": str(admin),
                    "HOTPOT_DASHBOARD_TOKEN": "wrong-env-viewer",
                    "HOTPOT_DASHBOARD_TOKEN_FILE": str(viewer),
                    "HOTPOT_CLOUDFLARE_ENFORCEMENT_ENABLED": "true",
                    "HOTPOT_CLOUDFLARE_API_TOKEN": "wrong-env-cf",
                    "HOTPOT_CLOUDFLARE_API_TOKEN_FILE": str(cloudflare),
                    "HOTPOT_CLOUDFLARE_TARGETS": json.dumps(targets),
                },
                clear=False,
            ):
                dashboard = SecureProductionDashboard()
                self.assertEqual(dashboard.hotpot_token, "collector-file")
                self.assertEqual(dashboard.dashboard_token, "viewer-file")
                self.assertEqual(dashboard.cloudflare.api_token, "cf-file")
                self.assertTrue(dashboard.cloudflare.configured)
                # Construction temporarily injects file-backed values only while
                # legacy constructors run, then restores the original environment.
                self.assertEqual(os.environ["HOTPOT_ADMIN_TOKEN"], "wrong-env-admin")
                self.assertEqual(
                    os.environ["HOTPOT_DASHBOARD_TOKEN"], "wrong-env-viewer"
                )
                self.assertEqual(
                    os.environ["HOTPOT_CLOUDFLARE_API_TOKEN"], "wrong-env-cf"
                )


class SessionTests(unittest.TestCase):
    def test_session_is_signed_expiring_and_csrf_bound(self) -> None:
        with patch.dict(
            os.environ,
            {"HOTPOT_DASHBOARD_SESSION_TIMEOUT_SECONDS": "3600"},
            clear=False,
        ):
            manager = SessionManager("viewer-token")
        token, context, csrf = manager.issue("hotpot")
        verified = manager.verify(token)
        self.assertIsNotNone(verified)
        assert verified is not None
        self.assertEqual(verified.username, "hotpot")
        self.assertEqual(verified.session_id, context.session_id)
        self.assertTrue(manager.verify_csrf(verified, csrf))
        self.assertFalse(manager.verify_csrf(verified, csrf + "x"))
        self.assertIsNone(manager.verify(token + "tampered"))

    def test_session_signing_secret_file_is_supported(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "session"
            path.write_text("session-file-key\n", encoding="utf-8")
            with patch.dict(
                os.environ,
                {"HOTPOT_DASHBOARD_SESSION_SECRET_FILE": str(path)},
                clear=False,
            ):
                first = SessionManager("viewer-token")
                token, _, _ = first.issue("hotpot")
                second = SessionManager("different-viewer-token")
                self.assertIsNotNone(second.verify(token))

    def test_action_rate_limiter_blocks_after_limit(self) -> None:
        with patch.dict(
            os.environ,
            {"HOTPOT_DASHBOARD_ACTION_RATE_LIMIT_PER_MINUTE": "2"},
            clear=False,
        ):
            limiter = ActionRateLimiter()
        self.assertTrue(limiter.check("session")[0])
        self.assertTrue(limiter.check("session")[0])
        allowed, retry = limiter.check("session")
        self.assertFalse(allowed)
        self.assertGreaterEqual(retry, 1)


class SecurityAuditTests(unittest.IsolatedAsyncioTestCase):
    async def test_dashboard_principal_and_session_are_persisted(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SecureEnforcementStore(Path(tmp), retention_days=90)
            await store.record_dashboard_action(
                event_type="dashboard_reconcile",
                message="Manual reconciliation",
                principal="hotpot",
                session_id="session-123",
                details={"http_status": 200},
            )
            rows = await store.audit_log(limit=10)
            self.assertEqual(rows[0]["principal"], "hotpot")
            self.assertEqual(rows[0]["session_id"], "session-123")
            self.assertEqual(rows[0]["source"], "dashboard")
            self.assertEqual(rows[0]["event_type"], "dashboard_reconcile")


if __name__ == "__main__":
    unittest.main()
