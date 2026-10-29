from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from dashboard.auto_response import (
    AutoResponseConfig,
    AutoResponseController,
    AutoResponseStateStore,
    evaluate_candidate,
)


def recommendation(
    *,
    action: str = "recommend_challenge",
    confidence: str = "high",
    target: str = "45.138.12.26",
    level: int = 3,
    hits: int = 20,
    apps: int = 2,
    categories: int = 3,
    severity: int = 4,
    high_severity: int = 3,
    high_level: int = 3,
) -> dict:
    return {
        "recommendation_id": "rec-1",
        "actor_key": target,
        "action": action,
        "confidence": confidence,
        "target_type": "ip",
        "target_value": target,
        "evidence": {
            "source_type": "ip",
            "global_level": level,
            "observed_hits": hits,
            "app_count": apps,
            "category_count": categories,
            "max_severity": severity,
            "high_severity_events": high_severity,
            "high_level_events": high_level,
        },
    }


class AutoResponsePolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.config = AutoResponseConfig()

    def test_shadow_mode_marks_high_confidence_challenge_eligible(self) -> None:
        result = evaluate_candidate(
            recommendation(), self.config, mode="shadow", bot_check_available=True
        )
        self.assertTrue(result["eligible"])
        self.assertGreaterEqual(result["signal_count"], 2)

    def test_challenge_only_mode_keeps_blocks_manual(self) -> None:
        result = evaluate_candidate(
            recommendation(action="recommend_block", level=4),
            self.config,
            mode="challenge",
            bot_check_available=True,
        )
        self.assertFalse(result["eligible"])
        self.assertIn("challenge-only", result["reason"])

    def test_active_mode_allows_strong_l4_block(self) -> None:
        result = evaluate_candidate(
            recommendation(action="recommend_block", level=4),
            self.config,
            mode="active",
            bot_check_available=True,
        )
        self.assertTrue(result["eligible"])
        self.assertGreaterEqual(result["signal_count"], 3)

    def test_long_block_is_never_automatic(self) -> None:
        result = evaluate_candidate(
            recommendation(action="recommend_long_block", level=4),
            self.config,
            mode="active",
            bot_check_available=True,
        )
        self.assertFalse(result["eligible"])
        self.assertIn("manual approval", result["reason"])

    def test_verified_bot_is_excluded(self) -> None:
        result = evaluate_candidate(
            recommendation(),
            self.config,
            mode="active",
            verified_bot=True,
            bot_check_available=True,
        )
        self.assertFalse(result["eligible"])
        self.assertIn("verified bot", result["reason"])

    def test_bot_check_failure_fails_closed(self) -> None:
        result = evaluate_candidate(
            recommendation(),
            self.config,
            mode="active",
            verified_bot=False,
            bot_check_available=False,
        )
        self.assertFalse(result["eligible"])
        self.assertIn("unavailable", result["reason"])

    def test_policy_suppression_blocks_automation(self) -> None:
        result = evaluate_candidate(
            recommendation(),
            self.config,
            mode="active",
            policy_suppressed=True,
            bot_check_available=True,
        )
        self.assertFalse(result["eligible"])
        self.assertIn("suppressed", result["reason"])

    def test_non_global_ip_is_not_automated(self) -> None:
        result = evaluate_candidate(
            recommendation(target="192.168.1.10"),
            self.config,
            mode="active",
            bot_check_available=True,
        )
        self.assertFalse(result["eligible"])
        self.assertIn("globally routable", result["reason"])

    def test_insufficient_independent_signals_are_rejected(self) -> None:
        result = evaluate_candidate(
            recommendation(
                hits=2,
                apps=1,
                categories=1,
                severity=2,
                high_severity=0,
                high_level=0,
            ),
            self.config,
            mode="active",
            bot_check_available=True,
        )
        self.assertFalse(result["eligible"])
        self.assertIn("required", result["reason"])


class AutoResponseControllerTests(unittest.IsolatedAsyncioTestCase):
    async def test_mode_rejection_is_retained_and_audited(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            class Store:
                def __init__(self, path: Path):
                    self.path = path
                    self.audit = []

                async def record_dashboard_action(self, **kwargs):
                    self.audit.append(kwargs)

            class ResponsePolicy:
                enabled = True
                active_window_hours = 24

            class Cloudflare:
                configured = True
                can_remove = True

            class Dashboard:
                def __init__(self, path: Path):
                    self.store = Store(path)
                    self.response_policy = ResponsePolicy()
                    self.cloudflare = Cloudflare()

                async def _maybe_reconcile_cloudflare(self, *, force=False):
                    return {
                        "status": "healthy",
                        "rollback_cleanup_pending": 1,
                        "orphaned": 0,
                    }

            path = Path(tmp) / "dashboard.sqlite3"
            dashboard = Dashboard(path)
            controller = AutoResponseController(dashboard)

            with self.assertRaisesRegex(
                ValueError, "rollback cleanup jobs are pending"
            ):
                await controller.set_mode("challenge", principal="hotpot")

            # Background state changes must not erase the operator-facing rejection.
            controller.last_circuit = {
                "status": "standby",
                "reason": "no pending recommendations",
            }
            status = await controller.status()
            self.assertEqual(status["circuit_breaker"]["status"], "standby")
            rejection = status["last_mode_change_rejection"]
            self.assertIsNotNone(rejection)
            assert rejection is not None
            self.assertEqual(rejection["attempted_mode"], "challenge")
            self.assertIn("rollback cleanup jobs are pending", rejection["reason"])
            self.assertEqual(dashboard.store.audit[0]["event_type"], "auto_response_mode_rejected")
            self.assertEqual(dashboard.store.audit[0]["status"], "rejected")


class AutoResponseStateStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "dashboard.sqlite3"
        conn = sqlite3.connect(self.path)
        conn.execute(
            """
            CREATE TABLE events (
                attacker_key TEXT,
                ts TEXT NOT NULL,
                payload_json TEXT NOT NULL
            )
            """
        )
        conn.commit()
        conn.close()
        self.store = AutoResponseStateStore(self.path)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_mode_override_is_persistent(self) -> None:
        initial = self.store.mode_state("off")
        self.assertEqual(initial["mode"], "off")
        self.assertEqual(initial["source"], "environment-default")
        self.store.set_mode("shadow")
        saved = self.store.mode_state("off")
        self.assertEqual(saved["mode"], "shadow")
        self.assertEqual(saved["source"], "dashboard-override")

    def test_verified_bot_is_detected_from_event_payload(self) -> None:
        conn = sqlite3.connect(self.path)
        conn.execute(
            "INSERT INTO events(attacker_key, ts, payload_json) VALUES (?, ?, ?)",
            (
                "45.138.12.26",
                datetime.now(timezone.utc).isoformat(),
                json.dumps(
                    {
                        "bot_verified": True,
                        "bot_identity": "Googlebot",
                    },
                    separators=(",", ":"),
                ),
            ),
        )
        conn.commit()
        conn.close()
        status = self.store.verified_bot_status(
            "45.138.12.26", active_window_hours=24
        )
        self.assertTrue(status["available"])
        self.assertTrue(status["verified"])

    def test_action_counts_include_applied_and_failed_attempts(self) -> None:
        rec = recommendation()
        self.store.record_decision(
            rec,
            mode="active",
            decision="applied",
            reason="ok",
            signals=["volume", "multiple-apps"],
        )
        counts = self.store.action_counts()
        self.assertEqual(counts["last_hour"], 1)
        self.assertEqual(counts["last_24_hours"], 1)


if __name__ == "__main__":
    unittest.main()
