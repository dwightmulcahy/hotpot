import asyncio
import tempfile
import unittest
from pathlib import Path

from hotpot.store import IntelligenceStore


class StoreTests(unittest.TestCase):
    def test_persistent_attacker_history_and_snapshot(self):
        with tempfile.TemporaryDirectory() as td:
            async def run():
                store = IntelligenceStore(Path(td))
                event = {
                    "client_ip": "203.0.113.7",
                    "method": "GET",
                    "path": "/wp-admin/install.php",
                    "profile": "wordpress",
                    "rule": "wordpress-install",
                    "category": "wordpress-install",
                    "action": "tarpit",
                    "scanner": "WPScan",
                    "scanner_family": "wordpress-scanner",
                    "fingerprint": "abc123",
                    "severity": 3,
                }
                await store.record(event, score=3, escalation_level=1)
                await store.record(event, score=6, escalation_level=2)
                state = await store.state_for("203.0.113.7")
                self.assertEqual(state.hits, 2)
                self.assertEqual(state.score, 6)
                self.assertEqual(state.escalation_level, 2)
                snapshot = await store.dashboard_snapshot()
                self.assertEqual(snapshot["events"], 2)
                self.assertEqual(snapshot["unique_ips"], 1)
                history = await store.attacker_history("203.0.113.7")
                self.assertEqual(len(history["events"]), 2)
                self.assertEqual(history["attacker"]["hits"], 2)
            asyncio.run(run())

    def test_notification_claim_is_persistent_and_level_aware(self):
        with tempfile.TemporaryDirectory() as td:
            async def run():
                store = IntelligenceStore(Path(td))
                self.assertTrue(await store.claim_notification("203.0.113.9", 3, 3600))
                self.assertFalse(await store.claim_notification("203.0.113.9", 3, 3600))
                # A higher level alerts immediately even during the cooldown.
                self.assertTrue(await store.claim_notification("203.0.113.9", 4, 3600))
            asyncio.run(run())

    def test_cleanup_removes_old_events_and_stale_attackers(self):
        with tempfile.TemporaryDirectory() as td:
            async def run():
                store = IntelligenceStore(Path(td))
                event = {
                    "client_ip": "203.0.113.10", "method": "GET", "path": "/.env",
                    "category": "secret-discovery", "action": "tarpit", "severity": 4,
                }
                await store.record(event, score=4, escalation_level=1)
                # Backdate both durable records to make them eligible for cleanup.
                with store._connection() as conn:
                    conn.execute("UPDATE events SET ts = '2000-01-01T00:00:00+00:00'")
                    conn.execute("UPDATE attackers SET last_seen = '2000-01-01T00:00:00+00:00'")
                result = await store.cleanup(30, 90)
                self.assertEqual(result["events_deleted"], 1)
                self.assertEqual(result["attackers_deleted"], 1)
                snapshot = await store.dashboard_snapshot()
                self.assertEqual(snapshot["events"], 0)
                self.assertEqual(snapshot["unique_ips"], 0)
            asyncio.run(run())


if __name__ == "__main__":
    unittest.main()
