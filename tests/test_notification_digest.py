from __future__ import annotations

import sqlite3
import tempfile
import unittest
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from hotpot.digest_notifications import DigestAwareNotifier
from hotpot.notification_spool import NotificationSpool
from hotpot.runtime_components import ResilientSourceStore


class NotificationDigestTests(unittest.IsolatedAsyncioTestCase):
    async def test_suppressed_actor_alerts_become_one_durable_digest(self) -> None:
        with tempfile.TemporaryDirectory() as directory, patch.dict(
            "os.environ", {"HOTPOT_NOTIFY_DIGEST_SECONDS": "60"}, clear=False
        ):
            root = Path(directory)
            store = ResilientSourceStore(root)
            self.assertTrue(await store.claim_notification("34.62.82.165", 4, 3600))
            self.assertFalse(await store.claim_notification("34.62.82.165", 4, 3600))
            self.assertFalse(await store.claim_notification("34.62.82.165", 4, 3600))
            self.assertIsNotNone(store.notification_digest)
            self.assertEqual(await store.notification_digest.pending_count(), 1)

            digest_path = root / "notification-digest.sqlite3"
            with closing(sqlite3.connect(digest_path)) as conn:
                with conn:
                    conn.execute(
                        "UPDATE notification_digest SET due_at=? WHERE status='pending'",
                        ((datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat(),),
                    )

            spool = NotificationSpool(root, retry_seconds=60)
            jobs = await spool.due(limit=10)
            digest = next(job for job in jobs if job.get("job_source") == "digest")
            self.assertLess(digest["id"], 0)
            self.assertTrue(digest["claimed"])
            self.assertEqual(digest["event"]["digest_count"], 2)
            self.assertEqual(digest["event"]["attacker_key"], "34.62.82.165")

            await spool.mark_done(digest["id"])
            self.assertEqual(await spool.digest.pending_count(), 0)

            # A later cooldown window can create another digest for the same actor/level.
            self.assertFalse(await store.claim_notification("34.62.82.165", 4, 3600))
            self.assertEqual(await store.notification_digest.pending_count(), 1)

    def test_digest_email_explains_suppression_without_changing_response(self) -> None:
        event = {
            "event": "notification_digest",
            "attacker_key": "34.62.82.165",
            "client_ip": "34.62.82.165",
            "escalation_level": 4,
            "digest_count": 43,
            "digest_first_seen": "2026-10-08T14:00:00+00:00",
            "digest_last_seen": "2026-10-08T14:15:00+00:00",
            "digest_window_seconds": 900,
            "category": "repeated-activity",
        }
        text = DigestAwareNotifier._plain_text(event)
        html = DigestAwareNotifier._html_email(event)
        self.assertIn("43 repeated alert(s)", text)
        self.assertIn("first qualifying alert immediately", text)
        self.assertIn("43", html)
        self.assertIn("does not change Hotpot scoring", html)


if __name__ == "__main__":
    unittest.main()
