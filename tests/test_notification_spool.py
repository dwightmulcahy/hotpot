from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from hotpot.notification_spool import NotificationSpool


class NotificationSpoolTests(unittest.IsolatedAsyncioTestCase):
    async def test_spool_persists_deduplicates_and_completes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            event = {
                "attacker_key": "8.8.8.8",
                "client_ip": "8.8.8.8",
                "escalation_level": 4,
                "path": "/.env",
            }
            spool = NotificationSpool(Path(tmp), retry_seconds=10)
            first = await spool.enqueue(event, claimed=False, error="queue full")
            again = await spool.enqueue(event, claimed=False, error="queue full")
            self.assertEqual(first, again)

            reopened = NotificationSpool(Path(tmp), retry_seconds=10)
            due = await reopened.due()
            self.assertEqual(len(due), 1)
            self.assertFalse(due[0]["claimed"])
            self.assertEqual(due[0]["event"]["attacker_key"], "8.8.8.8")

            await reopened.mark_claimed(due[0]["id"])
            await reopened.mark_done(due[0]["id"], status="sent")
            self.assertEqual(await reopened.due(), [])
            state = await reopened.snapshot()
            self.assertEqual(state["pending"], 0)
            self.assertEqual(state["sent"], 1)


if __name__ == "__main__":
    unittest.main()
