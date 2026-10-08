from __future__ import annotations

import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from hotpot.policy import RuntimePolicyStore, snapshot_revision


class RuntimePolicyTests(unittest.TestCase):
    def test_rejects_default_route_allowlists(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = RuntimePolicyStore(Path(tmp), instance_id="one")
            entries = [
                {
                    "policy_id": "p1",
                    "kind": "allow_cidr",
                    "value": "0.0.0.0/0",
                    "reason": "too broad",
                }
            ]
            with self.assertRaisesRegex(ValueError, "default-route"):
                store.apply_snapshot(
                    {
                        "schema_version": 1,
                        "instance_id": "one",
                        "entries": entries,
                    }
                )

    def test_snapshot_is_atomic_reloadable_and_revision_checked(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)
            store = RuntimePolicyStore(
                path,
                instance_id="one",
                bootstrap_allow_cidrs=("10.0.0.10",),
            )
            entries = [
                {
                    "policy_id": "allow-office",
                    "kind": "allow_cidr",
                    "value": "192.0.2.25",
                    "reason": "operator exception",
                    "notes": "temporary test",
                    "created_by": "hotpot",
                    "created_at": datetime.now(timezone.utc).isoformat(),
                    "expires_at": None,
                }
            ]
            revision = snapshot_revision("one", entries)
            result = store.apply_snapshot(
                {
                    "schema_version": 1,
                    "instance_id": "one",
                    "revision": revision,
                    "entries": entries,
                }
            )
            self.assertEqual(result["revision"], revision)
            self.assertEqual(store.allow_match("192.0.2.25")["policy_id"], "allow-office")
            self.assertEqual(result["bootstrap_allow_cidrs"], ["10.0.0.10/32"])
            reloaded = RuntimePolicyStore(path, instance_id="one")
            self.assertEqual(reloaded.revision, revision)
            self.assertIsNotNone(reloaded.allow_match("192.0.2.25"))

            with self.assertRaisesRegex(ValueError, "revision"):
                store.apply_snapshot(
                    {
                        "schema_version": 1,
                        "instance_id": "one",
                        "revision": "bad",
                        "entries": entries,
                    }
                )

    def test_expiration_and_suppression_matches(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            now = datetime.now(timezone.utc)
            entries = [
                {
                    "policy_id": "expired",
                    "kind": "allow_cidr",
                    "value": "198.51.100.8/32",
                    "expires_at": (now - timedelta(minutes=1)).isoformat(),
                },
                {
                    "policy_id": "actor",
                    "kind": "suppress_actor",
                    "value": "203.0.113.9",
                    "reason": "known scanner",
                    "expires_at": (now + timedelta(hours=1)).isoformat(),
                },
                {
                    "policy_id": "scanner",
                    "kind": "suppress_scanner",
                    "value": "nuclei",
                    "expires_at": None,
                },
            ]
            store = RuntimePolicyStore(Path(tmp), instance_id="one")
            store.apply_snapshot(
                {"schema_version": 1, "instance_id": "one", "entries": entries}
            )
            self.assertIsNone(store.allow_match("198.51.100.8", now=now))
            self.assertEqual(
                store.suppression_match(actor_key="203.0.113.9", now=now)["policy_id"],
                "actor",
            )
            self.assertEqual(
                store.suppression_match(
                    actor_key="other", scanner_family="nuclei", now=now
                )["policy_id"],
                "scanner",
            )
            self.assertEqual(store.status()["expired_entries"], 1)


if __name__ == "__main__":
    unittest.main()
