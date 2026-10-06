import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from dashboard.durability import DurableGlobalStore
from dashboard.runtime import Instance
from hotpot.durable_store import SourceIdentityStore
from hotpot.network import CLOUDFLARE_WORKER_SHARED_IP, ClientIPResolver


class CloudflareWorkerResolverTests(unittest.TestCase):
    def test_cross_zone_worker_uses_zone_actor_key(self):
        resolver = ClientIPResolver("cloudflare", ("127.0.0.1/32",))
        identity = resolver.resolve(
            "127.0.0.1",
            {
                "CF-Connecting-IP": CLOUDFLARE_WORKER_SHARED_IP,
                "CF-Worker": "Scanner.Example.COM.",
            },
        )
        self.assertEqual(identity.client_ip, CLOUDFLARE_WORKER_SHARED_IP)
        self.assertEqual(identity.actor_key, "cf-worker:scanner.example.com")
        self.assertEqual(identity.source_type, "cloudflare-worker")
        self.assertEqual(identity.worker_zone, "scanner.example.com")
        self.assertEqual(identity.source, "cf-worker")

    def test_cross_zone_worker_without_zone_isolated_as_unknown(self):
        resolver = ClientIPResolver("cloudflare", ("127.0.0.1/32",))
        identity = resolver.resolve(
            "127.0.0.1",
            {"CF-Connecting-IP": CLOUDFLARE_WORKER_SHARED_IP},
        )
        self.assertEqual(identity.actor_key, "cf-worker:unknown")
        self.assertEqual(identity.source_type, "cloudflare-worker")
        self.assertIsNone(identity.worker_zone)

    def test_untrusted_peer_cannot_spoof_worker_identity(self):
        resolver = ClientIPResolver("cloudflare", ("127.0.0.1/32",))
        identity = resolver.resolve(
            "198.51.100.10",
            {
                "CF-Connecting-IP": CLOUDFLARE_WORKER_SHARED_IP,
                "CF-Worker": "scanner.example.com",
            },
        )
        self.assertEqual(identity.client_ip, "198.51.100.10")
        self.assertEqual(identity.actor_key, "198.51.100.10")
        self.assertEqual(identity.source_type, "ip")
        self.assertFalse(identity.trusted_proxy)


class WorkerAwareLocalStoreTests(unittest.IsolatedAsyncioTestCase):
    async def test_attacker_state_uses_actor_key_but_event_keeps_network_ip(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = SourceIdentityStore(Path(tmp))
            event = {
                "client_ip": CLOUDFLARE_WORKER_SHARED_IP,
                "attacker_key": "cf-worker:scanner.example.com",
                "source_type": "cloudflare-worker",
                "worker_zone": "scanner.example.com",
                "method": "GET",
                "path": "/wp-admin/install.php?step=1",
                "category": "wordpress-install",
                "severity": 3,
            }
            await store.record(event, score=3, escalation_level=1)

            actor = await store.state_for("cf-worker:scanner.example.com")
            shared_ip = await store.state_for(CLOUDFLARE_WORKER_SHARED_IP)
            self.assertEqual(actor.hits, 1)
            self.assertEqual(shared_ip.hits, 0)

            conn = sqlite3.connect(store.path)
            conn.row_factory = sqlite3.Row
            try:
                row = conn.execute("SELECT ip, details_json FROM events").fetchone()
            finally:
                conn.close()
            self.assertEqual(row["ip"], CLOUDFLARE_WORKER_SHARED_IP)
            details = json.loads(row["details_json"])
            self.assertEqual(details["attacker_key"], "cf-worker:scanner.example.com")
            self.assertEqual(details["worker_zone"], "scanner.example.com")


class WorkerAwareGlobalScoringTests(unittest.IsolatedAsyncioTestCase):
    async def test_same_shared_ip_different_worker_zones_score_separately(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = DurableGlobalStore(Path(tmp), retention_days=90)
            instance = Instance("one", "One", "http://one")
            await store.ingest(
                instance,
                [
                    {
                        "id": 1,
                        "ts": "2026-10-06T18:00:00+00:00",
                        "client_ip": CLOUDFLARE_WORKER_SHARED_IP,
                        "attacker_key": "cf-worker:a.example",
                        "source_type": "cloudflare-worker",
                        "worker_zone": "a.example",
                        "path": "/wp-admin/install.php?step=1",
                        "category": "wordpress-install",
                        "severity": 3,
                        "escalation_level": 1,
                    },
                    {
                        "id": 2,
                        "ts": "2026-10-06T18:01:00+00:00",
                        "client_ip": CLOUDFLARE_WORKER_SHARED_IP,
                        "attacker_key": "cf-worker:b.example",
                        "source_type": "cloudflare-worker",
                        "worker_zone": "b.example",
                        "path": "/.env",
                        "category": "secret",
                        "severity": 5,
                        "escalation_level": 1,
                    },
                ],
                2,
            )

            snapshot = await store.snapshot([])
            identities = {row["identity_key"] for row in snapshot["top_offenders"]}
            self.assertIn("cf-worker:a.example", identities)
            self.assertIn("cf-worker:b.example", identities)
            self.assertNotIn(CLOUDFLARE_WORKER_SHARED_IP, identities)

            a = await store.attacker_snapshot("cf-worker:a.example")
            b = await store.attacker_snapshot("cf-worker:b.example")
            self.assertEqual(a["hits"], 1)
            self.assertEqual(b["hits"], 1)
            self.assertEqual(a["client_ip"], CLOUDFLARE_WORKER_SHARED_IP)
            self.assertEqual(a["worker_zone"], "a.example")
            self.assertEqual(a["lifetime"]["lifetime_hits"], 1)
            self.assertEqual(b["lifetime"]["lifetime_hits"], 1)


if __name__ == "__main__":
    unittest.main()
