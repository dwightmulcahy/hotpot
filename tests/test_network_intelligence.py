from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from dashboard.network_intelligence import NetworkIntelligenceStore
from dashboard.production import PRODUCTION_HTML
from dashboard.runtime import Instance


class NetworkIntelligenceStoreTests(unittest.IsolatedAsyncioTestCase):
    async def test_persists_and_aggregates_asn_provider_country_intelligence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = NetworkIntelligenceStore(Path(tmp), retention_days=1)
            one = Instance("one", "One", "http://one")
            two = Instance("two", "Two", "http://two")

            await store.ingest(
                one,
                [
                    {
                        "id": 1,
                        "ts": "2020-01-01T00:00:00+00:00",
                        "client_ip": "8.8.8.8",
                        "path": "/.env",
                        "category": "secret",
                        "scanner": "scanner",
                        "action": "tarpit",
                        "severity": 5,
                        "escalation_level": 3,
                        "suppressed_before": 9,
                    },
                    {
                        "id": 2,
                        "ts": "2020-01-01T00:01:00+00:00",
                        "client_ip": "1.1.1.1",
                        "path": "/wp-admin/install.php",
                        "category": "wordpress-install",
                        "scanner": "scanner",
                        "action": "tarpit",
                        "severity": 2,
                        "escalation_level": 1,
                    },
                ],
                2,
            )
            await store.ingest(
                two,
                [
                    {
                        "id": 1,
                        "ts": "2020-01-01T00:02:00+00:00",
                        "client_ip": "8.8.4.4",
                        "path": "/.git/config",
                        "category": "git",
                        "scanner": "scanner",
                        "action": "tarpit",
                        "severity": 5,
                        "escalation_level": 4,
                        "suppressed_before": 24,
                    }
                ],
                1,
            )

            candidates = await store.network_enrichment_candidates("rev-a", 10)
            self.assertEqual(
                {row["identity_key"] for row in candidates},
                {"8.8.8.8", "8.8.4.4", "1.1.1.1"},
            )

            updated = await store.update_network_attributions(
                [
                    {
                        "identity_key": "8.8.8.8",
                        "client_ip": "8.8.8.8",
                        "revision": "rev-a",
                        "network": {
                            "asn": 15169,
                            "provider": "Google LLC",
                            "country_code": "US",
                            "country": "United States",
                            "city": "Mountain View",
                            "continent": "North America",
                            "enriched": True,
                        },
                    },
                    {
                        "identity_key": "8.8.4.4",
                        "client_ip": "8.8.4.4",
                        "revision": "rev-a",
                        "network": {
                            "asn": 15169,
                            "provider": "Google LLC",
                            "country_code": "US",
                            "country": "United States",
                            "city": None,
                            "continent": "North America",
                            "enriched": True,
                        },
                    },
                    {
                        "identity_key": "1.1.1.1",
                        "client_ip": "1.1.1.1",
                        "revision": "rev-a",
                        "network": {
                            "asn": 13335,
                            "provider": "Cloudflare, Inc.",
                            "country_code": "US",
                            "country": "United States",
                            "city": None,
                            "continent": "North America",
                            "enriched": True,
                        },
                    },
                ]
            )
            self.assertEqual(updated, 3)
            self.assertEqual(
                await store.network_enrichment_candidates("rev-a", 10), []
            )
            self.assertEqual(
                len(await store.network_enrichment_candidates("rev-b", 10)), 3
            )

            snapshot = await store.snapshot([])
            intel = snapshot["network_intelligence"]
            self.assertEqual(intel["attributed_attackers"], 3)
            self.assertFalse(intel["policy"]["asn_affects_score"])
            self.assertFalse(intel["policy"]["geography_affects_score"])

            google = next(row for row in intel["top_networks"] if row["asn"] == 15169)
            self.assertEqual(google["provider"], "Google LLC")
            self.assertEqual(google["attackers"], 2)
            self.assertEqual(google["hits"], 35)
            self.assertEqual(google["level3_plus"], 2)
            self.assertEqual(google["level4"], 1)
            self.assertEqual(
                {row["instance_name"] for row in google["top_apps"]},
                {"One", "Two"},
            )
            self.assertEqual(
                {row["category"] for row in google["top_categories"]},
                {"secret", "git"},
            )

            country = next(
                row for row in intel["top_countries"] if row["country_code"] == "US"
            )
            self.assertEqual(country["attackers"], 3)
            self.assertEqual(country["hits"], 36)

            detail = await store.network_snapshot(asn=15169)
            self.assertIsNotNone(detail)
            assert detail is not None
            self.assertEqual(detail["summary"]["attackers"], 2)
            self.assertEqual(detail["summary"]["hits"], 35)
            self.assertEqual(len(detail["attackers"]), 2)
            self.assertFalse(detail["policy"]["network_context_affects_score"])

            attacker = await store.attacker_snapshot("8.8.8.8")
            self.assertIsNotNone(attacker)
            assert attacker is not None
            self.assertEqual(attacker["lifetime"]["network"]["asn"], 15169)
            self.assertEqual(
                attacker["lifetime"]["network"]["provider"], "Google LLC"
            )

            result = await store.housekeeping(1)
            self.assertEqual(result["events_deleted"], 3)
            after = await store.attacker_snapshot("8.8.8.8")
            self.assertIsNotNone(after)
            assert after is not None
            self.assertEqual(after["hits"], 0)
            self.assertEqual(after["lifetime"]["network"]["asn"], 15169)

    def test_dashboard_surfaces_network_and_country_panels(self) -> None:
        self.assertIn("Top networks / ASNs", PRODUCTION_HTML)
        self.assertIn("Top countries", PRODUCTION_HTML)
        self.assertIn("network_intelligence", PRODUCTION_HTML)
        self.assertIn("/api/network?asn=", PRODUCTION_HTML)


if __name__ == "__main__":
    unittest.main()
