from __future__ import annotations

import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from dashboard.campaigns import CampaignAnalyzer
from dashboard.runtime import CentralStore, Instance


class CampaignCorrelationTests(unittest.IsolatedAsyncioTestCase):
    async def test_distributed_fingerprint_activity_forms_one_campaign(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = CentralStore(root)
            one = Instance("one", "One", "http://one")
            two = Instance("two", "Two", "http://two")
            now = datetime.now(timezone.utc)

            def event(event_id, actor, minute, path):
                return {
                    "id": event_id,
                    "ts": (now + timedelta(minutes=minute)).isoformat(),
                    "client_ip": actor,
                    "attacker_key": actor,
                    "method": "GET",
                    "path": path,
                    "category": "secret-discovery",
                    "action": "tarpit",
                    "scanner": "Nuclei",
                    "scanner_family": "nuclei",
                    "fingerprint": "fp-shared-campaign",
                    "severity": 4,
                    "escalation_level": 3,
                    "attacker_score": 30,
                    "suppressed_before": 0,
                    # Network context is intentionally irrelevant to campaign keys.
                    "country_code": "US",
                    "asn": 64500,
                }

            await store.ingest(
                one,
                [
                    event(1, "8.8.8.8", -20, "/.env"),
                    event(2, "1.1.1.1", -18, "/.env.backup"),
                    event(3, "9.9.9.9", -15, "/config/.env"),
                ],
                3,
            )
            await store.ingest(
                two,
                [
                    event(1, "8.8.8.8", -12, "/.env"),
                    event(2, "1.1.1.1", -10, "/.env.local"),
                    event(3, "9.9.9.9", -8, "/config/.env"),
                ],
                3,
            )

            with patch.dict(
                "os.environ",
                {
                    "HOTPOT_CAMPAIGN_LOOKBACK_HOURS": "24",
                    "HOTPOT_CAMPAIGN_WINDOW_MINUTES": "60",
                    "HOTPOT_CAMPAIGN_MIN_ACTORS": "2",
                    "HOTPOT_CAMPAIGN_MIN_HITS": "5",
                },
            ):
                analyzer = CampaignAnalyzer(root)
            campaigns = await analyzer.analyze()
            self.assertEqual(len(campaigns), 1)
            campaign = campaigns[0]
            self.assertEqual(campaign["actor_count"], 3)
            self.assertEqual(campaign["app_count"], 2)
            self.assertEqual(campaign["hits"], 6)
            self.assertEqual(campaign["persisted_events"], 6)
            self.assertEqual(campaign["scoring_effect"], "none")
            self.assertFalse(campaign["network_geography_used"])
            self.assertIn("fp-shared-campaign", campaign["fingerprints"])

    async def test_single_actor_noise_is_not_promoted_to_campaign(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = CentralStore(root)
            instance = Instance("one", "One", "http://one")
            now = datetime.now(timezone.utc)
            events = [
                {
                    "id": i,
                    "ts": (now - timedelta(minutes=i)).isoformat(),
                    "client_ip": "8.8.8.8",
                    "attacker_key": "8.8.8.8",
                    "method": "GET",
                    "path": "/wp-login.php",
                    "category": "wordpress",
                    "scanner": "scanner",
                    "scanner_family": "scanner",
                    "fingerprint": "one-actor",
                    "severity": 3,
                    "escalation_level": 3,
                    "attacker_score": 20,
                }
                for i in range(1, 7)
            ]
            await store.ingest(instance, events, 6)
            analyzer = CampaignAnalyzer(root)
            self.assertEqual(await analyzer.analyze(), [])


if __name__ == "__main__":
    unittest.main()
