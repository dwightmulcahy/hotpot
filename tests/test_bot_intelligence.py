from __future__ import annotations

import tempfile
import time
import unittest
from pathlib import Path

from hotpot.bot_intelligence import IPverseBotIntelligence


def _payload() -> dict:
    return {
        "fetched_at": time.time(),
        "feeds": {
            "crawler": {
                "services": {
                    "Googlebot": {
                        "user_agent_patterns": ["*Googlebot*"],
                        "ip_list_authoritative": True,
                        "ipv4": ["66.249.64.0/19"],
                        "ipv6": ["2001:4860:4801::/48"],
                    },
                    "ClaudeBot": {
                        "user_agent_patterns": ["*ClaudeBot*"],
                        "ip_list_authoritative": True,
                        "ipv4": ["192.0.2.0/24"],
                        "ipv6": [],
                    },
                    "LegacyCrawler": {
                        "user_agent_patterns": ["*LegacyCrawler*"],
                        "ip_list_authoritative": False,
                        "ipv4": [],
                        "ipv6": [],
                    },
                }
            },
            "monitor": {
                "services": {
                    "ExampleMonitor": {
                        "user_agent_patterns": ["*ExampleMonitor*"],
                        "ip_list_authoritative": True,
                        "ipv4": ["203.0.113.0/24"],
                        "ipv6": [],
                    }
                }
            },
        },
    }


class IPverseBotIntelligenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.intelligence = IPverseBotIntelligence(Path(self.tmp.name))
        self.intelligence._apply_payload(_payload())

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_authoritative_claim_inside_range_is_verified(self) -> None:
        result = self.intelligence.identify(
            "66.249.64.10", "Mozilla/5.0 (compatible; Googlebot/2.1)"
        )
        self.assertEqual(result.identity, "Googlebot")
        self.assertEqual(result.category, "crawler")
        self.assertTrue(result.verified)
        self.assertTrue(result.claim_verified)
        self.assertFalse(result.spoofed)

    def test_authoritative_claim_outside_range_is_spoofed(self) -> None:
        result = self.intelligence.identify(
            "198.51.100.25", "Mozilla/5.0 ClaudeBot/1.0"
        )
        self.assertEqual(result.claimed_identity, "ClaudeBot")
        self.assertFalse(result.verified)
        self.assertFalse(result.claim_verified)
        self.assertTrue(result.spoofed)
        self.assertTrue(result.authoritative_claim)

    def test_known_ip_is_attributed_even_without_matching_user_agent(self) -> None:
        result = self.intelligence.identify("203.0.113.22", "curl/8.5.0")
        self.assertEqual(result.ip_identity, "ExampleMonitor")
        self.assertEqual(result.identity, "ExampleMonitor")
        self.assertEqual(result.category, "monitor")
        self.assertTrue(result.verified)
        self.assertIsNone(result.claimed_identity)
        self.assertFalse(result.spoofed)

    def test_mismatched_known_source_and_claim_records_both(self) -> None:
        result = self.intelligence.identify(
            "66.249.64.10", "Mozilla/5.0 ClaudeBot/1.0"
        )
        self.assertEqual(result.ip_identity, "Googlebot")
        self.assertEqual(result.claimed_identity, "ClaudeBot")
        self.assertTrue(result.verified)
        self.assertTrue(result.spoofed)
        fields = result.event_fields()
        self.assertEqual(fields["bot_identity"], "Googlebot")
        self.assertEqual(fields["bot_claimed_identity"], "ClaudeBot")
        self.assertTrue(fields["bot_spoofed"])

    def test_non_authoritative_claim_is_not_called_spoofed(self) -> None:
        result = self.intelligence.identify(
            "198.51.100.99", "LegacyCrawler/4.2"
        )
        self.assertEqual(result.claimed_identity, "LegacyCrawler")
        self.assertFalse(result.authoritative_claim)
        self.assertFalse(result.spoofed)

    def test_ipv6_prefixes_are_supported(self) -> None:
        result = self.intelligence.identify(
            "2001:4860:4801::123", "Googlebot/2.1"
        )
        self.assertEqual(result.identity, "Googlebot")
        self.assertTrue(result.claim_verified)

    def test_status_reports_feed_shape(self) -> None:
        status = self.intelligence.status()
        self.assertTrue(status["loaded"])
        self.assertEqual(status["source"], "ipverse/bot-ip-blocks")
        self.assertEqual(status["services"], 4)
        self.assertEqual(status["ipv4_prefixes"], 3)
        self.assertEqual(status["ipv6_prefixes"], 1)
        self.assertEqual(status["ua_patterns"], 4)


if __name__ == "__main__":
    unittest.main()
