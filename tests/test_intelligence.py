import unittest

from hotpot.intelligence import actor_fingerprint, classify, escalation_for


class IntelligenceTests(unittest.TestCase):
    def test_wpscan_is_identified(self):
        result = classify("WPScan v3.8.27", "wordpress-enumeration", "GET", "/wp-json/")
        self.assertEqual(result.scanner, "WPScan")
        self.assertEqual(result.scanner_family, "wordpress-scanner")
        self.assertEqual(len(result.fingerprint), 16)

    def test_fingerprint_ignores_tool_version(self):
        a = classify("Nuclei - v3.1.0", "admin-probe", "GET", "/server-status")
        b = classify("Nuclei - v3.2.9", "admin-probe", "GET", "/server-status")
        self.assertEqual(a.fingerprint, b.fingerprint)

    def test_actor_fingerprint_is_path_independent_and_version_stable(self):
        first = actor_fingerprint(
            actor_key="203.0.113.9",
            user_agent="WPScan v3.8.27",
            scanner_family="wordpress-scanner",
            accept="*/*",
            accept_language="en-US,en;q=0.9",
            accept_encoding="gzip, deflate",
            http_version="HTTP/1.1",
        )
        second = actor_fingerprint(
            actor_key="203.0.113.9",
            user_agent="WPScan v3.9.1",
            scanner_family="wordpress-scanner",
            accept="*/*",
            accept_language="en-US,en;q=0.9",
            accept_encoding="gzip, deflate",
            http_version="HTTP/1.1",
        )
        self.assertEqual(first, second)
        self.assertEqual(len(first), 20)

    def test_actor_fingerprint_separates_clients_behind_same_address(self):
        wpscan = actor_fingerprint(
            actor_key="203.0.113.10",
            user_agent="WPScan v3.8.27",
            scanner_family="wordpress-scanner",
            accept="*/*",
            http_version="HTTP/1.1",
        )
        curl = actor_fingerprint(
            actor_key="203.0.113.10",
            user_agent="curl/8.5.0",
            scanner_family="scripted-client",
            accept="*/*",
            http_version="HTTP/1.1",
        )
        self.assertNotEqual(wpscan, curl)

    def test_repeat_offender_escalates_and_is_bounded(self):
        result = escalation_for(
            prior_hits=19,
            prior_score=58,
            severity=5,
            base_seconds=20,
            max_escalated_seconds=45,
        )
        self.assertEqual(result.level, 4)
        self.assertTrue(result.force_tarpit)
        self.assertEqual(result.tarpit_seconds, 45)
        self.assertEqual(result.score, 63)

    def test_first_low_severity_hit_does_not_force_tarpit(self):
        result = escalation_for(
            prior_hits=0,
            prior_score=0,
            severity=2,
            base_seconds=20,
            max_escalated_seconds=60,
        )
        self.assertEqual(result.level, 1)
        self.assertFalse(result.force_tarpit)


if __name__ == "__main__":
    unittest.main()
