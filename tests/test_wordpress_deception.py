import json
import tempfile
import unittest
from pathlib import Path

from hotpot.wordpress_deception import (
    DeceptionSessions,
    WordPressPersona,
    tarpit_profile,
    velocity_severity_bonus,
)


class WordPressPersonaTests(unittest.TestCase):
    def test_persona_persists_and_renders_consistently(self):
        with tempfile.TemporaryDirectory() as tmp:
            data_dir = Path(tmp)
            first = WordPressPersona.load_or_create(data_dir)
            second = WordPressPersona.load_or_create(data_dir)
            self.assertEqual(first, second)
            self.assertTrue((data_dir / "wordpress-persona.json").exists())

            readme = first.render("wordpress-readme", "fallback")
            self.assertIn(first.wordpress_version, readme)
            root = json.loads(first.render("wordpress-rest-api", "{}"))
            self.assertEqual(root["name"], first.site_name)
            self.assertIn(first.canary_path, root["_links"]["help"][0]["href"])

    def test_rest_users_posts_and_theme_share_same_persona(self):
        with tempfile.TemporaryDirectory() as tmp:
            persona = WordPressPersona.load_or_create(Path(tmp))
            users = json.loads(persona.render("wordpress-rest-users", "[]"))
            posts = json.loads(persona.render("wordpress-rest-posts", "[]"))
            theme = persona.render("wordpress-theme-style", "")
            self.assertEqual(users[0]["id"], posts[0]["author"])
            self.assertIn(persona.theme, theme)
            self.assertIn(persona.wordpress_version, theme)


class DeceptionSessionTests(unittest.TestCase):
    def test_bait_discovery_then_followup_becomes_exploit_attempt(self):
        sessions = DeceptionSessions()
        discovered = sessions.observe(
            ip="203.0.113.9",
            fingerprint="first-path-fingerprint",
            path="/wp-content/plugins/wp-file-manager/readme.txt",
            rule_name="wordpress-bait-file-manager-readme",
            category="wordpress-vulnerability-bait",
        )
        followed = sessions.observe(
            ip="203.0.113.9",
            fingerprint="different-path-fingerprint",
            path="/wp-content/plugins/wp-file-manager/lib/php/connector.minimal.php",
            rule_name="wordpress-bait-file-manager-followup",
            category="wordpress-bait-followup",
        )
        self.assertEqual(discovered["session_id"], followed["session_id"])
        self.assertEqual(discovered["bait_stage"], "discovered")
        self.assertEqual(followed["bait_stage"], "exploit-attempt")
        self.assertTrue(followed["bait_followed"])
        self.assertEqual(followed["session_step"], 2)

    def test_unprimed_followup_is_only_interaction(self):
        sessions = DeceptionSessions()
        event = sessions.observe(
            ip="203.0.113.10",
            fingerprint="x",
            path="/wp-json/contact-form-7/v1/contact-forms/1/feedback",
            rule_name="wordpress-bait-contact-form-7-followup",
            category="wordpress-bait-followup",
        )
        self.assertEqual(event["bait_stage"], "interacted")
        self.assertFalse(event["bait_followed"])

    def test_canary_is_high_confidence_follow(self):
        sessions = DeceptionSessions()
        event = sessions.observe(
            ip="203.0.113.11",
            fingerprint="x",
            path="/wp-content/uploads/.cache/wp-maintenance.json",
            rule_name="wordpress-canary",
            category="wordpress-canary-followup",
        )
        self.assertEqual(event["bait_stage"], "canary-followed")
        self.assertTrue(event["bait_followed"])

    def test_velocity_increases_severity(self):
        sessions = DeceptionSessions()
        observation = None
        for index in range(8):
            observation = sessions.observe(
                ip="203.0.113.12",
                fingerprint=str(index),
                path=f"/wp-json/test-{index}",
                rule_name="wordpress-tree",
                category="wordpress-enumeration",
            )
        assert observation is not None
        self.assertEqual(observation["hits_10s"], 8)
        self.assertEqual(velocity_severity_bonus(observation), 2)

    def test_tarpit_profile_changes_with_behavior(self):
        normal = {
            "hits_10s": 1,
            "bait_stage": None,
        }
        aggressive = {
            "hits_10s": 8,
            "bait_stage": "exploit-attempt",
        }
        login = tarpit_profile(
            rule_name="wordpress-login",
            observation=normal,
            fingerprint="abc",
            base_initial=0.1,
            base_chunk_delay=0.1,
        )
        exploit = tarpit_profile(
            rule_name="wordpress-bait-file-manager-followup",
            observation=aggressive,
            fingerprint="abc",
            base_initial=0.1,
            base_chunk_delay=0.1,
        )
        self.assertEqual(login["style"], "slow-headers")
        self.assertEqual(exploit["style"], "burst-then-stall")
        self.assertGreater(exploit["chunk_delay"], login["chunk_delay"])


if __name__ == "__main__":
    unittest.main()
