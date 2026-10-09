from pathlib import Path
import unittest

from hotpot.rules import RuleEngine


class RuleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.engine = RuleEngine.load(Path("profiles"), ("wordpress", "secrets", "git", "php", "generic"))

    def test_wordpress_install_is_tarpit(self):
        rule = self.engine.match("/wp-admin/install.php", "GET")
        self.assertIsNotNone(rule)
        self.assertEqual(rule.action, "tarpit")

    def test_env_is_tarpit(self):
        rule = self.engine.match("/.env", "GET")
        self.assertIsNotNone(rule)
        self.assertEqual(rule.category, "secret-discovery")

    def test_normal_page_is_not_matched(self):
        self.assertIsNone(self.engine.match("/dashboard", "GET"))

    def test_phpmyadmin_regex(self):
        self.assertIsNotNone(self.engine.match("/phpmyadmin/index.php", "GET"))

    def test_wordpress_rest_api_is_emulated(self):
        rule = self.engine.match("/wp-json/", "GET")
        self.assertIsNotNone(rule)
        self.assertEqual(rule.name, "wordpress-rest-api")
        self.assertEqual(rule.status, 200)
        self.assertIn('"wp/v2"', rule.response)

    def test_wordpress_readme_is_emulated(self):
        rule = self.engine.match("/readme.html", "GET")
        self.assertIsNotNone(rule)
        self.assertEqual(rule.name, "wordpress-readme")
        self.assertIn("WordPress", rule.response)

    def test_file_manager_lure_advertises_old_version(self):
        rule = self.engine.match("/wp-content/plugins/wp-file-manager/readme.txt", "GET")
        self.assertIsNotNone(rule)
        self.assertEqual(rule.category, "wordpress-vulnerability-bait")
        self.assertIn("Stable tag: 6.8", rule.response)

    def test_contact_form_lure_advertises_old_version(self):
        rule = self.engine.match("/wp-content/plugins/contact-form-7/readme.txt", "GET")
        self.assertIsNotNone(rule)
        self.assertEqual(rule.category, "wordpress-vulnerability-bait")
        self.assertIn("Stable tag: 5.3.1", rule.response)

    def test_file_manager_followup_is_tarpitted(self):
        rule = self.engine.match(
            "/wp-content/plugins/wp-file-manager/lib/php/connector.minimal.php", "POST"
        )
        self.assertIsNotNone(rule)
        self.assertEqual(rule.name, "wordpress-bait-file-manager-followup")
        self.assertEqual(rule.action, "tarpit")
        self.assertEqual(rule.category, "wordpress-bait-followup")

    def test_unknown_plugin_readme_does_not_invent_plugin(self):
        rule = self.engine.match("/wp-content/plugins/random-plugin/readme.txt", "GET")
        self.assertIsNotNone(rule)
        self.assertEqual(rule.name, "wordpress-plugin-enumeration")
        self.assertEqual(rule.status, 404)


if __name__ == "__main__":
    unittest.main()
