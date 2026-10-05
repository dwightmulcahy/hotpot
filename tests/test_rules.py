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


if __name__ == "__main__":
    unittest.main()
