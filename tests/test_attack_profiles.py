from pathlib import Path
import unittest

from hotpot.intelligence import classify
from hotpot.rules import RuleEngine


ROOT = Path(__file__).resolve().parents[1]
PROFILES = (
    "spring",
    "containers",
    "devops",
    "observability",
    "cms",
    "appliances",
)


class ExpandedAttackProfileTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.rules = RuleEngine.load(ROOT / "profiles", PROFILES)

    def match(self, path: str, method: str = "GET"):
        rule = self.rules.match(path, method)
        self.assertIsNotNone(rule, f"expected a rule for {method} {path}")
        return rule

    def test_spring_actuator_and_gateway_write(self) -> None:
        self.assertEqual(self.match("/actuator/env").name, "spring-actuator-sensitive")
        self.assertEqual(
            self.match("/actuator/gateway/routes/demo", "POST").name,
            "spring-cloud-gateway-write",
        )

    def test_container_discovery_and_exec(self) -> None:
        self.assertEqual(
            self.match("/v1.45/containers/json").name,
            "docker-api-discovery",
        )
        self.assertEqual(
            self.match("/api/v1/namespaces/default/pods/web/exec", "POST").name,
            "kubernetes-pod-exec",
        )

    def test_devops_high_signal_paths(self) -> None:
        self.assertEqual(self.match("/script", "POST").name, "jenkins-script-console")
        self.assertEqual(self.match("/.npmrc").name, "package-registry-credentials")
        self.assertEqual(self.match("/terraform.tfstate").name, "terraform-state")

    def test_observability_paths(self) -> None:
        self.assertEqual(self.match("/_cluster/health").name, "elasticsearch-cluster")
        self.assertEqual(self.match("/customers/_search", "POST").name, "elasticsearch-search")
        self.assertEqual(self.match("/api/v1/status/config").name, "prometheus-discovery")

    def test_cms_paths(self) -> None:
        self.assertEqual(self.match("/administrator/").name, "joomla-admin")
        self.assertEqual(self.match("/user/login").name, "drupal-login")
        self.assertEqual(self.match("/app/etc/env.php").name, "magento-env")
        self.assertEqual(
            self.match("/index.php?option=com_users").name,
            "joomla-component-probe",
        )

    def test_appliance_paths(self) -> None:
        self.assertEqual(self.match("/remote/login").name, "fortinet-ssl-vpn")
        self.assertEqual(self.match("/tmui/login.jsp").name, "f5-bigip-login")
        self.assertEqual(
            self.match("/mgmt/tm/util/bash", "POST").name,
            "f5-bigip-command",
        )
        self.assertEqual(
            self.match("/global-protect/login.esp").name,
            "paloalto-globalprotect",
        )

    def test_high_signal_rce_categories_reach_max_base_severity(self) -> None:
        rule = self.match("/mgmt/tm/util/bash", "POST")
        result = classify("curl/8.5.0", rule.category, "POST", "/mgmt/tm/util/bash")
        self.assertEqual(result.severity, 5)

    def test_normal_application_route_is_not_caught(self) -> None:
        self.assertIsNone(self.rules.match("/api/v1/orders", "GET"))
        self.assertIsNone(self.rules.match("/about", "GET"))


if __name__ == "__main__":
    unittest.main()
