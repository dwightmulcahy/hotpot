from pathlib import Path
import unittest

from hotpot.rules import RuleEngine
from hotpot.wordpress_deception import DeceptionSessions


ROOT = Path(__file__).resolve().parents[1]
PROFILES = (
    "spring",
    "containers",
    "devops",
    "observability",
    "cms",
    "appliances",
)


class ProfileJourneyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.rules = RuleEngine.load(ROOT / "profiles", PROFILES)

    def rule(self, path: str, method: str = "GET"):
        rule = self.rules.match(path, method)
        self.assertIsNotNone(rule, f"expected a rule for {method} {path}")
        return rule

    @staticmethod
    def observe(sessions: DeceptionSessions, rule, path: str, method: str = "GET"):
        return sessions.observe(
            actor_fingerprint="same-actor",
            request_fingerprint=f"{method}:{path}",
            path=path,
            rule_name=rule.name,
            category=rule.category,
            bait_id=rule.bait_id,
            bait_stage=rule.bait_stage,
        )

    def assert_followup(self, discovery_path: str, followup_path: str, followup_method: str = "GET"):
        sessions = DeceptionSessions()
        discovery = self.rule(discovery_path)
        first = self.observe(sessions, discovery, discovery_path)
        self.assertEqual(first["bait_stage"], "discovered")
        self.assertFalse(first["bait_followed"])

        followup = self.rule(followup_path, followup_method)
        second = self.observe(sessions, followup, followup_path, followup_method)
        self.assertEqual(second["session_id"], first["session_id"])
        self.assertEqual(second["bait_id"], first["bait_id"])
        self.assertTrue(second["bait_followed"])
        return second

    def test_spring_gateway_exploit_follows_discovery(self) -> None:
        result = self.assert_followup(
            "/actuator/gateway/routes",
            "/actuator/gateway/routes/internal-api",
            "POST",
        )
        self.assertEqual(result["bait_stage"], "exploit-attempt")

    def test_docker_exec_follows_api_discovery(self) -> None:
        result = self.assert_followup(
            "/_ping",
            "/v1.45/containers/web/exec",
            "POST",
        )
        self.assertEqual(result["bait_stage"], "exploit-attempt")

    def test_kubernetes_exec_follows_cluster_discovery(self) -> None:
        result = self.assert_followup(
            "/api/v1/nodes",
            "/api/v1/namespaces/default/pods/web/exec",
            "POST",
        )
        self.assertEqual(result["bait_stage"], "exploit-attempt")

    def test_jenkins_script_console_follows_discovery(self) -> None:
        result = self.assert_followup("/jenkins/api/json", "/script", "POST")
        self.assertEqual(result["bait_stage"], "exploit-attempt")

    def test_elasticsearch_write_follows_cluster_discovery(self) -> None:
        result = self.assert_followup("/_cluster/health", "/customers/_doc/42", "PUT")
        self.assertEqual(result["bait_stage"], "exploit-attempt")

    def test_f5_command_follows_login_discovery(self) -> None:
        result = self.assert_followup("/tmui/login.jsp", "/mgmt/tm/util/bash", "POST")
        self.assertEqual(result["bait_stage"], "exploit-attempt")

    def test_direct_exploit_without_discovery_is_not_marked_followed(self) -> None:
        sessions = DeceptionSessions()
        rule = self.rule("/mgmt/tm/util/bash", "POST")
        result = self.observe(sessions, rule, "/mgmt/tm/util/bash", "POST")
        self.assertEqual(result["bait_stage"], "interacted")
        self.assertFalse(result["bait_followed"])

    def test_profile_bait_metadata_is_loaded(self) -> None:
        rule = self.rule("/actuator/gateway/routes")
        self.assertEqual(rule.bait_id, "spring-cloud-gateway")
        self.assertEqual(rule.bait_stage, "discovered")


if __name__ == "__main__":
    unittest.main()
