from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone

from dashboard.cloudflare_enforcement import (
    IP_ACCESS_PROVIDER,
    CloudflareConfig,
    CloudflareEnforcer,
    CloudflareTarget,
)
from dashboard.enforcement_plan import build_enforcement_plan
from dashboard.cloudflare_enforcement_legacy import CloudflareEnforcementError


class FakeAccessEnforcer(CloudflareEnforcer):
    def __init__(self, config):
        super().__init__(config, client=object())
        self.access_rules: dict[str, dict[str, dict]] = {}
        self.created = 0
        self.patched = 0
        self.deleted = 0
        self.custom_waf_calls = 0

    async def _request(self, method, path, *, payload=None, allow_404=False):
        if "/rulesets" in path:
            self.custom_waf_calls += 1
            raise AssertionError(f"long IP block unexpectedly touched custom WAF: {path}")

        prefix = "/zones/"
        self.assert_path(path, prefix)
        zone_id = path[len(prefix) :].split("/", 1)[0]
        rules = self.access_rules.setdefault(zone_id, {})
        base = f"/zones/{zone_id}/firewall/access_rules/rules"

        if method == "GET" and path.startswith(base + "?"):
            return 200, {"success": True, "result": list(rules.values())}

        if method == "POST" and path == base:
            self.created += 1
            rule_id = f"access-{self.created}"
            item = {
                "id": rule_id,
                "mode": payload["mode"],
                "configuration": dict(payload["configuration"]),
                "notes": payload.get("notes", ""),
            }
            rules[rule_id] = item
            return 200, {"success": True, "result": dict(item)}

        if path.startswith(base + "/"):
            rule_id = path.rsplit("/", 1)[-1]
            if method == "GET":
                item = rules.get(rule_id)
                if item is None and allow_404:
                    return 404, None
                if item is None:
                    raise AssertionError(f"missing fake rule {rule_id}")
                return 200, {"success": True, "result": dict(item)}
            if method == "PATCH":
                self.patched += 1
                item = rules[rule_id]
                item.update(
                    {
                        "mode": payload["mode"],
                        "configuration": dict(payload["configuration"]),
                        "notes": payload.get("notes", ""),
                    }
                )
                return 200, {"success": True, "result": dict(item)}
            if method == "DELETE":
                self.deleted += 1
                rules.pop(rule_id, None)
                return 200, {"success": True, "result": {"id": rule_id}}

        raise AssertionError((method, path, payload, allow_404))

    @staticmethod
    def assert_path(path: str, prefix: str) -> None:
        if not path.startswith(prefix):
            raise AssertionError(path)


class CloudflareFreePlanEnforcementTests(unittest.IsolatedAsyncioTestCase):
    def config(self) -> CloudflareConfig:
        return CloudflareConfig(
            enabled=True,
            api_token="token",
            targets={
                "one": CloudflareTarget(
                    "one", "zone123456", ("www.example.com",)
                )
            },
        )

    @staticmethod
    def recommendation(
        recommendation_id: str,
        expires_at: str,
        target_value: str = "34.14.99.143",
    ) -> dict:
        return {
            "recommendation_id": recommendation_id,
            "actor_key": target_value,
            "action": "recommend_long_block",
            "target_type": "ip",
            "target_value": target_value,
            "enforcement_expires_at": expires_at,
            "evidence": {"instance_ids": ["one"]},
        }

    async def test_ip_access_capability_probe_uses_zone_access_rules_endpoint(self) -> None:
        enforcer = FakeAccessEnforcer(self.config())
        result = await enforcer.inspect_ip_access_capability("zone123456")
        self.assertTrue(result["accessible"])
        self.assertEqual(
            result["permission"], "Firewall Services Write"
        )

    async def test_ip_access_403_explains_required_cloudflare_permission(self) -> None:
        class ForbiddenEnforcer(CloudflareEnforcer):
            async def _request(self, method, path, *, payload=None, allow_404=False):
                raise CloudflareEnforcementError(
                    "Cloudflare API returned HTTP 403: Authentication error"
                )

        enforcer = ForbiddenEnforcer(self.config(), client=object())
        with self.assertRaisesRegex(
            CloudflareEnforcementError,
            "Zone Firewall Services Edit",
        ):
            await enforcer.inspect_ip_access_capability("zone123456")

    async def test_long_block_uses_ip_access_without_custom_waf_slot(self) -> None:
        expires = (datetime.now(timezone.utc) + timedelta(days=7)).isoformat()
        enforcer = FakeAccessEnforcer(self.config())
        rules = await enforcer.apply(self.recommendation("rec-one", expires))

        self.assertEqual(enforcer.created, 1)
        self.assertEqual(enforcer.custom_waf_calls, 0)
        self.assertEqual(rules[0]["provider"], IP_ACCESS_PROVIDER)
        self.assertTrue(rules[0]["zone_wide"])
        self.assertEqual(rules[0]["target_value"], "34.14.99.143")
        self.assertEqual(rules[0]["ruleset_id"], "")

    async def test_duplicate_long_block_reuses_rule_and_extends_expiry(self) -> None:
        now = datetime.now(timezone.utc)
        first_expiry = (now + timedelta(days=4)).isoformat()
        second_expiry = (now + timedelta(days=7)).isoformat()
        enforcer = FakeAccessEnforcer(self.config())

        first = await enforcer.apply(self.recommendation("rec-first", first_expiry))
        second = await enforcer.apply(self.recommendation("rec-second", second_expiry))

        self.assertEqual(enforcer.created, 1)
        self.assertEqual(enforcer.patched, 1)
        self.assertEqual(first[0]["rule_id"], second[0]["rule_id"])
        self.assertTrue(second[0]["reused"])

        # Expiring the older recommendation must not delete a block extended by a
        # newer recommendation sharing the same Cloudflare IP Access rule.
        self.assertEqual(await enforcer.remove(first), [])
        self.assertEqual(enforcer.deleted, 0)
        self.assertEqual(len(enforcer.access_rules["zone123456"]), 1)

        self.assertEqual(await enforcer.remove(second), [])
        self.assertEqual(enforcer.deleted, 1)
        self.assertEqual(enforcer.access_rules["zone123456"], {})

    async def test_ipv6_long_block_uses_ip6_configuration(self) -> None:
        expires = (datetime.now(timezone.utc) + timedelta(days=7)).isoformat()
        enforcer = FakeAccessEnforcer(self.config())
        rules = await enforcer.apply(
            self.recommendation("rec-v6", expires, "2001:db8::1234")
        )
        current = enforcer.access_rules["zone123456"][rules[0]["rule_id"]]
        self.assertEqual(current["configuration"]["target"], "ip6")
        self.assertEqual(current["configuration"]["value"], "2001:db8::1234")

    async def test_reconcile_verifies_ip_access_rule(self) -> None:
        expires = (datetime.now(timezone.utc) + timedelta(days=7)).isoformat()
        enforcer = FakeAccessEnforcer(self.config())
        recommendation = self.recommendation("rec-reconcile", expires)
        rules = await enforcer.apply(recommendation)
        report = await enforcer.reconcile(
            [{**recommendation, "enforcement_rules": rules}]
        )
        self.assertEqual(report["status"], "healthy")
        self.assertEqual(report["counts"]["healthy"], 1)
        self.assertEqual(
            report["recommendations"][0]["rules"][0]["provider"],
            IP_ACCESS_PROVIDER,
        )

    def test_plan_shows_zone_wide_ip_access_scope(self) -> None:
        expires = (datetime.now(timezone.utc) + timedelta(days=7)).isoformat()
        plan = build_enforcement_plan(
            self.recommendation("rec-plan", expires), self.config()
        )
        self.assertEqual(plan["provider"], IP_ACCESS_PROVIDER)
        self.assertEqual(plan["zones"][0]["provider"], IP_ACCESS_PROVIDER)
        self.assertEqual(plan["zones"][0]["scope"], "zone")
        self.assertIsNone(plan["zones"][0]["expression"])

    def test_status_explains_long_block_provider(self) -> None:
        status = self.config().public_status()
        self.assertEqual(
            status["long_block_provider"], "Cloudflare zone IP Access Rules"
        )
        self.assertFalse(status["long_blocks_consume_custom_rule_slots"])


if __name__ == "__main__":
    unittest.main()
