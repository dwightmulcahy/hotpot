from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone
from dashboard.cloudflare_enforcement import (
    IP_ACCESS_PROVIDER,
    POOL_PROVIDER,
    CloudflareConfig,
    CloudflareEnforcer,
    CloudflareTarget,
)
from dashboard.enforcement_plan import build_enforcement_plan


class FakeFreePlanEnforcer(CloudflareEnforcer):
    def __init__(self, config):
        super().__init__(config, client=object())
        self.zone_rules: dict[str, list[dict]] = {}
        self.access_rules: dict[tuple[str, str], dict[str, dict]] = {}
        self.created_waf = 0
        self.created_access = 0
        self.patched_waf = 0
        self.patched_access = 0
        self.deleted_waf = 0
        self.deleted_access = 0

    def _rules(self, zone_id: str) -> list[dict]:
        return self.zone_rules.setdefault(zone_id, [])

    @staticmethod
    def _copy_rules(rules: list[dict]) -> list[dict]:
        return [dict(row) for row in rules]

    async def _request(self, method, path, *, payload=None, allow_404=False):
        if path.startswith("/zones/") and "/rulesets/" in path:
            parts = path.split("/")
            zone_id = parts[2]
            rules = self._rules(zone_id)
            ruleset_id = f"ruleset-{zone_id}"

            if method == "GET" and path.endswith(
                "/rulesets/phases/http_request_firewall_custom/entrypoint"
            ):
                return 200, {
                    "success": True,
                    "result": {
                        "id": ruleset_id,
                        "rules": self._copy_rules(rules),
                    },
                }

            base = f"/zones/{zone_id}/rulesets/{ruleset_id}/rules"
            if method == "POST" and path == base:
                self.created_waf += 1
                row = {
                    "id": f"waf-{self.created_waf}",
                    "ref": payload["ref"],
                    "action": payload["action"],
                    "expression": payload["expression"],
                    "description": payload.get("description", ""),
                    "enabled": payload.get("enabled", True),
                }
                position = payload.get("position") or {}
                before = position.get("before")
                if before:
                    index = next(
                        (
                            idx
                            for idx, current in enumerate(rules)
                            if current.get("id") == before
                        ),
                        len(rules),
                    )
                    rules.insert(index, row)
                elif before == "":
                    rules.insert(0, row)
                else:
                    rules.append(row)
                return 200, {
                    "success": True,
                    "result": {
                        "id": ruleset_id,
                        "rules": self._copy_rules(rules),
                    },
                }

            if path.startswith(base + "/"):
                rule_id = path.rsplit("/", 1)[-1]
                current = next(
                    (row for row in rules if row.get("id") == rule_id), None
                )
                if method == "PATCH":
                    if current is None:
                        raise AssertionError(f"missing WAF rule {rule_id}")
                    self.patched_waf += 1
                    current.update(
                        {
                            "ref": payload["ref"],
                            "action": payload["action"],
                            "expression": payload["expression"],
                            "description": payload.get("description", ""),
                            "enabled": payload.get("enabled", True),
                        }
                    )
                    position = payload.get("position") or {}
                    before = position.get("before")
                    if before is not None:
                        rules.remove(current)
                        if before == "":
                            rules.insert(0, current)
                        else:
                            index = next(
                                (
                                    idx
                                    for idx, row in enumerate(rules)
                                    if row.get("id") == before
                                ),
                                len(rules),
                            )
                            rules.insert(index, current)
                    return 200, {
                        "success": True,
                        "result": dict(current),
                    }
                if method == "DELETE":
                    self.deleted_waf += 1
                    if current is not None:
                        rules.remove(current)
                    return 200, {"success": True, "result": {}}

        if "/firewall/access_rules/rules" in path:
            parts = path.split("/")
            if parts[1] == "accounts":
                scope, resource_id = "account", parts[2]
            elif parts[1] == "zones":
                scope, resource_id = "zone", parts[2]
            else:
                raise AssertionError(path)
            rules = self.access_rules.setdefault((scope, resource_id), {})
            base = f"/{parts[1]}/{resource_id}/firewall/access_rules/rules"

            if method == "GET" and "?" in path:
                return 200, {
                    "success": True,
                    "result": [dict(row) for row in rules.values()],
                }
            if method == "POST" and path == base:
                self.created_access += 1
                rule_id = f"access-{self.created_access}"
                row = {
                    "id": rule_id,
                    "mode": payload["mode"],
                    "configuration": dict(payload["configuration"]),
                    "notes": payload.get("notes", ""),
                }
                rules[rule_id] = row
                return 200, {"success": True, "result": dict(row)}
            if path.startswith(base + "/"):
                rule_id = path.rsplit("/", 1)[-1]
                current = rules.get(rule_id)
                if method == "GET":
                    if current is None and allow_404:
                        return 404, None
                    if current is None:
                        raise AssertionError(f"missing access rule {rule_id}")
                    return 200, {"success": True, "result": dict(current)}
                if method == "PATCH":
                    if current is None:
                        raise AssertionError(f"missing access rule {rule_id}")
                    self.patched_access += 1
                    current.update(
                        {
                            "mode": payload["mode"],
                            "configuration": dict(payload["configuration"]),
                            "notes": payload.get("notes", ""),
                        }
                    )
                    return 200, {"success": True, "result": dict(current)}
                if method == "DELETE":
                    self.deleted_access += 1
                    rules.pop(rule_id, None)
                    return 200, {"success": True, "result": {}}

        raise AssertionError((method, path, payload, allow_404))


class CloudflareFreePlanEnforcementTests(unittest.IsolatedAsyncioTestCase):
    def config(self) -> CloudflareConfig:
        return CloudflareConfig(
            enabled=True,
            api_token="token",
            targets={
                "one": CloudflareTarget(
                    "one", "zone123456", ("www.example.com",)
                ),
                "two": CloudflareTarget(
                    "two", "zone123456", ("api.example.com",)
                ),
            },
            account_id="account123",
        )

    @staticmethod
    def recommendation(
        recommendation_id: str,
        action: str,
        target_value: str,
        expires_at: str,
    ) -> dict:
        return {
            "recommendation_id": recommendation_id,
            "actor_key": target_value,
            "action": action,
            "target_type": "ip",
            "target_value": target_value,
            "duration_hours": 6 if action == "recommend_challenge" else 24,
            "enforcement_expires_at": expires_at,
            "evidence": {"instance_ids": ["one"]},
        }

    async def test_challenges_share_one_waf_rule_and_expire_by_membership(self) -> None:
        now = datetime.now(timezone.utc)
        enforcer = FakeFreePlanEnforcer(self.config())
        first = await enforcer.apply(
            self.recommendation(
                "rec-one",
                "recommend_challenge",
                "34.14.99.143",
                (now + timedelta(hours=6)).isoformat(),
            )
        )
        second = await enforcer.apply(
            self.recommendation(
                "rec-two",
                "recommend_challenge",
                "45.138.12.26",
                (now + timedelta(hours=6)).isoformat(),
            )
        )

        rules = enforcer.zone_rules["zone123456"]
        self.assertEqual(len(rules), 1)
        self.assertEqual(rules[0]["ref"], "hotpot_pool_challenge")
        self.assertIn("34.14.99.143", rules[0]["expression"])
        self.assertIn("45.138.12.26", rules[0]["expression"])
        self.assertIn("www.example.com", rules[0]["expression"])
        self.assertIn("api.example.com", rules[0]["expression"])
        self.assertEqual(first[0]["provider"], POOL_PROVIDER)
        self.assertEqual(second[0]["rule_id"], first[0]["rule_id"])

        self.assertEqual(await enforcer.remove(first), [])
        self.assertEqual(len(rules), 1)
        self.assertNotIn("34.14.99.143", rules[0]["expression"])
        self.assertIn("45.138.12.26", rules[0]["expression"])

        self.assertEqual(await enforcer.remove(second), [])
        self.assertEqual(rules, [])

    async def test_block_pool_is_ordered_before_challenge_pool(self) -> None:
        now = datetime.now(timezone.utc)
        enforcer = FakeFreePlanEnforcer(self.config())
        await enforcer.apply(
            self.recommendation(
                "rec-challenge",
                "recommend_challenge",
                "34.14.99.143",
                (now + timedelta(hours=6)).isoformat(),
            )
        )
        await enforcer.apply(
            self.recommendation(
                "rec-block",
                "recommend_block",
                "45.138.12.26",
                (now + timedelta(hours=24)).isoformat(),
            )
        )
        refs = [row["ref"] for row in enforcer.zone_rules["zone123456"]]
        self.assertEqual(refs, ["hotpot_pool_block", "hotpot_pool_challenge"])

    async def test_long_block_uses_one_account_ip_access_rule(self) -> None:
        now = datetime.now(timezone.utc)
        enforcer = FakeFreePlanEnforcer(self.config())
        first_expiry = (now + timedelta(days=4)).isoformat()
        second_expiry = (now + timedelta(days=7)).isoformat()

        first = await enforcer.apply(
            self.recommendation(
                "rec-long-one",
                "recommend_long_block",
                "34.14.99.143",
                first_expiry,
            )
        )
        second = await enforcer.apply(
            self.recommendation(
                "rec-long-two",
                "recommend_long_block",
                "34.14.99.143",
                second_expiry,
            )
        )

        account_rules = enforcer.access_rules[("account", "account123")]
        self.assertEqual(len(account_rules), 1)
        self.assertEqual(enforcer.created_access, 1)
        self.assertEqual(enforcer.patched_access, 1)
        self.assertEqual(enforcer.zone_rules.get("zone123456", []), [])
        self.assertEqual(first[0]["provider"], IP_ACCESS_PROVIDER)
        self.assertTrue(first[0]["account_wide"])
        self.assertEqual(first[0]["scope"], "account")
        self.assertEqual(first[0]["account_id"], "account123")
        self.assertEqual(first[0]["rule_id"], second[0]["rule_id"])

        self.assertEqual(await enforcer.remove(first), [])
        self.assertEqual(len(account_rules), 1)
        self.assertEqual(await enforcer.remove(second), [])
        self.assertEqual(account_rules, {})

    async def test_legacy_zone_ip_access_rule_remains_removable(self) -> None:
        now = datetime.now(timezone.utc)
        enforcer = FakeFreePlanEnforcer(self.config())
        rec = self.recommendation(
            "legacy-zone",
            "recommend_long_block",
            "34.14.99.143",
            (now + timedelta(days=7)).isoformat(),
        )
        rules = await enforcer._apply_ip_access(
            rec, {"zone123456": ("www.example.com",)}
        )
        self.assertEqual(rules[0]["scope"], "zone")
        self.assertEqual(await enforcer.remove(rules), [])
        self.assertEqual(
            enforcer.access_rules[("zone", "zone123456")],
            {},
        )

    def test_plan_describes_shared_pool_and_account_wide_long_block(self) -> None:
        now = datetime.now(timezone.utc)
        config = self.config()
        challenge = build_enforcement_plan(
            self.recommendation(
                "plan-challenge",
                "recommend_challenge",
                "34.14.99.143",
                (now + timedelta(hours=6)).isoformat(),
            ),
            config,
        )
        self.assertEqual(challenge["provider"], POOL_PROVIDER)
        self.assertFalse(challenge["account_wide"])
        self.assertEqual(challenge["zones"][0]["ref"], "hotpot_pool_challenge")
        self.assertTrue(challenge["zones"][0]["shared_rule"])

        long_block = build_enforcement_plan(
            self.recommendation(
                "plan-long",
                "recommend_long_block",
                "34.14.99.143",
                (now + timedelta(days=7)).isoformat(),
            ),
            config,
        )
        self.assertEqual(long_block["provider"], IP_ACCESS_PROVIDER)
        self.assertTrue(long_block["account_wide"])
        self.assertEqual(long_block["zones"][0]["scope"], "account")
        self.assertEqual(long_block["zones"][0]["account_id"], "account123")

    def test_status_explains_free_plan_rule_budget(self) -> None:
        status = self.config().public_status()
        self.assertEqual(status["pooled_waf_rules_per_zone"], 2)
        self.assertEqual(
            status["challenge_provider"],
            "Cloudflare pooled zone WAF custom rule",
        )
        self.assertEqual(
            status["long_block_provider"],
            "Cloudflare account IP Access Rule",
        )
        self.assertFalse(status["long_blocks_consume_custom_rule_slots"])
        self.assertTrue(status["long_block_ready"])

    def test_long_block_requires_account_id(self) -> None:
        config = CloudflareConfig(
            enabled=True,
            api_token="token",
            targets=self.config().targets,
        )
        now = datetime.now(timezone.utc)
        with self.assertRaisesRegex(ValueError, "HOTPOT_CLOUDFLARE_ACCOUNT_ID"):
            build_enforcement_plan(
                self.recommendation(
                    "no-account",
                    "recommend_long_block",
                    "34.14.99.143",
                    (now + timedelta(days=7)).isoformat(),
                ),
                config,
            )


if __name__ == "__main__":
    unittest.main()
