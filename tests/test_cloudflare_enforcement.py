from __future__ import annotations

import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from dashboard.cloudflare_enforcement import (
    CloudflareConfig,
    CloudflareEnforcer,
    CloudflareTarget,
    build_expression,
    parse_cloudflare_targets,
)
from dashboard.response_enforcement_store import (
    ApprovalResponsePolicy,
    EnforcementStore,
)
from dashboard.runtime import Instance


class CloudflareExpressionTests(unittest.TestCase):
    def test_ip_rule_is_hostname_scoped(self) -> None:
        expression = build_expression(
            "ip",
            "2001:4860:4860::8888",
            ("www.example.com", "api.example.com"),
        )
        self.assertIn("ip.src eq 2001:4860:4860::8888", expression)
        self.assertIn('http.host eq "www.example.com"', expression)
        self.assertIn('http.host eq "api.example.com"', expression)

    def test_worker_rule_uses_cloudflare_worker_field(self) -> None:
        expression = build_expression(
            "cloudflare-worker-zone",
            "scanner.example",
            ("www.example.com",),
        )
        self.assertIn('cf.worker.upstream_zone eq "scanner.example"', expression)
        self.assertNotIn("CF-Worker", expression)

    def test_target_json_is_validated_and_normalized(self) -> None:
        targets = parse_cloudflare_targets(
            '{"one":{"zone_id":"zone-1","hosts":["WWW.Example.COM","api.example.com"]}}'
        )
        self.assertEqual(targets["one"].zone_id, "zone-1")
        self.assertEqual(
            targets["one"].hosts,
            ("api.example.com", "www.example.com"),
        )


class FakeCloudflareEnforcer(CloudflareEnforcer):
    def __init__(self, config, *, existing: bool = False):
        super().__init__(config, client=object())
        self.existing = existing
        self.created = 0
        self.deleted = []

    async def _request(self, method, path, *, payload=None, allow_404=False):
        if method == "GET" and path.endswith("/entrypoint"):
            rules = []
            if self.existing:
                rules = [
                    {
                        "id": "rule-existing",
                        "ref": "hotpot_rec123_zone1234",
                        "action": "block",
                        "expression": '(ip.src eq 8.8.8.8) and (http.host eq "www.example.com")',
                        "enabled": True,
                    }
                ]
            return 200, {
                "success": True,
                "result": {"id": "ruleset-1", "rules": rules},
            }
        if method == "POST" and path.endswith("/rules"):
            self.created += 1
            return 200, {
                "success": True,
                "result": {
                    "id": "ruleset-1",
                    "rules": [
                        {
                            "id": "rule-new",
                            "ref": payload["ref"],
                            "action": payload["action"],
                            "expression": payload["expression"],
                        }
                    ],
                },
            }
        if method == "DELETE":
            self.deleted.append(path)
            return 200, {"success": True, "result": {}}
        raise AssertionError((method, path, payload, allow_404))


class CloudflareEnforcerTests(unittest.IsolatedAsyncioTestCase):
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

    def recommendation(self):
        return {
            "recommendation_id": "rec123",
            "actor_key": "8.8.8.8",
            "action": "recommend_block",
            "target_type": "ip",
            "target_value": "8.8.8.8",
            "enforcement_expires_at": "2026-10-08T00:00:00+00:00",
            "evidence": {"instance_ids": ["one"]},
        }

    async def test_apply_creates_rule_and_returns_deletion_metadata(self) -> None:
        enforcer = FakeCloudflareEnforcer(self.config())
        rules = await enforcer.apply(self.recommendation())
        self.assertEqual(enforcer.created, 1)
        self.assertEqual(rules[0]["rule_id"], "rule-new")
        self.assertEqual(rules[0]["action"], "block")
        errors = await enforcer.remove(rules)
        self.assertEqual(errors, [])
        self.assertEqual(len(enforcer.deleted), 1)

    async def test_apply_reuses_deterministic_existing_rule_after_restart(self) -> None:
        enforcer = FakeCloudflareEnforcer(self.config(), existing=True)
        rules = await enforcer.apply(self.recommendation())
        self.assertEqual(enforcer.created, 0)
        self.assertTrue(rules[0]["reused"])
        self.assertEqual(rules[0]["rule_id"], "rule-existing")

    async def test_reconcile_confirms_expected_rule(self) -> None:
        enforcer = FakeCloudflareEnforcer(self.config(), existing=True)
        rules = await enforcer.apply(self.recommendation())
        recommendation = {**self.recommendation(), "enforcement_rules": rules}
        report = await enforcer.reconcile([recommendation])
        self.assertEqual(report["status"], "healthy")
        self.assertEqual(report["counts"]["healthy"], 1)
        self.assertEqual(report["orphaned"], 0)
        self.assertEqual(
            report["recommendations"][0]["rules"][0]["status"], "healthy"
        )

    async def test_reconcile_detects_missing_and_orphaned_rules(self) -> None:
        expected = {
            **self.recommendation(),
            "enforcement_rules": [
                {
                    "zone_id": "zone123456",
                    "ruleset_id": "ruleset-1",
                    "rule_id": "rule-existing",
                    "ref": "hotpot_rec123_zone1234",
                    "action": "block",
                    "expression": '(ip.src eq 8.8.8.8) and (http.host eq "www.example.com")',
                }
            ],
        }
        missing = await FakeCloudflareEnforcer(self.config()).reconcile([expected])
        self.assertEqual(missing["counts"]["missing"], 1)
        self.assertEqual(missing["status"], "drifted")

        orphaned = await FakeCloudflareEnforcer(
            self.config(), existing=True
        ).reconcile([])
        self.assertEqual(orphaned["orphaned"], 1)
        self.assertEqual(orphaned["orphans"][0]["ref"], "hotpot_rec123_zone1234")


class EnforcementStoreTests(unittest.IsolatedAsyncioTestCase):
    async def _store_with_l4(self, path: Path) -> tuple[EnforcementStore, Instance]:
        store = EnforcementStore(path, retention_days=90)
        instance = Instance("one", "One", "http://one")
        await store.ingest(
            instance,
            [
                {
                    "id": 1,
                    "ts": datetime.now(timezone.utc).isoformat(),
                    "client_ip": "8.8.8.8",
                    "path": "/.env",
                    "category": "secret",
                    "scanner": "scanner",
                    "action": "tarpit",
                    "severity": 5,
                    "escalation_level": 4,
                    "suppressed_before": 24,
                }
            ],
            1,
        )
        return store, instance

    async def test_approval_persists_target_apps_and_applied_rule_lifecycle(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store, _ = await self._store_with_l4(Path(tmp))
            policy = ApprovalResponsePolicy()
            apps = [
                {
                    "id": "one",
                    "name": "One",
                    "allowlist_cidrs": [],
                    "trusted_proxy_cidrs": ["127.0.0.1/32"],
                }
            ]
            response = await store.sync_response_recommendations(policy, apps)
            rec = response["recommendations"][0]
            approved = await store.approve_recommendation(
                rec["recommendation_id"], policy, apps
            )
            self.assertIsNotNone(approved)
            assert approved is not None
            self.assertEqual(approved["status"], "approved")
            self.assertEqual(approved["evidence"]["instance_ids"], ["one"])
            self.assertIsNotNone(approved["enforcement_expires_at"])

            applied = await store.mark_applied(
                rec["recommendation_id"],
                [
                    {
                        "zone_id": "zone-1",
                        "ruleset_id": "ruleset-1",
                        "rule_id": "rule-1",
                        "ref": "hotpot_test_zone1",
                        "action": "block",
                        "expression": '(ip.src eq 8.8.8.8) and (http.host eq "www.example.com")',
                    }
                ],
            )
            self.assertIsNotNone(applied)
            assert applied is not None
            self.assertEqual(applied["status"], "applied")
            self.assertEqual(applied["enforcement_rules"][0]["rule_id"], "rule-1")

            drift_report = {
                "checked_at": datetime.now(timezone.utc).isoformat(),
                "status": "drifted",
                "counts": {"healthy": 0, "drifted": 0, "missing": 1, "error": 0},
                "recommendations": [
                    {
                        "recommendation_id": rec["recommendation_id"],
                        "actor_key": "8.8.8.8",
                        "status": "missing",
                        "rules": [
                            {
                                "zone_id": "zone-1",
                                "ref": "hotpot_test_zone1",
                                "status": "missing",
                                "detail": "expected Hotpot rule was not found",
                            }
                        ],
                    }
                ],
                "orphans": [],
                "orphaned": 0,
                "zone_errors": [],
                "zones_checked": 1,
            }
            await store.record_reconciliation(drift_report)
            drifted = await store.recommendation(rec["recommendation_id"])
            assert drifted is not None
            self.assertEqual(drifted["reconciliation_status"], "missing")

            healthy_report = {
                **drift_report,
                "checked_at": datetime.now(timezone.utc).isoformat(),
                "status": "healthy",
                "counts": {"healthy": 1, "drifted": 0, "missing": 0, "error": 0},
                "recommendations": [
                    {
                        "recommendation_id": rec["recommendation_id"],
                        "actor_key": "8.8.8.8",
                        "status": "healthy",
                        "rules": [
                            {
                                "zone_id": "zone-1",
                                "ref": "hotpot_test_zone1",
                                "status": "healthy",
                                "detail": "matches persisted Hotpot rule",
                            }
                        ],
                    }
                ],
            }
            await store.record_reconciliation(healthy_report)

            # An actor with active enforcement must not immediately get a second
            # pending recommendation on the next dashboard refresh.
            again = await store.sync_response_recommendations(policy, apps)
            self.assertEqual(again["summary"]["pending"], 0)

            conn = store._connect()
            try:
                conn.execute(
                    "UPDATE response_recommendations SET enforcement_expires_at = ? "
                    "WHERE recommendation_id = ?",
                    (
                        (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat(),
                        rec["recommendation_id"],
                    ),
                )
                conn.commit()
            finally:
                conn.close()

            due = await store.due_removals()
            self.assertEqual(len(due), 1)
            expired = await store.mark_removal_result(rec["recommendation_id"], [])
            self.assertIsNotNone(expired)
            assert expired is not None
            self.assertEqual(expired["status"], "expired")
            self.assertIsNotNone(expired["removed_at"])

            audit = await store.audit_log(limit=50)
            event_types = {row["event_type"] for row in audit}
            self.assertIn("recommendation_created", event_types)
            self.assertIn("approved", event_types)
            self.assertIn("applied", event_types)
            self.assertIn("reconciliation_issue", event_types)
            self.assertIn("reconciliation_resolved", event_types)
            self.assertIn("removed", event_types)

            storage = await store.storage_self_check()
            self.assertTrue(storage["writable"])
            self.assertEqual(storage["quick_check"].lower(), "ok")

    async def test_approval_rechecks_allowlist(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store, _ = await self._store_with_l4(Path(tmp))
            policy = ApprovalResponsePolicy()
            initial_apps = [
                {
                    "id": "one",
                    "allowlist_cidrs": [],
                    "trusted_proxy_cidrs": [],
                }
            ]
            response = await store.sync_response_recommendations(policy, initial_apps)
            rec = response["recommendations"][0]
            changed_apps = [
                {
                    "id": "one",
                    "allowlist_cidrs": ["8.8.8.0/24"],
                    "trusted_proxy_cidrs": [],
                }
            ]
            with self.assertRaises(ValueError):
                await store.approve_recommendation(
                    rec["recommendation_id"], policy, changed_apps
                )


if __name__ == "__main__":
    unittest.main()
