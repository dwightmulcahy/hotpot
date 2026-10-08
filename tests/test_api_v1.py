from __future__ import annotations

import unittest

from aiohttp import web

from dashboard.api_v1 import API_VERSION, _envelope, _normalize, register_api_routes


class _DashboardStub:
    async def _handler(self, request):
        return web.json_response({"ok": True})

    api_overview = _handler
    api_network = _handler
    api_recommendations = _handler
    api_recommendation = _handler
    api_audit = _handler
    api_notifications = _handler
    api_cleanup_jobs = _handler
    api_notification_test = _handler
    api_dismiss_recommendation = _handler
    api_approve_recommendation = _handler
    api_remove_enforcement = _handler
    api_repair_enforcement = _handler
    api_remove_orphan = _handler
    api_reconcile_enforcement = _handler
    api_system_check = _handler


class ApiV1Tests(unittest.TestCase):
    def test_identity_fields_are_explicit_and_legacy_ip_names_are_removed(self) -> None:
        normalized = _normalize(
            {
                "identity_key": "cf-worker:example.com",
                "client_ip": "2a06:98c0:3600::103",
                "ip": "legacy-overload",
                "source_type": "cloudflare-worker",
                "worker_zone": "example.com",
                "nested": {"ip": "203.0.113.9", "hits": 4},
            }
        )
        self.assertEqual(normalized["actor_key"], "cf-worker:example.com")
        self.assertEqual(normalized["observed_ip"], "2a06:98c0:3600::103")
        self.assertEqual(normalized["source_type"], "cloudflare-worker")
        self.assertEqual(normalized["worker_zone"], "example.com")
        self.assertNotIn("identity_key", normalized)
        self.assertNotIn("client_ip", normalized)
        self.assertNotIn("ip", normalized)
        self.assertEqual(normalized["nested"]["observed_ip"], "203.0.113.9")
        self.assertNotIn("ip", normalized["nested"])

    def test_actor_with_only_legacy_ip_keeps_it_as_observed_ip(self) -> None:
        normalized = _normalize(
            {"identity_key": "198.51.100.7", "ip": "198.51.100.7", "hits": 4}
        )
        self.assertEqual(normalized["actor_key"], "198.51.100.7")
        self.assertEqual(normalized["observed_ip"], "198.51.100.7")
        self.assertNotIn("ip", normalized)

    def test_envelope_declares_schema_version(self) -> None:
        envelope = _envelope(
            "campaign",
            {"campaign_id": "campaign_123", "client_ip": "203.0.113.8"},
        )
        self.assertEqual(envelope["schema_version"], API_VERSION)
        self.assertEqual(envelope["resource"], "campaign")
        self.assertIn("generated_at", envelope)
        self.assertEqual(envelope["data"]["observed_ip"], "203.0.113.8")

    def test_v1_routes_coexist_with_legacy_campaign_route_and_keep_session_bootstrap(self) -> None:
        app = web.Application()
        register_api_routes(app, _DashboardStub())
        paths = {resource.canonical for resource in app.router.resources()}
        self.assertIn("/api/campaign/{campaign_id}", paths)
        self.assertIn("/api/v1/meta", paths)
        self.assertIn("/api/v1/campaigns", paths)
        self.assertIn("/api/v1/campaigns/{campaign_id}", paths)
        self.assertIn("/api/v1/attackers/{actor_key}", paths)
        self.assertIn("/api/v1/overview", paths)
        self.assertIn("/api/v1/recommendations/{recommendation_id}/approve", paths)
        self.assertNotIn("/api/v1/session", paths)


if __name__ == "__main__":
    unittest.main()
