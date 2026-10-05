import unittest

from aiohttp import ClientSession, web
from aiohttp.test_utils import TestServer

from hotpot.config import Settings
from hotpot.notifications import Notifier


def settings_for(webhook_url: str) -> Settings:
    from pathlib import Path
    return Settings(
        bind="127.0.0.1", port=8080, upstream="http://example.invalid", data_dir=Path("/tmp"),
        profiles_dir=Path("profiles"), enabled_profiles=(), max_request_body=1024,
        upstream_timeout=10, trust_forwarded_for=False, tarpit_enabled=True,
        tarpit_max_concurrent=1, tarpit_initial_delay=0, tarpit_chunk_delay=0,
        tarpit_max_seconds=1, tarpit_escalated_max_seconds=2, admin_token="x",
        allow_cidrs=(), retention_days=30, attacker_retention_days=90,
        housekeeping_interval_seconds=21600, notify_min_level=3, notify_cooldown_seconds=3600,
        notify_webhook_url=webhook_url, notify_webhook_bearer="secret-token",
        smtp_host=None, smtp_port=587, smtp_starttls=True, smtp_username=None,
        smtp_password=None, smtp_from=None, smtp_to=(),
    )


class NotificationTests(unittest.IsolatedAsyncioTestCase):
    async def test_webhook_notification(self):
        received = []

        async def handler(request):
            received.append((request.headers.get("Authorization"), await request.json()))
            return web.Response(status=204)

        app = web.Application()
        app.router.add_post("/alert", handler)
        server = TestServer(app)
        await server.start_server()
        try:
            notifier = Notifier(settings_for(str(server.make_url("/alert"))))
            async with ClientSession() as client:
                channels = await notifier.send(client, {"client_ip": "203.0.113.4", "escalation_level": 3})
            self.assertEqual(channels, ["webhook"])
            self.assertEqual(received[0][0], "Bearer secret-token")
            self.assertEqual(received[0][1]["source"], "hotpot")
        finally:
            await server.close()


if __name__ == "__main__":
    unittest.main()
