from __future__ import annotations

import os
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from aiohttp.test_utils import make_mocked_request

from hotpot.config import Settings
from hotpot.server import HotpotServer


class CoreAuthScopeTests(unittest.TestCase):
    def _server(self, env: dict[str, str]) -> HotpotServer:
        with patch.dict(
            os.environ,
            {"HOTPOT_UPSTREAM": "http://example:8080", **env},
            clear=True,
        ):
            settings = Settings.from_env()
        server = object.__new__(HotpotServer)
        server.settings = settings
        return server

    @staticmethod
    def _request(token: str | None):
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        return make_mocked_request("GET", "/_hotpot/status", headers=headers)

    def test_collector_token_can_read_but_cannot_change_policy(self) -> None:
        server = self._server(
            {
                "HOTPOT_COLLECTOR_TOKEN": "collector",
                "HOTPOT_POLICY_TOKEN": "policy",
            }
        )
        request = self._request("collector")
        self.assertTrue(server.authorized(request))
        self.assertFalse(server.authorized_policy(request))

    def test_policy_token_can_read_and_change_policy(self) -> None:
        server = self._server(
            {
                "HOTPOT_COLLECTOR_TOKEN": "collector",
                "HOTPOT_POLICY_TOKEN": "policy",
            }
        )
        request = self._request("policy")
        self.assertTrue(server.authorized(request))
        self.assertTrue(server.authorized_policy(request))

    def test_legacy_admin_token_remains_full_access_fallback(self) -> None:
        server = self._server({"HOTPOT_ADMIN_TOKEN": "legacy-admin"})
        request = self._request("legacy-admin")
        self.assertTrue(server.authorized(request))
        self.assertTrue(server.authorized_policy(request))

    def test_collector_token_never_inherits_policy_scope_from_admin_absence(self) -> None:
        server = self._server({"HOTPOT_COLLECTOR_TOKEN": "collector-only"})
        self.assertTrue(server.authorized(self._request("collector-only")))
        self.assertFalse(server.authorized_policy(self._request("collector-only")))
        self.assertFalse(server.authorized(self._request("wrong")))
        self.assertFalse(server.authorized(self._request(None)))


if __name__ == "__main__":
    unittest.main()
