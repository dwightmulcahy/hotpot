from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from aiohttp import web


SESSION_COOKIE = "hotpot_dashboard_session"
CSRF_HEADER = "X-Hotpot-CSRF"
ACTION_HEADER = "X-Hotpot-Action"


def _env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def secret_from_env(name: str, *, required: bool = False) -> str:
    """Read a secret from NAME_FILE when set, otherwise from NAME.

    The file form takes precedence so deployments can move credentials out of the
    container environment without changing application behavior.
    """

    file_name = os.getenv(f"{name}_FILE", "").strip()
    if file_name:
        try:
            value = Path(file_name).read_text(encoding="utf-8").strip()
        except OSError as exc:
            raise RuntimeError(f"Could not read {name}_FILE: {exc}") from exc
    else:
        value = os.getenv(name, "").strip()
    if required and not value:
        if file_name:
            raise RuntimeError(f"{name}_FILE did not contain a value")
        raise RuntimeError(f"{name} or {name}_FILE is required")
    return value


@dataclass(frozen=True)
class AuthContext:
    username: str
    session_id: str | None
    expires_at: int | None
    via: str

    def audit(self) -> dict[str, str | None]:
        return {
            "principal": self.username,
            "session_id": self.session_id,
            "source": "dashboard",
        }


class SessionManager:
    """Stateless signed dashboard sessions with per-session CSRF tokens."""

    def __init__(self, dashboard_token: str) -> None:
        explicit = secret_from_env("HOTPOT_DASHBOARD_SESSION_SECRET")
        material = explicit or dashboard_token
        # Domain-separate the signing key even when the dashboard password is used
        # as the seed. The raw credential is never placed in a cookie or CSRF token.
        self.key = hashlib.sha256(
            b"hotpot-dashboard-session-v1\x00" + material.encode("utf-8")
        ).digest()
        self.ttl_seconds = max(
            300,
            int(os.getenv("HOTPOT_DASHBOARD_SESSION_TIMEOUT_SECONDS", "3600")),
        )
        self.cookie_secure = _env_bool("HOTPOT_DASHBOARD_COOKIE_SECURE", False)

    @staticmethod
    def _b64encode(value: bytes) -> str:
        return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")

    @staticmethod
    def _b64decode(value: str) -> bytes:
        padding = "=" * (-len(value) % 4)
        return base64.urlsafe_b64decode(value + padding)

    def _sign(self, payload: str) -> str:
        return self._b64encode(
            hmac.new(self.key, payload.encode("ascii"), hashlib.sha256).digest()
        )

    def issue(self, username: str) -> tuple[str, AuthContext, str]:
        now = int(time.time())
        expires = now + self.ttl_seconds
        session_id = secrets.token_urlsafe(24)
        payload_obj = {
            "v": 1,
            "u": username or "hotpot",
            "sid": session_id,
            "iat": now,
            "exp": expires,
        }
        payload = self._b64encode(
            json.dumps(payload_obj, separators=(",", ":"), sort_keys=True).encode(
                "utf-8"
            )
        )
        token = payload + "." + self._sign(payload)
        context = AuthContext(
            username=str(payload_obj["u"]),
            session_id=session_id,
            expires_at=expires,
            via="session",
        )
        return token, context, self.csrf_token(context)

    def verify(self, token: str | None) -> AuthContext | None:
        if not token or "." not in token:
            return None
        payload, signature = token.rsplit(".", 1)
        if not hmac.compare_digest(signature, self._sign(payload)):
            return None
        try:
            raw = json.loads(self._b64decode(payload).decode("utf-8"))
            version = int(raw.get("v", 0))
            username = str(raw.get("u") or "hotpot")
            session_id = str(raw.get("sid") or "")
            expires = int(raw.get("exp", 0))
        except (ValueError, TypeError, UnicodeDecodeError, json.JSONDecodeError):
            return None
        if version != 1 or not session_id or expires <= int(time.time()):
            return None
        return AuthContext(username, session_id, expires, "session")

    def csrf_token(self, context: AuthContext) -> str:
        if not context.session_id:
            return ""
        value = hmac.new(
            self.key,
            ("csrf:" + context.session_id).encode("utf-8"),
            hashlib.sha256,
        ).digest()
        return self._b64encode(value)

    def verify_csrf(self, context: AuthContext, supplied: str | None) -> bool:
        if not context.session_id or not supplied:
            return False
        return hmac.compare_digest(self.csrf_token(context), supplied)

    def set_cookie(self, response: web.StreamResponse, token: str) -> None:
        response.set_cookie(
            SESSION_COOKIE,
            token,
            max_age=self.ttl_seconds,
            httponly=True,
            secure=self.cookie_secure,
            samesite="Strict",
            path="/",
        )

    def clear_cookie(self, response: web.StreamResponse) -> None:
        response.del_cookie(SESSION_COOKIE, path="/")

    def public_session(self, context: AuthContext, csrf: str) -> dict[str, Any]:
        expires_at = (
            datetime.fromtimestamp(context.expires_at, tz=timezone.utc).isoformat()
            if context.expires_at
            else None
        )
        return {
            "authenticated": True,
            "user": context.username,
            "expires_at": expires_at,
            "timeout_seconds": self.ttl_seconds,
            "csrf_token": csrf,
            "cookie_secure": self.cookie_secure,
        }


class ActionRateLimiter:
    """Small in-memory fixed-window limiter for dashboard mutation endpoints."""

    def __init__(self) -> None:
        self.limit = max(
            1,
            int(os.getenv("HOTPOT_DASHBOARD_ACTION_RATE_LIMIT_PER_MINUTE", "30")),
        )
        self.window_seconds = 60.0
        self._state: dict[str, list[float]] = {}

    def check(self, key: str) -> tuple[bool, int]:
        now = time.monotonic()
        cutoff = now - self.window_seconds
        values = [value for value in self._state.get(key, []) if value > cutoff]
        if len(values) >= self.limit:
            retry = max(1, int(self.window_seconds - (now - values[0])))
            self._state[key] = values
            return False, retry
        values.append(now)
        self._state[key] = values
        if len(self._state) > 5000:
            # Opportunistic cleanup; dashboard sessions are low volume and the
            # limiter is deliberately process-local rather than security state.
            for state_key, state_values in list(self._state.items()):
                active = [value for value in state_values if value > cutoff]
                if active:
                    self._state[state_key] = active
                else:
                    self._state.pop(state_key, None)
        return True, 0
