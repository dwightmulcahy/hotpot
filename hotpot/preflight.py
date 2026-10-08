from __future__ import annotations

import os
import socket
import tempfile
from pathlib import Path
from urllib.parse import urlsplit

from .config import Settings
from .network import Allowlist, ClientIPResolver
from .rules import RuleEngine


def _check(checks: list[dict], check_id: str, ok: bool, detail: str, *, warning: bool = False) -> None:
    checks.append(
        {
            "id": check_id,
            "status": "warning" if warning and ok else ("pass" if ok else "fail"),
            "detail": detail,
        }
    )


def _secret_files(checks: list[dict]) -> None:
    for name in (
        "HOTPOT_ADMIN_TOKEN",
        "HOTPOT_NOTIFY_WEBHOOK_BEARER",
        "HOTPOT_SMTP_PASSWORD",
    ):
        configured = os.getenv(f"{name}_FILE", "").strip()
        if not configured:
            continue
        path = Path(configured)
        try:
            value = path.read_text(encoding="utf-8").strip()
            ok = bool(value)
            detail = f"{name}_FILE is readable and non-empty" if ok else f"{name}_FILE is empty"
        except OSError as exc:
            ok = False
            detail = f"{name}_FILE is not readable: {type(exc).__name__}"
        _check(checks, f"secret:{name}", ok, detail)


def _bind_available(bind: str, port: int) -> tuple[bool, str]:
    family = socket.AF_INET6 if ":" in bind else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_STREAM)
    try:
        sock.bind((bind, port))
    except OSError as exc:
        return False, f"{bind}:{port} cannot be bound: {type(exc).__name__}"
    finally:
        sock.close()
    return True, f"{bind}:{port} is available"


def run_preflight(settings: Settings | None = None, *, check_bind: bool = True) -> dict:
    """Validate Hotpot configuration without contacting the protected upstream."""

    checks: list[dict] = []
    _secret_files(checks)
    try:
        resolved = settings or Settings.from_env()
    except Exception as exc:
        _check(checks, "settings", False, f"Settings invalid: {type(exc).__name__}: {exc}")
        return {"ok": False, "checks": checks}

    _check(checks, "settings", True, "Environment settings parsed successfully")
    parsed = urlsplit(resolved.upstream)
    upstream_ok = parsed.scheme in {"http", "https"} and bool(parsed.hostname)
    _check(
        checks,
        "upstream",
        upstream_ok,
        "Upstream URL has an http/https scheme and hostname" if upstream_ok else "HOTPOT_UPSTREAM must be an http/https URL with a hostname",
    )

    port_ok = 1 <= int(resolved.port) <= 65535
    _check(checks, "port", port_ok, f"Listen port {resolved.port} is valid" if port_ok else "HOTPOT_PORT must be between 1 and 65535")
    if check_bind and port_ok:
        ok, detail = _bind_available(resolved.bind, resolved.port)
        _check(checks, "bind", ok, detail)

    try:
        resolved.data_dir.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(prefix=".hotpot-preflight-", dir=resolved.data_dir, delete=True):
            pass
        _check(checks, "data-dir", True, "Data directory is writable")
    except Exception as exc:
        _check(checks, "data-dir", False, f"Data directory is not writable: {type(exc).__name__}: {exc}")

    try:
        engine = RuleEngine.load(resolved.profiles_dir, resolved.enabled_profiles)
        _check(checks, "profiles", bool(engine.rules), f"Loaded {len(engine.rules)} deception rule(s)")
    except Exception as exc:
        _check(checks, "profiles", False, f"Profiles failed to load: {type(exc).__name__}: {exc}")

    try:
        Allowlist(resolved.allow_cidrs)
        ClientIPResolver(resolved.client_ip_mode, resolved.trusted_proxy_cidrs)
        _check(checks, "network-policy", True, "Allowlist and trusted-proxy CIDRs are valid")
    except Exception as exc:
        _check(checks, "network-policy", False, f"Network policy is invalid: {type(exc).__name__}: {exc}")

    if resolved.admin_token:
        _check(checks, "admin-token", True, "Admin API token is configured")
    else:
        _check(
            checks,
            "admin-token",
            True,
            "Admin API token is not configured; authenticated status, events and metrics endpoints will be unavailable",
            warning=True,
        )

    smtp_values = [resolved.smtp_host, resolved.smtp_from, resolved.smtp_to, resolved.smtp_username, resolved.smtp_password]
    smtp_requested = any(bool(value) for value in smtp_values)
    smtp_ok = not smtp_requested or bool(resolved.smtp_host and resolved.smtp_from and resolved.smtp_to)
    _check(
        checks,
        "smtp",
        smtp_ok,
        "SMTP notification settings are coherent" if smtp_ok else "SMTP notifications require host, from address and at least one recipient",
    )

    failures = [item for item in checks if item["status"] == "fail"]
    return {
        "ok": not failures,
        "instance_id": resolved.instance_id,
        "checks": checks,
        "failures": len(failures),
        "warnings": sum(1 for item in checks if item["status"] == "warning"),
        "network_calls_performed": False,
    }
