from __future__ import annotations

import os
import socket
import tempfile
from pathlib import Path
from urllib.parse import urlsplit

from .cloudflare_enforcement import parse_cloudflare_targets
from .notifications import NotificationConfig
from .runtime import instances_from_env
from .security import secret_from_env


def _check(checks: list[dict], check_id: str, ok: bool, detail: str, *, warning: bool = False) -> None:
    checks.append(
        {
            "id": check_id,
            "status": "warning" if warning and ok else ("pass" if ok else "fail"),
            "detail": detail,
        }
    )


def _env_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


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


def run_preflight(*, check_bind: bool = True) -> dict:
    """Validate dashboard configuration without making network calls or mutations."""

    checks: list[dict] = []
    for name in ("HOTPOT_ADMIN_TOKEN", "HOTPOT_DASHBOARD_TOKEN"):
        try:
            value = secret_from_env(name, required=True)
            _check(checks, f"secret:{name}", bool(value), f"{name} is configured")
        except Exception as exc:
            _check(checks, f"secret:{name}", False, f"{name} is unavailable: {type(exc).__name__}: {exc}")

    try:
        instances = instances_from_env()
        invalid = []
        for instance in instances:
            parsed = urlsplit(instance.url)
            if parsed.scheme not in {"http", "https"} or not parsed.hostname:
                invalid.append(instance.instance_id)
        _check(
            checks,
            "instances",
            not invalid,
            f"Configured {len(instances)} dashboard instance(s)" if not invalid else "Invalid instance URL(s): " + ", ".join(invalid),
        )
    except Exception as exc:
        _check(checks, "instances", False, f"Dashboard instances are invalid: {type(exc).__name__}: {exc}")

    data_dir = Path(os.getenv("HOTPOT_DASHBOARD_DATA_DIR", "/data"))
    try:
        data_dir.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(prefix=".hotpot-dashboard-preflight-", dir=data_dir, delete=True):
            pass
        _check(checks, "data-dir", True, "Dashboard data directory is writable")
    except Exception as exc:
        _check(checks, "data-dir", False, f"Dashboard data directory is not writable: {type(exc).__name__}: {exc}")

    bind = os.getenv("HOTPOT_DASHBOARD_BIND", "127.0.0.1")
    try:
        port = int(os.getenv("HOTPOT_DASHBOARD_PORT", "19090"))
        port_ok = 1 <= port <= 65535
    except ValueError:
        port, port_ok = 0, False
    _check(checks, "port", port_ok, f"Dashboard port {port} is valid" if port_ok else "HOTPOT_DASHBOARD_PORT must be an integer from 1 to 65535")
    if check_bind and port_ok:
        ok, detail = _bind_available(bind, port)
        _check(checks, "bind", ok, detail)

    enforcement_enabled = _env_bool("HOTPOT_CLOUDFLARE_ENFORCEMENT_ENABLED", False)
    try:
        targets = parse_cloudflare_targets(os.getenv("HOTPOT_CLOUDFLARE_TARGETS", ""))
        token = secret_from_env("HOTPOT_CLOUDFLARE_API_TOKEN")
        cloudflare_ok = not enforcement_enabled or bool(token and targets)
        _check(
            checks,
            "cloudflare",
            cloudflare_ok,
            (
                f"Cloudflare target mapping parsed for {len(targets)} instance(s)"
                if cloudflare_ok
                else "Cloudflare enforcement is enabled but token or target mappings are missing"
            ),
        )
    except Exception as exc:
        _check(checks, "cloudflare", False, f"Cloudflare configuration is invalid: {type(exc).__name__}: {exc}")

    try:
        notifications = NotificationConfig.from_env()
        notification_ok = not notifications.enabled or bool(notifications.channels)
        _check(
            checks,
            "notifications",
            notification_ok,
            (
                "Notification configuration is coherent"
                if notification_ok
                else "External notifications are enabled but no complete webhook or SMTP channel is configured"
            ),
        )
    except Exception as exc:
        _check(checks, "notifications", False, f"Notification configuration is invalid: {type(exc).__name__}: {exc}")

    configured_geoip = 0
    missing_geoip: list[str] = []
    for name in ("HOTPOT_GEOIP_ASN_DB", "HOTPOT_GEOIP_COUNTRY_DB", "HOTPOT_GEOIP_CITY_DB"):
        raw = os.getenv(name, "").strip()
        if not raw:
            continue
        configured_geoip += 1
        if not Path(raw).is_file():
            missing_geoip.append(name)
    _check(
        checks,
        "geoip",
        not missing_geoip,
        (
            f"{configured_geoip} GeoIP database path(s) configured"
            if not missing_geoip
            else "Configured GeoIP database file(s) missing: " + ", ".join(missing_geoip)
        ),
        warning=configured_geoip == 0 and not missing_geoip,
    )

    failures = [item for item in checks if item["status"] == "fail"]
    return {
        "ok": not failures,
        "checks": checks,
        "failures": len(failures),
        "warnings": sum(1 for item in checks if item["status"] == "warning"),
        "network_calls_performed": False,
    }
