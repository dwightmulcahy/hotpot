from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .investigation_store import InvestigationStore


_ALLOWED_CHANNELS = {"webhook", "email"}


def _channel_list(name: str, default: str) -> tuple[str, ...]:
    values = tuple(
        value.strip().lower()
        for value in os.getenv(name, default).replace(";", ",").split(",")
        if value.strip()
    )
    invalid = sorted(set(values) - _ALLOWED_CHANNELS)
    if invalid:
        raise RuntimeError(f"{name} contains unsupported channel(s): {', '.join(invalid)}")
    return tuple(dict.fromkeys(values))


@dataclass(frozen=True)
class NotificationRoutingPolicy:
    critical: tuple[str, ...]
    warning: tuple[str, ...]
    info: tuple[str, ...]

    @classmethod
    def from_env(cls) -> "NotificationRoutingPolicy":
        return cls(
            critical=_channel_list(
                "HOTPOT_DASHBOARD_NOTIFY_CRITICAL_CHANNELS", "webhook,email"
            ),
            warning=_channel_list(
                "HOTPOT_DASHBOARD_NOTIFY_WARNING_CHANNELS", "email"
            ),
            info=_channel_list("HOTPOT_DASHBOARD_NOTIFY_INFO_CHANNELS", ""),
        )

    def configured_route(
        self,
        severity: str,
        *,
        configured_channels: tuple[str, ...] | list[str],
        enabled: bool,
    ) -> list[str]:
        if not enabled:
            return []
        requested = {
            "critical": self.critical,
            "warning": self.warning,
            "info": self.info,
        }.get(str(severity).lower(), self.info)
        available = set(configured_channels)
        return [channel for channel in requested if channel in available]

    def as_dict(
        self,
        *,
        configured_channels: tuple[str, ...] | list[str],
        enabled: bool,
    ) -> dict[str, Any]:
        return {
            severity: {
                "requested": list(getattr(self, severity)),
                "active": self.configured_route(
                    severity,
                    configured_channels=configured_channels,
                    enabled=enabled,
                ),
            }
            for severity in ("critical", "warning", "info")
        }


class RoutedInvestigationStore(InvestigationStore):
    """Investigation store that applies severity routing at durable queue time."""

    def __init__(
        self,
        data_dir: Path,
        *,
        retention_days: int,
        routing: NotificationRoutingPolicy,
        configured_channels: tuple[str, ...] | list[str],
        delivery_enabled: bool,
    ) -> None:
        self.notification_routing = routing
        self.configured_notification_channels = tuple(configured_channels)
        self.notification_delivery_enabled = bool(delivery_enabled)
        super().__init__(data_dir, retention_days=retention_days)

    def channels_for(self, severity: str) -> list[str]:
        return self.notification_routing.configured_route(
            severity,
            configured_channels=self.configured_notification_channels,
            enabled=self.notification_delivery_enabled,
        )

    async def queue_notification(
        self,
        *,
        event_key: str,
        event_type: str,
        severity: str,
        subject: str,
        message: str,
        channels: list[str],
        actor_key: str | None = None,
        recommendation_id: str | None = None,
        payload: dict[str, Any] | None = None,
    ) -> tuple[dict[str, Any], bool]:
        routed = (
            list(self.configured_notification_channels)
            if event_type == "notification_test" and self.notification_delivery_enabled
            else self.channels_for(severity)
        )
        return await super().queue_notification(
            event_key=event_key,
            event_type=event_type,
            severity=severity,
            subject=subject,
            message=message,
            channels=routed,
            actor_key=actor_key,
            recommendation_id=recommendation_id,
            payload=payload,
        )

    async def notification_delivery_summary(self, *, limit: int = 200) -> dict[str, Any]:
        rows = await self.recent_notifications(limit=max(1, min(1000, int(limit))))
        summary: dict[str, Any] = {
            "last_success_at": None,
            "last_failure_at": None,
            "last_error": None,
            "channels": {
                channel: {
                    "last_success_at": None,
                    "last_failure_at": None,
                    "last_error": None,
                }
                for channel in self.configured_notification_channels
            },
        }

        def newest(current: str | None, candidate: str | None) -> str | None:
            if not candidate:
                return current
            return candidate if current is None or candidate > current else current

        for row in rows:
            delivery = row.get("delivery") if isinstance(row.get("delivery"), dict) else {}
            for channel, state in delivery.items():
                if not isinstance(state, dict):
                    continue
                target = summary["channels"].setdefault(
                    channel,
                    {"last_success_at": None, "last_failure_at": None, "last_error": None},
                )
                at = str(state.get("at") or row.get("last_attempt_at") or "") or None
                if state.get("status") == "sent":
                    target["last_success_at"] = newest(target["last_success_at"], at)
                    summary["last_success_at"] = newest(summary["last_success_at"], at)
                elif state.get("status") == "failed":
                    target["last_failure_at"] = newest(target["last_failure_at"], at)
                    summary["last_failure_at"] = newest(summary["last_failure_at"], at)
                    if at == target["last_failure_at"]:
                        target["last_error"] = state.get("error") or row.get("last_error")
                    if at == summary["last_failure_at"]:
                        summary["last_error"] = state.get("error") or row.get("last_error")
        summary["generated_at"] = datetime.now(timezone.utc).isoformat()
        return summary
