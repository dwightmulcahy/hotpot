from __future__ import annotations

import asyncio
import hashlib
import json
import os
import smtplib
import ssl
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from typing import Any

from aiohttp import ClientSession

from .investigation_store import InvestigationStore
from .security import secret_from_env


def _env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class NotificationConfig:
    enabled: bool
    webhook_url: str
    webhook_bearer: str
    smtp_host: str
    smtp_port: int
    smtp_starttls: bool
    smtp_ssl: bool
    smtp_username: str
    smtp_password: str
    smtp_from: str
    smtp_to: tuple[str, ...]
    retry_seconds: int

    @classmethod
    def from_env(cls) -> "NotificationConfig":
        recipients = tuple(
            value.strip()
            for value in os.getenv("HOTPOT_DASHBOARD_SMTP_TO", "")
            .replace(";", ",")
            .split(",")
            if value.strip()
        )
        return cls(
            enabled=_env_bool("HOTPOT_DASHBOARD_NOTIFICATIONS_ENABLED", False),
            webhook_url=os.getenv("HOTPOT_DASHBOARD_NOTIFY_WEBHOOK_URL", "").strip(),
            webhook_bearer=secret_from_env("HOTPOT_DASHBOARD_NOTIFY_WEBHOOK_BEARER"),
            smtp_host=os.getenv("HOTPOT_DASHBOARD_SMTP_HOST", "").strip(),
            smtp_port=max(1, int(os.getenv("HOTPOT_DASHBOARD_SMTP_PORT", "587"))),
            smtp_starttls=_env_bool("HOTPOT_DASHBOARD_SMTP_STARTTLS", True),
            smtp_ssl=_env_bool("HOTPOT_DASHBOARD_SMTP_SSL", False),
            smtp_username=os.getenv("HOTPOT_DASHBOARD_SMTP_USERNAME", "").strip(),
            smtp_password=secret_from_env("HOTPOT_DASHBOARD_SMTP_PASSWORD"),
            smtp_from=os.getenv("HOTPOT_DASHBOARD_SMTP_FROM", "").strip(),
            smtp_to=recipients,
            retry_seconds=max(
                60, int(os.getenv("HOTPOT_DASHBOARD_NOTIFY_RETRY_SECONDS", "300"))
            ),
        )

    @property
    def webhook_configured(self) -> bool:
        return bool(self.webhook_url)

    @property
    def smtp_configured(self) -> bool:
        return bool(self.smtp_host and self.smtp_from and self.smtp_to)

    @property
    def channels(self) -> list[str]:
        if not self.enabled:
            return []
        result: list[str] = []
        if self.webhook_configured:
            result.append("webhook")
        if self.smtp_configured:
            result.append("email")
        return result

    def public_status(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "webhook_configured": self.webhook_configured,
            "smtp_configured": self.smtp_configured,
            "channels": self.channels,
            "retry_seconds": self.retry_seconds,
            "records_events_when_delivery_disabled": True,
        }


class NotificationCenter:
    """Turn only high-value dashboard events into durable notifications."""

    AUDIT_CURSOR_KEY = "notification_audit_cursor_v1"
    HEALTH_STATE_KEY = "notification_instance_health_v1"

    def __init__(self, config: NotificationConfig, store: InvestigationStore) -> None:
        self.config = config
        self.store = store

    async def _candidate_from_audit(
        self, audit: dict[str, Any]
    ) -> dict[str, Any] | None:
        event_type = str(audit.get("event_type") or "")
        actor = str(audit.get("actor_key") or "unknown")
        details = audit.get("details") if isinstance(audit.get("details"), dict) else {}

        if event_type == "recommendation_created":
            recommendation_id = str(audit.get("recommendation_id") or "")
            recommendation = (
                await self.store.recommendation(recommendation_id)
                if recommendation_id
                else None
            )
            if recommendation is None:
                return None
            action = str(recommendation.get("action") or "")
            confidence = str(recommendation.get("confidence") or "")
            evidence = recommendation.get("evidence") or {}
            score = int(evidence.get("global_score", 0) or 0)
            hits = int(evidence.get("observed_hits", 0) or 0)
            apps = int(evidence.get("app_count", 0) or 0)
            if action in {"recommend_block", "recommend_long_block"}:
                return {
                    "severity": "critical",
                    "subject": f"L4 response recommendation for {actor}",
                    "message": (
                        f"Hotpot recommends {action.replace('recommend_', '').replace('_', ' ')} "
                        f"for {actor}: score {score}, {hits} hits across {apps} app(s)."
                    ),
                    "payload": {
                        "action": action,
                        "confidence": confidence,
                        "global_score": score,
                        "observed_hits": hits,
                        "app_count": apps,
                    },
                }
            if action == "recommend_challenge" and confidence == "high":
                return {
                    "severity": "warning",
                    "subject": f"High-confidence L3 challenge recommendation for {actor}",
                    "message": (
                        f"Hotpot recommends a managed challenge for {actor}: score {score}, "
                        f"{hits} hits across {apps} app(s)."
                    ),
                    "payload": {
                        "action": action,
                        "confidence": confidence,
                        "global_score": score,
                        "observed_hits": hits,
                        "app_count": apps,
                    },
                }
            return None

        mapping: dict[str, tuple[str, str, str]] = {
            "applied": (
                "info",
                f"Cloudflare enforcement applied for {actor}",
                "Cloudflare enforcement applied",
            ),
            "apply_failed": (
                "critical",
                f"Cloudflare enforcement failed for {actor}",
                "Cloudflare enforcement apply failed",
            ),
            "removal_failed": (
                "critical",
                f"Cloudflare rule removal failed for {actor}",
                "Cloudflare rule removal failed",
            ),
            "orphan_detected": (
                "warning",
                "Orphaned Hotpot Cloudflare rule detected",
                "Orphaned Hotpot Cloudflare rule detected",
            ),
        }
        if event_type in mapping:
            severity, subject, fallback = mapping[event_type]
            return {
                "severity": severity,
                "subject": subject,
                "message": str(audit.get("message") or fallback),
                "payload": details,
            }
        if event_type == "reconciliation_issue":
            reconciliation = details.get("reconciliation") if isinstance(details, dict) else {}
            status = str((reconciliation or {}).get("status") or "drifted")
            return {
                "severity": "critical" if status in {"missing", "error"} else "warning",
                "subject": f"Cloudflare reconciliation {status} for {actor}",
                "message": str(
                    audit.get("message") or f"Cloudflare reconciliation detected {status}"
                ),
                "payload": details,
            }
        return None

    async def sync_audit_events(self, client: ClientSession) -> dict[str, int]:
        state = await self.store.observability_state(self.AUDIT_CURSOR_KEY)
        if state is None:
            # Seed at the current high-water mark so enabling notifications does not
            # send a backlog of historical enforcement messages.
            current = await self.store.latest_audit_id()
            await self.store.set_observability_state(
                self.AUDIT_CURSOR_KEY, {"audit_id": current}
            )
            await self.deliver_due(client)
            return {"processed": 0, "queued": 0, "seeded_at": current}

        cursor = max(0, int(state.get("audit_id", 0) or 0))
        processed = 0
        queued = 0
        while True:
            rows = await self.store.audit_events_after(cursor, limit=500)
            if not rows:
                break
            for audit in rows:
                audit_id = int(audit.get("audit_id", 0) or 0)
                candidate = await self._candidate_from_audit(audit)
                if candidate is not None:
                    _, created = await self.store.queue_notification(
                        event_key=f"audit:{audit_id}",
                        event_type=str(audit.get("event_type") or "audit"),
                        severity=str(candidate["severity"]),
                        subject=str(candidate["subject"]),
                        message=str(candidate["message"]),
                        channels=self.config.channels,
                        actor_key=str(audit.get("actor_key") or "") or None,
                        recommendation_id=(
                            str(audit.get("recommendation_id") or "") or None
                        ),
                        payload={
                            "audit_id": audit_id,
                            "occurred_at": audit.get("created_at"),
                            "details": candidate.get("payload") or {},
                        },
                    )
                    queued += int(created)
                cursor = max(cursor, audit_id)
                processed += 1
            await self.store.set_observability_state(
                self.AUDIT_CURSOR_KEY, {"audit_id": cursor}
            )
            if len(rows) < 500:
                break
        await self.deliver_due(client)
        return {"processed": processed, "queued": queued, "cursor": cursor}

    async def process_instance_health(
        self, apps: list[dict[str, Any]], client: ClientSession
    ) -> int:
        now = datetime.now(timezone.utc).isoformat()
        previous = await self.store.observability_state(self.HEALTH_STATE_KEY) or {}
        updated: dict[str, Any] = dict(previous)
        queued = 0
        for app in apps:
            instance_id = str(app.get("id") or "")
            if not instance_id:
                continue
            healthy = bool(app.get("healthy"))
            prior = previous.get(instance_id)
            prior_healthy = prior.get("healthy") if isinstance(prior, dict) else None
            name = str(app.get("name") or instance_id)
            error = str(
                app.get("error")
                or (app.get("upstream_health") or {}).get("error")
                or "health check failed"
            )
            if prior_healthy is None and not healthy:
                queued += int(
                    await self._queue_health(
                        f"instance-unhealthy:{instance_id}:{now}",
                        "instance_unhealthy",
                        "critical",
                        f"Hotpot instance unhealthy: {name}",
                        f"{name} is unhealthy: {error}",
                        instance_id,
                        app,
                    )
                )
            elif prior_healthy is True and not healthy:
                queued += int(
                    await self._queue_health(
                        f"instance-unhealthy:{instance_id}:{now}",
                        "instance_unhealthy",
                        "critical",
                        f"Hotpot instance unhealthy: {name}",
                        f"{name} changed from healthy to unhealthy: {error}",
                        instance_id,
                        app,
                    )
                )
            elif prior_healthy is False and healthy:
                incident = str((prior or {}).get("changed_at") or now)
                queued += int(
                    await self._queue_health(
                        f"instance-recovered:{instance_id}:{incident}",
                        "instance_recovered",
                        "info",
                        f"Hotpot instance recovered: {name}",
                        f"{name} is healthy again.",
                        instance_id,
                        {"id": instance_id, "name": name, "healthy": True},
                    )
                )
            changed = prior_healthy is None or bool(prior_healthy) != healthy
            updated[instance_id] = {
                "healthy": healthy,
                "changed_at": now if changed else (prior or {}).get("changed_at", now),
                "checked_at": now,
            }
        await self.store.set_observability_state(self.HEALTH_STATE_KEY, updated)
        await self.deliver_due(client)
        return queued

    async def _queue_health(
        self,
        event_key: str,
        event_type: str,
        severity: str,
        subject: str,
        message: str,
        instance_id: str,
        app: dict[str, Any],
    ) -> bool:
        _, created = await self.store.queue_notification(
            event_key=event_key,
            event_type=event_type,
            severity=severity,
            subject=subject,
            message=message,
            channels=self.config.channels,
            payload={"instance_id": instance_id, "app": app},
        )
        return created

    async def record_system_check_failure(
        self, result: dict[str, Any], client: ClientSession
    ) -> bool:
        if str(result.get("status") or "") != "fail":
            return False
        failed = [
            str(item.get("id") or item.get("name") or "unknown")
            for item in result.get("checks") or []
            if isinstance(item, dict) and item.get("status") == "fail"
        ]
        fingerprint = hashlib.sha256(
            "|".join(sorted(failed)).encode("utf-8")
        ).hexdigest()[:16]
        bucket = datetime.now(timezone.utc).strftime("%Y%m%d%H")
        summary = result.get("summary") or {}
        _, created = await self.store.queue_notification(
            event_key=f"system-check-failed:{fingerprint}:{bucket}",
            event_type="system_check_failed",
            severity="critical",
            subject="Hotpot system self-test failed",
            message=(
                f"System self-test reported {int(summary.get('failed', len(failed)) or 0)} "
                f"failure(s): {', '.join(failed) or 'unknown check'}"
            ),
            channels=self.config.channels,
            payload={"result": result},
        )
        await self.deliver_due(client)
        return created

    async def deliver_due(self, client: ClientSession) -> int:
        due = await self.store.due_notifications(
            datetime.now(timezone.utc).isoformat(), limit=50
        )
        delivered = 0
        for notification in due:
            if await self._deliver_one(notification, client):
                delivered += 1
        return delivered

    async def _deliver_one(
        self, notification: dict[str, Any], client: ClientSession
    ) -> bool:
        event_key = str(notification.get("event_key") or "")
        channels = [str(value) for value in notification.get("channels") or []]
        delivery = (
            notification.get("delivery")
            if isinstance(notification.get("delivery"), dict)
            else {}
        )
        outcomes: dict[str, dict[str, Any]] = {}
        for channel in channels:
            current = delivery.get(channel)
            if isinstance(current, dict) and current.get("status") == "sent":
                continue
            try:
                if channel == "webhook":
                    await self._send_webhook(notification, client)
                elif channel == "email":
                    await asyncio.to_thread(self._send_email, notification)
                else:
                    raise RuntimeError(f"unknown notification channel: {channel}")
                outcomes[channel] = {
                    "status": "sent",
                    "at": datetime.now(timezone.utc).isoformat(),
                }
            except Exception as exc:
                outcomes[channel] = {
                    "status": "failed",
                    "error": f"{type(exc).__name__}: {exc}"[:2000],
                    "at": datetime.now(timezone.utc).isoformat(),
                }
        if not outcomes:
            return str(notification.get("status") or "") == "sent"
        failed = any(value.get("status") != "sent" for value in outcomes.values())
        next_attempt = (
            datetime.now(timezone.utc) + timedelta(seconds=self.config.retry_seconds)
        ).isoformat() if failed else None
        updated = await self.store.mark_notification_delivery(
            event_key, outcomes, next_attempt_at=next_attempt
        )
        return bool(updated and updated.get("status") == "sent")

    async def _send_webhook(
        self, notification: dict[str, Any], client: ClientSession
    ) -> None:
        if not self.config.webhook_url:
            raise RuntimeError("webhook URL is not configured")
        payload = {
            "source": "hotpot-dashboard",
            "event_type": notification.get("event_type"),
            "severity": notification.get("severity"),
            "subject": notification.get("subject"),
            "message": notification.get("message"),
            "actor_key": notification.get("actor_key"),
            "recommendation_id": notification.get("recommendation_id"),
            "occurred_at": notification.get("created_at"),
            "details": notification.get("payload") or {},
        }
        headers = {"Content-Type": "application/json"}
        if self.config.webhook_bearer:
            headers["Authorization"] = f"Bearer {self.config.webhook_bearer}"
        async with client.post(
            self.config.webhook_url, json=payload, headers=headers
        ) as response:
            if response.status < 200 or response.status >= 300:
                detail = (await response.text())[:500]
                raise RuntimeError(
                    f"webhook returned HTTP {response.status}: {detail}"
                )

    def _send_email(self, notification: dict[str, Any]) -> None:
        if not self.config.smtp_configured:
            raise RuntimeError("SMTP notification channel is not configured")
        message = EmailMessage()
        message["Subject"] = f"[Hotpot] {notification.get('subject') or 'Dashboard alert'}"
        message["From"] = self.config.smtp_from
        message["To"] = ", ".join(self.config.smtp_to)
        payload = notification.get("payload") or {}
        message.set_content(
            "\n".join(
                [
                    str(notification.get("message") or ""),
                    "",
                    f"Severity: {notification.get('severity')}",
                    f"Event: {notification.get('event_type')}",
                    f"Actor: {notification.get('actor_key') or 'n/a'}",
                    f"Recommendation: {notification.get('recommendation_id') or 'n/a'}",
                    f"Time: {notification.get('created_at')}",
                    "",
                    "Details:",
                    json.dumps(payload, indent=2, sort_keys=True)[:12000],
                ]
            )
        )
        context = ssl.create_default_context()
        if self.config.smtp_ssl:
            server: smtplib.SMTP = smtplib.SMTP_SSL(
                self.config.smtp_host,
                self.config.smtp_port,
                timeout=10,
                context=context,
            )
        else:
            server = smtplib.SMTP(
                self.config.smtp_host, self.config.smtp_port, timeout=10
            )
        try:
            if not self.config.smtp_ssl and self.config.smtp_starttls:
                server.starttls(context=context)
            if self.config.smtp_username:
                server.login(self.config.smtp_username, self.config.smtp_password)
            server.send_message(message)
        finally:
            try:
                server.quit()
            except Exception:
                server.close()
