from __future__ import annotations

import asyncio
import json
import smtplib
from email.message import EmailMessage
from typing import Any

from aiohttp import ClientSession

from .config import Settings


class Notifier:
    def __init__(self, settings: Settings):
        self.settings = settings

    @property
    def enabled(self) -> bool:
        return bool(self.settings.notify_webhook_url or (self.settings.smtp_host and self.settings.smtp_from and self.settings.smtp_to))

    async def send(self, client: ClientSession, event: dict[str, Any]) -> list[str]:
        delivered: list[str] = []
        if self.settings.notify_webhook_url:
            headers = {"Content-Type": "application/json"}
            if self.settings.notify_webhook_bearer:
                headers["Authorization"] = f"Bearer {self.settings.notify_webhook_bearer}"
            async with client.post(
                self.settings.notify_webhook_url,
                json={"source": "hotpot", "event": event},
                headers=headers,
            ) as response:
                if 200 <= response.status < 300:
                    delivered.append("webhook")
                else:
                    body = (await response.text())[:200]
                    raise RuntimeError(f"notification webhook returned {response.status}: {body}")

        if self.settings.smtp_host and self.settings.smtp_from and self.settings.smtp_to:
            await asyncio.to_thread(self._send_email, event)
            delivered.append("email")
        return delivered

    def _send_email(self, event: dict[str, Any]) -> None:
        message = EmailMessage()
        level = event.get("escalation_level", "?")
        ip = event.get("client_ip", "unknown")
        message["Subject"] = f"[Hotpot] Level {level} attacker: {ip}"
        message["From"] = self.settings.smtp_from
        message["To"] = ", ".join(self.settings.smtp_to)
        message.set_content(
            "Hotpot escalation alert\n\n"
            + json.dumps(event, indent=2, sort_keys=True, ensure_ascii=False)
        )

        with smtplib.SMTP(self.settings.smtp_host, self.settings.smtp_port, timeout=15) as smtp:
            smtp.ehlo()
            if self.settings.smtp_starttls:
                smtp.starttls()
                smtp.ehlo()
            if self.settings.smtp_username:
                smtp.login(self.settings.smtp_username, self.settings.smtp_password or "")
            smtp.send_message(message)
