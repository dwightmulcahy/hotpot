from __future__ import annotations

import asyncio
import html
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
        return bool(
            self.settings.notify_webhook_url
            or (
                self.settings.smtp_host
                and self.settings.smtp_from
                and self.settings.smtp_to
            )
        )

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
                    raise RuntimeError(
                        f"notification webhook returned {response.status}: {body}"
                    )

        if self.settings.smtp_host and self.settings.smtp_from and self.settings.smtp_to:
            await asyncio.to_thread(self._send_email, event)
            delivered.append("email")
        return delivered

    @staticmethod
    def _value(event: dict[str, Any], key: str, default: str = "Unknown") -> str:
        value = event.get(key)
        if value is None or value == "":
            return default
        return str(value)

    @classmethod
    def _label(cls, event: dict[str, Any], key: str, default: str = "Unknown") -> str:
        value = cls._value(event, key, default)
        if value == default:
            return value
        return value.replace("_", " ").replace("-", " ").title()

    @staticmethod
    def _yes_no(value: Any) -> str:
        return "Yes" if bool(value) else "No"

    @classmethod
    def _plain_text(cls, event: dict[str, Any]) -> str:
        level = cls._value(event, "escalation_level", "?")
        raw = json.dumps(event, indent=2, sort_keys=True, ensure_ascii=False)
        lines = [
            f"Hotpot Level {level} Threat Detected",
            "",
            "ATTACKER",
            f"IP:              {cls._value(event, 'client_ip')}",
            f"Actor:           {cls._value(event, 'attacker_key')}",
            f"Score:           {cls._value(event, 'attacker_score')}",
            f"Escalation:      Level {level}",
            f"Observed hits:   {cls._value(event, 'observed_hits')}",
            "",
            "TARGET",
            f"Host:            {cls._value(event, 'host')}",
            f"Path:            {cls._value(event, 'path')}",
            f"Method:          {cls._value(event, 'method')}",
            "",
            "DETECTION",
            f"Category:        {cls._label(event, 'category')}",
            f"Rule:            {cls._label(event, 'rule')}",
            f"Severity:        {cls._value(event, 'severity')}",
            f"Scanner:         {cls._label(event, 'scanner_family')}",
            "",
            "RESPONSE",
            f"Action:          {cls._label(event, 'action')}",
            f"Profile:         {cls._label(event, 'profile')}",
            "",
            "SOURCE",
            f"Client IP source: {cls._label(event, 'client_ip_source')}",
            f"Trusted proxy:    {cls._yes_no(event.get('trusted_proxy'))}",
            f"User agent:       {cls._value(event, 'user_agent')}",
            f"Fingerprint:      {cls._value(event, 'fingerprint')}",
            "",
            "RAW EVENT DETAILS",
            "-----------------",
            raw,
            "",
        ]
        return "\n".join(lines)

    @classmethod
    def _html_email(cls, event: dict[str, Any]) -> str:
        level = cls._value(event, "escalation_level", "?")
        try:
            level_number = int(level)
        except ValueError:
            level_number = 0
        accent = {
            4: "#dc2626",
            3: "#d97706",
            2: "#2563eb",
            1: "#059669",
        }.get(level_number, "#475569")

        def esc(value: Any) -> str:
            return html.escape(str(value), quote=True)

        def row(label: str, value: Any) -> str:
            return (
                '<tr>'
                f'<td style="padding:7px 12px 7px 0;color:#94a3b8;white-space:nowrap;vertical-align:top;font-size:13px;">{esc(label)}</td>'
                f'<td style="padding:7px 0;color:#e5e7eb;font-weight:600;vertical-align:top;font-size:13px;word-break:break-word;">{esc(value)}</td>'
                '</tr>'
            )

        def section(title: str, rows: list[tuple[str, Any]]) -> str:
            rendered = "".join(row(label, value) for label, value in rows)
            return (
                '<div style="margin:0 0 18px 0;padding:16px 18px;background:#111827;border:1px solid #263244;border-radius:10px;">'
                f'<div style="margin:0 0 8px 0;color:#cbd5e1;font-size:12px;font-weight:700;letter-spacing:.08em;text-transform:uppercase;">{esc(title)}</div>'
                f'<table role="presentation" style="width:100%;border-collapse:collapse;">{rendered}</table>'
                '</div>'
            )

        raw = html.escape(
            json.dumps(event, indent=2, sort_keys=True, ensure_ascii=False), quote=False
        )
        category = cls._label(event, "category")
        action = cls._label(event, "action")
        ip = cls._value(event, "client_ip")
        host = cls._value(event, "host")
        path = cls._value(event, "path")

        sections = "".join(
            [
                section(
                    "Attacker",
                    [
                        ("IP", ip),
                        ("Actor", cls._value(event, "attacker_key")),
                        ("Score", cls._value(event, "attacker_score")),
                        ("Escalation", f"Level {level}"),
                        ("Observed hits", cls._value(event, "observed_hits")),
                    ],
                ),
                section(
                    "Target",
                    [
                        ("Host", host),
                        ("Path", path),
                        ("Method", cls._value(event, "method")),
                    ],
                ),
                section(
                    "Detection",
                    [
                        ("Category", category),
                        ("Rule", cls._label(event, "rule")),
                        ("Severity", cls._value(event, "severity")),
                        ("Scanner", cls._label(event, "scanner_family")),
                    ],
                ),
                section(
                    "Response",
                    [
                        ("Action", action),
                        ("Profile", cls._label(event, "profile")),
                    ],
                ),
                section(
                    "Source",
                    [
                        ("Client IP source", cls._label(event, "client_ip_source")),
                        ("Trusted proxy", cls._yes_no(event.get("trusted_proxy"))),
                        ("User agent", cls._value(event, "user_agent")),
                        ("Fingerprint", cls._value(event, "fingerprint")),
                    ],
                ),
            ]
        )

        return f"""<!doctype html>
<html>
  <body style="margin:0;padding:0;background:#0b1020;color:#e5e7eb;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;">
    <div style="max-width:720px;margin:0 auto;padding:24px 14px;">
      <div style="overflow:hidden;border:1px solid #263244;border-radius:14px;background:#0f172a;box-shadow:0 12px 30px rgba(0,0,0,.22);">
        <div style="padding:22px 24px;background:{accent};color:#fff;">
          <div style="font-size:12px;font-weight:700;letter-spacing:.09em;text-transform:uppercase;opacity:.9;">Hotpot security alert</div>
          <div style="margin-top:4px;font-size:24px;font-weight:800;line-height:1.2;">Level {esc(level)} Threat Detected</div>
          <div style="margin-top:9px;font-size:14px;line-height:1.5;opacity:.95;">{esc(ip)} · {esc(category)} · {esc(action)}</div>
        </div>
        <div style="padding:22px 22px 10px 22px;">
          <div style="margin:0 0 18px 0;padding:14px 16px;background:#172033;border-radius:10px;border-left:4px solid {accent};font-size:14px;line-height:1.55;">
            Hotpot observed <strong>{esc(cls._value(event, 'observed_hits'))}</strong> hit(s) from <strong>{esc(ip)}</strong> and responded with <strong>{esc(action)}</strong> while the actor probed <strong>{esc(host)}{esc(path)}</strong>.
          </div>
          {sections}
          <div style="margin:0 0 18px 0;padding:16px 18px;background:#0b1220;border:1px solid #263244;border-radius:10px;">
            <div style="margin:0 0 10px 0;color:#94a3b8;font-size:12px;font-weight:700;letter-spacing:.08em;text-transform:uppercase;">Raw event details</div>
            <pre style="margin:0;white-space:pre-wrap;word-break:break-word;color:#cbd5e1;font:12px/1.5 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;">{raw}</pre>
          </div>
          <div style="padding:0 2px 16px 2px;color:#64748b;font-size:11px;line-height:1.5;">Generated automatically by Hotpot. Raw event details are included for troubleshooting and audit purposes.</div>
        </div>
      </div>
    </div>
  </body>
</html>
"""

    def _build_email(self, event: dict[str, Any]) -> EmailMessage:
        message = EmailMessage()
        level = self._value(event, "escalation_level", "?")
        ip = self._value(event, "client_ip")
        category = self._label(event, "category")
        message["Subject"] = f"[Hotpot] L{level} · {ip} · {category}"
        message["From"] = self.settings.smtp_from
        message["To"] = ", ".join(self.settings.smtp_to)
        message.set_content(self._plain_text(event))
        message.add_alternative(self._html_email(event), subtype="html")
        return message

    def _send_email(self, event: dict[str, Any]) -> None:
        message = self._build_email(event)

        with smtplib.SMTP(
            self.settings.smtp_host, self.settings.smtp_port, timeout=15
        ) as smtp:
            smtp.ehlo()
            if self.settings.smtp_starttls:
                smtp.starttls()
                smtp.ehlo()
            if self.settings.smtp_username:
                smtp.login(self.settings.smtp_username, self.settings.smtp_password or "")
            smtp.send_message(message)
