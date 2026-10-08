from __future__ import annotations

import html
from typing import Any

from .notifications import Notifier


class DigestAwareNotifier(Notifier):
    """Render cooldown digests clearly while preserving normal Hotpot alerts."""

    @classmethod
    def _plain_text(cls, event: dict[str, Any]) -> str:
        count = int(event.get("digest_count", 0) or 0)
        if count <= 0:
            return super()._plain_text(event)
        actor = cls._value(event, "attacker_key")
        level = cls._value(event, "escalation_level", "?")
        return "\n".join(
            [
                f"Hotpot Level {level} Activity Digest",
                "",
                f"Actor:          {actor}",
                f"Suppressed:     {count} repeated alert(s)",
                f"First seen:     {cls._value(event, 'digest_first_seen')}",
                f"Last seen:      {cls._value(event, 'digest_last_seen')}",
                f"Digest window:  {cls._value(event, 'digest_window_seconds')} seconds",
                "",
                "Hotpot sent the first qualifying alert immediately. These repeated alerts",
                "were suppressed during the cooldown and summarized here to reduce email noise.",
                "Actor scoring, deception behavior, and enforcement decisions were not changed",
                "by notification suppression.",
                "",
            ]
        )

    @classmethod
    def _html_email(cls, event: dict[str, Any]) -> str:
        count = int(event.get("digest_count", 0) or 0)
        if count <= 0:
            return super()._html_email(event)

        def esc(value: Any) -> str:
            return html.escape(str(value), quote=False)

        actor = cls._value(event, "attacker_key")
        level = cls._value(event, "escalation_level", "?")
        first_seen = cls._value(event, "digest_first_seen")
        last_seen = cls._value(event, "digest_last_seen")
        window = cls._value(event, "digest_window_seconds")
        return f"""<!doctype html>
<html><body style="margin:0;padding:0;background:#0b1020;color:#e5e7eb;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;">
<div style="max-width:680px;margin:0 auto;padding:24px 14px"><div style="border:1px solid #263244;border-radius:14px;background:#0f172a;overflow:hidden">
<div style="padding:22px 24px;background:#7c3aed;color:#fff"><div style="font-size:12px;font-weight:700;text-transform:uppercase;letter-spacing:.08em">Hotpot security digest</div><div style="font-size:24px;font-weight:800;margin-top:4px">Level {esc(level)} repeated activity</div></div>
<div style="padding:22px"><div style="padding:16px;background:#172033;border-radius:10px;border-left:4px solid #7c3aed;line-height:1.6"><strong>{count}</strong> repeated alert(s) for <strong>{esc(actor)}</strong> were suppressed after the first immediate alert and are summarized here.</div>
<table role="presentation" style="width:100%;border-collapse:collapse;margin-top:18px;font-size:13px"><tr><td style="padding:7px;color:#94a3b8">Actor</td><td style="padding:7px;font-weight:600">{esc(actor)}</td></tr><tr><td style="padding:7px;color:#94a3b8">First suppressed</td><td style="padding:7px">{esc(first_seen)}</td></tr><tr><td style="padding:7px;color:#94a3b8">Last suppressed</td><td style="padding:7px">{esc(last_seen)}</td></tr><tr><td style="padding:7px;color:#94a3b8">Digest window</td><td style="padding:7px">{esc(window)} seconds</td></tr></table>
<div style="margin-top:18px;color:#94a3b8;font-size:12px;line-height:1.55">Notification suppression only reduces repeated messages. It does not change Hotpot scoring, deception, tarpit behavior, or Cloudflare enforcement decisions.</div></div></div></div>
</body></html>"""
