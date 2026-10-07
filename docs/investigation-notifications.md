# Investigation timeline and notification center

Hotpot combines retained probe telemetry and durable response/audit events into one per-actor investigation timeline. Open any threat in the dashboard drawer to see the sequence that led from probing to escalation and, when applicable, recommendation, approval, Cloudflare enforcement, reconciliation, and removal.

## Timeline

`GET /api/attacker?key=<actor>` now includes a `timeline` array in addition to the existing attacker snapshot. The timeline merges:

- retained HTTP probes, including app, path, category, scanner, action, severity, score, and suppressed-request counts
- synthetic escalation markers when retained activity rises to L2, L3, or L4
- durable response audit entries such as recommendation, approval, apply/failure, removal/failure, and reconciliation changes
- the authenticated dashboard principal/session attribution for manual actions when available

Raw-event retention still applies to probe entries. Durable enforcement/audit entries remain available after raw probes age out according to their own database lifecycle.

## Notification center

Important operational/security events are written to `dashboard_notification_log` in `dashboard.sqlite3`. This local notification history is recorded even when external delivery is disabled. It appears in **Operations → Notification center**.

Hotpot intentionally does **not** notify for routine L1/L2 scanner noise. Notification candidates are limited to:

- L4 block/long-block recommendations
- high-confidence L3 managed-challenge recommendations
- Cloudflare enforcement applied
- Cloudflare apply failure
- automatic/manual rule-removal failure
- reconciliation drift, missing rules, or Cloudflare read errors
- orphaned Hotpot Cloudflare rules
- protected instance unhealthy transitions and recovery
- failed manual system self-tests

When notification support is first deployed, Hotpot seeds its audit cursor at the current audit high-water mark so it does not send a burst of historical enforcement messages. New meaningful events are processed after that point.

## Delivery

External notification delivery is opt-in:

```dotenv
HOTPOT_DASHBOARD_NOTIFICATIONS_ENABLED=true
HOTPOT_DASHBOARD_NOTIFY_RETRY_SECONDS=300
```

If delivery is disabled or no channel is configured, meaningful events are still stored locally with status `recorded`.

### Webhook

```dotenv
HOTPOT_DASHBOARD_NOTIFY_WEBHOOK_URL=https://example.invalid/hotpot
HOTPOT_DASHBOARD_NOTIFY_WEBHOOK_BEARER=
# or HOTPOT_DASHBOARD_NOTIFY_WEBHOOK_BEARER_FILE=/run/secrets/dashboard_webhook_bearer
```

The webhook receives JSON similar to:

```json
{
  "source": "hotpot-dashboard",
  "event_type": "reconciliation_issue",
  "severity": "warning",
  "subject": "Cloudflare reconciliation drifted for 203.0.113.8",
  "message": "Cloudflare reconciliation changed from healthy to drifted",
  "actor_key": "203.0.113.8",
  "recommendation_id": "...",
  "occurred_at": "2026-10-07T12:00:00+00:00",
  "details": {}
}
```

### Email / SMTP

```dotenv
HOTPOT_DASHBOARD_SMTP_HOST=smtp.example.com
HOTPOT_DASHBOARD_SMTP_PORT=587
HOTPOT_DASHBOARD_SMTP_STARTTLS=true
HOTPOT_DASHBOARD_SMTP_SSL=false
HOTPOT_DASHBOARD_SMTP_USERNAME=
HOTPOT_DASHBOARD_SMTP_PASSWORD=
# or HOTPOT_DASHBOARD_SMTP_PASSWORD_FILE=/run/secrets/dashboard_smtp_password
HOTPOT_DASHBOARD_SMTP_FROM=hotpot@example.com
HOTPOT_DASHBOARD_SMTP_TO=admin@example.com,security@example.com
```

For implicit-TLS SMTP (commonly port 465), set `HOTPOT_DASHBOARD_SMTP_SSL=true`. `STARTTLS` is ignored when implicit TLS is selected.

## Retry and deduplication

Every meaningful event has a stable notification key. Audit-backed alerts use the durable audit ID, so dashboard refreshes cannot create duplicate messages. Successful channels are remembered individually; if email succeeds and a webhook fails, the retry sends only the failed webhook rather than duplicating the email.

Failed deliveries retry after `HOTPOT_DASHBOARD_NOTIFY_RETRY_SECONDS` (default 300 seconds). The Notification center shows delivery state and the latest error without exposing webhook bearer tokens or SMTP passwords.

Instance health notifications are transition-based rather than refresh-based, so one unhealthy period produces one alert plus one recovery message instead of a message every 15 seconds.

Failed system-check notifications are fingerprinted and rate-deduplicated to one matching alert per hour.

## API

Authenticated dashboard clients can read recent notification state:

```text
GET /api/notifications
GET /api/notifications?limit=30
```

The response includes public channel/configuration status and recent local notification records. Secret values are never returned.
