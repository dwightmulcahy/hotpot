# Dashboard API v1 and campaign investigation

Hotpot dashboard API v1 provides a stable envelope and explicit identity field names for new integrations while keeping the existing `/api/*` endpoints available for compatibility.

## Response envelope

Successful v1 responses use:

```json
{
  "schema_version": 1,
  "resource": "campaign",
  "generated_at": "2026-10-08T12:00:00+00:00",
  "data": {}
}
```

Responses also include `X-Hotpot-API-Version: 1` and `Cache-Control: no-store`.

The browser session bootstrap remains `GET /api/session` because that endpoint issues the signed dashboard session cookie. It is intentionally not wrapped by `/api/v1/`.

## Identity model

New v1 responses use these names consistently:

- `actor_key`: stable scoring and investigation identity. Examples include an IP actor or `cf-worker:<zone>`.
- `observed_ip`: network address observed on the request/event. This is distinct from the actor identity.
- `source_type`: origin of the actor identity, such as `ip` or a Cloudflare Worker identity.
- `worker_zone`: Cloudflare Worker upstream zone when known.
- `campaign_id`: observational identity for a distributed scanning campaign.

Historical `ip`, `client_ip`, and `identity_key` fields are normalized out of v1 payloads. Existing `/api/*` responses are unchanged for compatibility.

## Read endpoints

- `GET /api/v1/meta`
- `GET /api/v1/overview`
- `GET /api/v1/attackers/{actor_key}`
- `GET /api/v1/network`
- `GET /api/v1/campaigns`
- `GET /api/v1/campaigns/{campaign_id}`
- `GET /api/v1/recommendations`
- `GET /api/v1/recommendation`
- `GET /api/v1/audit`
- `GET /api/v1/notifications`
- `GET /api/v1/enforcement/cleanup-jobs`

The existing dashboard also uses `GET /api/campaign/{campaign_id}` as a compatibility endpoint for the campaign investigation drawer.

## Action endpoints

State-changing v1 routes preserve the same signed-session, CSRF, rate-limit, and `X-Hotpot-Action` requirements as their legacy equivalents:

- `POST /api/v1/notifications/test`
- `POST /api/v1/recommendations/{id}/dismiss`
- `POST /api/v1/recommendations/{id}/approve`
- `POST /api/v1/recommendations/{id}/remove`
- `POST /api/v1/recommendations/{id}/repair`
- `POST /api/v1/enforcement/orphans/remove`
- `POST /api/v1/enforcement/reconcile`
- `POST /api/v1/system-check`

## Campaign investigation

The Threats view makes each distributed campaign row clickable. The investigation drawer shows participating actors and observed IPs, affected apps, fingerprints, scanner/category evidence, top paths, and a retained event timeline. Clicking a participating actor switches to the existing actor investigation view.

Campaign correlation is deliberately observational. It does **not** change actor scores, create response recommendations, approve Cloudflare rules, or use ASN/provider/geography as scoring inputs.

Campaign notifications are deduplicated by `campaign_id` and severity band. A campaign can therefore produce one warning and later one critical escalation, but ordinary dashboard refreshes do not resend unchanged alerts. Current meaningful-alert thresholds are:

- critical: campaign reaches escalation level 4;
- warning: level 3 with at least 3 actors or 10 hits;
- warning: at least 5 actors and 20 hits.

These notifications use the existing dashboard notification routing policy and remain informational; enforcement continues to be actor-level and approval-driven.
