# Threat-response recommendations and approved Cloudflare enforcement

Hotpot's dashboard turns active attacker intelligence into reviewable response recommendations. Recommendations never enforce automatically. A dashboard user must explicitly approve an enforceable recommendation before Hotpot creates a temporary Cloudflare WAF custom rule.

Approved rules are persisted with the recommendation, scoped to the protected hostnames that actor targeted, and removed automatically when the approved duration expires. A dashboard restart does not lose the expiry/removal state.

## Default policy

The dashboard evaluates retained events from a 24-hour active window and suppresses recommendations for actors not seen for 6 hours. The default mapping is:

- Global L1: observe only (not persisted as a recommendation)
- Global L2: watch
- Global L3: recommend a temporary managed challenge (normally 6 hours)
- Global L4: recommend a 24-hour temporary block
- repeated/high-volume L4 behavior: recommend a longer temporary block (normally 7 days)

The decision records the active score, hits, applications, categories, severity, recency, lifetime peak, lifetime hits, source type, Worker zone, top paths, and last-known network attribution. ASN/provider/country are context only and do not raise the recommendation level.

## Safety exclusions

The dashboard collects each Hotpot instance's configured allowlist and trusted-proxy CIDRs from `/_hotpot/status`. An actor whose observed client IP matches either set is never approved for challenge/block action. Approval re-evaluates the current actor and safety policy instead of trusting an old recommendation snapshot.

Cloudflare's shared cross-zone Worker address (`2a06:98c0:3600::103`) is never used as an enforcement IP when a trustworthy Worker zone is unavailable. For a known Worker zone, Hotpot creates a WAF expression using `cf.worker.upstream_zone`, which is the Cloudflare field available during WAF rule evaluation.

Rules are also hostname-scoped. If an actor targeted `hvac.bytemeloser.com`, approving that recommendation does not automatically block the same actor from every hostname in the `bytemeloser.com` zone unless those other protected instances were also part of the recommendation.

## Lifecycle

Recommendations and enforcement metadata are persisted in `dashboard.sqlite3`:

- `pending`: waiting for review
- `dismissed`: suppressed for the configured dismissal cooldown
- `approved`: user approved; Cloudflare rule creation is pending/recoverable
- `applied`: Cloudflare rule(s) are active
- `failed`: an approved Cloudflare apply attempt failed
- `expired`: recommendation expired or active Cloudflare rules were successfully removed

Approval is durable. If Hotpot stops after recording `approved` but before completing the Cloudflare request, the dashboard refresh loop resumes the apply operation. Rule refs are deterministic, so a crash after Cloudflare accepted the rule but before SQLite was updated does not intentionally create a duplicate rule.

When `enforcement_expires_at` is reached, the dashboard deletes each stored Cloudflare rule. If deletion fails, the recommendation remains `applied`, the error is recorded, and later refreshes retry removal. A Cloudflare `404` during deletion is treated as already removed.

The dashboard also provides **Remove now** for an applied enforcement. If the actor is still active and still meets policy after early removal, a new recommendation can appear later. Active-rule cards show a live relative countdown while retaining the absolute expiration time in the detail/tooltip.

## Cloudflare reconciliation

Hotpot periodically performs a **read-only reconciliation** between applied enforcement stored in `dashboard.sqlite3` and the live Cloudflare custom-WAF entrypoint. Reconciliation never creates, repairs, changes, or deletes a rule by itself.

For each applied recommendation Hotpot verifies the deterministic rule reference, Cloudflare rule ID, ruleset ID, action, expression, and enabled state. The dashboard reports:

- `healthy`: the live Cloudflare rule matches the persisted Hotpot rule
- `drifted`: the rule exists but was changed, disabled, or moved to a different ID/ruleset
- `missing`: Hotpot believes the rule is applied but the expected rule is absent
- `error`: Cloudflare could not be read for that rule/zone
- `orphaned`: a `hotpot_...` rule exists in a configured or previously-used zone but no current applied recommendation owns it

The default reconciliation interval is 300 seconds and can be changed with `HOTPOT_CLOUDFLARE_RECONCILE_SECONDS` (minimum 60 seconds). The Enforcement tab also has **Reconcile now**, which performs the same read-only comparison immediately.

A successful approval triggers an immediate reconciliation so the dashboard can confirm that the newly applied rule exists. A successful manual removal also triggers a fresh read.

## Durable enforcement audit trail

Enforcement lifecycle events are written to the additive `response_audit_log` table in `dashboard.sqlite3`. The audit trail records recommendation creation, approval, apply success/failure, manual or automatic removal, removal failures, reconciliation issues/resolution, and orphan detection/resolution.

Dashboard-triggered actions also record the authenticated Basic username, signed dashboard session ID, and `source=dashboard`. Automatic lifecycle activity remains `source=system`. This makes manual approvals/removals/reconciliation distinguishable from background processing.

Audit entries store timestamps, recommendation/actor references where applicable, a human-readable message, and bounded JSON details such as Cloudflare rule identifiers. Repeated reconciliation checks do not continuously duplicate the same issue in the audit log; a new audit event is written when the reconciliation state changes.

The Enforcement tab reads the permanent audit trail from `/api/audit` instead of reconstructing history from current recommendation states.

## Operational system self-test

The Operations tab includes **Run system check**. It is non-destructive and checks:

- authenticated `/_hotpot/status` access and health for every protected instance
- authenticated event API access for every protected instance
- SQLite `quick_check` plus a transaction that is rolled back after verifying write access
- configured GeoIP databases and load errors
- Cloudflare target mappings
- read-only access to each configured Cloudflare custom-WAF entrypoint; a zone with no entrypoint yet is still considered accessible
- recorded housekeeping state and maintenance errors

The system check does not create a test WAF rule and does not change Cloudflare configuration.

## Cloudflare implementation

Hotpot uses the zone Rulesets API and the `http_request_firewall_custom` phase. It creates one temporary custom rule per affected Cloudflare zone, while combining all targeted configured hostnames in that zone into the rule expression.

Actions map as follows:

- `recommend_challenge` -> Cloudflare `managed_challenge`
- `recommend_block` -> Cloudflare `block`
- `recommend_long_block` -> Cloudflare `block`

IP actors use an `ip.src` expression. Known Cloudflare Worker actors use `cf.worker.upstream_zone`. Hotpot never uses country, provider, or ASN as an enforcement selector.

The API token should be restricted to the required zones and have **Zone WAF Write** permission. Keep it only in the dashboard environment or use `HOTPOT_CLOUDFLARE_API_TOKEN_FILE`; never put it in the repository.

## Dashboard action security

The initial dashboard login remains HTTP Basic for compatibility. Loading the dashboard issues a signed, expiring session cookie plus a per-session CSRF token. Read-only APIs accept either the signed session or the existing Basic credentials.

State-changing endpoints require:

1. a current signed dashboard session cookie
2. the matching `X-Hotpot-CSRF` token
3. the expected `X-Hotpot-Action` header

The browser dashboard supplies the CSRF token automatically. Mutation requests are rate-limited per session. Reload the dashboard to renew an expired session. See `docs/dashboard-security.md` for `_FILE` secret support and session settings.

## API

```text
GET  /api/session
GET  /api/recommendations
GET  /api/recommendations?status=applied
GET  /api/recommendations?status=failed
GET  /api/recommendation?id=<recommendation_id>
GET  /api/audit
GET  /api/audit?recommendation_id=<recommendation_id>&limit=100

POST /api/recommendation/<recommendation_id>/dismiss
     X-Hotpot-Action: dismiss
     X-Hotpot-CSRF: <session csrf token>

POST /api/recommendation/<recommendation_id>/approve
     X-Hotpot-Action: approve
     X-Hotpot-CSRF: <session csrf token>

POST /api/recommendation/<recommendation_id>/remove
     X-Hotpot-Action: remove
     X-Hotpot-CSRF: <session csrf token>

POST /api/enforcement/reconcile
     X-Hotpot-Action: reconcile
     X-Hotpot-CSRF: <session csrf token>

POST /api/system-check
     X-Hotpot-Action: system-check
     X-Hotpot-CSRF: <session csrf token>
```

There is no automatic approval endpoint. Hotpot will automatically **remove** an already approved/applied rule at expiry, but it will not automatically approve or create a new enforcement rule. Reconciliation is detection-only; it does not automatically repair drift or remove orphaned rules.

## Configuration

Recommendation settings:

```dotenv
HOTPOT_RESPONSE_ENABLED=true
HOTPOT_RESPONSE_ACTIVE_WINDOW_HOURS=24
HOTPOT_RESPONSE_STALE_MINUTES=360
HOTPOT_RESPONSE_RECOMMENDATION_TTL_HOURS=24
HOTPOT_RESPONSE_DISMISS_HOURS=24
```

Cloudflare enforcement is opt-in and disabled by default:

```dotenv
HOTPOT_CLOUDFLARE_ENFORCEMENT_ENABLED=false
HOTPOT_CLOUDFLARE_API_TOKEN=REPLACE_WITH_ZONE_WAF_WRITE_TOKEN
# or HOTPOT_CLOUDFLARE_API_TOKEN_FILE=/run/secrets/cloudflare_api_token
HOTPOT_CLOUDFLARE_RECONCILE_SECONDS=300
HOTPOT_CLOUDFLARE_TARGETS={"monkeyhead":{"zone_id":"ZONE_ID","hosts":["www.monkeyheadbrewing.com"]},"watersolver":{"zone_id":"ZONE_ID","hosts":["brewwatersolver.com","www.brewwatersolver.com"]},"hvac":{"zone_id":"ZONE_ID","hosts":["hvac.bytemeloser.com"]},"tapmenu":{"zone_id":"ZONE_ID","hosts":["tapmenu.bytemeloser.com"]}}
```

`HOTPOT_CLOUDFLARE_TARGETS` keys must match the `id` values in `HOTPOT_DASHBOARD_INSTANCES`. Multiple instances may use the same `zone_id`; Hotpot deduplicates them into one rule for that zone when appropriate.

Enable enforcement only after the token and target mapping are complete:

```dotenv
HOTPOT_CLOUDFLARE_ENFORCEMENT_ENABLED=true
```

No database reset is required. All reconciliation, audit, and dashboard-security migrations are additive.
