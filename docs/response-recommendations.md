# Threat-response recommendations and approved Cloudflare enforcement

Hotpot's dashboard turns active attacker intelligence into reviewable response recommendations. Manual approval is always available. Optional guarded automation can be enabled in stages for selected high-confidence challenge/block recommendations; 7-day zone-wide long blocks always remain manual.

Applied rules are persisted with the recommendation and removed automatically when their duration expires. A dashboard restart does not lose the expiry/removal state.

See [`auto-response.md`](auto-response.md) for the staged automatic-response rollout and guardrails.

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

Short challenges and 24-hour blocks are hostname-scoped Custom WAF rules. Long IP blocks use Cloudflare IP Access Rules and are zone-wide, so Hotpot keeps them manual even when guarded automation is active.

## Lifecycle

Recommendations and enforcement metadata are persisted in `dashboard.sqlite3`:

- `pending`: waiting for review or guarded automation
- `dismissed`: suppressed for the configured dismissal cooldown
- `approved`: user or guarded automation approved; Cloudflare rule creation is pending/recoverable
- `applied`: Cloudflare rule(s) are active
- `failed`: an approved apply attempt failed
- `expired`: recommendation expired or active Cloudflare rules were successfully removed

Approval is durable. If Hotpot stops after recording `approved` but before completing the Cloudflare request, the dashboard refresh loop resumes the apply operation. Rule refs are deterministic, so a crash after Cloudflare accepted the rule but before SQLite was updated does not intentionally create a duplicate rule.

When `enforcement_expires_at` is reached, the dashboard deletes each stored Cloudflare rule. If deletion fails, the recommendation remains `applied`, the error is recorded, and later refreshes retry removal. A Cloudflare `404` during deletion is treated as already removed.

The dashboard also provides **Remove now** for an applied enforcement. If the actor is still active and still meets policy after early removal, a new recommendation can appear later. Active-rule cards show a live relative countdown while retaining the absolute expiration time in the detail/tooltip.

## Guarded automatic response

The dashboard supports four stages:

- `off`: kill switch; all new enforcement requires manual approval
- `shadow`: records what would be automated but performs no Cloudflare writes
- `challenge`: automatically applies eligible high-confidence 6-hour managed challenges only
- `active`: also applies eligible high-confidence 24-hour L4 hostname-scoped blocks

Automatic response is fail-closed. It requires a direct globally routable IP, high confidence, multiple independent malicious signals, a healthy Cloudflare reconciliation, available rollback/removal capability, no policy suppression, and no verified legitimate IPverse bot match. It also has hourly/daily action caps.

`recommend_long_block` is never automated.

The dashboard persists mode changes in `dashboard.sqlite3`. Switching to `off` is the runtime kill switch and prevents the next automatic write even when an evaluation cycle is already running. An already-started Cloudflare transaction is allowed to finish rather than being cancelled mid-write.

## Cloudflare reconciliation

Hotpot periodically performs a **read-only reconciliation** between applied enforcement stored in `dashboard.sqlite3` and live Cloudflare state. Reconciliation never creates, repairs, changes, or deletes a rule by itself.

For each applied recommendation Hotpot verifies the expected provider-specific Cloudflare state and reports:

- `healthy`: live Cloudflare state matches persisted Hotpot state
- `drifted`: a rule exists but differs from the persisted action/target/expiry
- `missing`: Hotpot believes enforcement is applied but the expected rule is absent
- `error`: Cloudflare could not be read for that rule/zone
- `orphaned`: a Hotpot-owned rule exists but no current applied recommendation owns it

The default reconciliation interval is 300 seconds and can be changed with `HOTPOT_CLOUDFLARE_RECONCILE_SECONDS` (minimum 60 seconds). The Enforcement tab also has **Reconcile now**, which performs the same read-only comparison immediately.

A successful apply triggers an immediate reconciliation so the dashboard can confirm the new Cloudflare state. A successful manual removal also triggers a fresh read.

Guarded automation forces a healthy reconciliation immediately before automatic Cloudflare writes. Drift, missing rules, read errors, orphaned Hotpot rules, or pending transactional rollback cleanup opens the automation circuit breaker.

## Durable enforcement audit trail

Enforcement lifecycle events are written to the additive `response_audit_log` table in `dashboard.sqlite3`. The audit trail records recommendation creation, approval, apply success/failure, manual or automatic removal, automatic-response shadow/approval/application events, mode changes, reconciliation issues/resolution, and orphan detection/resolution.

Dashboard-triggered actions record the authenticated username and signed dashboard session context. Automatic lifecycle activity records `principal=system`, making manual and automatic actions distinguishable.

Audit entries store timestamps, recommendation/actor references where applicable, a human-readable message, and bounded JSON details such as Cloudflare rule identifiers. Repeated reconciliation checks do not continuously duplicate the same issue in the audit log; a new audit event is written when the reconciliation state changes.

The Enforcement tab reads the permanent audit trail from `/api/audit` instead of reconstructing history from current recommendation states.

## Operational system self-test

The Operations tab includes **Run system check**. It is non-destructive and checks:

- authenticated `/_hotpot/status` access and health for every protected instance
- authenticated event API access for every protected instance
- SQLite `quick_check` plus a transaction that is rolled back after verifying write access
- configured GeoIP databases and load errors
- Cloudflare target mappings
- read-only access to configured Cloudflare enforcement entrypoints
- recorded housekeeping state and maintenance errors

The system check does not create a test Cloudflare rule and does not change Cloudflare configuration.

## Cloudflare implementation

Hotpot uses two Cloudflare enforcement mechanisms on the Free-plan-friendly path:

- `recommend_challenge` -> hostname-scoped Custom WAF `managed_challenge`
- `recommend_block` -> hostname-scoped Custom WAF `block`
- `recommend_long_block` targeting an IP -> zone-wide IP Access Rule `block`
- `recommend_long_block` targeting a known Worker zone -> hostname-scoped Custom WAF `block`

IP actors use their IP target. Known Cloudflare Worker actors use `cf.worker.upstream_zone` for Custom WAF enforcement. Hotpot never uses country, provider, or ASN as an enforcement selector.

The API token should be restricted to the required zones and include the permissions needed for Custom WAF rules plus Firewall/IP Access Rules when long IP blocks are used. Keep it only in the dashboard environment or use `HOTPOT_CLOUDFLARE_API_TOKEN_FILE`; never put it in the repository.

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
GET  /api/auto-response

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

POST /api/auto-response/mode
     X-Hotpot-Action: auto-response-mode
     X-Hotpot-CSRF: <session csrf token>
     Content-Type: application/json
     {"mode":"off|shadow|challenge|active"}

POST /api/system-check
     X-Hotpot-Action: system-check
     X-Hotpot-CSRF: <session csrf token>
```

Hotpot automatically removes applied enforcement at expiry. Reconciliation remains detection-only; it does not automatically repair drift or remove orphaned rules.

## Configuration

Recommendation settings:

```dotenv
HOTPOT_RESPONSE_ENABLED=true
HOTPOT_RESPONSE_ACTIVE_WINDOW_HOURS=24
HOTPOT_RESPONSE_STALE_MINUTES=360
HOTPOT_RESPONSE_RECOMMENDATION_TTL_HOURS=24
HOTPOT_RESPONSE_DISMISS_HOURS=24
```

Guarded automatic-response settings:

```dotenv
HOTPOT_AUTO_RESPONSE_MODE=off
HOTPOT_AUTO_RESPONSE_CYCLE_SECONDS=30
HOTPOT_AUTO_RESPONSE_MAX_PER_HOUR=5
HOTPOT_AUTO_RESPONSE_MAX_PER_DAY=20
HOTPOT_AUTO_RESPONSE_MIN_CHALLENGE_SIGNALS=2
HOTPOT_AUTO_RESPONSE_MIN_BLOCK_SIGNALS=3
HOTPOT_AUTO_RESPONSE_EXCLUDE_VERIFIED_BOTS=true
```

Cloudflare enforcement is opt-in and disabled by default:

```dotenv
HOTPOT_CLOUDFLARE_ENFORCEMENT_ENABLED=false
HOTPOT_CLOUDFLARE_API_TOKEN=REPLACE_WITH_CLOUDFLARE_WRITE_TOKEN
# or HOTPOT_CLOUDFLARE_API_TOKEN_FILE=/run/secrets/cloudflare_api_token
HOTPOT_CLOUDFLARE_RECONCILE_SECONDS=300
HOTPOT_CLOUDFLARE_TARGETS={"monkeyhead":{"zone_id":"ZONE_ID","hosts":["www.monkeyheadbrewing.com"]},"watersolver":{"zone_id":"ZONE_ID","hosts":["brewwatersolver.com","www.brewwatersolver.com"]},"hvac":{"zone_id":"ZONE_ID","hosts":["hvac.bytemeloser.com"]},"tapmenu":{"zone_id":"ZONE_ID","hosts":["tapmenu.bytemeloser.com"]}}
```

`HOTPOT_CLOUDFLARE_TARGETS` keys must match the `id` values in `HOTPOT_DASHBOARD_INSTANCES`. Multiple instances may use the same `zone_id`; Hotpot deduplicates them into one rule for that zone when appropriate.

Enable Cloudflare enforcement only after the token and target mapping are complete:

```dotenv
HOTPOT_CLOUDFLARE_ENFORCEMENT_ENABLED=true
```

No database reset is required. All automatic-response, reconciliation, audit, and dashboard-security migrations are additive.
