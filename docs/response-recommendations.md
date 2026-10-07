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

The dashboard also provides **Remove now** for an applied enforcement. If the actor is still active and still meets policy after early removal, a new recommendation can appear later.

## Cloudflare implementation

Hotpot uses the zone Rulesets API and the `http_request_firewall_custom` phase. It creates one temporary custom rule per affected Cloudflare zone, while combining all targeted configured hostnames in that zone into the rule expression.

Actions map as follows:

- `recommend_challenge` -> Cloudflare `managed_challenge`
- `recommend_block` -> Cloudflare `block`
- `recommend_long_block` -> Cloudflare `block`

IP actors use an `ip.src` expression. Known Cloudflare Worker actors use `cf.worker.upstream_zone`. Hotpot never uses country, provider, or ASN as an enforcement selector.

The API token should be restricted to the required zones and have **Zone WAF Write** permission. Keep it only in the dashboard environment; never put it in the repository.

## API

All response endpoints require the dashboard's existing HTTP Basic authentication. State-changing endpoints also require an explicit `X-Hotpot-Action` header.

```text
GET  /api/recommendations
GET  /api/recommendations?status=applied
GET  /api/recommendations?status=failed
GET  /api/recommendation?id=<recommendation_id>

POST /api/recommendation/<recommendation_id>/dismiss
     X-Hotpot-Action: dismiss

POST /api/recommendation/<recommendation_id>/approve
     X-Hotpot-Action: approve

POST /api/recommendation/<recommendation_id>/remove
     X-Hotpot-Action: remove
```

There is no automatic approval endpoint. Hotpot will automatically **remove** an already approved/applied rule at expiry, but it will not automatically approve or create a new enforcement rule.

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
HOTPOT_CLOUDFLARE_TARGETS={"monkeyhead":{"zone_id":"ZONE_ID","hosts":["www.monkeyheadbrewing.com"]},"watersolver":{"zone_id":"ZONE_ID","hosts":["brewwatersolver.com","www.brewwatersolver.com"]},"hvac":{"zone_id":"ZONE_ID","hosts":["hvac.bytemeloser.com"]},"tapmenu":{"zone_id":"ZONE_ID","hosts":["tapmenu.bytemeloser.com"]}}
```

`HOTPOT_CLOUDFLARE_TARGETS` keys must match the `id` values in `HOTPOT_DASHBOARD_INSTANCES`. Multiple instances may use the same `zone_id`; Hotpot deduplicates them into one rule for that zone when appropriate.

Enable enforcement only after the token and target mapping are complete:

```dotenv
HOTPOT_CLOUDFLARE_ENFORCEMENT_ENABLED=true
```

No database reset is required. The migration is additive.
