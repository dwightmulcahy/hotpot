# Threat-response recommendations

Hotpot's dashboard can turn active attacker intelligence into reviewable response recommendations. This feature is deliberately **recommendation-only**: it does not create Cloudflare rules, block traffic, or change deception behavior.

## Default policy

The dashboard evaluates retained events from a 24-hour active window and suppresses recommendations for actors not seen for 6 hours. The default mapping is:

- Global L1: observe only (not persisted as a recommendation)
- Global L2: watch
- Global L3: recommend a temporary challenge
- Global L4: recommend a 24-hour temporary block
- repeated/high-volume L4 behavior: recommend a longer temporary block (normally 7 days)

The decision records the active score, hits, applications, categories, severity, recency, lifetime peak, lifetime hits, source type, Worker zone, top paths, and last-known network attribution. ASN/provider/country are context only and do not raise the recommendation level.

## Safety exclusions

The dashboard collects each Hotpot instance's configured allowlist and trusted-proxy CIDRs from `/_hotpot/status`. An actor whose observed client IP matches either set is never recommended for challenge/block action.

Cloudflare's documented shared cross-zone Worker address (`2a06:98c0:3600::103`) is never recommended for an IP block when a trustworthy `CF-Worker` zone is unavailable. A known Worker zone is represented as a distinct future enforcement target rather than treating the shared IPv6 address as one attacker.

## Lifecycle

Recommendations are persisted in `dashboard.sqlite3` with these lifecycle states:

- `pending`
- `dismissed`
- `expired`
- `approved` (reserved for a later approval workflow)
- `applied` (reserved for a later enforcement integration)
- `failed` (reserved for a later enforcement integration)

Dismissal suppresses recreation for the configured dismissal cooldown. Continued activity refreshes the evidence and expiration of an existing pending recommendation instead of creating duplicates.

## API

All response endpoints require the dashboard's existing HTTP Basic authentication.

```text
GET  /api/recommendations
GET  /api/recommendations?status=dismissed
GET  /api/recommendation?id=<recommendation_id>
POST /api/recommendation/<recommendation_id>/dismiss
```

Dismissal requires the header:

```text
X-Hotpot-Action: dismiss
```

There is intentionally no apply/block endpoint in this release.

## Configuration

```dotenv
HOTPOT_RESPONSE_ENABLED=true
HOTPOT_RESPONSE_ACTIVE_WINDOW_HOURS=24
HOTPOT_RESPONSE_STALE_MINUTES=360
HOTPOT_RESPONSE_RECOMMENDATION_TTL_HOURS=24
HOTPOT_RESPONSE_DISMISS_HOURS=24
```

The defaults are conservative and intended to run in production first so the recommendation quality can be observed before any Cloudflare mutation capability is added.
