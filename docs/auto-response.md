# Guarded automatic response

Hotpot can automate selected Cloudflare response actions without making 7-day zone-wide blocks automatic. The feature is intentionally staged and fail-closed.

## Modes

| Mode | Behavior |
| --- | --- |
| `off` | Kill switch. All new enforcement requires manual approval. |
| `shadow` | Evaluates automatic-response guardrails and records what would have been applied, but performs no Cloudflare writes. |
| `challenge` | Automatically applies eligible high-confidence 6-hour managed challenges. 24-hour blocks remain manual. |
| `active` | Also automatically applies eligible high-confidence 24-hour L4 hostname-scoped blocks. |

`recommend_long_block` is never automated. Long IP blocks use zone-wide Cloudflare IP Access Rules and always require explicit dashboard approval.

The configured default is controlled by `HOTPOT_AUTO_RESPONSE_MODE`, but mode changes made in the dashboard are persisted in `dashboard.sqlite3` and survive restarts. Switching to `off` is the runtime kill switch.

## Automatic-action guardrails

A recommendation is eligible only when all applicable checks pass:

- action is `recommend_challenge` or `recommend_block`;
- confidence is `high`;
- target is a direct, globally routable IP address;
- actor source type is a direct IP, not a Cloudflare Worker/proxy identity;
- the actor is not suppressed by Hotpot policy;
- the current recommendation still passes Hotpot's normal approval-time allowlist/trusted-proxy safety checks;
- verified IPverse bot infrastructure is excluded by default;
- enough independent malicious signals are present;
- Cloudflare reconciliation is healthy immediately before writes;
- no rollback-cleanup jobs or orphaned Hotpot Cloudflare rules are pending;
- hourly and daily automatic-action caps have not been reached.

The independent signals are intentionally broad rather than tied to one signature:

- at least 10 observed hits;
- activity across at least 2 protected applications;
- at least 3 attack categories;
- high-severity evidence (`max_severity >= 4` or at least 3 high-severity events);
- at least 3 high-level events.

Challenges require 2 independent signals by default. 24-hour L4 blocks require 3.

## Circuit breaker

Before an automatic Cloudflare write, Hotpot forces a reconciliation read. Automation stops when reconciliation is not `healthy`, when an orphaned Hotpot rule is present, or when transactional rollback cleanup is still pending.

A failed automatic Cloudflare apply also opens the circuit for the remainder of that cycle. Manual response remains available.

## Rate limits

Defaults:

```dotenv
HOTPOT_AUTO_RESPONSE_MAX_PER_HOUR=5
HOTPOT_AUTO_RESPONSE_MAX_PER_DAY=20
```

Failed automatic apply attempts count toward the limits so a broken Cloudflare configuration cannot create a rapid retry loop.

## Dashboard control

The Enforcement tab adds an **Automatic response** panel with four controls:

- Off
- Shadow
- Auto challenge
- Active

Changing to `challenge` or `active` requires a healthy Cloudflare reconciliation at that moment. The mode-change endpoint is protected by the same signed dashboard session, CSRF token, action header, and dashboard action rate limiter as other state-changing controls.

`Off` stops new automatic actions immediately. An already-started Cloudflare transaction is allowed to finish rather than being cancelled mid-write, after which no further automatic action starts.

## Recommended rollout

1. Run `shadow` for at least 7 days.
2. Review shadow decisions against recommendations you approved/dismissed manually.
3. Enable `challenge` first.
4. Leave it there for about another week and review results.
5. Enable `active` only after the challenge stage remains clean.
6. Keep zone-wide 7-day long blocks manual.

Hotpot does not automatically advance between stages.

## Configuration

```dotenv
HOTPOT_AUTO_RESPONSE_MODE=off
HOTPOT_AUTO_RESPONSE_CYCLE_SECONDS=30
HOTPOT_AUTO_RESPONSE_MAX_PER_HOUR=5
HOTPOT_AUTO_RESPONSE_MAX_PER_DAY=20
HOTPOT_AUTO_RESPONSE_MIN_CHALLENGE_SIGNALS=2
HOTPOT_AUTO_RESPONSE_MIN_BLOCK_SIGNALS=3
HOTPOT_AUTO_RESPONSE_EXCLUDE_VERIFIED_BOTS=true
```

The mode stored by the dashboard takes precedence over `HOTPOT_AUTO_RESPONSE_MODE` after a dashboard user changes it.

## API

Read status:

```text
GET /api/auto-response
GET /api/v1/auto-response
```

Change mode:

```text
POST /api/auto-response/mode
X-Hotpot-Action: auto-response-mode
X-Hotpot-CSRF: <session csrf token>
Content-Type: application/json

{"mode":"shadow"}
```

Valid mode values are `off`, `shadow`, `challenge`, and `active`.
