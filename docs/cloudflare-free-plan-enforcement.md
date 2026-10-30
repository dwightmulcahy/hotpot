# Cloudflare Free-plan enforcement

Hotpot is designed to stay useful on Cloudflare's Free plan without consuming one custom WAF rule for every attacker.

## Enforcement mapping

| Hotpot recommendation | Cloudflare mechanism | Scope | WAF slots |
| --- | --- | --- | --- |
| `recommend_challenge` targeting an IP | Shared Managed Challenge WAF pool | Configured protected hostnames in each affected zone | At most 1 per zone |
| `recommend_block` targeting an IP | Shared Block WAF pool | Configured protected hostnames in each affected zone | At most 1 per zone |
| `recommend_long_block` targeting an IP | IP Access Rule | Entire configured Cloudflare account | 0 |
| Worker-zone recommendations | Individual Custom WAF rule | Configured protected hostnames | 1 per active rule |

For ordinary IP attackers, Hotpot therefore uses at most **two custom WAF rules per zone**, regardless of how many IPs are simultaneously challenged or blocked.

## Shared WAF pools

Each zone can have two Hotpot-owned shared rules:

- `hotpot_pool_challenge` with action `managed_challenge`;
- `hotpot_pool_block` with action `block`.

The rule expression contains a set of active IP addresses and the union of configured protected hostnames for that zone. Adding another attacker updates the IP set instead of creating another Cloudflare custom rule.

Hotpot keeps each attacker's expiry in SQLite. When one recommendation expires, Hotpot removes only that IP from the shared expression. The Cloudflare rule is deleted only when its final member expires.

Because Block and Managed Challenge are terminating actions, Hotpot keeps the Block pool before the Challenge pool in Cloudflare rule order.

Hotpot serializes Cloudflare mutations inside the dashboard so concurrent approvals cannot overwrite each other's shared-pool membership updates.

## Expression capacity

Cloudflare custom-rule expressions have a finite length. Hotpot uses a conservative 3,900-character ceiling for a pooled expression and fails closed rather than silently truncating an IP set. This still permits far more simultaneous IP memberships than one-rule-per-attacker enforcement on the Free plan.

## 7-day long blocks

A manually approved 7-day IP long block uses the account-scoped Cloudflare IP Access Rules endpoint:

`/accounts/{account_id}/firewall/access_rules/rules`

This avoids consuming a custom WAF rule slot. It also means the block applies across **every Cloudflare zone in that account**, not just the site where Hotpot observed the attacker.

Hotpot makes that scope explicit in the approval dialog and never automates long blocks.

Set:

```text
HOTPOT_CLOUDFLARE_ACCOUNT_ID=<your Cloudflare account id>
```

The dashboard disables IP Long block approval when the account ID is not configured.

## API token permissions

The dashboard token needs:

- **Zone WAF Write/Edit** for the shared challenge/block WAF pools;
- **Account Firewall Access Rules Write/Edit** for account-wide 7-day IP blocks.

Keep the token in a Docker secret or `HOTPOT_CLOUDFLARE_API_TOKEN_FILE` rather than embedding it in Compose.

## Backward compatibility

Hotpot keeps provider metadata with every applied recommendation.

Existing pre-pool custom-WAF rules continue to reconcile, repair, expire, and remove normally. Existing legacy zone-scoped IP Access Rules also retain their original zone scope for repair/removal. New IP challenges/24-hour blocks use shared WAF pools, and new IP long blocks use account-scoped IP Access Rules.

## Safety behavior

Pooling does not weaken response guardrails:

- automatic actions still honor allowlists, trusted-proxy exclusions, verified-bot checks, rate limits, and circuit breakers;
- long blocks remain manual-only;
- every mutation is verified against Cloudflare;
- reconciliation detects missing/drifted pool memberships and untracked pool members;
- rollback cleanup removes only the affected pooled membership rather than deleting unrelated attackers;
- temporary enforcement still expires automatically.
