# Cloudflare Free-plan enforcement

Hotpot uses two Cloudflare enforcement mechanisms so temporary response actions do not exhaust the Free plan's small custom-WAF rule quota.

## Enforcement mapping

| Hotpot recommendation | Cloudflare mechanism | Scope |
| --- | --- | --- |
| `recommend_challenge` | Custom WAF rule | Configured hostnames only |
| `recommend_block` | Custom WAF rule | Configured hostnames only |
| `recommend_long_block` targeting an IP | IP Access Rule | Entire Cloudflare zone |
| `recommend_long_block` targeting a Worker zone | Custom WAF rule | Configured hostnames only |

Long IP blocks therefore no longer consume a custom-WAF rule slot.

## Important scope difference

Cloudflare IP Access Rules are zone-wide. A long-blocked IP is blocked from every proxied hostname in that zone, not only the hostname where Hotpot observed the attack. Hotpot only chooses this mechanism for the highest-duration IP recommendation and still requires explicit dashboard approval.

If zone-wide blocking is too broad for a particular deployment, dismiss the long-block recommendation or use a shorter hostname-scoped response instead.

## Duplicate IPs and expiry

Hotpot searches for an existing Hotpot-owned IP Access Rule before creating a new one. If the same IP receives another long-block recommendation in the same zone:

- the existing rule is reused;
- the expiry is extended only when the new recommendation expires later;
- expiration of the older recommendation does not remove a rule that a newer recommendation extended;
- the last active recommendation removes the shared rule at expiry.

This prevents repeated activity from one IP from consuming multiple Cloudflare rules.

## Existing deployments

Rules applied by older Hotpot releases remain backward compatible. Existing long blocks that were created as custom-WAF rules stay in place and expire/remove normally. New long IP blocks use IP Access Rules after the dashboard is upgraded.

Repair also preserves the provider recorded with an existing rule instead of silently switching providers behind persisted dashboard state.

## API token permissions

The Cloudflare API token used by the dashboard must retain the permissions needed for Custom WAF rule management and also be allowed to manage Firewall/IP Access Rules for the configured zones/account. Cloudflare currently documents Firewall Access Rules read/write permissions for the IP Access Rules API.

Use the narrowest token that works for the zones Hotpot manages. Keep the token in a Docker secret or `HOTPOT_CLOUDFLARE_API_TOKEN_FILE` rather than embedding it in Compose.

## Safety behavior

Nothing about this change enables automatic blocking. Hotpot continues to require explicit approval before applying a recommendation, continues to honor allowlists/trusted-proxy checks, reconciles persisted Cloudflare state, and automatically removes temporary enforcement when it expires.
