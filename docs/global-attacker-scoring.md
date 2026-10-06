# Global attacker scoring

The centralized Hotpot dashboard calculates a dashboard-only score for each source IP across every protected application. Local Hotpot escalation continues to operate independently; global scoring does not automatically block traffic or push policy back into individual Hotpot instances.

## Inputs

For each source IP, the dashboard tracks:

- observed hits across all applications
- persisted hits
- events suppressed by per-source flood protection
- cumulative persisted event severity
- number of distinct protected applications targeted
- number of distinct deception categories targeted
- maximum local severity and local escalation level
- first and last seen timestamps

Suppressed events are included in the observed hit count through the `suppressed_before` metadata carried by the next persisted event. They do not linearly add severity points, so a single high-volume source cannot dominate ranking solely by producing millions of duplicate probes.

## Score

The global score is:

`severity score + volume bonus + application bonus + category bonus`

The components are intentionally simple and explainable:

- severity score: sum of severity for persisted events
- volume bonus: 4 points each time observed volume roughly doubles, capped at 20
- application bonus: 8 points for each additional protected application beyond the first
- category bonus: 4 points for each additional deception category beyond the first

## Global levels

Global levels are assigned using both score and behavioral thresholds:

- Level 1: isolated low-volume activity
- Level 2: at least 3 observed hits, score at least 10, or at least 2 applications targeted
- Level 3: at least 10 observed hits, score at least 30, at least 3 applications targeted, or at least 3 categories targeted
- Level 4: at least 20 observed hits, score at least 60, or at least 4 applications targeted

The cross-application thresholds are deliberate: one source probing unrelated applications is more suspicious than the same number of requests against one application.

## Dashboard/API

`/api/overview` includes global scores in `top_offenders` and a `global_scoring` object describing the current policy version and level distribution.

`/api/attacker?ip=<address>` returns the full global view for one source, including score components, application activity, category activity, and the most recent collected events.

Both endpoints require dashboard authentication.

## Safety boundary

Global scoring is intelligence only. It does not automatically create firewall rules, Cloudflare blocks, or bans. Any future enforcement integration should remain opt-in and should use a separate confidence/policy layer rather than treating the numeric score alone as sufficient evidence for blocking.
