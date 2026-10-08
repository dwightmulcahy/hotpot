# Policy control plane

Hotpot's dashboard can act as the durable source of truth for operational security policy while each core proxy retains a last-known-good local snapshot. Policy changes are explicit, authenticated dashboard actions; Cloudflare enforcement remains approval-only and is never triggered automatically by a policy entry.

## Policy types

- **Allow CIDR** bypasses deception for matching client addresses on the selected applications. It does not change trusted-proxy handling or forwarding-header trust.
- **Suppress actor** keeps collecting/deceiving traffic but suppresses external escalation notifications and prevents response approval for the matching actor.
- **Suppress scanner** suppresses core escalation notifications for the matching scanner family. It does not disable deception or scoring.
- **Exclude category** suppresses core escalation notifications for the matching category and removes matching dashboard recommendations from the approval queue.

Every dashboard policy records a reason, notes, creator, creation time, optional application scope, optional expiration, and disable history. A blank application scope means all protected applications. Temporary exceptions are preferred.

Default-route allowlists (`0.0.0.0/0` and `::/0`) are prohibited rather than hidden behind a confirmation dialog.

## Synchronization and failure behavior

The dashboard stores policy rows and audit history in `dashboard.sqlite3`. It compiles a canonical snapshot for each configured Hotpot instance, hashes that snapshot, and compares the desired revision with the revision reported by `/_hotpot/api/policy`.

When a revision differs, the dashboard sends the new snapshot using the shared Hotpot admin token and `X-Hotpot-Action: policy-sync`. The core validates the complete snapshot before atomically replacing `/data/policy.json`. Invalid snapshots are rejected and the previous valid snapshot remains active.

If the dashboard is unavailable, each Hotpot continues using its last valid `/data/policy.json`. `HOTPOT_ALLOW_CIDRS` remains independent bootstrap/emergency policy and is never overwritten by the dashboard.

The normal reconciliation interval is controlled by:

```text
HOTPOT_DASHBOARD_POLICY_RECONCILE_SECONDS=60
```

The Policy tab also provides **Reconcile now**, which bypasses the interval and immediately verifies every configured instance.

## Manual response controls

The threat investigation drawer includes **Challenge**, **Block 1h**, **Block 24h**, and **Long block** controls when Cloudflare enforcement is configured. These controls use the same transaction, verification, rollback, expiry, and reconciliation machinery as recommendation approval.

Manual response always follows two distinct operations:

1. `/api/manual-response/preview` constructs the exact Cloudflare plan and performs no Cloudflare writes.
2. `/api/manual-response/apply` requires a signed dashboard session, CSRF token, and `X-Hotpot-Action: manual-response`; it persists the explicit operator action and then applies the verified Cloudflare transaction.

The preview shows target type/value, duration, zones, hostnames, Cloudflare action, exact expression, deterministic rule reference, and expected effect before confirmation.

Manual response refuses targets that currently match an allowlist or trusted-proxy CIDR. The shared cross-zone Cloudflare Worker address is also refused unless a trustworthy Worker zone is available.

## Investigation shortcuts

From the threat drawer, **Allowlist**, **Suppress actor**, and (when available) **Suppress scanner** pre-fill the Policy tab. They do not save anything by themselves. The operator must review the scope/reason/expiry, run the non-writing policy preview, and confirm creation.

The drawer also evaluates current dashboard policy for the investigated actor and explains whether a policy would bypass deception, suppress notifications, or prevent response approval.

## Backup and recovery

Central policies and their audit history live inside `dashboard.sqlite3`, so the normal dashboard backup/restore-verification workflow covers them automatically. Each core's `/data/policy.json` is a derived last-known-good copy stored in the existing persistent Hotpot data bind mount; it can be recreated by dashboard reconciliation after a core data loss.

## Deployment notes

This feature changes both images. After creating a release, recreate the dashboard and every Hotpot proxy container so both sides support the policy protocol. No new volume is required as long as `/data` is already persistent for both core and dashboard containers.

Before recreating containers, the existing configuration preflight remains useful:

```text
python -m hotpot.main --check-config
python -m dashboard.main --check-config
```

After deployment, open **Policy** in the dashboard and run **Reconcile now**. Every configured instance should report identical desired/applied revision prefixes and an in-sync state.
