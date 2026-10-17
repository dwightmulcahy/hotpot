# App registry and multi-app deployment

Hotpot can protect many applications while keeping one isolated core proxy per
application. The central dashboard aggregates events from every core. The app
registry is the source of truth that joins those two layers without turning the
traffic path into one shared proxy.

## What belongs in the registry

A registry entry can define:

- stable application ID and display name;
- enabled deception profiles;
- the core URL used by the dashboard;
- the Compose service used in deployment plans;
- Cloudflare zone and hostnames; and
- file paths for the app's read-only collector token and policy-management token.

Traffic-specific values stay in Compose:

- `HOTPOT_INSTANCE_ID`;
- `HOTPOT_PORT`; and
- `HOTPOT_UPSTREAM`.

This lets Hotpot answer two different questions cleanly: Compose says **where this
container sends traffic**; `apps.toml` says **which protected application this
container represents and how the control plane manages it**.

## Example

```toml
[[apps]]
id = "app-one"
name = "Example App One"
profiles = ["wordpress", "secrets", "git", "php", "generic"]

[apps.dashboard]
url = "http://127.0.0.1:18081"

[apps.deployment]
service = "security-gateway-one"

[apps.cloudflare]
zone_id = "REPLACE_ZONE_ID"
hosts = ["app-one.example.com"]

[apps.credentials]
collector_token_file = "/run/secrets/app-one/collector_token"
policy_token_file = "/run/secrets/app-one/policy_token"
```

Set `HOTPOT_APP_REGISTRY=/config/apps.toml` in every registry-managed core and in
the centralized dashboard.

When a core starts in registry mode, `HOTPOT_INSTANCE_ID` must match exactly one
registry entry. The registry's name and profiles become authoritative. A missing
instance or a registry entry without profiles fails closed at startup rather than
silently applying a generic profile set.

## Scoped credentials

Collector and policy credentials have separate scopes:

- the **collector token** can read status/event/intelligence endpoints but cannot
  change policy;
- the **policy token** can read and update the core policy endpoint;
- `HOTPOT_ADMIN_TOKEN` remains a legacy full-access fallback for migration and
  simple single-core deployments.

Keep the two tokens different.

A QNAP host can use this layout:

```text
/share/Data/config/cloudflared/
├── hotpot-apps.toml
├── hotpot.env
├── dashboard.env
└── secrets/
    ├── dashboard_token
    ├── cloudflare_api_token
    ├── app-one/
    │   ├── collector_token
    │   └── policy_token
    └── app-two/
        ├── collector_token
        └── policy_token
```

Each core should receive **only its own** credential directory:

```yaml
volumes:
  - /share/Data/config/cloudflared/hotpot-apps.toml:/config/apps.toml:ro
  - /share/Data/config/cloudflared/secrets/app-one:/run/secrets/app-one:ro
```

The centralized dashboard needs all app credential files, so it receives the
read-only root:

```yaml
volumes:
  - /share/Data/config/cloudflared/hotpot-apps.toml:/config/apps.toml:ro
  - /share/Data/config/cloudflared/secrets:/run/secrets:ro
```

This matters for containment: compromising one core does not automatically expose
credentials for every other core.

## Compose labels

Use labels to identify managed services independently of their Compose names:

```yaml
labels:
  - "io.hotpot.managed=true"
  - "io.hotpot.role=core"
  - "io.hotpot.instance-id=app-one"
```

For the dashboard:

```yaml
labels:
  - "io.hotpot.managed=true"
  - "io.hotpot.role=dashboard"
```

The QNAP rollout helper discovers those labels from running containers in the
selected Compose project. Nonstandard service names therefore work normally.
Explicit service overrides remain available, and `hotpot-*` naming remains a
legacy migration fallback.

## Central event aggregation does not change

Each core still stores its own local event stream and durable attacker state. The
dashboard polls every registry app's authenticated event API and stores the combined
stream in `dashboard.sqlite3` with the app's `instance_id`.

That preserves both views:

- **per app:** attacks, health, profiles, upstream status and policy for one core;
- **global:** unique attackers, cross-app campaigns, top paths/categories/scanners,
  response recommendations and enforcement state across all protected apps.

Separate traffic plane, centralized intelligence.

## Safe migration from the legacy environment configuration

A controlled migration can be done without a flag day:

1. Create unique collector and policy tokens for every protected application.
2. Put those tokens in per-app secret files readable by the Hotpot container UID.
3. Build `hotpot-apps.toml` from the existing dashboard instance list, profile
   choices, Cloudflare targets and Compose service names.
4. Mount the registry and the app-specific secret directory into each core.
5. Mount the registry and the full secret tree read-only into the dashboard.
6. Add the `io.hotpot.*` labels to cores and dashboard.
7. Keep the legacy `HOTPOT_ADMIN_TOKEN`, `HOTPOT_DASHBOARD_INSTANCES`, and
   `HOTPOT_CLOUDFLARE_TARGETS` available during the transition if desired.
8. Run `docker compose config -q`.
9. Run `qnap-upgrade.sh --dry-run` and verify the discovered core/dashboard names.
10. Recreate cores sequentially, then recreate the dashboard last.
11. Verify Deployment is green and Policy revisions are in sync.
12. Verify new events from multiple applications continue appearing in the central
    dashboard.
13. Remove the legacy shared-admin/JSON configuration after the registry path has
    been proven in production.

If an app is intentionally different, put that difference in its registry entry.
Per-app profiles are expected to differ and no longer count as fleet-wide
configuration drift.

## Compatibility and rollback

The dashboard still accepts the legacy instance and Cloudflare JSON variables when
`HOTPOT_APP_REGISTRY` is not configured. Cores still accept the legacy environment
profile list and admin token when they are not running in registry mode.

That fallback is intentional for migration and rollback. It should not be treated as
the preferred multi-app configuration after the registry cutover is complete.
