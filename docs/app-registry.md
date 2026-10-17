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

## Migrating an existing QNAP deployment

The repository includes `scripts/migrate_qnap_registry.py` specifically for an
existing QNAP/Container Station deployment. It reads the **current** Compose
configuration through `docker compose config --format json`, combines that with
`hotpot.env` and `dashboard.env`, and builds the registry from the configuration
that is actually in use.

The defaults match the standard QNAP layout:

```text
/share/Data/config/cloudflared/docker-compose.yml
/share/Data/config/cloudflared/hotpot.env
/share/Data/config/cloudflared/dashboard.env
/share/Data/config/cloudflared/hotpot-apps.toml
/share/Data/config/cloudflared/secrets/
```

### Stage 1: preview

Run the migration tool **without** `--apply` first:

```sh
python3 scripts/migrate_qnap_registry.py
```

Plan mode is read-only. It:

- discovers every current Hotpot core by its effective
  `HOTPOT_INSTANCE_ID`/`HOTPOT_UPSTREAM`;
- reads the existing dashboard instance and Cloudflare target maps;
- preserves per-service profile differences;
- shows the proposed registry, Compose changes and env changes;
- redacts token/password/bearer values from displayed diffs;
- validates the proposed Compose file with `docker compose config -q`; and
- does **not** create credentials, replace files or restart containers.

If your files live somewhere else, pass explicit paths:

```sh
python3 scripts/migrate_qnap_registry.py \
  --compose /path/to/docker-compose.yml \
  --hotpot-env /path/to/hotpot.env \
  --dashboard-env /path/to/dashboard.env \
  --secrets-dir /path/to/secrets
```

### Stage 2: stage the registry/scoped credentials

After reviewing the plan:

```sh
python3 scripts/migrate_qnap_registry.py --apply
```

This stage:

1. creates a timestamped backup under
   `/share/Data/config/cloudflared/hotpot-migration-backups/`;
2. creates `hotpot-apps.toml`;
3. generates a unique collector token and policy token for every app;
4. copies supported shared core secret values such as SMTP/webhook credentials into
   each app's scoped secret directory when needed;
5. changes each core from the broad `/run/secrets` mount to only that app's
   secret directory;
6. mounts the registry into every core and the dashboard;
7. adds the `io.hotpot.*` discovery labels;
8. adds service-specific secret-file overrides so existing notification settings
   continue to work;
9. validates the final Compose configuration; and
10. automatically restores the backed-up configuration if the apply fails.

The script never prints generated credential values and writes scoped secret files
with mode `0600`. When the Compose services use a numeric `user:`, the migration
also checks that those files can be owned/read by that container user.

**Stage 2 does not restart anything.**

For rollback safety, it intentionally leaves the old
`HOTPOT_ADMIN_TOKEN`, `HOTPOT_PROFILES`,
`HOTPOT_DASHBOARD_INSTANCES`, and `HOTPOT_CLOUDFLARE_TARGETS` settings in place.
Registry-aware images prefer the new configuration, but the old images can still
restart while the rollout is in progress.

### Stage 3: roll out the registry-aware images

Do not apply the migration until the core/dashboard image you intend to deploy
contains app-registry support.

Preview the normal controlled rollout:

```sh
scripts/qnap-upgrade.sh \
  --compose /share/Data/config/cloudflared/docker-compose.yml \
  --tag YOUR_NEW_TAG \
  --dry-run
```

Then perform it:

```sh
scripts/qnap-upgrade.sh \
  --compose /share/Data/config/cloudflared/docker-compose.yml \
  --tag YOUR_NEW_TAG
```

The existing QNAP helper recreates cores one at a time, health-gates each one and
recreates the dashboard last.

Before continuing, verify:

- every core is healthy;
- expected/remote instance IDs match;
- the dashboard is receiving new events from multiple apps;
- global-policy fingerprint state is sane;
- each app reports scoped collector/policy credentials; and
- Policy reports the desired/applied revisions in sync.

### Stage 4: retire the legacy fallbacks

Only after the new deployment has been verified, preview cleanup:

```sh
python3 scripts/migrate_qnap_registry.py --retire-legacy
```

Then apply it:

```sh
python3 scripts/migrate_qnap_registry.py --retire-legacy --apply
```

This creates another timestamped backup and removes the old shared admin credential,
shared profile setting, dashboard instance JSON and Cloudflare target JSON from the
active configuration. It also removes now-redundant per-service legacy name/profile
overrides.

Run the controlled QNAP rollout one more time so the running containers drop the
legacy credentials from their process environment:

```sh
scripts/qnap-upgrade.sh \
  --compose /share/Data/config/cloudflared/docker-compose.yml \
  --tag YOUR_NEW_TAG
```

This two-stage cutover is deliberate: a configuration edit never takes away the old
restart path before the new image has proven it can read the registry.

### What the migration tool will not do

It will not:

- restart, stop or remove containers;
- run `docker compose down`;
- change Cloudflare itself;
- delete the original shared secret files;
- print existing or generated credential values; or
- overwrite a conflicting existing scoped secret file.

If it finds an ambiguous configuration—for example multiple legacy secret roots,
unknown dashboard apps, invalid IDs, or a referenced secret file it cannot safely
copy—it fails before modifying the deployment.

## Compatibility and rollback

The dashboard still accepts the legacy instance and Cloudflare JSON variables when
`HOTPOT_APP_REGISTRY` is not configured. Cores still accept the legacy environment
profile list and admin token when they are not running in registry mode.

The automated migration deliberately keeps those fallbacks through the first
registry-aware rollout. If the new image must be rolled back at that point, restore
the timestamped configuration backup and use the previous image tag with
`qnap-upgrade.sh`.

`--retire-legacy --apply` creates a second backup before removing the fallbacks.
The original shared secret files are not deleted automatically, so an operator can
restore an earlier configuration without having to reconstruct credential files.

That fallback is intentional for migration and rollback. It should not be treated as
the preferred multi-app configuration after the registry cutover is complete.
