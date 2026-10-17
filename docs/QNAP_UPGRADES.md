# QNAP deployment and upgrades

Hotpot's centralized dashboard includes a **Deployment** tab for release identity,
health, policy synchronization, global-policy drift, restore-verified backup status,
and an exact QNAP rollout plan. The dashboard is deliberately read-only with respect
to Docker: it never mounts the Docker socket and it never recreates containers itself.

The recommended QNAP layout uses `hotpot-apps.toml` as the protected-application
registry. Compose remains responsible for traffic wiring and isolation; the registry
owns application identity, enabled profiles, dashboard URLs, deployment service
mapping, Cloudflare targets, and scoped credential-file references.

See [App registry and multi-app deployment](app-registry.md) for the complete layout
and migration procedure.

## Recommended image pinning

Use the Compose image variable already shown in `compose.qnap.example.yml`:

```yaml
image: dwightmulcahy/hotpot:${HOTPOT_IMAGE_TAG:-latest}
```

and for the dashboard:

```yaml
image: dwightmulcahy/hotpot-dashboard:${HOTPOT_IMAGE_TAG:-latest}
```

`latest` works and remains convenient with Watchtower, but it is mutable. For a
controlled production upgrade, prefer an immutable release tag such as `0.7.0`.
That makes a rollout repeatable and rollback means simply running the same helper
with the previous tag.

The Git tag that publishes a release includes the leading `v` (for example
`v0.7.0`), while Docker Hub receives `0.7.0`, `0.7`, `0`, and `latest`
aliases. Use the Docker tag without the leading `v` with `HOTPOT_IMAGE_TAG`.

## Dashboard pre-upgrade gate

Before changing containers, open **Deployment** in the Hotpot dashboard. A fully
ready deployment means:

- every Hotpot core and protected upstream is healthy;
- dashboard instance IDs match the core IDs;
- all cores report a compatible release identity;
- the dashboard and cores report the expected release build;
- the fleet-wide global-policy fingerprint matches across cores;
- per-app profiles, allowlists, proxy wiring, listener ports, and upstreams are
  allowed to differ without creating false fleet-drift warnings;
- dashboard-managed policy revisions are synchronized;
- dashboard configuration preflight passes, including scoped credential files; and
- a restore-verified dashboard backup exists, unless operational backups are
  intentionally disabled.

A deployment fingerprint contains no credential values. Hotpot reports only the
credential source, such as `registry-file`, `file`, `environment`, or `unset`.

The Deployment tab's rollout commands are advisory. Copying a command does not run
it on the NAS.

## Hotpot service labels

Managed QNAP services should carry explicit labels:

```yaml
labels:
  - "io.hotpot.managed=true"
  - "io.hotpot.role=core"
  - "io.hotpot.instance-id=app-one"
```

The dashboard carries:

```yaml
labels:
  - "io.hotpot.managed=true"
  - "io.hotpot.role=dashboard"
```

The rollout helper uses those labels on running containers, so Compose service names
do not have to start with `hotpot-`. The previous `hotpot-*` discovery remains
only as a migration fallback when the labels are not present. Explicit
`--services`, `--dashboard-service`, `HOTPOT_QNAP_CORE_SERVICES`, and
`HOTPOT_QNAP_DASHBOARD_SERVICE` overrides remain available.

## Migrate an existing legacy QNAP configuration

For an existing deployment, use the registry migration helper before the rollout
helper:

```sh
# Read-only: inspect current Compose/env configuration and show a redacted plan.
python3 scripts/migrate_qnap_registry.py

# After review: back up and stage registry/scoped credentials. No restart occurs.
python3 scripts/migrate_qnap_registry.py --apply
```

The migration tool builds `hotpot-apps.toml` from the current deployment, generates
unique per-app collector/policy tokens, narrows each core's secret mount, adds the
Hotpot service labels, and validates the candidate/final Compose configuration.

The first apply **keeps the legacy shared admin/profile/dashboard maps** so an older
image can still restart during the cutover. After rolling out and verifying the
registry-aware image, clean those fallbacks in a separate transaction:

```sh
# Preview.
python3 scripts/migrate_qnap_registry.py --retire-legacy

# Apply with another timestamped backup.
python3 scripts/migrate_qnap_registry.py --retire-legacy --apply
```

Then recreate the registry-aware containers once more with `qnap-upgrade.sh` so
their running environments no longer contain the legacy shared credential.

The default QNAP paths and detailed failure/rollback behavior are documented in
[App registry and multi-app deployment](app-registry.md).

## Install the QNAP helper

The repository includes `scripts/qnap-upgrade.sh`. It validates Compose, discovers
managed services, pulls the target image, recreates one core at a time, waits for
that core's Docker health gate, recreates the dashboard last, and writes an image-ID
deployment manifest.

A typical installation on the NAS is:

```sh
cp scripts/qnap-upgrade.sh /share/Data/config/cloudflared/qnap-upgrade.sh
chmod 750 /share/Data/config/cloudflared/qnap-upgrade.sh
```

Preview an upgrade without making changes:

```sh
/share/Data/config/cloudflared/qnap-upgrade.sh \
  --compose /share/Data/config/cloudflared/docker-compose.yml \
  --tag 0.7.0 \
  --dry-run
```

Run it after reviewing the dry run:

```sh
/share/Data/config/cloudflared/qnap-upgrade.sh \
  --compose /share/Data/config/cloudflared/docker-compose.yml \
  --tag 0.7.0
```

The helper performs this sequence:

1. `docker compose ... config -q` — fail before changing anything if Compose is
   invalid.
2. Inspect services in the current Compose project and discover running containers
   labeled `io.hotpot.managed=true` plus `io.hotpot.role=core` or
   `io.hotpot.role=dashboard`.
3. If labels are absent during a migration, use the legacy `hotpot-*` naming
   fallback, or use the explicit service overrides.
4. Pull only the discovered/configured Hotpot cores and dashboard.
5. Recreate each core one at a time and wait for its Docker healthcheck before
   moving to the next service.
6. Recreate the dashboard last and wait for its Docker healthcheck.
7. Record image names, immutable image IDs, start times, the requested tag, and the
   Compose path under `/share/Data/config/cloudflared/hotpot-deployments/`.

If a health gate fails, the script stops immediately, prints the last container logs
for that service, and leaves later services untouched. It does **not** silently roll
back and it never runs `docker compose down`.

The helper does not restart `cloudflared` or `geoipupdate`, and it does not inspect
or print container environment variables or secret values.

## Rollback

With immutable release tags, rollback is the same controlled rollout to the last
known-good tag:

```sh
/share/Data/config/cloudflared/qnap-upgrade.sh \
  --compose /share/Data/config/cloudflared/docker-compose.yml \
  --tag 0.6.3
```

Persistent `/data` directories are retained. Review release notes before rolling
back across a release that contains a one-way schema migration. Hotpot's dashboard
creates pre-migration and operational SQLite backups, but a rollback should still
be an explicit operator decision.

During the app-registry migration, keep the legacy environment values available
until every core and the dashboard are running a registry-capable image. The code
accepts legacy dashboard instance/Cloudflare JSON and the legacy admin token as
fallbacks, so the configuration can be migrated before those fallbacks are removed
from a private deployment.

## Deployment-tab configuration

These dashboard settings only describe the rollout plan shown in the UI; they do
not grant the dashboard permission to operate Docker:

```text
HOTPOT_APP_REGISTRY=/config/apps.toml
HOTPOT_DASHBOARD_COMPOSE_FILE=/share/Data/config/cloudflared/docker-compose.yml
HOTPOT_DASHBOARD_DEPLOY_TAG=latest
HOTPOT_DASHBOARD_DEPLOY_SERVICES=
HOTPOT_DASHBOARD_DEPLOY_DASHBOARD_SERVICE=hotpot-dashboard
```

Set `HOTPOT_DASHBOARD_DEPLOY_TAG` to the release you normally deploy if you want
the UI's copyable commands to default to that immutable tag. When
`HOTPOT_DASHBOARD_DEPLOY_SERVICES` is empty, the dashboard uses each registry
entry's `[apps.deployment].service` mapping and appends the dashboard service.
Only legacy entries without a service mapping fall back to
`hotpot-<instance-id>`.

## After the rollout

Return to **Deployment** and refresh. The expected steady state is:

- all configured cores healthy;
- matching expected/remote instance IDs;
- expected release compatibility;
- matching global-policy fingerprints;
- scoped collector/policy credentials available for every app;
- policy synchronization green; and
- no failed preflight checks.

Then visit **Policy** and run **Reconcile now** if any policy revision still shows
drift. A core continues using its last-known-good `/data/policy.json` while the
dashboard is unavailable during its own recreation.

The centralized dashboard continues to ingest events from every registry entry into
its central SQLite store. Per-app traffic remains isolated in separate Hotpot cores,
while cross-app attacker/campaign intelligence remains aggregated.
