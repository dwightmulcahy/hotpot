# QNAP deployment and upgrades

Hotpot's centralized dashboard includes a **Deployment** tab for release identity,
health, policy synchronization, config-fingerprint drift, restore-verified backup
status, and an exact QNAP rollout plan. The dashboard is deliberately read-only
with respect to Docker: it never mounts the Docker socket and it never recreates
containers itself.

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
`v0.7.0`), while Docker Hub receives `0.7.0`, `0.7`, `0`, and `latest` aliases.
Use the Docker tag without the leading `v` with `HOTPOT_IMAGE_TAG`.

## Dashboard pre-upgrade gate

Before changing containers, open **Deployment** in the Hotpot dashboard. A fully
ready deployment means:

- every Hotpot core and protected upstream is healthy;
- dashboard instance IDs match the core IDs;
- all cores report the same release identity;
- the dashboard and cores report the same release build;
- shared, secret-free Hotpot configuration fingerprints match across cores;
- dashboard-managed policy revisions are synchronized;
- dashboard configuration preflight passes; and
- a restore-verified dashboard backup exists, unless operational backups are
  intentionally disabled.

A config fingerprint contains no credential values. Hotpot reports only whether a
supported secret comes from a file, the environment, or is unset.

The Deployment tab's rollout commands are advisory. Copying a command does not run
it on the NAS.

## Install the QNAP helper

The repository includes `scripts/qnap-upgrade.sh`. It validates Compose, pulls the
target image, recreates one core at a time, waits for that core's health endpoint,
recreates the dashboard last, and writes an image-ID deployment manifest.

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
2. Pull only the four Hotpot cores and `hotpot-dashboard`.
3. Recreate `hotpot-monkeyhead`; wait for `/_hotpot/health`.
4. Recreate `hotpot-watersolver`; wait for health.
5. Recreate `hotpot-hvac`; wait for health.
6. Recreate `hotpot-tapmenu`; wait for health.
7. Recreate `hotpot-dashboard` last; wait for `/health`.
8. Record image names, immutable image IDs, start times, the requested tag, and the
   Compose path under `/share/Data/config/cloudflared/hotpot-deployments/`.

If a health gate fails, the script stops immediately, prints the last container
logs for that service, and leaves later services untouched. It does **not** silently
roll back and it never runs `docker compose down`.

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

## Deployment-tab configuration

These dashboard settings only describe the rollout plan shown in the UI; they do
not grant the dashboard permission to operate Docker:

```text
HOTPOT_DASHBOARD_COMPOSE_FILE=/share/Data/config/cloudflared/docker-compose.yml
HOTPOT_DASHBOARD_DEPLOY_TAG=latest
HOTPOT_DASHBOARD_DEPLOY_SERVICES=hotpot-monkeyhead,hotpot-watersolver,hotpot-hvac,hotpot-tapmenu,hotpot-dashboard
```

Set `HOTPOT_DASHBOARD_DEPLOY_TAG` to the release you normally deploy if you want the
UI's copyable commands to default to that immutable tag. You can always pass a
different `--tag` to the shell helper.

## After the rollout

Return to **Deployment** and refresh. The expected steady state is:

- 4/4 healthy cores;
- matching core releases and dashboard release;
- matching shared config fingerprints;
- matching expected/remote instance IDs;
- policy synchronization green; and
- no failed preflight checks.

Then visit **Policy** and run **Reconcile now** if any policy revision still shows
drift. A core continues using its last-known-good `/data/policy.json` while the
dashboard is unavailable during its own recreation.
