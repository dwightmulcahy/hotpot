#!/bin/sh
set -eu

COMPOSE_FILE="${HOTPOT_QNAP_COMPOSE_FILE:-/share/Data/config/cloudflared/docker-compose.yml}"
IMAGE_TAG="${HOTPOT_IMAGE_TAG:-latest}"
WAIT_SECONDS="${HOTPOT_QNAP_WAIT_SECONDS:-90}"
DEPLOYMENT_DIR="${HOTPOT_QNAP_DEPLOYMENT_DIR:-/share/Data/config/cloudflared/hotpot-deployments}"
DRY_RUN=0
SKIP_PULL=0

CORE_SERVICES="${HOTPOT_QNAP_CORE_SERVICES:-}"
DASHBOARD_SERVICE="${HOTPOT_QNAP_DASHBOARD_SERVICE:-}"
ALL_SERVICES=""

usage() {
  cat <<'EOF'
Usage: qnap-upgrade.sh [options]

Safely roll Hotpot across a QNAP host-network deployment one service at a time.
The script validates Compose, optionally pulls the target images, recreates each
core with a health gate, recreates the dashboard last, and records an image-ID
manifest. It never runs docker compose down and never prints container env/secrets.

Options:
  --compose PATH     Compose file (default: /share/Data/config/cloudflared/docker-compose.yml)
  --tag TAG          Hotpot Docker tag supplied as HOTPOT_IMAGE_TAG (default: latest)
  --wait SECONDS     Health timeout per service (default: 90)
  --deployment-dir PATH  Directory for deployment manifests
  --services LIST    Space-separated Hotpot core Compose services
                     (default: discover io.hotpot.role=core labels)
  --dashboard-service NAME  Dashboard Compose service
                     (default: discover io.hotpot.role=dashboard label)
  --skip-pull        Do not pull images before recreation
  --dry-run          Print the rollout without changing containers
  -h, --help         Show this help
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --compose)
      [ "$#" -ge 2 ] || { echo "--compose requires a path" >&2; exit 2; }
      COMPOSE_FILE=$2
      shift 2
      ;;
    --tag)
      [ "$#" -ge 2 ] || { echo "--tag requires a value" >&2; exit 2; }
      IMAGE_TAG=$2
      shift 2
      ;;
    --wait)
      [ "$#" -ge 2 ] || { echo "--wait requires seconds" >&2; exit 2; }
      WAIT_SECONDS=$2
      shift 2
      ;;
    --deployment-dir)
      [ "$#" -ge 2 ] || { echo "--deployment-dir requires a path" >&2; exit 2; }
      DEPLOYMENT_DIR=$2
      shift 2
      ;;
    --services)
      [ "$#" -ge 2 ] || { echo "--services requires a space-separated list" >&2; exit 2; }
      CORE_SERVICES=$2
      shift 2
      ;;
    --dashboard-service)
      [ "$#" -ge 2 ] || { echo "--dashboard-service requires a service name" >&2; exit 2; }
      DASHBOARD_SERVICE=$2
      shift 2
      ;;
    --skip-pull)
      SKIP_PULL=1
      shift
      ;;
    --dry-run)
      DRY_RUN=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

case "$WAIT_SECONDS" in
  ''|*[!0-9]*) echo "--wait must be a positive integer" >&2; exit 2 ;;
esac
[ "$WAIT_SECONDS" -gt 0 ] || { echo "--wait must be greater than zero" >&2; exit 2; }

command -v docker >/dev/null 2>&1 || { echo "docker is required" >&2; exit 1; }
[ -f "$COMPOSE_FILE" ] || { echo "Compose file not found: $COMPOSE_FILE" >&2; exit 1; }

echo_cmd() {
  printf '+ HOTPOT_IMAGE_TAG=%s docker compose -f %s' "$IMAGE_TAG" "$COMPOSE_FILE"
  for arg in "$@"; do printf ' %s' "$arg"; done
  printf '\n'
}

compose() {
  echo_cmd "$@"
  [ "$DRY_RUN" -eq 1 ] && return 0
  HOTPOT_IMAGE_TAG="$IMAGE_TAG" docker compose -f "$COMPOSE_FILE" "$@"
}

container_id_for_service() {
  HOTPOT_IMAGE_TAG="$IMAGE_TAG" docker compose -f "$COMPOSE_FILE" ps -q "$1"
}

discover_labeled_services() {
  wanted_role=$1
  for candidate in $(HOTPOT_IMAGE_TAG="$IMAGE_TAG" docker compose -f "$COMPOSE_FILE" config --services); do
    container_id=$(container_id_for_service "$candidate")
    [ -n "$container_id" ] || continue
    managed=$(docker inspect --format '{{index .Config.Labels "io.hotpot.managed"}}' "$container_id" 2>/dev/null || true)
    role=$(docker inspect --format '{{index .Config.Labels "io.hotpot.role"}}' "$container_id" 2>/dev/null || true)
    if [ "$managed" = "true" ] && [ "$role" = "$wanted_role" ]; then
      printf '%s\n' "$candidate"
    fi
  done
}

wait_for_health() {
  service=$1
  if [ "$DRY_RUN" -eq 1 ]; then
    echo "+ wait up to ${WAIT_SECONDS}s for $service Docker healthcheck"
    return 0
  fi

  elapsed=0
  while [ "$elapsed" -lt "$WAIT_SECONDS" ]; do
    container_id=$(container_id_for_service "$service")
    if [ -n "$container_id" ]; then
      has_health=$(docker inspect --format '{{if .State.Health}}yes{{else}}no{{end}}' "$container_id" 2>/dev/null || echo no)
      status=$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$container_id" 2>/dev/null || echo unknown)
      if [ "$has_health" = "yes" ] && [ "$status" = "healthy" ]; then
        echo "✓ $service healthy"
        return 0
      fi
      if [ "$has_health" = "no" ] && [ "$status" = "running" ]; then
        echo "✓ $service running (no Docker HEALTHCHECK configured)"
        return 0
      fi
    fi
    sleep 2
    elapsed=$((elapsed + 2))
  done

  echo "ERROR: $service did not become healthy within ${WAIT_SECONDS}s" >&2
  echo "Last service logs:" >&2
  HOTPOT_IMAGE_TAG="$IMAGE_TAG" docker compose -f "$COMPOSE_FILE" logs --tail 80 "$service" >&2 2>&1 || true
  return 1
}

record_manifest() {
  [ "$DRY_RUN" -eq 1 ] && { echo "+ write deployment manifest under $DEPLOYMENT_DIR"; return 0; }
  mkdir -p "$DEPLOYMENT_DIR"
  stamp=$(date -u +'%Y%m%dT%H%M%SZ')
  manifest="$DEPLOYMENT_DIR/deployment-$stamp.txt"
  {
    echo "schema_version=1"
    echo "created_at=$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
    echo "hotpot_image_tag=$IMAGE_TAG"
    echo "compose_file=$COMPOSE_FILE"
    for service in $ALL_SERVICES; do
      container_id=$(container_id_for_service "$service")
      if [ -n "$container_id" ]; then
        docker inspect --format '{{.Name}} image={{.Config.Image}} image_id={{.Image}} started={{.State.StartedAt}}' "$container_id" 2>/dev/null || echo "$service inspect=unavailable"
      else
        echo "$service inspect=unavailable"
      fi
    done
  } > "$manifest"
  chmod 600 "$manifest" 2>/dev/null || true
  echo "Deployment manifest: $manifest"
}

echo "Hotpot QNAP rollout"
echo "  compose: $COMPOSE_FILE"
echo "  tag:     $IMAGE_TAG"
[ "$IMAGE_TAG" = "latest" ] && echo "  warning: latest is mutable; an immutable release tag is safer for rollback"

# Parse/interpolate the exact Compose before touching any container. This still
# runs during --dry-run because validation and discovery are read-only.
echo_cmd config -q
HOTPOT_IMAGE_TAG="$IMAGE_TAG" docker compose -f "$COMPOSE_FILE" config -q

if [ -z "$DASHBOARD_SERVICE" ]; then
  DASHBOARD_SERVICE=$(discover_labeled_services dashboard | head -n 1)
fi
if [ -z "$DASHBOARD_SERVICE" ]; then
  DASHBOARD_SERVICE=hotpot-dashboard
  echo "  warning: dashboard label not found; using legacy service fallback: $DASHBOARD_SERVICE"
fi

if [ -z "$CORE_SERVICES" ]; then
  CORE_SERVICES=$(discover_labeled_services core)
fi
if [ -z "$CORE_SERVICES" ]; then
  CORE_SERVICES=$(HOTPOT_IMAGE_TAG="$IMAGE_TAG" docker compose -f "$COMPOSE_FILE" config --services | awk -v dashboard="$DASHBOARD_SERVICE" '$0 ~ /^hotpot-/ && $0 != dashboard {print}')
  [ -z "$CORE_SERVICES" ] || echo "  warning: core labels not found; using legacy hotpot-* naming fallback"
fi
[ -n "$CORE_SERVICES" ] || {
  echo "No Hotpot core services found. Add io.hotpot.role=core labels or use --services/HOTPOT_QNAP_CORE_SERVICES." >&2
  exit 1
}
ALL_SERVICES="$CORE_SERVICES $DASHBOARD_SERVICE"

echo "  cores:   $CORE_SERVICES"
echo "  dashboard: $DASHBOARD_SERVICE"

if [ "$SKIP_PULL" -eq 0 ]; then
  compose pull $ALL_SERVICES
else
  echo "Skipping image pull."
fi

# Do not take every gateway down at once. Each core must pass its Docker health
# gate before the next core is recreated. The dashboard is intentionally last.
for service in $CORE_SERVICES; do
  echo "\nRecreating $service..."
  compose up -d --no-deps --force-recreate "$service"
  wait_for_health "$service"
done

echo "\nRecreating $DASHBOARD_SERVICE..."
compose up -d --no-deps --force-recreate "$DASHBOARD_SERVICE"
wait_for_health "$DASHBOARD_SERVICE"

record_manifest

echo "\n✓ Hotpot rollout completed successfully."
