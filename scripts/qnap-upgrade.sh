#!/bin/sh
set -eu

COMPOSE_FILE="${HOTPOT_QNAP_COMPOSE_FILE:-/share/Data/config/cloudflared/docker-compose.yml}"
IMAGE_TAG="${HOTPOT_IMAGE_TAG:-latest}"
WAIT_SECONDS="${HOTPOT_QNAP_WAIT_SECONDS:-90}"
DEPLOYMENT_DIR="${HOTPOT_QNAP_DEPLOYMENT_DIR:-/share/Data/config/cloudflared/hotpot-deployments}"
DRY_RUN=0
SKIP_PULL=0

CORE_SERVICES="hotpot-monkeyhead hotpot-watersolver hotpot-hvac hotpot-tapmenu"
DASHBOARD_SERVICE="hotpot-dashboard"
ALL_SERVICES="$CORE_SERVICES $DASHBOARD_SERVICE"

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
command -v curl >/dev/null 2>&1 || { echo "curl is required" >&2; exit 1; }
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

health_url() {
  case "$1" in
    hotpot-monkeyhead) echo "http://127.0.0.1:18088/_hotpot/health" ;;
    hotpot-watersolver) echo "http://127.0.0.1:12120/_hotpot/health" ;;
    hotpot-hvac) echo "http://127.0.0.1:18080/_hotpot/health" ;;
    hotpot-tapmenu) echo "http://127.0.0.1:18111/_hotpot/health" ;;
    hotpot-dashboard) echo "http://127.0.0.1:19090/health" ;;
    *) return 1 ;;
  esac
}

wait_for_health() {
  service=$1
  url=$(health_url "$service")
  if [ "$DRY_RUN" -eq 1 ]; then
    echo "+ wait up to ${WAIT_SECONDS}s for $url"
    return 0
  fi

  elapsed=0
  while [ "$elapsed" -lt "$WAIT_SECONDS" ]; do
    if curl -fsS --max-time 3 "$url" >/dev/null 2>&1; then
      echo "✓ $service healthy ($url)"
      return 0
    fi
    sleep 2
    elapsed=$((elapsed + 2))
  done

  echo "ERROR: $service did not become healthy within ${WAIT_SECONDS}s" >&2
  echo "Last container logs:" >&2
  docker logs --tail 80 "$service" >&2 2>&1 || true
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
      docker inspect --format '{{.Name}} image={{.Config.Image}} image_id={{.Image}} started={{.State.StartedAt}}' "$service" 2>/dev/null || echo "$service inspect=unavailable"
    done
  } > "$manifest"
  chmod 600 "$manifest" 2>/dev/null || true
  echo "Deployment manifest: $manifest"
}

echo "Hotpot QNAP rollout"
echo "  compose: $COMPOSE_FILE"
echo "  tag:     $IMAGE_TAG"
[ "$IMAGE_TAG" = "latest" ] && echo "  warning: latest is mutable; an immutable release tag is safer for rollback"

# Parse/interpolate the exact Compose before touching any container.
compose config -q

if [ "$SKIP_PULL" -eq 0 ]; then
  compose pull $ALL_SERVICES
else
  echo "Skipping image pull."
fi

# Do not take every gateway down at once. Each core must pass its public health
# endpoint before the next core is recreated. The dashboard is intentionally last.
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
