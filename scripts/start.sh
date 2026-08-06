#!/usr/bin/env sh
set -eu
cd "$(dirname "$0")/.."

command -v docker >/dev/null 2>&1 || { echo "Docker is not installed" >&2; exit 1; }
docker info >/dev/null 2>&1 || { echo "Docker daemon is not running" >&2; exit 1; }

[ -f .env ] || cp .env.example .env

echo "Building API and migration binaries..."
docker compose --progress plain build

echo "Starting PostgreSQL, Redis, migrations, and API..."
docker compose up -d --wait

PORT_BINDING=""
attempt=0
while [ -z "$PORT_BINDING" ] && [ "$attempt" -lt 40 ]; do
  PORT_BINDING=$(docker compose port api 8080 2>/dev/null | head -n 1 || true)
  attempt=$((attempt + 1))
  [ -n "$PORT_BINDING" ] || sleep 0.25
done
[ -n "$PORT_BINDING" ] || { echo "Could not determine the published API port" >&2; exit 1; }
HOST_PORT=${PORT_BINDING##*:}
BASE_URL="http://localhost:$HOST_PORT"
curl --fail --silent "$BASE_URL/health/ready" >/dev/null

printf '\nAuth Service backend is ready:\n'
printf 'API:       %s\n' "$BASE_URL"
printf 'Readiness: %s/health/ready\n' "$BASE_URL"
printf 'Liveness:  %s/health/live\n' "$BASE_URL"
printf 'Metrics:   %s/metrics\n' "$BASE_URL"
printf '\nRun ./scripts/smoke-test.sh to verify the complete flow.\n'
