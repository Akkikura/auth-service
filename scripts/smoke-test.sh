#!/usr/bin/env sh
set -eu

BASE_URL="${BASE_URL:-http://localhost:8080}"
EMAIL="demo-$(date +%s)@example.com"
PASSWORD="correct-horse-battery-staple"

curl --fail --silent "$BASE_URL/health/ready" >/dev/null

curl --fail --silent -X POST "$BASE_URL/register" \
  -H 'Content-Type: application/json' \
  -d "{\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\"}" >/dev/null

LOGIN=$(curl --fail --silent -X POST "$BASE_URL/login" \
  -H 'Content-Type: application/json' \
  -d "{\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\"}")
TOKEN=$(printf '%s' "$LOGIN" | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')
[ -n "$TOKEN" ] || { echo "Could not parse token" >&2; exit 1; }

ME=$(curl --fail --silent "$BASE_URL/me" -H "Authorization: Bearer $TOKEN")
printf '%s' "$ME" | grep -F "\"email\":\"$EMAIL\"" >/dev/null

curl --fail --silent -X POST "$BASE_URL/logout" \
  -H "Authorization: Bearer $TOKEN" >/dev/null

STATUS=$(curl --silent --output /dev/null --write-out '%{http_code}' \
  "$BASE_URL/me" -H "Authorization: Bearer $TOKEN")
[ "$STATUS" = "401" ] || { echo "Expected 401 after logout, got $STATUS" >&2; exit 1; }

echo "Smoke test passed for $EMAIL"
