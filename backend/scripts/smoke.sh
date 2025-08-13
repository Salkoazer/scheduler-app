#!/usr/bin/env bash
set -euo pipefail

API="http://localhost:${PORT:-3000}"
ORIGIN=${ORIGIN:-http://localhost:9000}
COOKIE_FILE="/tmp/scheduler.cookies"

cleanup() {
  rm -f "$COOKIE_FILE" || true
}
trap cleanup EXIT

printf "\n[1/5] Healthcheck...\n"
curl -si -H "Origin: $ORIGIN" "$API/api/healthcheck" | sed -n '1,40p'

printf "\n[2/5] CORS preflight for /api/reservations...\n"
curl -si -X OPTIONS "$API/api/reservations" \
  -H "Origin: $ORIGIN" \
  -H "Access-Control-Request-Method: GET" \
  -H "Access-Control-Request-Headers: content-type,authorization" | sed -n '1,80p'

printf "\n[3/5] Get CSRF token...\n"
curl -si -H "Origin: $ORIGIN" -c "$COOKIE_FILE" "$API/api/csrf" | sed -n '1,80p'

printf "\n[4/6] Invalid login (should be 401)...\n"
CSRF=$(grep -i csrfToken "$COOKIE_FILE" | awk '{print $7}' | tail -n1)
curl -si -H "Origin: $ORIGIN" -H "Content-Type: application/json" -H "X-CSRF-Token: $CSRF" \
  -b "$COOKIE_FILE" -d '{"username":"admin","password":"wrong"}' "$API/api/auth" | sed -n '1,80p'

printf "\n[5/6] Valid login (set cookie)...\n"
curl -si -H "Origin: $ORIGIN" -H "Content-Type: application/json" -H "X-CSRF-Token: $CSRF" \
  -b "$COOKIE_FILE" -c "$COOKIE_FILE" \
  -d '{"username":"admin","password":"admin"}' "$API/api/auth" | sed -n '1,120p'

printf "\n[6/6] Authenticated /api/reservations (1 week range)...\n"
START=$(date -u +%Y-%m-%dT00:00:00.000Z)
END=$(date -u -d "+7 days" +%Y-%m-%dT23:59:59.999Z)
curl -si -H "Origin: $ORIGIN" -b "$COOKIE_FILE" "$API/api/reservations?start=$START&end=$END" | sed -n '1,120p'
