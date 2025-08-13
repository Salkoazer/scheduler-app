#!/usr/bin/env bash
set -euo pipefail

# Simple JWT secret rotation helper
# Usage: ./scripts/rotate-secret.sh <new-secret>

if [[ ${1-} == "" ]]; then
  echo "Usage: $0 <new-secret>" >&2
  exit 1
fi

NEW_SECRET="$1"
ENV_FILE="$(dirname "$0")/../.env"

# Create .env if missing
if [[ ! -f "$ENV_FILE" ]]; then
  touch "$ENV_FILE"
fi

# Read current values
CURRENT_SECRET=$(grep -E '^JWT_SECRET=' "$ENV_FILE" | sed 's/^JWT_SECRET=//') || true

# Write previous -> current, current -> new
TMP=$(mktemp)
awk -v prev="$CURRENT_SECRET" -v newv="$NEW_SECRET" '
  BEGIN{printed_secret=0;printed_prev=0}
  /^JWT_SECRET_PREV=/ {print "JWT_SECRET_PREV=" prev; printed_prev=1; next}
  /^JWT_SECRET=/ {print "JWT_SECRET=" newv; printed_secret=1; next}
  {print}
  END{
    if(!printed_prev){print "JWT_SECRET_PREV=" prev}
    if(!printed_secret){print "JWT_SECRET=" newv}
  }
' "$ENV_FILE" > "$TMP"
mv "$TMP" "$ENV_FILE"

echo "Updated $ENV_FILE";
cat "$ENV_FILE" | sed 's/JWT_SECRET=.*/JWT_SECRET=****/; s/JWT_SECRET_PREV=.*/JWT_SECRET_PREV=****/'
