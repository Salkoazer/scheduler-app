#!/usr/bin/env bash
set -euo pipefail
# Generate a 64-byte random hex secret for JWT
if command -v openssl >/dev/null 2>&1; then
  openssl rand -hex 64
elif command -v python3 >/dev/null 2>&1; then
  python3 - <<'PY'
import secrets
print(secrets.token_hex(64))
PY
else
  echo "Install openssl or python3 to generate secrets" >&2
  exit 1
fi
