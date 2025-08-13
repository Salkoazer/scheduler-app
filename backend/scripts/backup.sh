#!/usr/bin/env bash
set -euo pipefail

# Simple MongoDB backup using mongodump
# Requires mongodump in PATH. Set MONGO_URI env or pass as $1.

URI=${1:-${MONGO_URI:-"mongodb://localhost:27017/scheduler"}}
OUT_DIR=${OUT_DIR:-"./backups"}
STAMP=$(date -u +%Y%m%d-%H%M%S)
DEST="$OUT_DIR/mongodump-$STAMP"

mkdir -p "$OUT_DIR"

mongodump --uri="$URI" --out "$DEST"

# Optional: prune old backups (keep last 7)
ls -1dt "$OUT_DIR"/mongodump-* 2>/dev/null | tail -n +8 | xargs -r rm -rf

echo "Backup completed: $DEST"
