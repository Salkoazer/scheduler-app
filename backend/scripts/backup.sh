#!/usr/bin/env bash
set -euo pipefail

# Simple MongoDB backup using mongodump
# Requires mongodump in PATH. Set MONGO_URI env or pass as $1.

URI=${1:-${MONGO_URI:-"mongodb://localhost:27017/scheduler"}}
OUT_DIR=${OUT_DIR:-"./backups"}
STAMP=$(date -u +%Y%m%d-%H%M%S)
WORKDIR=$(mktemp -d)
ARCHIVE="$OUT_DIR/scheduler-backup-$STAMP.tgz"

mkdir -p "$OUT_DIR"

if command -v mongodump >/dev/null 2>&1; then
	echo "Using mongodump"
	mongodump --uri="$URI" --out "$WORKDIR/dump"
else
	echo "mongodump not found; falling back to mongoexport (JSON)"
	mkdir -p "$WORKDIR/dump"
	# shellcheck disable=SC2016
	mongo --quiet "$URI" --eval 'db.getCollectionNames().join("\n")' | while read -r c; do
		[ -z "$c" ] && continue
		echo "Exporting $c"
		if command -v mongoexport >/dev/null 2>&1; then
			mongoexport --uri="$URI" --collection="$c" --out "$WORKDIR/dump/$c.json"
		else
			echo "mongoexport not available; cannot export $c" >&2
		fi
	done
fi

tar -czf "$ARCHIVE" -C "$WORKDIR" dump
rm -rf "$WORKDIR"

# Optional: prune old archives (keep last 7)
ls -1t "$OUT_DIR"/scheduler-backup-*.tgz 2>/dev/null | tail -n +8 | xargs -r rm -f

echo "Backup completed: $ARCHIVE"
