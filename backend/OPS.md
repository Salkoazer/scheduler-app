# Operations Guide

## JWT Secret Rotation

- Token signing key: `JWT_SECRET`
- Grace key: `JWT_SECRET_PREV` (verification only)
- New tokens are signed with `JWT_SECRET`. Verification first tries `JWT_SECRET`, then falls back to `JWT_SECRET_PREV`.

Recommended rotation cadence: every 90 days, or immediately on suspicion of compromise.

Rotation steps (zero-downtime):
1. Generate a strong new secret (32–64 random bytes, base64 or hex).
2. Update your deployment environment:
   - Set `JWT_SECRET_PREV` to the current (old) `JWT_SECRET` value.
   - Set `JWT_SECRET` to the new value.
3. Roll out/restart all app instances.
4. Wait for at least the token TTL (default 1 hour) + small buffer.
5. Remove `JWT_SECRET_PREV` from the environment.

Hard cut (force logout): Omit `JWT_SECRET_PREV` when deploying the new `JWT_SECRET`.

Local/testing helper: `./scripts/rotate-secret.sh <new-secret>` writes backend/.env for dev only.

## MongoDB Backups

### Automated backups (GitHub Actions)
- Workflow: `.github/workflows/backup.yml`
- Schedule: daily at 02:17 UTC.
- Produces an artifact and optionally uploads to S3 if these secrets are configured:
  - `PROD_MONGO_URI` (e.g., `mongodb+srv://user:pass@cluster/db`)
  - `AWS_REGION`, `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`
  - `S3_BACKUP_BUCKET` (and optional `S3_BACKUP_PREFIX`, `S3_KMS_KEY_ID`)

### Manual backup
- Requires `mongodump` or falls back to `mongoexport` if available.
- Run: `./scripts/backup.sh [MONGO_URI]`
- Output: `backend/backups/scheduler-backup-<timestamp>.tgz`

### Restore
- If backup was created with `mongodump` inside the archive:
  1. Extract: `tar -xzf scheduler-backup-<timestamp>.tgz`
  2. Restore: `mongorestore --nsInclude <db>.* dump/`
- If created via JSON export fallback:
  1. Extract: `tar -xzf scheduler-backup-<timestamp>.tgz`
  2. For each `dump/*.json`: `mongoimport --uri "$URI" --collection <name> --file dump/<name>.json --jsonArray` (add `--drop` to replace).

Notes:
- Prefer `mongodump`/`mongorestore` for full-fidelity backups (indexes, metadata). JSON exports won’t capture indexes; re-create as needed.
- Keep backups encrypted at rest (S3 SSE-KMS or SSE-S3) and restrict access.
- Test restores periodically.

## Credential leak response

If a database URI or password leaks (repo, logs, chat):
1. Immediately rotate the user password in MongoDB Atlas (or create a new user and disable the old one).
2. Update all places that reference the URI:
  - Local dev: `backend/.env` (untracked by Git)
  - CI: GitHub Secrets like `PROD_MONGO_URI`
  - Hosting/Prod: your platform's secret manager
3. In Git, ensure `.env` files are ignored (they are). If secrets were committed, rewrite history with BFG or git-filter-repo after rotation.
4. Add or run secret scanning (Gitleaks workflow included) to prevent regressions.
