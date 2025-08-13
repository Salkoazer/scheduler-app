---
name: Production Cutover Checklist
about: Steps to configure secrets, backups, and deployment for production
labels: ops, production
---

## Secrets (Repo Settings → Secrets and variables → Actions)
- [ ] `PROD_MONGO_URI` set
- [ ] `AWS_REGION` set (if S3 upload desired)
- [ ] `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` set (if S3)
- [ ] `S3_BACKUP_BUCKET` (and optional `S3_BACKUP_PREFIX`, `S3_KMS_KEY_ID`) set
- [ ] `JWT_SECRET` strong value set at runtime (in platform env)
- [ ] `JWT_SECRET_PREV` unset unless rotating

## Backups
- [ ] Confirm Daily Mongo Backup workflow is enabled
- [ ] Run workflow_dispatch once to verify artifact & optional S3 upload
- [ ] Document storage location & retention

## App Config
- [ ] `CORS_ALLOWED_ORIGINS` includes production domains
- [ ] HTTPS termination (LB/Ingress) in place; HSTS enabled
- [ ] CSRF token set/verified; cookies Secure+SameSite(None) in prod

## Validation
- [ ] Smoke test environment (backend/scripts/smoke.sh) against prod URL
- [ ] Confirm indexes created and performance acceptable
- [ ] Create and cancel a test reservation; verify logs include request IDs

## Post-Launch
- [ ] Set rotation reminder for JWT secret (e.g., 90 days)
- [ ] Review logs/alerts; baseline rate limiter metrics
