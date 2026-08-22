# Operations and backup

## Daily checks

- Confirm the latest CertStream window and public freshness state.
- Treat `success`, `healthy_empty`, `skipped` and `failed` as distinct states. `healthy_empty` means a bounded window produced no match; it is not evidence that no phishing domains exist.
- Review new and high-scoring candidates before treating them as actionable.
- Inspect controlled provider errors and queue state without removing the three-request provider budget.

## Backup

Use the CLI so SQLite creates an online consistent copy:

```sh
open-domain-radar backup --output backups/radar-2026-08-22.sqlite3
```

Store the database backup separately from the master key and provider credentials. Test restoration on a disconnected instance. A public response is not a backup: it omits observations, notes, sessions, secret configuration and review history.

The database uses a forward-only `schema_migrations` ledger. Application startup applies missing supported migrations and refuses to open a database with a newer schema. Before upgrading, create a backup with the currently running release and retain the matching master key separately.

## Restore and rollback rehearsal

Stop the web and worker first. Restore into a new, disconnected data directory whenever possible:

```sh
export ODR_DATA_DIR=/srv/open-domain-radar-restore-test
open-domain-radar restore /secure-backups/radar-2026-08-22.sqlite3
open-domain-radar init
open-domain-radar serve
```

Check `/health/ready`, sign in locally, confirm target/candidate/review counts and inspect recent collection history. Do not enable collection during the rehearsal.

To replace an existing stopped instance:

```sh
open-domain-radar restore /secure-backups/radar-2026-08-22.sqlite3 --force
open-domain-radar init
```

Before replacement, the command writes a timestamped `radar.before-restore-*.db` copy beside the live database. It validates the selected backup with `PRAGMA quick_check`, checks required tables and rejects future or broken migration histories. It then copies through SQLite's backup API, validates the temporary copy and atomically replaces the destination. If post-restore verification fails, stop the processes and restore the `before-restore` copy with the same command.

For Docker Compose, bind a host backup directory only for the maintenance command:

```sh
docker compose stop web worker
docker compose run --rm -v ./backups:/backups web open-domain-radar backup --output /backups/radar.sqlite3
docker compose run --rm -v ./backups:/backups web open-domain-radar restore /backups/radar.sqlite3 --force
docker compose up -d
```

Restore does not copy or replace `master.key`. Keep that key, environment secrets and database backups in separate protected locations. A database restored without its matching key remains usable, but stored provider credentials must be cleared and re-entered.

## Credential rotation

Replace a stored provider key in the console or change the environment secret, test the integration, then revoke the old key at the provider. Environment values require process restart and cannot be removed through the UI. Removing a database secret cannot revoke the external credential.

## Corrections and retention

Restore a false positive instead of deleting its earlier event. Review broad suppressions and official domains regularly; stale exceptions silently reduce coverage.

Keep normalized observations and run metadata only as long as the research purpose requires. Raw provider bodies are not stored. Public absence is not interpreted as takedown, offline status or resolution.
