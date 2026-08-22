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

## Credential rotation

Replace a stored provider key in the console or change the environment secret, test the integration, then revoke the old key at the provider. Environment values require process restart and cannot be removed through the UI. Removing a database secret cannot revoke the external credential.

## Corrections and retention

Restore a false positive instead of deleting its earlier event. Review broad suppressions and official domains regularly; stale exceptions silently reduce coverage.

Keep normalized observations and run metadata only as long as the research purpose requires. Raw provider bodies are not stored. Public absence is not interpreted as takedown, offline status or resolution.
