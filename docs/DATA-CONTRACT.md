# Public data contract

The anonymous API exposes a bounded projection of policy-visible candidates. Automated `potential` candidates and analyst-confirmed `published` candidates are both public by design; `false_positive` and `closed` records remain private. This is a lead catalogue, not a verdict feed or operational-database dump.

## Signal

| Field | Meaning |
| --- | --- |
| `id` | Stable candidate identifier within this installation |
| `observable`, `domain` | Same defanged normalized domain |
| `type` | `domain` |
| `target` | Configured target display name |
| `confidence`, `score` | Same deterministic match-strength score, not probability |
| `status` | `potential` or `published` |
| `first_seen_at`, `last_seen_at` | UTC observation bounds |
| `firstSeen`, `lastSeen` | Compatibility aliases for the same bounds |
| `sources` | Controlled provider labels |
| `reasons` | Controlled matching reason codes |

Candidate domains are never clickable. If an adapter receives an HTTP(S) URL, credentials are rejected and the port, path, query and fragment are discarded; the domain is the only candidate identity. Private notes, raw provider responses and references, secret state, session data and refanged indicators are excluded.

## Pagination

`GET /api/public/v1/signals` accepts bounded `page`, `page_size`, `query`, `status`, `target` and `source` filters. Responses contain `items`, `page`, `pageSize`, `total`, `pages` and a matching `pagination` object. Unsupported public statuses and sources return validation errors.

## Health

Public health separates database availability from primary collection freshness. The latest CertStream run alone determines the primary state: a failed or older-than-20-minute run is `degraded`, no run is `unknown`, and `skipped` means no target was enabled. Optional-provider state remains in the protected provider and pivot views and cannot mask primary discovery health. Counts never imply complete Internet or CT-log coverage.

The schema is pre-1.0 and may change. Pin deployments to a tagged release before building external automation.
