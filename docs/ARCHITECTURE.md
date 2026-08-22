# Architecture

Open Domain Radar is a single-node, Python-first CTI application with two separate trust surfaces.

```text
anonymous reader --> public dashboard/API --> bounded public projection
operator ---------> protected console/API --> SQLite/WAL <-- one worker
                                                |             |- CertStream
                                                |             |- URLScan (optional)
                                                |             `- VirusTotal (optional)
                                                `- observations and review events
```

The web process handles bounded reads and short administrative transactions. The worker owns network collection and pivot execution. Network calls occur outside SQLite write transactions. Both processes share one private data directory. One web process, one worker and SQLite/WAL are the supported deployment; PostgreSQL is not currently supported.

## Data flow

1. A provider emits an untrusted source record.
2. The pipeline validates size and type, canonicalizes IDNA, rejects URL credentials/non-default ports, discards every path/query/fragment and uses only the hostname as candidate identity.
3. All known official domains and active suppressions are applied before scoring.
4. The matcher records controlled reason codes and rejects every multi-target ambiguity.
5. A timestamped source observation and fingerprint are appended; the candidate is a derived current projection.
6. A new CertStream match may queue shallow, bounded passive jobs for enabled providers with credentials. Missing credentials never delay the candidate.
7. Related provider results must independently match the originating target. They do not recursively queue more work.
8. An analyst can mark the candidate confirmed, false positive, restored or closed through append-only review events.
9. The anonymous API emits a defanged domain projection without secrets, notes, provider references or normalized payloads. The private API exposes only an allowlisted, defanged evidence projection.

Automated `potential` candidates are intentionally visible. `published` means analyst-confirmed, not newly exposed. Provider enrichment is supporting context and never proves maliciousness or attribution.

## Persistence

The schema separates targets and official domains, provider configuration and encrypted secrets, immutable source observations, candidate projections, shallow pivot jobs, collection health, suppressions, append-only review events and hashed admin sessions.

Normalized provider fields are stored inside bounded observation payloads. Oversized payloads are replaced by a truncation marker and SHA-256 digest. Raw response bodies, downloaded artifacts and screenshots are not retained; typed artifact storage requires a future schema migration and explicit retention policy.

## Coverage boundary

CertStream is a live stream and cannot replay downtime. Repeated bounded windows improve coverage but do not constitute a daily global snapshot. A future durable deployment should add checkpointed Certificate Transparency log polling or another replayable source. Public health shows recent run state and freshness instead of claiming continuous coverage.

## Non-goals

- automated phishing confirmation or attribution;
- active browsing, crawling, screenshot capture or scan submission;
- arbitrary remote-feed URLs or executable user regex;
- multi-tenant identity, RBAC or hosted SaaS operation;
- a deep infrastructure graph, certificate/hash pivot engine or provider quota ledger; and
- replacement for MISP, OpenCTI, STIX/TAXII or case management.
