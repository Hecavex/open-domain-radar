# Open Domain Radar

[![CI](https://github.com/Hecavex/open-domain-radar/actions/workflows/ci.yml/badge.svg)](https://github.com/Hecavex/open-domain-radar/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

Open Domain Radar is a brand-neutral, self-hosted application for finding, enriching, reviewing and publishing potential domain-impersonation candidates. It combines passive Certificate Transparency discovery with optional passive intelligence providers, an append-only analyst review trail and a public read-only dashboard.

It is intentionally a **candidate system, not an automated phishing verdict engine**. A certificate name, lexical match, provider verdict or shared infrastructure relationship can justify review; none of them alone proves malicious intent.

The project is an alpha release intended for small, self-hosted deployments and research. Review the documented operating limits before exposing it to the internet.

## What it provides

- persistent SQLite/WAL storage for targets, observations, candidates, evidence, pivots, collection runs and review events;
- a bounded, reconnecting CertStream collector that works without any API key;
- optional URLScan and VirusTotal enrichment that skips cleanly when credentials are absent;
- configurable watch targets with aliases, official-domain suppression and conservative fuzzy matching;
- an authenticated operator console for integrations, targets, triage, false positives and pivot jobs;
- an anonymous read-only dashboard with defanged, non-clickable indicators;
- write-only encrypted provider secrets, CSRF-protected sessions and loopback-first defaults;
- container and native-Python operation without a Node.js runtime.

No production registry, proprietary logic, historical data, credentials or live observations are included. The example target uses reserved `.example` domains only.

## How it works

1. CertStream supplies newly observed certificate names.
2. The matcher compares each normalized domain with the targets you configured.
3. Matching domains are saved as candidates even when no enrichment provider is configured.
4. An operator reviews the evidence, records corrections and decides what can appear on the public dashboard.

URLScan and VirusTotal add context when keys are available. They are enrichers, not publication gates, and the application never opens an observed website.

## Trust boundary

The public dashboard does not expose administration, provider secrets, raw responses or private analyst notes. The operator console and workers require the Python service and database; they cannot be safely hosted on GitHub Pages. Provider calls use fixed HTTPS origins and never visit or submit a candidate website.

## Quick start

Requirements: Python 3.12 or later.

```powershell
python -m venv .venv
.\.venv\Scripts\python -m pip install -e ".[dev]"
.\.venv\Scripts\open-domain-radar init
.\.venv\Scripts\open-domain-radar create-admin --username operator
.\.venv\Scripts\open-domain-radar serve
```

Open `http://127.0.0.1:8787/admin` and sign in with the operator created by the CLI. Browser-based account creation is deliberately unavailable, including on loopback. In a second terminal, start collection and pivot processing:

```powershell
.\.venv\Scripts\open-domain-radar worker
```

The worker stores matching CertStream candidates immediately. When an enabled optional provider has a key, a new CertStream candidate queues one bounded enrichment pass; a missing key is recorded as unavailable and never blocks the candidate. Add keys through the protected Integrations view or inject them as environment secrets.

After signing in, add one watch target and at least one official domain. Keep the target disabled until the aliases and official-domain list are correct, then enable it and start with conservative thresholds. The bundled `.example` record is documentation only and is disabled by default.

Create the single operator from a trusted terminal before exposing any deployment:

```powershell
.\.venv\Scripts\open-domain-radar create-admin --username operator
```

## Development checks

```powershell
.\scripts\check.ps1
```

The check runs Ruff, MyPy, unit/integration coverage, source-boundary checks, a clean installed-wheel smoke test and a real responsive browser audit.

## Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [Detection and scoring](docs/DETECTION.md)
- [Providers and pivots](docs/PROVIDERS.md)
- [Security model](docs/SECURITY-MODEL.md)
- [Deployment](docs/DEPLOYMENT.md)
- [Operations and backup](docs/OPERATIONS.md)
- [Public data contract](docs/DATA-CONTRACT.md)

## Licence and data terms

Software is licensed under Apache-2.0. Synthetic examples are offered under CC0-1.0. Provider results, screenshots and other third-party data remain subject to their original terms; see [DATA-LICENSE.md](DATA-LICENSE.md) and [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).
