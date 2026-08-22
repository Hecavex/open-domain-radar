# Release qualification and rehearsal

This file records what the automated release gate proves and what still requires a human or the intended host. It is evidence for the alpha release, not a security certification.

## Automated release gate

The release suite runs against reserved domains and disposable state. It verifies:

- strict linting, formatting and Python type checks;
- unit and API tests with coverage enforcement;
- forward-only migration creation, adoption of a pre-ledger 0.1.0 database, rejection of future schemas and append-only evidence triggers;
- online backup, restore into a fresh instance, forced replacement, automatic rollback-copy recovery and invalid-backup rejection;
- wheel contents and application startup from the installed artifact;
- anonymous and operator layouts at 320, 390, 768, 1024 and 1440 CSS pixels;
- keyboard-visible focus and skip navigation, named controls, reduced motion, forced colours, 200% text scaling and the 320-pixel reflow equivalent of 400% desktop zoom;
- JavaScript-disabled public output and an explicit operator-console fallback;
- local HTTPS termination through a reverse proxy, including HSTS and Secure/HttpOnly session cookies;
- valid local documentation targets and HTTPS-only non-loopback links; and
- optional live reachability of external documentation links when `ODR_CHECK_EXTERNAL_LINKS=1`.

Run the same split used by CI:

```sh
python -m ruff check .
python -m ruff format --check .
python -m mypy
python -m pytest -m "not release" --cov=open_domain_radar --cov-report=term-missing
python -m pytest -m release
python -m build
```

Use the opt-in external check immediately before publishing documentation:

```sh
ODR_CHECK_EXTERNAL_LINKS=1 python -m pytest tests/test_documentation_links.py
```

## Latest local rehearsal

The 23 August 2026 rehearsal used Python 3.12.8 and Chromium on Windows. Ruff, formatting and strict mypy checks passed. The hermetic suite passed 81 tests with 84.37% statement coverage; the release selection passed nine tests with one expected opt-in network check skipped. A separate enabled network run passed both documentation-link checks, and the source distribution and wheel built successfully.

The database exercise restored a known-good backup, confirmed that post-backup rows disappeared, then restored the automatically preserved pre-restore copy and confirmed those rows returned. The proxy exercise served both public and authenticated routes through local HTTPS without installing a system proxy. Representative public and operator views were captured at 390 and 1440 pixels and inspected for clipping, overflow and focus loss.

The local Docker daemon was unavailable, so the container-image build could not be repeated on that workstation. The repository CI performs the same Dockerfile build and command smoke test on the published revision; its result is required alongside the local package checks.

## Human and host checks

Automation cannot complete these checks honestly:

- NVDA, VoiceOver or another real screen-reader pass through the public and operator workflows;
- browser zoom and operating-system high-contrast inspection on the operator's supported browser/OS matrix;
- production DNS, certificate chain, TLS policy, firewall, VPN/IP allowlist and reverse-proxy rate limiting;
- restore from the operator's encrypted off-host backup storage on the actual host;
- provider-key rotation and confirmation that revoked credentials fail; and
- an analyst review of target quality, suppressions and false-positive outcomes using the operator's own data.

Complete those checks before describing a deployment as production-ready. Record the date, reviewer, tested release, environment and deviations in the operator's private runbook; never publish credentials, database contents or operational screenshots.
