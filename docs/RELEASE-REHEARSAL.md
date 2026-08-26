# Release qualification and rehearsal

This document separates repository checks from the behavior that a maintainer must inspect on the intended host. Passing the automated gate qualifies an artifact for manual review; it is not a security certification or proof of production readiness.

## Automated gate

Continuous integration performs checks that do not require credentials, operational data or contact with third-party services:

- Ruff linting and formatting;
- strict mypy analysis of the Python package;
- Python bytecode compilation;
- an audit of installed Python dependencies against known vulnerability advisories;
- source-distribution and wheel builds;
- installation of the built wheel followed by a CLI startup check; and
- a Docker image build followed by the same CLI startup check.

Run the source and package checks locally:

```sh
python -m pip install -e ".[dev]"
python -m ruff check .
python -m ruff format --check .
python -m mypy
python -m compileall -q src
python -m pip_audit . --strict --progress-spinner off
python -m build
```

Inspect `dist/`, install the wheel into a clean virtual environment and run:

```sh
open-domain-radar --help
```

When Docker is available, build the image from the release revision and confirm its packaged command starts:

```sh
docker build --tag open-domain-radar:release .
docker run --rm open-domain-radar:release open-domain-radar --help
```

## Manual application rehearsal

Use only reserved domains and disposable state while completing this section. Record the release revision, reviewer, Python/browser versions, operating system and every deviation in a private release record.

Confirm all of the following before publishing a release:

- a fresh database initializes and an operator can be created from the CLI;
- a database from the previous release upgrades without rewriting observations or append-only review history;
- a database created by a newer release fails closed;
- backup, restore into a fresh instance, forced replacement and rollback-copy recovery work on stopped processes;
- the anonymous dashboard never exposes operator notes, provider keys or clickable candidate indicators;
- sign-in, CSRF protection, session expiry, logout, review, restoration and suppression flows behave as documented;
- missing optional provider keys skip enrichment without preventing CertStream candidates from being stored;
- provider errors and rate limits remain bounded and visible to the operator;
- public and operator layouts remain usable at 320, 390, 768, 1024 and 1440 CSS pixels;
- keyboard focus, skip navigation, reduced motion, forced colours, 200% text scaling and narrow reflow remain usable;
- public content remains meaningful with JavaScript disabled and the operator console presents an explicit fallback; and
- documentation links resolve to repository files or intended HTTPS destinations.

## Host rehearsal

On the intended host, verify production DNS, the certificate chain, TLS policy, firewall, VPN or IP allowlist, proxy request limits and login rate limits. Exercise the application only through the browser-facing HTTPS origin and confirm HSTS and Secure/HttpOnly session cookies.

Restore an encrypted off-host backup into an isolated directory, rotate a disposable provider credential and verify that revocation is reflected as a controlled failure. Complete a real screen-reader pass with NVDA, VoiceOver or another supported assistive technology.

Do not publish credentials, databases, provider responses, private analyst notes or operational screenshots as release evidence.

## Qualification boundary

The repository gate cannot establish target quality, provider availability, collection completeness, detection accuracy or the safety of an operator's network boundary. A maintainer must review watch targets, official domains, suppressions, false-positive outcomes and retention choices using the deployment's own context before describing it as production-ready.
