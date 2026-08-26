# Contributing

Open Domain Radar accepts narrowly scoped, reviewable changes that preserve its passive-collection and evidence-boundary guarantees.

## Before changing behavior

Open a design issue for schema changes, new providers, new automatic publication rules, authentication changes or anything that contacts an observed host. Describe the intelligence requirement, operator decision, evidence semantics, rate/retention cost and false-positive risk.

## Local checks

```powershell
python -m pip install -e ".[dev]"
python -m ruff check .
python -m ruff format --check .
python -m mypy
python -m pip_audit . --strict --progress-spinner off
python -m build
```

Describe how detection changes behave for positive, ambiguous and benign cases, using reserved domains in review notes. Provider changes must document missing-credential, rate-limit, invalid-content, oversized-response and redirect behavior. Do not use real suspicious infrastructure, provider credentials or analyst data in a contribution.

Schema changes require a new immutable entry in `src/open_domain_radar/migrations.py`, a documented upgrade from the previous release, a fresh-install rehearsal and a backup/restore rehearsal. Never edit an already released migration or implement downgrade SQL. A newer database must continue to fail closed on an older application.

## Safety rules

- Do not commit API keys, cookies, database files, raw provider responses, operational screenshots or analyst notes. Sanitized documentation images must use only reserved domains and blank credentials.
- Do not add active crawling, browser automation or URL submission under the label “passive”.
- Do not turn a lexical score or provider verdict into an automatic statement of maliciousness.
- Keep candidate indicators defanged and non-clickable in public output.
- Preserve append-only review history; corrections are compensating events.
- Reject ambiguous target identity rather than choosing the highest score silently.

Contributions are licensed under Apache-2.0. Contributors must have the right to submit all included code and documentation.
