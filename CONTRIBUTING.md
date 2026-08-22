# Contributing

Open Domain Radar accepts narrowly scoped, reviewable changes that preserve its passive-collection and evidence-boundary guarantees.

## Before changing behavior

Open a design issue for schema changes, new providers, new automatic publication rules, authentication changes or anything that contacts an observed host. Describe the intelligence requirement, operator decision, evidence semantics, rate/retention cost and false-positive risk.

## Local checks

```powershell
python -m pip install -e ".[dev]"
.\scripts\check.ps1
```

Every detection change needs positive, ambiguous and benign fixtures using reserved domains. Every provider change needs mocked HTTP/WebSocket tests for missing credentials, rate limiting, invalid content, oversized responses and redirects. Never use real suspicious infrastructure in tests.

## Safety rules

- Do not commit API keys, cookies, database files, raw provider responses, screenshots or analyst notes.
- Do not add active crawling, browser automation or URL submission under the label “passive”.
- Do not turn a lexical score or provider verdict into an automatic statement of maliciousness.
- Keep candidate indicators defanged and non-clickable in public output.
- Preserve append-only review history; corrections are compensating events.
- Reject ambiguous target identity rather than choosing the highest score silently.

Contributions are licensed under Apache-2.0. Contributors must have the right to submit all included code and fixtures.
