# Providers and pivots

All built-in providers are passive and use fixed service origins. The application never follows a candidate URL and never submits it for scanning.

## CertStream

CertStream requires no API key. It supplies certificate names from a live WebSocket stream. The worker repeatedly opens bounded collection windows and reconnects between them. Stream downtime is not replayable and must remain visible in coverage disclosures. A matching certificate name is stored immediately and never waits for enrichment.

## URLScan

URLScan is optional. The adapter searches existing public reports by exact domain and retains bounded normalized fields: domain, scan identifier, validated result reference, time, IP, country and response status. URL paths, queries and fragments are not retained as candidate identity or returned by the operator API. The adapter does not submit or visit a candidate URL, download screenshots, or perform hash pivots in this release.

## VirusTotal

VirusTotal is optional. The adapter requests bounded passive domain-resolution relationships permitted by the operator's API tier. Provider data remains supporting evidence and never changes an analyst disposition automatically.

## Missing credentials

Missing credentials are a normal state. CertStream collection continues, matching candidates are stored, and an unavailable optional provider is skipped. Environment credentials override encrypted database credentials.

## Pivot safeguards

- provider results do not recursively create more pivot jobs;
- result limits are bounded to 100 URLScan rows and 40 VirusTotal rows;
- automatic jobs use a 24-hour per-candidate/provider cooldown and active manual jobs are deduplicated;
- responses are limited to 2 MiB with fixed timeouts and no redirects;
- each provider job has one shared budget of at most three exponentially delayed HTTP attempts; auth and invalid-response failures are terminal;
- stored errors are controlled codes rather than copied provider bodies; and
- a related domain must independently match the originating target before it can become a candidate.

This first graph is deliberately shallow: a pivot records its candidate, provider and trigger. Parent-child edge traversal, certificate/hash expansion and provider quota ledgers are future work, not implied by the current UI.
