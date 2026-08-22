# Deployment

## Native development

```powershell
python -m venv .venv
.\.venv\Scripts\python -m pip install -e ".[dev]"
.\.venv\Scripts\open-domain-radar init
.\.venv\Scripts\open-domain-radar create-admin --username operator
.\.venv\Scripts\open-domain-radar serve
```

Run `open-domain-radar worker` in a separate terminal. The default web listener is `127.0.0.1:8787`.

Browser-based account creation is disabled for every deployment. Create the single operator from a trusted terminal before starting or exposing the service:

```sh
open-domain-radar create-admin --username operator
```

## Container

Initialize the shared volume once, then start both services:

```sh
docker compose build
docker compose run --rm web open-domain-radar init
docker compose run --rm web open-domain-radar create-admin --username operator
docker compose up -d
```

The supplied host mapping remains loopback-only. Put a TLS reverse proxy in front if remote access is required. Non-loopback `ODR_PUBLIC_ORIGIN` values must use HTTPS and invalid origins fail at startup. Keep `/admin` behind a VPN or IP allowlist when practical. Apply proxy-side request-size and per-client login limits: the application deliberately ignores forwarding headers, so an upstream proxy otherwise appears as one peer to its in-process limiter.

## Secrets

Prefer a secret manager for `ODR_MASTER_KEY`, `URLSCAN_API_KEY` and `VIRUSTOTAL_API_KEY`. Environment keys override stored values and are reported only as configured, never returned. The web and worker processes need the same environment view so the console can report availability and the worker can execute jobs. Do not place real values in examples, images, CI logs or public output.

## Scaling boundary

The supported initial shape is one web process and one worker sharing one SQLite volume. Do not start multiple web or worker processes against the same database. PostgreSQL, distributed locks and multi-worker scheduling require a future tested release.

GitHub Pages can host a future sanitized static export, but cannot host this database, admin console, worker or secret store.
