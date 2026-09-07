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

Set `ODR_PUBLIC_ORIGIN` to the exact browser-facing origin, without a path. A minimal Nginx boundary looks like this; certificate paths and network policy remain deployment-specific:

```nginx
limit_req_zone $binary_remote_addr zone=odr_login:10m rate=5r/m;

server {
    listen 443 ssl;
    server_name radar.example.org;
    ssl_certificate /etc/letsencrypt/live/radar.example.org/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/radar.example.org/privkey.pem;
    client_max_body_size 32k;

    location = /api/admin/v1/login {
        limit_req zone=odr_login burst=3 nodelay;
        proxy_pass http://127.0.0.1:8787;
        proxy_set_header Host $host;
    }

    location / {
        proxy_pass http://127.0.0.1:8787;
        proxy_set_header Host $host;
    }
}
```

The application does not trust `X-Forwarded-For` or `X-Forwarded-Proto`; rate limiting and client attribution stay at the proxy. Keep the application port bound to loopback and do not expose it alongside the HTTPS endpoint.

Before a release is deployed, rehearse this topology with an ephemeral self-signed certificate and a loopback TLS-terminating proxy. Confirm application behavior through the boundary, including HSTS and Secure/HttpOnly session cookies. This does not validate a production certificate, firewall, VPN, DNS or a hosting provider's proxy configuration.

## Secrets

Prefer a secret manager for `ODR_MASTER_KEY`, `URLSCAN_API_KEY` and `VIRUSTOTAL_API_KEY`. Environment keys override stored values and are reported only as configured, never returned. The web and worker processes need the same environment view so the console can report availability and the worker can execute jobs. Do not place real values in examples, images, CI logs or public output.

## Scaling boundary

The supported initial shape is one web process and one worker sharing one SQLite volume. Do not start multiple web or worker processes against the same database. PostgreSQL, distributed locks and multi-worker scheduling require a future tested release.

GitHub Pages can host a future sanitized static export, but cannot host this database, admin console, worker or secret store.

## Runtime image maintenance

The Docker build uses Python 3.12.14 on Debian Bookworm slim, pinned to an immutable image digest in the Dockerfile. Weekly Docker dependency proposals and the scheduled CI run keep image maintenance separate from application dependency locks.

CI exports the built runtime image and checks it with a digest-pinned Trivy scanner. Fixable HIGH and CRITICAL findings fail the verification job. This check does not claim that an image has no vulnerabilities. Unfixed findings, deployment configuration and newly published advisories still require review. A failed scheduled check is a maintenance signal, not an automatic production upgrade. Review the image proposal, pass the same tests and rebuild deliberately.
