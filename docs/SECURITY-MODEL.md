# Security model

The system processes attacker-controlled domain names and third-party responses while holding provider credentials. Every collected value is untrusted.

## Boundaries

- The anonymous API is read-only and emits bounded, defanged public fields.
- Administrative mutations require an authenticated opaque session and matching CSRF token.
- Session tokens are random and only their hashes are stored. Cookies are SameSite=Strict and Secure outside loopback development; the session cookie is HttpOnly.
- Passwords use Argon2id. Login failures use a bounded per-peer in-memory limiter, password verification has a concurrency ceiling, login bodies are capped, and missing users take the same Argon2 verification path.
- Provider secrets are encrypted at rest with a server-side master key and never returned after submission.
- Provider destinations are compiled into adapters. Arbitrary remote URLs, candidate browsing, credentialed URLs and redirects are not accepted.
- Candidate values are rendered as text and defanged. They are never hyperlinks.

## First-run ownership

There is no browser account-creation endpoint. Every deployment must create the single operator with `open-domain-radar create-admin` from a trusted terminal before exposure. Origin checks protect browser login requests from cross-site submission; they are not treated as proof of operator identity. Reverse proxies must add their own per-client rate limit because forwarded client addresses are not trusted.

## Master key

`ODR_MASTER_KEY` must be a generated Fernet key and should come from an OS or container secret. A local deployment may create a protected key file under `ODR_DATA_DIR`. Native state directories are hardened to owner-only access and key/database files to owner read/write where the platform supports POSIX permissions. The key is separate from the database so a database-only leak does not directly disclose provider keys.

Back up the database and key separately. Losing the key makes stored provider secrets unrecoverable; re-enter them rather than attempting custom recovery.

## Content and deployment policy

The interface uses self-hosted static files and a restrictive CSP. It does not render provider HTML, inline event handlers or raw JSON. Screenshot proxying is deliberately disabled because it introduces redistribution, privacy and content-safety responsibilities.

Loopback is the default. Remote deployments require TLS, a correct public origin and preferably a VPN or IP allowlist. This is a single-admin research tool, not a hardened multi-tenant service.
