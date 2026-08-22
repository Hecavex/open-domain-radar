# Security policy

## Supported versions

The project is an alpha release. Security fixes apply to the current default branch and the newest tagged `0.1.x` release.

## Reporting

Use [GitHub private vulnerability reporting](https://github.com/Hecavex/open-domain-radar/security/advisories/new) for security reports. Do not file a public issue containing credentials, session tokens, private evidence, exploitable deployment details or personal data. Ordinary non-sensitive bugs can use the public issue tracker.

## Operator responsibilities

- Keep the operator console behind HTTPS and, preferably, a VPN or IP restriction.
- Inject `ODR_MASTER_KEY` through a secret manager or protect the generated key file separately from database backups.
- Rotate provider keys after suspected exposure; deleting a stored secret does not revoke it at the provider.
- Back up the database and master key separately and test restoration.
- Review public exports for provider terms, private notes and unsafe live links.

The project intentionally does not accept arbitrary provider URLs, actively visit candidates, render raw provider HTML or expose provider secrets through its API.
