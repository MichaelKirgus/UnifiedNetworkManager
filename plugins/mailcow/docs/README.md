# Mailcow Plugin — Documentation

Plugin for the Unified Network Manager (UNM). Manages [mailcow](https://docs.mailcow.email/)
(mailcow-dockerized) mail servers over their REST API: domain, mailbox and alias inventory
plus full CRUD actions, and security checks that surface failed login attempts.

## Capabilities

| Capability | Requirement | Notes |
| --- | --- | --- |
| Monitoring | — | System version + service health of the mailcow stack. |
| Inventory | — | Domains, mailboxes, aliases with their key attributes for UNM's inventory views. |
| Configuration actions | — | 9 catalog actions: create/update/delete domains, mailboxes and aliases. |
| Planning / rollouts | — | Multi-device intents for fleet mail configuration. |
| Security checks | — | Failed-login findings surfaced in the security-checks view. |

## Credential slots

1. **Primary** — `apiKeyNoSecret` secret type: a mailcow API key (Setup → API) with the username it belongs to; no password component.

## License

EUPL-1.2 — see [LICENSE.md](../LICENSE.md).
