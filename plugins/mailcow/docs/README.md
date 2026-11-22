# Mailcow Plugin — Documentation

Plugin for the Unified Network Manager (UNM). Manages [mailcow](https://docs.mailcow.email/)
(mailcow-dockerized) mail servers over their REST API: domain, mailbox and alias inventory
plus full CRUD actions, security checks (fail2ban, DKIM, rspamd, login activity) and the
netfilter jail log as firewall events.

## Capabilities

| Capability | Requirement | Notes |
| --- | --- | --- |
| Monitoring | — | System version + service health of the mailcow stack. |
| Inventory | — | Domains, mailboxes, aliases with their key attributes for UNM's inventory views. |
| Configuration actions | — | 9 catalog actions: create/update/delete domains, mailboxes and aliases. |
| Planning / rollouts | — | Multi-device intents for fleet mail configuration. |
| Security checks | — | fail2ban ban state (rate limiting), per-domain DKIM presence/strength (email auth), rspamd spam-filter state (reject/soft-reject tallies + version) and SASL login activity by source IP — an external IP authenticating as ≥3 distinct users raises a credential-stuffing warning. Findings surface in the cross-device Security page. |
| Firewall events | — | The netfilter jail log (`get/logs/netfilter`) is classified (brute-force pre-ban warnings, failed mail auth, non-SMTP port scans) and pushed to UNM's shared firewall-events table with a time cursor + deterministic dedupe key; rows appear on the Firewall Events page. Toggle: `netfilterLogEnabled` option. |

## Credential slots

1. **Primary** — `apiKeyNoSecret` secret type: a mailcow API key (Setup → API) with the username it belongs to; no password component.

## License

EUPL-1.2 — see [LICENSE.md](../LICENSE.md).
