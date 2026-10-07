# Generic SSH Plugin — Documentation

Plugin for the Unified Network Manager (UNM). A generic **Linux monitoring & management**
plugin that works over plain SSH on any POSIX box — from busybox routers to full servers.
Data sources are plain reads of `/proc`, `/sys` and standard tools (`iproute2`, `df`,
`lsblk`), so every section degrades gracefully when a tool is missing.

## Capabilities

| Capability | Requirement | Notes |
| --- | --- | --- |
| Monitoring | — | CPU/memory/load/disk gauges, per-interface throughput from `/proc/net/dev`, 30 s cadence. |
| Inventory | — | Interfaces, ARP/NDP tables, routes, filesystems, disks (lsblk), services. |
| Configuration actions | — | Routes, services, packages, timezone/clock and more from the action catalog. |
| Planning / rollouts | — | Multi-device intents for fleet configuration. |
| Updates | — | Package update status + apply via apt/dnf/pacman (detected per device). |
| Security checks | — | Read-only SSH checks: failed logins, file-integrity baselines, account/rate-limit findings. |
| Interactive SSH console | — | Shell button on the device page (PTY over the same credential). |
| SFTP file manager | — | Files tab: browse/upload/download/delete on the remote filesystem. |

## Credential slots

1. **Primary** — `usernamePassword` or `sshKeyPair` secret (ed25519/rsa key pair supported), plus port override.

## Firewall events

The plugin can tail the kernel's netfilter log lines from journald and forward them to UNM's
Firewall Events page (`firewallEventsEnabled`, default on). To make drops appear, enable
kernel drop logging with the `firewall.log.enable` action (nftables) — a **write-risk**
action that only runs through the plan workflow (2FA + audit trail); `firewall.log.disable`
reverts it. Monitoring itself is strictly read-only and never injects rules.

## License

EUPL-1.2 — see [LICENSE.md](../LICENSE.md).
