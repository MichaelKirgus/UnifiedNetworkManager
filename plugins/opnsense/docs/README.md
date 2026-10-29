# OPNsense Plugin — Documentation

Plugin for the Unified Network Manager (UNM). Manages [OPNsense](https://www.opnsense.org/)
firewall appliances over its REST API, with an optional SSH slot that unlocks ZFS
storage inventory and security checks.

## Capabilities

| Capability | Requirement | Notes |
| --- | --- | --- |
| Monitoring | — | System status, CPU/memory/disk gauges, per-interface traffic table (30 s cadence). |
| Inventory | — | Hostname/version, ARP + NDP tables, configured networks (IP/CIDR/VLAN), DHCP leases, PPPoE tunnels, routes, firewall rules, services, gateways. 15-min window. |
| Static DNS entries | — | The dnsmasq/unbound host-record table (`dnsEntries` metric) for the DNS page; backend auto-detected per appliance. |
| Configuration actions | — | Single-device actions from the action catalog (reboot, service restarts, …). |
| Planning / rollouts | — | Multi-device intents: `network.create`, `network.delete`, `dns.set`, `dns.delete` (see write paths below). |
| Firmware + package updates | — | Live status from the appliance's own update engine; minor point releases and major upgrades applied through OPNsense's update jobs. |
| ZFS storage inventory | **SSH slot bound** AND appliance runs ZFS | Pools, datasets, zvols, scrub state, snapshots, per-disk health. The OPNsense API exposes no ZFS listing — only the mounted-root overview (`system_disk`). Without this slot you still get the mounted-filesystem rows. |
| Security checks | **SSH slot bound** | File-integrity baselines, failed-login scans, rate-limit/account checks over SSH at inventory cadence. Read-only commands. |

## Credential slots

1. **Primary — API key** (`apiKey` secret type). The OPNsense REST API credential pair
   (System → Access → API Keys). Required for everything above.
2. **Optional — `ssh` slot.** Accepts a username/password login OR an ed25519 key pair.
   Unbound = API-only mode: monitoring, inventory, configuration and updates all work;
   ZFS pool/dataset detail and security checks are skipped silently.

### Network-intent write paths (firmware split)

The canonical `network.create` / `network.delete` intents write interface assignments
through two different paths depending on the appliance's firmware line:

- **OPNsense 26.7+** — REST API (`setAssignmentItem` + reconfigure). No extra credentials needed.
- **OPNsense ≤ 26.4** — SSH config upsert (the REST assignment endpoints are not
  available on these releases). A bound `ssh` slot is required; without it the intents
  are reported as *not effective* for that device in UNM's support matrix.

## Supported firmware lines

Release lines published on the official package mirror (`https://pkg.opnsense.org/releases/`):

22.1 · 22.7 · 23.1 · 23.7 · 24.1 · 24.7 · 25.1 · 25.7 · 26.1 · **26.7** (current)

Point releases (`pN`) are handled by the Updates page; major upgrades boot a new
environment and require a reboot.

## Supported hardware

Any x86_64 or ARM appliance running OPNsense, including:

- Deciso rack appliances — DEC3920, DEC3940, DEC3960, DEC4280, DEC4240, DEC2770,
  DEC2752, DEC3862, DEC3852, DEC2687
- Deciso desktop appliances — DEC850, DEC750, DEC740, DEC697, DEC677
- Custom / DIY builds

The model selection in the UNM device form is informational (icon + firmware catalog);
the plugin works identically on all of them.

## License

EUPL-1.2 — see [LICENSE.md](../LICENSE.md).
