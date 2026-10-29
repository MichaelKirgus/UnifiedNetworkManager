# Plugin catalog — supported vendors & devices

UNM ships **24 plugins** as independent microservices (one directory each under `plugins/`, plus `_template/` as the scaffold for new ones). Every plugin speaks one common contract and self-registers with the API on boot, so adding a device family never means touching the core — see [PLUGIN-DEVELOPMENT.md](PLUGIN-DEVELOPMENT.md) for how to build your own.

A device can carry **multiple plugins at once** (e.g. generic SNMP + a vendor plugin), each with its own credentials; exactly one is *primary*. Every plugin also supports multi-instance deployments (`PLUGIN_INSTANCE_ID`) for remote sites.

## Vendor adapters

| Plugin | Directory | Vendor(s) | Supported devices / models | Capabilities |
|--------|-----------|-----------|----------------------------|--------------|
| OPNsense Plugin | `plugins/opnsense/` | OPNsense | Any x86_64 box running OPNsense — DEC2687, DEC2752, DEC2770, DEC3852, DEC3862, DEC3920, DEC3940, DEC3960, DEC4240, DEC4280, DEC677, DEC697, DEC740, DEC750, DEC850 + Custom/DIY | monitoring, inventory, configuration (WireGuard/IPsec/OpenVPN/routes plan intents), planning, deviceState, ssh, updates (read-only — OS updates go through the web UI), quickActions, securityChecks |
| LANCOM LX-Series Plugin | `plugins/lancom-lx/` | LANCOM | Wi-Fi 6/7 access points: LC-LX-6200(E), LC-LX-6212, LC-LX-6400, LC-LX-6402, LC-LX-6500(E), LC-LX-7200(E), LC-LX-7300, LC-LX-7400, LC-LX-7500 | monitoring (LCOS-LX-MIB: radios, SSIDs, stations, RF environment), inventory, configuration, planning, deviceState, sshConsole, updates, quickActions, securityChecks |
| LANCOM LCOS Plugin | `plugins/lancom-lcos/` | LANCOM | Routers: LC-730VA, LC-883-VoIP, LC-884-VoIP, LC-1640E, LC-1650E, LC-1780EF, LC-1781VA, LC-1790EF, LC-1793VA, LC-1800EF, LC-1803VA(W), LC-1803VAW-5G, LC-1900EF, LC-1906VA, LC-1926VAG, LC-1930EF, LC-1936VAG, LC-2100EF, LC-IAP-821/822, LC-OAP-5G, LC-ISG-1000/4000/5000/8000, vRouter + Other/custom | monitoring (system/LAN/WAN throughput, VPN, temperature), inventory, configuration over SNMP SET (`lcsSetup`) with web-UI config backup via a second credential slot, planning, sshConsole, updates, quickActions, securityChecks |
| LANCOM SX-Series Plugin | `plugins/lancom-sx/` | LANCOM | Managed switches — unified 4.x MIB **and** legacy GS-2310 3.x tree (auto-detected): GS-2310, GS-2412(P), GS-2426(P), GS-3126X(P), GS-3128X(P), IGS-3128XP/F, GS-3152P/X/XP/XSP, GS-3252P, GS-3510X/XP, IGS-3510XUP, XS-3510YUP, XS-3526YUP, GS-3528X/XP/XSP/XUP, XS-3550YUP, GS-3628X/XP/XUP, GS-3652X/XP/XUP + Other/custom | monitoring (system/PSU/fans/temp, ports + throughput, PoE, LAG/LACP), inventory, configuration over SNMP SET, planning, deviceState, updates, quickActions |
| MikroTik RouterOS Plugin | `plugins/mikrotik-routeros/` | MikroTik | Any RouterOS 7.x router via the REST API (`/rest/`) + SSH/SFTP for backup/restore — CCR/hEX/CRS with RouterOS, RB-series and QEMU images | monitoring (system, interfaces, firewall rules), inventory, configuration (interfaces/VLANs/routes/gateways/DHCP/DNS, firewall rules, WireGuard/IPsec VPN, system identity/clock/NTP/users/services/scheduler/logging, config backup+restore, firmware update), planning, deviceState, sshConsole, updates, quickActions |
| MikroTik SwOS Plugin | `plugins/mikrotik-swos/` | MikroTik | CRS305-1G-4S+, CRS309-1G-8S+(2H+P), CRS310-8G+2S+, CRS326-24S+2Q, CRS328-24P-2S+Q (SwOS) and CSS326-24G-2S+, CSS610-8G/8P-2S+ (SwOS Lite), via the `.b-file` HTTP API (Digest auth) | monitoring (system, ports, PoE, SFP, VLANs), inventory, configuration (port config, PoE, LAG, per-port VLANs, VLAN table, SNMP, system identity), planning, deviceState, updates, quickActions |
| FBox Plugin | `plugins/fbox/` | AVM | FRITZ!Box 4060, 7530 AX, 7590, 7690 + Custom/Other — over the box's own web-UI session API | monitoring (system/WAN/LAN/WiFi), inventory (LAN devices, WLAN clients, SSIDs propagation), quickActions |
| OpenWRT Plugin | `plugins/openwrt/` | OpenWrt | Any device running OpenWrt (ubus/uci) — two-tier cadence: live metrics every poll, ARP/NDP/DHCP/networks/routes/tunnels/Wi-Fi/firewall at the 15-min interval | monitoring, inventory, configuration (firewall, DNS, DHCP, VPN), planning, deviceState, ssh, probe, sshConsole, quickActions, securityChecks |
| TrueNAS Plugin | `plugins/ix-truenas/` | iXsystems | TrueNAS SCALE — JSON-RPC + SSH data path: system/pools/shares monitoring, VMs, containers/apps (app-store templates drive the Containers page's Create-app dialog) | monitoring, configuration (VMs, containers, storage, shares), planning, deviceState, ssh, probe, filesystem (SFTP file manager), sshConsole, updates, quickActions |
| Mailcow Plugin | `plugins/mailcow/` | mailcow | mailcow dockerized — domains, mailboxes and aliases over the REST API | monitoring (system version + service health), inventory, configuration (domain/mailbox/alias CRUD), planning, securityChecks (fail2ban rate limiting, per-domain DKIM) |
| Zabbix Plugin | `plugins/zabbix/` | Zabbix | Any Zabbix server as an external inventory source | monitoring, inventorySync |
| netcup SCP Plugin | `plugins/netcup-scp/` | netcup | netcup VPS fleet via the SCP REST API (one Bearer token per account) | monitoring (server + task tables), inventory (networks from VM interface IP aliases, firewall rules from interface policies), configuration (~20 plan-gated actions: power, hostname/nickname, snapshots, rescue system, ISO attach/detach, OS image setup, firewall policy CRUD + apply, rDNS, task cancellation — with pre-change rollback snapshot), planning |

## Generic & platform adapters

Vendor-neutral plugins that work with any device exposing the respective protocol — useful on their own or stacked alongside a vendor plugin.

| Plugin | Directory | Works with | What it does | Capabilities |
|--------|-----------|------------|--------------|--------------|
| Generic SNMP Plugin | `plugins/generic-snmp/` | Any device exposing SNMPv1/v2c/v3 | System group + interface throughput monitoring, inventory via the net-snmp UDP stack; IEEE 802.11 MIB Wi-Fi collection (gated by the `collectWifi` option) | monitoring, inventory |
| ICMP Plugin | `plugins/icmp/` | Any IP-reachable host — no credentials needed | Reachability / latency / jitter / loss + IP/MAC inventory propagation | monitoring, inventory |
| Generic HTTP(S) Plugin | `plugins/generic-http/` | Any HTTP/HTTPS endpoint | Live response-time/status metrics every poll; TLS certificate probe at the 15-min interval (feeds the Certificates page) | monitoring, inventory |
| Generic (S)NTP Plugin | `plugins/generic-ntp/` | Any NTP server | Reachability + served-time metrics feeding the cross-device Time page (`system.ntpServed`) | monitoring, inventory |
| Generic SSH Plugin (Linux) | `plugins/generic-ssh/` | Any Linux host over SSH | System metrics, Docker/compose containers (Containers page), filesystem browsing, firewall events/sessions, package updates, interactive console | monitoring, inventory, configuration, planning, ssh, filesystem, probe, sshConsole, updates, securityChecks |
| Generic IPMI Plugin | `plugins/generic-ipmi/` | Any bare-metal server BMC over RMCP+ (UDP 623) — protocol stack implemented in-process, no ipmitool subprocess | Chassis power state → health, SDR sensor walk with live readings + threshold states, FRU identity, SEL tail, LAN channel inventory; plan-gated control actions (power on/soft-off/hard-off/reset, boot options, SEL clear, NMI pulse, BMC LAN writes); IPMI SOL serial console | monitoring, inventory, configuration, planning, sshConsole |
| Docker Plugin | `plugins/docker/` | Any Docker host via the Engine API (+ optional SSH slot for compose deploys) | Containers/images/apps inventory, per-container start/stop/restart/delete, change-image action (recreate on a new image tag/ref), deploy-compose action (Create-app dialog), live per-container stats probe | monitoring, configuration, planning, deviceState, probe |
| Flow Collector (sFlow/NetFlow) | `plugins/flow-collector/` | — (push-based ingest service; no devices of its own) | Receives sFlow/NetFlow samples and feeds the Flows page (top talkers, pairs, internet egress) | ingest only |

## Infrastructure plugins

Not device-facing — they serve the UNM core itself and are swappable via `AUTH_PLUGIN_ID` / `SECRETS_PLUGIN_ID`.

| Plugin | Directory | Role | Capabilities |
|--------|-----------|------|--------------|
| Basic Auth (Local Users + TOTP) | `plugins/basic-auth/` | Identity provider — local users + TOTP verification on behalf of the API | identityProvider |
| Secrets Provider (Device Credentials) | `plugins/secrets-provider/` | Crypto holder — encryption at rest (owns `MASTER_KEY`) + key/cert generation (WireGuard key pairs, tunnel PSKs, OpenVPN CA/cert/key) | secretsProvider |
| File Repo (Storage Backend) | `plugins/file-repo/` | Stateless bytes half of the central file repository — content-addressed (SHA-256) store on a local volume; the API owns all metadata and brokers every read/write. Multi-instance via `PLUGIN_INSTANCE_ID` for per-segment repos | fileRepo |
| Web Fetch (Internet Egress) | `plugins/web-fetch/` | Pull-based egress service for the API (e.g. GeoIP lookups); no devices of its own | webFetch |

## Adding a new plugin

Start from [`plugins/_template/`](../plugins/_template/) and follow [PLUGIN-DEVELOPMENT.md](PLUGIN-DEVELOPMENT.md) — contract, SDK usage, settings loop, credential slots, device-model catalogs, logging pipeline and deployment. A third-party plugin needs **zero changes** to the main app: it self-registers on boot with its `UNM_API_URL` + `PLUGIN_API_KEY`.
