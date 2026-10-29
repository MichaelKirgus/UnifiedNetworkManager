# Fleet intents — canonical cross-vendor action contract

Fleet **intents** are the cross-vendor abstraction layer for rolling out whole
networks (VLANs, optionally with L3 addresses / DHCP / WLAN SSID) across a site
or tag. One intent maps to ONE canonical action id + input schema per vendor
plugin; every plugin that implements it advertises the SAME id and a COMPATIBLE
subset of the schema in its `/discover` catalog. The UNM plan machinery then
fans the intent out per device (one step per device) unchanged, and the webapp's
Network Rollout dialog can target a site/tag once and let every implementing
plugin pick it up.

- **Machine-readable source of truth:** `packages/plugin-sdk/src/intents.ts` —
  canonical ids (`INTENT_NETWORK_CREATE`, …), the superset input schemas
  (`NETWORK_CREATE_SCHEMA`, `NETWORK_DELETE_SCHEMA`), the `L2Topology` type,
  and the preflight contract. This file is the human reference for it.
- **How to build a plugin:** see [PLUGIN-DEVELOPMENT.md](./PLUGIN-DEVELOPMENT.md).

## Canonical intent ids

| Intent id | SDK constant | Purpose | Fan-out (`deviceCount`) |
|---|---|---|---|
| `network.create` | `INTENT_NETWORK_CREATE` | Create a named VLAN + optional L3 address (+DHCP/SSID on LCOS) | `'N'` — one step per device, any count |
| `network.delete` | `INTENT_NETWORK_DELETE` | Remove the named network's rows (idempotent no-op when absent) | `'N'` |
| `dns.set` | `INTENT_DNS_SET` | Add/update a static DNS host entry (hostname → IP), idempotent upsert | `'N'` — one step per device, any count |
| `dns.delete` | `INTENT_DNS_DELETE` | Remove the named static DNS entry (idempotent no-op when absent) | `'N'` |
| `l2.topology.read` | `INTENT_L2_TOPOLOGY_READ` | Read-only L2 hierarchy — attach-point source for preflight | `1` — single-device read helper, NOT a fan-out intent |

Reserved (not yet implemented): `tunnel.create`, `tunnel.delete`.

> **`deviceCount` semantics.** `'N'` = the action fans out across a batch
> (one step per device). A numeric count means "exactly N devices" (future
> multi-device intents like tunnels will use e.g. `2`). The API treats canonical
> intent ids as fan-out regardless of a stale persisted number, but plugins MUST
> declare `'N'` for the two network intents and `1` for `l2.topology.read`.

## Naming conventions (binding)

- **Address fields are family-explicit CIDRs.** IPv4 = `cidr`, IPv6 = `cidrV6`.
  A bare `ip` field is NOT allowed in an intent input — it reads as "the IP"
  next to a v6 sibling and hides the address family. (The legacy `ip`+`netmask`
  alternative pair was removed from all plugins and from the SDK superset schema;
  `cidr` is the only IPv4 form.) Use bare `ip`-style names only in intents that
  are genuinely family-agnostic — today's exception: `dns.set.ip` /
  `dns.delete.ip`, where a single entry may be v4 OR v6 and there is no sibling.
- **Names are unique per device** (`name`, 1..64 chars) and double as the
  idempotency key for create/delete.
- **Optional fields advertise capability.** A plugin MAY implement only a subset
  of an intent's optional fields — its catalog entry advertises exactly what it
  supports via its own `inputSchema` (validated per-plugin at plan time). The SDK
  schemas are the SUPERSET contract; anything not in a plugin's schema is simply
  not offered by that vendor.

## `network.create` — field contract

| Field | Type / constraint | Meaning | Supported by |
|---|---|---|---|
| `name` | string, required, 1..64 | Network name (unique per device; idempotency key) | all 7 |
| `vlanId` | number, 1..4094 | VLAN ID to create/attach. Omit for an L3-only network on an existing interface (LCOS: binds to default VLAN 1). **Required on swos** (L2-only switch). | all 7 |
| `cidr` | string, IPv4 CIDR (`a.b.c.d/p`) | Static IPv4 L3 address. Optional everywhere except where the plugin is L3-capable and nothing else was given. | opnsense, openwrt, lcos, routeros, truenas, generic-ssh (skipped on swos) |
| `cidrV6` | string, IPv6 CIDR (`…/p`) | Optional IPv6 L3 address — dual-stack when set alongside `cidr`. | same as `cidr` (skipped on swos) |
| `interface` | string, ≤64 | Attach point / VLAN parent. Resolved per device in preflight; user can override. Vendor-specific layering: LCOS binds L3 to a BRG-x bridge/BUNDLE, not a physical port. | all 7 |
| `vlanPorts` | string[] (port names) | Explicit logical ports carrying the VLAN tag at L2. When omitted the plugin uses its own convention (LCOS copies an existing VLAN's member list on the same bridge). **swos also accepts 1-based numbers** (coerced at runtime — documented deviation; canonical contract is `string[]`). | lcos, routeros (`switch.vlan`, switch-chip SoCs only), swos |
| `dhcpPool` | object `{ start, end }` (IPv4) | Optional DHCP pool served on this network. | **declared:** lcos · **undeclared but honored:** opnsense (dnsmasq backend; Kea → reported skipped) — see "Known deviations" |
| `ssid` | object `{ name, passphrase?, slot? }` | Optional WLAN SSID on a local radio slot (devices with built-in radios only). generic-ssh reports `ssidSkipped` when passed. | lcos |

A rollout must provide at least one of `vlanId` / `cidr` / `cidrV6` / `ssid`
so there is something to create (swos: `vlanId` alone suffices).

## `network.delete` — field contract

| Field | Type / constraint | Meaning | Supported by |
|---|---|---|---|
| `name` | string, required, 1..64 | Network name to remove. Idempotent: a missing name is a no-op (`skipped`). | all 7 |
| `vlanId` | number, 1..4094 (optional) | **swos only** — takes precedence over the name match when set (switch VLAN rows are id-addressed). | swos |

## `dns.set` / `dns.delete` — field contract

Static DNS host entries (hostname → IP) kept in each device's local resolver
config. UNM groups them by lowercase hostname on the **DNS page**; rollout and
delete fan out like network intents.

| Field | Type / constraint | Meaning | Supported by |
|---|---|---|---|
| `name` | string, required, 1..253 (RFC 1123) | Hostname — the idempotency key for set/delete. UNM stores it lowercase; plugins compare case-insensitively where the vendor upper-cases names. | opnsense, openwrt, routeros, lcos |
| `ip` | string, required (set) / optional (delete), IPv4 or IPv6 | The address the hostname resolves to. Record type is derived from the shape (v4 = A, v6 = AAAA — no separate field). On `dns.set`: an existing entry with the same name but a different address is UPDATED in place. On `dns.delete`: when the name maps to several addresses, only this one is removed; omitted = remove all of them. | opnsense, openwrt, routeros, lcos |
| `description` | string, optional, ≤255 | Free-text note for the entry. Only vendors with a native field persist it — **routeros** stores it in `/ip/dns/static`'s `comment`; opnsense / openwrt / lcos have no such column and ignore it (accepted for contract symmetry). On `dns.delete` it is never matched on. | routeros (stored); others (ignored) |

Vendor storage: OPNsense dnsmasq host records / unbound local-zone overrides
(dual backend auto-detected), OpenWrt UCI `dhcp` package `@host[N]`/`@map[N]`
sections (dnsmasq), RouterOS `/ip/dns/static`, LCOS `Setup/DNS/DNS-List` table
(columns Host-name, Rtg-tag=0, IP-Address, IPV6-Address — CLI over SSH PTY).

## `l2.topology.read` — result contract

Empty input schema. Returns an `L2Topology`
(`packages/plugin-sdk/src/intents.ts`): `physicalPorts[]` (name, assignment,
optional trunk/pvid/vlans), `bridges[]`, `bundles[]`, optional
`l3Interfaces` map and `uplinks[]`. Uplinks are NEVER valid attach points —
plugins that know their WAN interface list it so `suggestL2AttachPoint` skips
it.

## Implementation matrix (as of 2026-09)

| Plugin | create | delete | l2.topology.read | preflight resolver | Notes |
|---|---|---|---|---|---|
| opnsense | ✅ `'N'` write | ✅ `'N'` write | ✅ `1` read | yes | staged REST (26.7+) or SSH fallback; DHCP via dnsmasq only |
| openwrt | ✅ `'N'` write | ✅ `'N'` write | ✅ `1` read | yes | UCI over SSH, one batch + commit + reload |
| lancom-lcos | ✅ `'N'` write | ✅ `'N'` **dangerous** | ✅ `1` read | yes | LCOS CLI tables; only plugin with `dhcpPool`+`ssid`; delete tears down 5 tables |
| mikrotik-routeros | ✅ `'N'` write | ✅ `'N'` write | ✅ `1` read | yes | RouterOS API; `vlanPorts` → `/interface/switch.vlan` (switch-chip SoCs) |
| mikrotik-swos | ✅ `'N'` write (**L2-only**) | ✅ `'N'` write | ✅ `1` read | yes | `vlanId` required; L3 inputs reported `l3Skipped`; delete accepts optional `vlanId` |
| generic-ssh | ✅ `'N'` write | ✅ `'N'` write | ✅ `1` read | yes | iproute2 over SSH + best-effort ifupdown hook persistence |
| ix-truenas | ✅ `'N'` write | ✅ `'N'` write | ✅ `1` read | yes | `interface.assign` upsert (full property set); no DHCP/SSID surface |

All seven plugins register a preflight resolver for `network.create`
(`PREFLIGHT_RESOLVERS` in each plugin's `index.ts`).

## Preflight contract (the "smart" half of rollout)

Before planning, the webapp POSTs `/preflight` to every supporting plugin with
`{ intentActionId, inputs, device }` — the same body shape as a single-device
step dispatch, so resolvers may do READ-ONLY live probes. Resolvers MUST NOT
write anything; they return `PreflightResult`:

- `values[]` — suggested input fields keyed by the SAME names as the intent's
  input schema (`interface`, `cidr`, …), each with a confidence + human note.
  The webapp renders them generically and lets the user override any of them;
  overrides ride back in `PlanRequest.deviceInputs`.
- `ports[]` / `interfaces[]` — physical ports (with trunk status) and candidate
  attach interfaces, so the dialog can offer dropdowns/quick-selects.
- `capabilities` — e.g. `{ vlanPorts: false }` when the device has no per-port
  concept.
- `degraded` + `error` — the resolver could not inspect the device (offline, no
  creds); the device can still be planned with defaults.

Typical suggestions: the attach point via `suggestL2AttachPoint(topo)`
(bridge carrying L3 > bundle > direct port > any bridge > active bundle), an
idempotency hint when a network with that name already exists, and per-device
`cidr`/`cidrV6` hints from free-subnet computation.

## Idempotency & verification (binding)

- **Create** is idempotent by `name`: an existing matching network is left
  untouched (`applied: false`, `skipped` detail); a conflicting one is refused,
  never overwritten. Where the platform allows it, missing addresses are topped
  up on an existing interface (truenas).
- **Delete** is idempotent by `name`: absent = no-op success.
- Every write is verified by re-read before reporting success.

## API behavior for canonical intents (`api/src/routes/plans.ts`)

- Fan-out: one step per device, any count — the numeric-count check is skipped
  for canonical intent ids (a stale persisted number never blocks rollout).
- Credential requirement: fan-out steps require a bound secret or credential
  slot on every target device (checked at plan creation).
- Server-side safety net: in "block" mode a `network.create` whose name/subnet/
  VLAN collides with the live inventory is rejected before any plugin call.
- Single-device step endpoints (`addPlanStep`, bulk) accept only actions with
  `deviceCount === 1` — which is why the two network intents (declared `'N'`)
  are added as steps via plan creation fan-out, not via "Add step".

## Known deviations (intentional, documented here on purpose)

1. **opnsense `dhcpPool`** — honored in execute (dnsmasq backend only; Kea →
   `dhcpSkipped`) but NOT declared in its `inputSchema`, so plan-time validation
   and the rollout UI don't surface it. The API's validator ignores undeclared
   fields, so direct-API plans still work. Fix by declaring the field when the
   DHCP surface is promoted to a first-class intent capability.
2. **swos `vlanPorts` numbers** — accepts 1-based port numbers in addition to
   the canonical `string[]`; coerced at runtime (`normalizeVlanPortInput`).
3. **lcos `network.delete` riskLevel `'dangerous'`** — all other deletes are
   `'write'`. LCOS delete removes rows from five tables (incl. DHCP + IPv6);
   the webapp treats `'dangerous'` as "confirm dialog + never a quick action",
   which is the desired behavior for this one.
4. **swos `network.delete` optional `vlanId`** — precedence over name match;
   canonical delete is name-addressed, swos rows are id-addressed.

## Adding / changing an intent

1. Define or extend the canonical schema in `packages/plugin-sdk/src/intents.ts`
   (ids + superset schema + doc comment). The SDK file is the machine-readable
   contract; keep its comments and this page in sync.
2. Implement it per vendor under the SAME id with a compatible subset of fields,
   honoring the naming conventions above (family-explicit CIDRs, `name` as
   idempotency key, `'N'` for fan-out).
3. Register a preflight resolver so rollout can resolve attach points per device.
4. Update the implementation matrix in this file and the plugin's catalog tests.
