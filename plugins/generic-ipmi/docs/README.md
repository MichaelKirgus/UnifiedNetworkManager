# Generic IPMI Plugin

Bare-metal server management over **IPMI 2.0 (RMCP+)** — UDP port 623. One UNM
device = one BMC, identified by a username/password pair. The plugin speaks the
protocol itself: the RMCP+ session handshake (RAKP1–4 challenge/response),
AES-CBC-128 payload encryption and HMAC-SHA1-96 integrity are implemented in
TypeScript inside this container. **No `ipmitool` subprocess** — the BMC
password lives only in Node crypto memory, never in argv, env or on disk.

## What you get

| Area | Detail |
| --- | --- |
| Health | BMC reachability + RAKP auth; powered-off server → warning; sensor threshold violations → warning/critical |
| Chassis | Power state, power-control-lost flag, restore policy (`ipmi.chassis`) |
| Sensors | Full SDR walk: every full-sensor record with live reading (m/b/k1/k2 conversion), unit and ok/warning/critical state vs. thresholds (`ipmi.sensors`) |
| FRU | Chassis/board/product identity fields — manufacturer, product name, serials (`ipmi.fru`) |
| SEL | Last 50 System Event Log entries with decoded timestamps + severity (`ipmi.sel`) |
| Inventory | BMC LAN channel IP/mask/MAC → UNM's network inventory (`networks[]` row) |
| Control (plan-gated) | Power on / ACPI soft-off / hard-off / reset, boot options, SEL clear, NMI pulse, BMC LAN IP/mask/gateway writes — all verified by re-reading state afterwards; dangerous ones require the plan confirm dialog |
| Console | **SOL serial console** — the device's "Shell" button opens an interactive terminal on the server's serial port (IPMI Serial-over-LAN) |

## BMC setup

1. **Enable the LAN channel.** In your BMC firmware (AMI MegaRAC, IPMItool,
   iDRAC/iLO/SeaBIOS-adjacent UIs differ): enable IPMI over LAN on a dedicated
   management interface/VLAN and set a static IPv4 address (or DHCP).
2. **Create a user.** Add an IPMI user with:
   - a password (max 16 chars — the RMCP+ Kuid is derived from it),
   - privilege level **Administrator** (the plugin requests admin and falls back
     to operator automatically if the BMC refuses),
   - enabled on the LAN channel.
3. **Cipher suite.** The plugin defaults to **cipher suite 3** (RAKP-HMAC-SHA1
   auth + HMAC-SHA1-96 integrity + AES-CBC-128 payload encryption) — this is what
   `ipmitool -I lanplus` uses by default and what every modern BMC accepts. If a
   legacy BMC rejects the session, set the plugin option **cipherSuiteId = 0**
   on that device (no auth/integrity/encryption — only do this on an isolated
   management network).
4. **SOL console.** Enable "Serial over LAN" / "SOL" in the BMC firmware and
   point it at the serial port you want to see (usually COM1, 115200 8N1). The
   plugin activates SOL on channel 1 when you open the Shell.

## Adding a device in UNM

1. Devices → New Device → vendor **generic**, model free text (e.g. `Dell R740`),
   management address = the BMC's IP (port defaults to 623).
2. Bind a **"Username & Password"** secret with the IPMI user credentials.
3. Assign this plugin. Health turns green once the RAKP handshake succeeds; the
   device detail page shows chassis state, sensors, FRU and SEL tables plus the
   Shell button for SOL.

## Security model

- The password is zero-padded to 20 bytes (the IPMI *Kuid*) in memory and used
  as the HMAC key of the RAKP challenge/response — it is never sent on the wire,
  never logged, and never passed to a subprocess.
- Session keys K1/K2 are derived per session; payload encryption uses AES-CBC-128
  with a random IV per packet (cipher suite 3).
- All write operations flow through UNM's plan workflow: catalog entry → confirm
  dialog for `dangerous` actions → audit trail → re-read verification.

## Limitations

- IPv4 LAN channel only (the IPMI v2 spec's IPv6 LAN config is not read/written).
- Sensor conversion covers the standard m/b/k1/k2 linearization; OEM sensors are
  listed with raw values.
- SOL has no window-size negotiation — terminal geometry changes are ignored by
  the BMC (most serial consoles cope fine).
