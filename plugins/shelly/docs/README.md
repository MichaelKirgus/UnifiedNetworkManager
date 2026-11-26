# Shelly Plugin (UNM)

UnifiedNetworkManager plugin for [Shelly](https://www.shelly.com/) smart devices — plugs, relays, switches and sensors across **all generations**:

- **Gen1** (ESP8266, fw 3.x–4.x): legacy REST API (`/shelly`, `/status`, `/settings/sta`, `/ota`, `POST /reboot`).
- **Gen2+** (Plus / Pro / Wave / Gen3 / Gen4, fw 1.x and 2.x+): JSON-RPC 2.0 over `POST /rpc` with batched requests — one round-trip per poll. Both namespace families are supported: classic (`Shelly.*`, `WiFi.*`, `Firmware.*`) on fw 1.x and modern (`Sys.*`, `Wifi.*`) on fw 2.x+.

The generation and namespace family are **detected at runtime per device** (auth-free probe first, then JSON-RPC namespace probing) and cached — no per-device configuration is needed.

## Capabilities

| Capability | Details |
|---|---|
| Monitoring | One batched request per device per poll: firmware version, uptime, RAM/flash, relays, power meters, WLAN (RSSI / SSID / channel / BSSID / station IP) |
| Updates | Firmware update rows on the Updates page; `shelly.firmware.update` action with `stable`/`beta` stage (Gen2+) — Gen1 has a single stable channel |
| Actions | `shelly.firmware.update`, `shelly.reboot` |
| Plans | Fan-out plans for firmware updates include a 120 s settle wait + inventory refresh (the device reboots mid-update and is unreachable for ~1–2 min) |

## Options

| Key | Default | Description |
|---|---|---|
| `transport` | `http` | Endpoint scheme: `http`, `https`, or `auto` (HTTPS preferred). Shelly devices serve plain HTTP by default. |
| `httpPort` / `httpsPort` | `80` / `443` | Management ports when the address carries no explicit port. |
| `timeoutMs` | `5000` (max 9000) | Per-request timeout; capped below the poll budget. |

## Credentials (optional)

Many Shelly devices ship with local login disabled — monitoring works without credentials. When your device has a local login enabled, bind a **username/password** secret to the `login` credential slot on the assignment: Gen1 sends HTTP Basic auth, Gen2+ performs the `shellyun-auth` cookie handshake and reuses the session per device.

## Metrics

| Metric | Kind | Notes |
|---|---|---|
| `system.swVersion` | text | Running firmware version — emitted every poll (canonical) |
| `hostname` | text | Device name |
| `shelly.model` / `shelly.mac` | text | e.g. `SHPLG-1`, `SWN-1PM` |
| `shelly.uptimeSeconds` | gauge | |
| `shelly.ramFreeBytes` / `shelly.ramTotalBytes` | gauge | Gen1 always; Gen2+ when reported |
| `shelly.fsFreeBytes` | gauge | Warning at ≥90 % flash used (Gen1) |
| `shelly.wifiRssiDbm` | gauge | Warning at ≤ −85 dBm |
| `shelly.wifiSsid` / `shelly.wifiChannel` / `shelly.wifiBssid` / `shelly.wifiStaIp` | text | First-class WLAN metrics (Gen2+ channel/BSSID when reported) |
| `shelly.relay{i}On` | gauge | 1/0 per relay component |
| `shelly.powerW` / `shelly.energyWh` | gauge | First power meter, when present |
| `shelly.fwUpdateAvailable` | gauge | 1 when a firmware update is pending |

Health: `ok` normally; `warning` on weak WLAN RSSI, low RAM (Gen1 device threshold), ≥90 % flash used or overtemperature; `critical` when the device is unreachable or rejects authentication.

## Development

```sh
npm install && npm run build   # tsc
npm test                       # jest (detect / monitoring gen1+gen2 / updates / actions / plan)
npm run smoke-test             # boots the plugin + a mock Shelly (Gen1 & Gen2+) and exercises the routes
```

## API notes

- **Gen detection**: `GET /shelly` (auth-free) ⇒ Gen1; otherwise `Shelly.GetDeviceInfo` ⇒ Gen2 classic; otherwise `Sys.GetDeviceInfo` ⇒ Gen2 modern. Remembered per device in a TTL cache.
- **Gen2+ polling** is a single JSON-RPC batch: `[GetDeviceInfo, GetStatus, WiFi/Wifi.GetStatus, Firmware.GetStatus]` in one `POST /rpc`.
- **Updates emission contract**: a present-but-empty `updates: []` is authoritative (device checked, nothing pending); on transport failure the key is omitted so previously stored rows survive an outage.
- Exact response shapes follow the official Shelly API documentation examples; confirm on real hardware per generation before relying on them in production.
