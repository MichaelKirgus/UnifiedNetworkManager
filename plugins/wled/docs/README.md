# WLED Plugin — Documentation

Plugin for the Unified Network Manager (UNM). Monitors **WLED** light controllers
(ESP8266/ESP32) over their plain-HTTP JSON API and — the headline feature —
performs **firmware updates through UNM**, mirroring exactly what WLED's own web
UI does.

## Capabilities

| Capability | Requirement | Notes |
| --- | --- | --- |
| Monitoring | — | Free heap, LED fps/count/power, uptime, WiFi RSSI/channel, version per poll. |
| Updates | web-fetch plugin online | GitHub release feed of the device's own `info.repo` (default `wled/WLED`) → Updates page row with one-click apply. |
| Configuration | — | Plan actions: firmware update/revert, rename, on/brightness state. |
| Quick actions | — | One-click open of the WLED web UI from the Devices page. |

## Credentials

Monitoring is **credential-free**. When a controller has a settings PIN
(WLED UI → Settings → Security), bind an `apiKey` secret to the optional **pin**
slot — its key field carries the PIN. It is used for rename and for firmware
uploads on PIN-protected controllers; monitoring works without it.

## Firmware update flow

1. The Updates page row is built from GitHub's `releases/latest` of the device's
   own repository (6 h cache per repo) — downloaded through UNM's **web-fetch
   broker**, never by this plugin or the API directly.
2. Applying runs `wled.firmware.update`: the .bin is fetched via the same broker,
   uploaded to the device's `/update` endpoint as a multipart form (field
   `update`, optional PIN), and the action polls `/json/info` after the reboot
   until the device reports the target version.

## License

EUPL-1.2 — see [LICENSE.md](../LICENSE.md).
