# FreeRADIUS Plugin — Documentation

Plugin for the Unified Network Manager (UNM). Companion to the **unm-radius**
sidecar service (FreeRADIUS 3.x) that provides WiFi EAP-TLS authentication for
client certificates issued by UNM's CA.

## What it does

| Capability | Requirement | Notes |
| --- | --- | --- |
| RADIUS (`radius`) | — | Advertised so the Certificates page shows its "WiFi (EAP-TLS) client certificates" section and the CA enrollment flow knows a RADIUS server exists on this instance. |

## What it deliberately does NOT do

FreeRADIUS has no HTTP API, so this plugin adds **no control surface** — no
reload/restart/test-auth actions and no endpoints beyond the SDK's standard
`/healthz` + `/discover`. All config changes already hot-apply through the
API's render → shared volume → SIGHUP path (the only mutation channel that
exists). Adding a control endpoint inside an auth-critical RADIUS container was
rejected as new attack surface; revisit if a real operational need appears.

There is also **no sidecar liveness probe**: a RADIUS server ignores requests
from any source IP not in its `clients.conf` allowlist (radiusd logs "Ignoring
request … from unknown client" and sends no reply), so the plugin's container —
not an authorized NAS — could never receive a response. Sidecar process
liveness is covered by its compose healthcheck (`pgrep freeradius`) + restart
policy; config correctness by the API's render path (validated before writing).

## Configuration (env)

Standard UNM plugin variables only (`UNM_API_URL`, `PLUGIN_API_KEY`, mTLS via
`UNM_TLS`, privilege-drop vars). No sidecar-specific settings.

## Credential slots

None — the plugin holds no secrets and performs no device-facing work.

## License

EUPL-1.2 — see [LICENSE.md](../LICENSE.md).
