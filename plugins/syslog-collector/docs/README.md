# Syslog Collector (RFC5424/BSD)

Push-based syslog ingest service for the UNM **security events** feature. Devices
(firewalls, routers, switches) forward their syslog output to this collector; it
parses each line and pushes normalized rows to the UNM API, which stores them in
the `security_events` table (retention: `securityEventRetentionDays`, default 7).

## How it works

- Listens on **UDP and TCP port 514** inside the container. In compose the host's
  standard syslog ports are published (`514/udp` + `514/tcp`) — point your devices'
  syslog forwarding at `<unm-host>:514`.
- Parses each line as **RFC 5424** (`<PRI>VERSION TS HOST APP PROC MSGID [SD] MSG`)
  or **BSD syslog** (`<PRI>Mmm dd hh:mm:ss host tag[pid]: message`), sniffed per
  line. Lines without a PRI header default to `user.notice`. BSD timestamps carry
  no timezone — they are interpreted in the collector's local zone, so set
  `SYSLOG_TZ` (compose: `TZ`) to your fleet's zone; RFC5424 lines carry explicit
  offsets and are unaffected. Stamps more than 5 minutes ahead of now are clamped
  to now (broken clock / TZ mismatch guard — keeps rows inside "now"-anchored
  query windows and automation watermarks sane).
- Maps the 8-level syslog severity onto UNM's four log levels:
  emergency/alert/critical/error → `error`, warning → `warn`, notice/info → `info`,
  debug → `debug`.
- Extracts **src/dst IPs** from well-known vendor message shapes (OPNsense/pf
  `ip:port -> ip:port` arrows, MikroTik `from … to …`, Linux netfilter
  `SRC=… DST=…`). Unrecognized messages are stored without addressing.
- Each row gets a stable dedup key (`sha1(hostname|tsMs|message)`); the API ignores
  re-sent batches (at-least-once delivery is safe).
- The API resolves each row's **deviceId from its hostname** — inventory hosts
  first (hostname or IP match), then devices (name / management address). Rows
  whose hostname matches nothing are kept with a null device.

## Backpressure

The receive path never blocks on the API: parsed rows go into a bounded in-memory
queue (`SYSLOG_MAX_QUEUE_EVENTS`, default 50k) that drops the OLDEST rows on
overflow (counted + surfaced via self-metrics). Pushes to the API are
fire-and-forget batches of up to 5,000 rows every `SYSLOG_PUSH_INTERVAL_MS`
(default 2s) with one retry.

## Environment variables

| Variable | Default | Purpose |
| --- | --- | --- |
| `TZ` (compose: `SYSLOG_TZ`) | `UTC` | Local zone for BSD syslog stamps — set to your fleet's zone (e.g. `Europe/Berlin`) |
| `SYSLOG_PORT` | `514` | UDP/TCP listen port inside the container |
| `SYSLOG_UDP` | `1` | Set `0` to disable the UDP listener |
| `SYSLOG_TCP` | `1` | Set `0` to disable the TCP listener |
| `SYSLOG_PUSH_INTERVAL_MS` | `2000` | Push cadence to the API |
| `SYSLOG_MAX_QUEUE_EVENTS` | `50000` | Bounded queue size (oldest dropped) |
| `PORT` / `ADVERTISED_ENDPOINT` / `UNM_API_URL` / `PLUGIN_API_KEY` | — | Standard UNM plugin wiring |

> **Note:** the container runs as root (`UNM_RUN_AS_ROOT=1` in compose) because it
> must bind privileged port 514 inside the container — this also keeps it reachable
> on 514 when deployed with direct L2/macvlan reachability instead of published ports.

## Multi-instance

Set `PLUGIN_INSTANCE_ID` (e.g. `site-a`) to run several collectors; each advertises
a distinct identity and events are attributed per collector in the API.
