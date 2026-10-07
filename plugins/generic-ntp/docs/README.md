# Generic NTP Plugin — Documentation

Plugin for the Unified Network Manager (UNM). A generic **NTP/SNTP checker**: it queries an
NTP server and records drift, stratum, precision, root delay/dispersion and reference ID.
Its results also feed UNM's Time page (`system.ntpServed`) so you can see how well the
network time base is doing.

## Capabilities

| Capability | Requirement | Notes |
| --- | --- | --- |
| NTP checks | — | Drift, stratum, precision, root delay/dispersion, referenceId per poll. |
| Probe | — | Pre-flight reachability check used by the device form. |

## Credential slots

None — NTP is an open protocol (UDP 123). No credentials required.

## License

EUPL-1.2 — see [LICENSE.md](../LICENSE.md).
