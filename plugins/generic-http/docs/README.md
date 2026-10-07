# Generic HTTP Plugin — Documentation

Plugin for the Unified Network Manager (UNM). A generic **HTTP(S) reachability** monitor:
it polls a URL, records response time and status, and inventories the endpoint's TLS
certificate (issuer, SANs, days-to-expiry) so certificate expiry shows up in UNM.

## Capabilities

| Capability | Requirement | Notes |
| --- | --- | --- |
| Monitoring | — | Reachability, HTTP status, response-time metrics per poll. |
| TLS inventory | — | Certificate subject/issuer/SANs + `daysToExpiry` fed to the Certificates page. |

## Credential slots

None by default — plain GET requests. Basic-auth headers can be supplied via device options when the endpoint requires them.

## License

EUPL-1.2 — see [LICENSE.md](../LICENSE.md).
