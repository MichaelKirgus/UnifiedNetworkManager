# Flow Collector Plugin — Documentation

Plugin for the Unified Network Manager (UNM). A network flow collector: it listens for
**sFlow** and **NetFlow v5/v9** samples over UDP, feeds them into UNM's flows pipeline
(top talkers, pairs, internet egress) and reports its own ingestion health as self-metrics.

## Capabilities

| Capability | Requirement | Notes |
| --- | --- | --- |
| Flows | — | sFlow + NetFlow v5/v9 decode → UNM flow store; powers the Flows page (top talkers, pairs, internet egress). |
| Monitoring | — | Self-metrics: samples/sec, dropped packets, listener health. |

## Credential slots

None — the plugin is a passive UDP listener. Point your switches/routers' flow exporters at this container's IP and port.

## License

EUPL-1.2 — see [LICENSE.md](../LICENSE.md).
