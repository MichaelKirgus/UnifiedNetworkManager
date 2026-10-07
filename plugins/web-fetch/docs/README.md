# Web Fetch Plugin — Documentation

Plugin for the Unified Network Manager (UNM). A **web fetch** service: it downloads files and
web content from the internet on behalf of UNM (e.g. firmware images, release archives) so
that API-side workflows can retrieve artifacts without each plugin implementing its own
downloader. Handles compressed archives (tar, zip) transparently.

## Capabilities

| Capability | Requirement | Notes |
| --- | --- | --- |
| Web fetch (`webFetch`) | — | URL download with size/type metadata; archive extraction for tar/zip payloads. |

## Credential slots

None — the plugin performs plain HTTPS GETs from its own container network position.

## License

EUPL-1.2 — see [LICENSE.md](../LICENSE.md).
