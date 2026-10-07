# File Repository Plugin — Documentation

Plugin for the Unified Network Manager (UNM). A stateless **file repository** storage backend:
it serves firmware images, ISOs and configuration backups from a local volume so that other
plugins (e.g. update workflows) can fetch artifacts through UNM's file API instead of reaching
the internet directly.

## Capabilities

| Capability | Requirement | Notes |
| --- | --- | --- |
| File repository (`fileRepo`) | — | Upload/list/download/delete files on a mounted volume; content-type and size metadata for the Files page. |

## Credential slots

None — the plugin stores files on its own local volume (bind mount). No device credentials involved.

## License

EUPL-1.2 — see [LICENSE.md](../LICENSE.md).
