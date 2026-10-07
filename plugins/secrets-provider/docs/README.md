# Secrets Provider Plugin — Documentation

Plugin for the Unified Network Manager (UNM). A **secrets provider** service: it encrypts,
decrypts and manages device secrets on behalf of UNM so that raw credentials never have to be
stored in plaintext at rest. Other plugins call into it through the `secretsProvider`
capability instead of handling keys themselves.

## Capabilities

| Capability | Requirement | Notes |
| --- | --- | --- |
| Secrets provider (`secretsProvider`) | — | Encrypt/decrypt/manage secret material; key rotation support. |

## Credential slots

None for device access — the plugin holds its own encryption keys on a local volume (bind mount).

## License

EUPL-1.2 — see [LICENSE.md](../LICENSE.md).
