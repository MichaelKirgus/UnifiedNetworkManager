# Basic Auth Plugin — Documentation

Plugin for the Unified Network Manager (UNM). Acts as UNM's **identity provider**:
it stores local user accounts and issues the JWTs that protect the API, with optional
TOTP two-factor authentication on top. It is not a device plugin in the usual sense —
it manages no network devices and needs no device credentials of its own.

## Capabilities

| Capability | Requirement | Notes |
| --- | --- | --- |
| Identity provider | — | Local user store (bcrypt-hashed passwords), login, JWT minting, TOTP 2FA enrollment/verification, passkey support hooks. |

## Credential slots

None — this plugin *is* the credential authority for UNM itself.

## License

EUPL-1.2 — see [LICENSE.md](../LICENSE.md).
