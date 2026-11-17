# Security model

How UNM protects itself and the devices it manages: RBAC, 2FA, secrets handling, transport choices and — most importantly — how to keep the appliance off the public internet. The full permission catalog lives in [PERMISSIONS.md](PERMISSIONS.md).

## Model overview

- **RBAC** — flat permission catalog (`api/src/auth/permissions.ts` is the single source of truth; `GET /v1/permissions` serves it to the UIs). Users carry their effective permissions in JWT claims; roles are DB-backed bundles unioned into explicit grants at login time. New permissions added to the catalog are **backfilled onto existing admin users and the built-in admin role** on API start, so upgrades never lock admins out.
- **2FA (TOTP)** — required for privileged operations (`configs:apply`); enrollment is per-user via the My Account page or by an admin with `users:manage-credentials`. The first sign-in of a fresh deployment runs a mandatory setup wizard that forces a password change + second-factor enrollment before anything else works.
- **Secrets** — values are encrypted by the secrets-provider plugin; the API stores only ciphertext and never sees plaintext. The webapp shows metadata only.
- **SNMP transport** — SNMP queries run in-process over native UDP (`@unm/snmp-client` on the `net-snmp` npm package); credentials (community strings, USM passphrases) are never passed as command-line arguments or written to logs. DES privacy is rejected at credential-validation time (Node ≥17 OpenSSL dropped it) — use AES.
- **API tokens** — long-lived bearer tokens (`unm_…`) for agents/scripts, self-service on the Tokens page or `POST /v1/tokens`, with per-token permission narrowing.

The full catalog — all ~58 permissions, the API route → permission map, inline gates (secrets personal area, self-vs-other credential ops) and webapp page guards — is documented in [PERMISSIONS.md](PERMISSIONS.md).

## Network exposure — keep it off the public internet

> **UNM is a management appliance. The web UI must never, ever be made available on the public internet.**
>
> It authenticates as *admin* to every device it manages and can rewrite their configuration (firewalls included). Exposing it directly means handing an attacker your entire network's keys.
>
> **Only expose it via:**
>
> - a **VPN** (WireGuard/IPsec/OpenVPN — UNM itself can plan those for you), or
> - a **reverse proxy with additional authentication** in front (TLS termination + auth, e.g. an SSO/OAuth proxy or mutual TLS), ideally combined with source-IP allow-listing. See [REVERSE-PROXY.md](REVERSE-PROXY.md) for examples and the required `UNM_TRUST_PROXY` / client-IP env vars.
>
> Security has layers: even if every best practice above is applied, each layer only matters while the others hold. A single vulnerability — in UNM, its dependencies, or a misconfigured proxy — becomes fatal when the admin plane sits directly on the internet. Treat "reachable from anywhere" as an incident, not a convenience.
