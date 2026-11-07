# RADIUS failover (replicated slave)

UNM's built-in FreeRADIUS server can be made redundant by running a **second,
minimal UNM instance** that mirrors the primary's RADIUS configuration. Your
WLC / access points then list both RADIUS servers and keep authenticating when
the primary goes down — no per-server config drift, because the slave's NAS
client list (IPs + shared secrets), user profiles, revocation list and CA trust
are replicated from the primary automatically.

This uses the standard replication feature (`/v1/replication/*`) with a
dedicated `radius` section plus the portable `secrets` envelope — no new
protocol. The webapp's Backups page has a **"RADIUS failover slave" preset**
for the target dialog; everything below can also be done via API.

## What gets replicated

| Table | Content | Merge key |
|---|---|---|
| `radius_nas_clients` | NAS/WLC IPs + reference to the shared secret | **IP** (natural key — a client deleted+recreated on the primary converges on the slave instead of colliding) |
| `radius_user_profiles` | Per-cert VLAN / static IP / session limits | **serial** (the cert serial number) |
| `revoked_serials` | EAP-TLS revocation list checked per-auth | serial (PK) |

Plus, outside the tables:

- **Shared secrets** — when the target has *Include secrets* enabled, every
  secret referenced by the radius section is decrypted via the provider broker
  and re-wrapped in a passphrase-encrypted envelope (scrypt → AES-256-GCM). No
  plaintext ever lands on the wire or in an archive. On import the values are
  re-encrypted under the **slave's own** secrets-provider key, keeping their
  **original ids** so the NAS client references keep working. The envelope is
  fully self-contained — the two instances do **not** need matching
  `MASTER_KEY`/`CRYPTO_SALT`; only the passphrase matters.
- **CA trust anchor** — the primary's step-ca root certificate is adopted into
  the slave's `radiusTrustedCaPem` setting (only when it actually changed, so a
  primary CA re-key follows automatically). The slave's radius sidecar renders
  it to `trusted-ca.pem`, builds `ca/bundle.pem` from it (plus its own local
  root, if any), and points the EAP-TLS module's `ca_file` at that bundle — so
  a slave **without its own step-ca** still validates client certs issued by
  the primary's CA.

Deliberately **not** replicated: `radpostauth` (live accounting logs),
`radius_db_credentials` (each instance has its own least-privilege DB role) and
`radius_probe_client` (each instance probes from its own API container IP).

Merge semantics are the standard **safe merge**: upsert, never delete. Rows that
exist only on the slave are left untouched; existing secrets are skipped, never
overwritten. See [Limitations](#limitations--caveats) for what that means in
practice.

## Slave stack requirements

The slave is a full UNM instance with **no device plugins** — but it still needs
the two platform services every instance requires:

| Service | Why the slave needs it |
|---|---|
| `api` + Postgres | The replication receiver, settings store, and the renderer that turns replicated rows into FreeRADIUS config. |
| **basic-auth plugin** | Identity provider — without a registered one the slave can't authenticate anyone (no login, no peer token). It is an identity service, not a device plugin. |
| **secrets-provider plugin** | Crypto holder for imported secrets (re-encrypts them under its own key on import). Also a platform service, not a device plugin. |
| `unm-radius` sidecar | The actual FreeRADIUS server the WLC fails over to. |

The slave's RADIUS port must be reachable from your NAS/WLC (UDP 1812/1813),
and the primary's API container must reach the slave's API for push syncs.

## Setup

### 1. Deploy the slave stack

A minimal compose file (adjust image tags / secrets for production):

```yaml
services:
  pg:
    image: postgres:16-alpine
    environment: { POSTGRES_USER: unm, POSTGRES_PASSWORD: <strong-password>, POSTGRES_DB: unm }
    volumes: [ "pgdata:/var/lib/postgresql/data" ]

  api:
    image: ghcr.io/michaelkirgus/unifiednetworkmanager-api:<tag>   # same build as the primary
    environment:
      - DATABASE_URL=postgresql://unm:<strong-password>@pg:5432/unm
      - JWT_SECRET=<random-64-hex>
      # Identity + secrets providers (reserved built-in UUIDs):
      - AUTH_PLUGIN_ID=00000000-0000-4000-8000-000000000001
      - SECRETS_PLUGIN_ID=00000000-0000-4000-8000-000000000002
      - PLUGIN_API_KEY=<shared-plugin-key>
      # RADIUS sidecar as seen from THIS container:
      - UNM_RADIUS_HOST=radius
    volumes: [ "radius-cfg:/data/radius", "ca-cfg:/data/ca" ]

  basic-auth:
    image: ghcr.io/michaelkirgus/unifiednetworkmanager-basic-auth-plugin:<tag>
    environment:
      - ADVERTISED_ENDPOINT=http://basic-auth:4080
      - UNM_API_URL=http://api:3000/v1
      - PLUGIN_API_KEY=<shared-plugin-key>

  secrets-provider:
    image: ghcr.io/michaelkirgus/unifiednetworkmanager-secrets-provider-plugin:<tag>
    environment:
      - ADVERTISED_ENDPOINT=http://secrets-provider:4080
      - UNM_API_URL=http://api:3000/v1
      - PLUGIN_API_KEY=<shared-plugin-key>

  radius:
    image: ghcr.io/michaelkirgus/unifiednetworkmanager-unm-radius:<tag>
    restart: unless-stopped   # the entrypoint exits non-zero if radiusd dies on a broken config — docker recycles it
    ports: [ "1812:1812/udp", "1813:1813/udp" ]   # reachable from your WLC!
    volumes: [ "radius-cfg:/data/radius", "ca-cfg:/data/ca:ro" ]

volumes: { pgdata: {}, radius-cfg: {}, ca-cfg: {} }
```

Note the slave's `ca` volume is intentionally **empty** — it has no step-ca of
its own; trust comes from the replicated primary root.

### 2. Mint a peer token on the slave

Log in to the slave (admin), then create an API token with the
`instance:backup` permission (it is what authorizes inbound syncs):

```sh
curl -X POST https://slave.example.com/v1/tokens \
  -H "Authorization: Bearer <session-jwt>" \
  -d '{"label":"replication-from-primary","permissions":["instance:backup"],"expiresAt":null}'
# → { "rawToken": "…" }   (shown once — store it)
```

### 3. Create the replication target on the primary

Webapp: **Backups → Replication targets → New** and pick the
**"RADIUS failover slave"** preset, or via API:

```sh
curl -X POST https://primary.example.com/v1/replication/targets \
  -H "Authorization: Bearer <admin-token>" \
  -d '{
    "name": "radius-slave",
    "baseUrl": "https://slave.example.com/v1",
    "token": "<peer token from step 2>",
    "direction": "push",
    "sections": ["radius"],
    "includeSecrets": true,
    "secretsPassphrase": "<strong-passphrase>"
  }'
```

`intervalMinutes` (optional) schedules automatic syncs; leave it null for
manual-only. The passphrase is stored in the primary's database and never
returned by any API — protect DB access accordingly.

### 4. Run a sync and verify

```sh
curl -X POST https://primary.example.com/v1/replication/sync \
  -H "Authorization: Bearer <admin-token>" -d '{"targetId":"<id>"}'
# → { "report": { "status": "ok", "sections": ["radius","secrets"], ... } }
```

Then on the **slave**:

- `GET /v1/radius/status` → `probe.outcome: "ok"` (the built-in probe client
  authenticates against the slave's own radiusd; it takes up to ~1 minute for
  the next monitor cycle).
- The rendered config carries the real values: on the slave's radius container,
  `/data/radius/clients.conf` lists every NAS IP with its **decrypted** shared
  secret, and `ca/bundle.pem` contains the primary's root.

### 5. Point your WLC / APs at both servers

Configure the RADIUS server list on your wireless controller with the primary
first and the slave as fallback (vendor-specific; e.g. UniFi: *Settings →
Wireless → 802.1X → RADIUS Servers*). Because replication keeps the NAS client
entries identical — same IP, same shared secret — no per-server differences are
needed on the WLC side.

### Scaling to multiple slaves

There is **no single-slave limit** — the topology scales to N slaves by design:

- A slave is just another UNM instance; nothing on either side tracks "the"
  slave. Create one replication target per slave (webapp preset or API), each
  with its own peer token and passphrase if you like. Syncs are independent
  per target (own schedule, own in-flight guard, own last-sync report).
- Each slave is fully self-contained: own Postgres, own radiusd, own probe
  client entry (rendered from its own API container IP), own copy of the CA
  trust anchor. Slaves never talk to each other — failover is decided by your
  WLC's RADIUS server list, which you extend with one entry per slave.
- Load: most WLCs try the servers in order (failover); some support
  round-robin/load-balancing mode for RADIUS — that's a vendor setting, not a
  UNM one. Accounting (`radpostauth`) is written by whichever server handled
  the auth and is NOT replicated — treat it as per-instance audit data.
- Cost to know: with *Include secrets* enabled, every sync ships the whole
  passphrase-encrypted secret store to that slave (not just RADIUS-referenced
  ones), so each slave holds a full local copy of all secrets re-encrypted
  under its own key. If that's too broad for your threat model, run the target
  without `includeSecrets` and provision the NAS shared secrets on the slave
  manually (they must match byte-for-byte).

Verified live: one primary → two independent slaves in parallel, both
converging to identical rendered config with a green self-monitoring probe.

## Operations

- **Sync cadence** — manual (`POST /replication/sync`) or scheduled via the
  target's `intervalMinutes`. Each sync re-renders the slave's FreeRADIUS
  config; the radius sidecar hot-applies it (SIGHUP) and its supervisor
  *verifies* every reload against the radiusd log — if a re-read ever fails,
  it gracefully restarts radiusd instead of leaving it stale. (FreeRADIUS 3.x
  quirk: one failed config re-read makes all later HUPs fail until the process
  restarts; the supervisor handles this automatically.)
- **Health** — `GET /v1/radius/status` on each instance gives the probe
  outcome (`ok` / `bad-auth` / `timeout`) and last-24h counters. A slave whose
  probe is not `ok` should be treated as out of rotation.
- **CA re-key** — when the primary's CA root changes, the next sync adopts it
  (the setting follows in lockstep) and the slave's bundle rebuilds on its next
  config sync.
- **Secret rotation** — create a NEW secret on the primary and update the NAS
  client to reference it; do not edit an existing secret in place (existing
  secrets are never overwritten by a sync).

## Limitations / caveats

- **One-way, push only.** The slave's RADIUS configuration is read-only in its
  own webapp — make changes on the primary and let them replicate.
- **Deletions do not propagate** (safe merge). A NAS client or profile deleted
  on the primary keeps existing on the slave until you remove it there too
  (`radius.nas-client.delete` / `radius.profile.delete` plan, or directly in the
  slave's database). Stale entries still authenticate with their last-known
  secret — clean them up when decommissioning hardware.
- **Existing secrets are never overwritten.** In-place edits to a secret on the
  primary do not reach the slave; rotate by creating + re-pointing (see above).
- **The passphrase lives in the primary's database** (`replication_targets`).
  Anyone with DB access can read it and decrypt future sync payloads — treat
  the primary's Postgres as at least as sensitive as the secrets themselves.
- **Build parity.** Both instances should run the same UNM build; a mismatch
  only produces a warning, but schema drift between very different versions is
  not supported for replicated sections.
