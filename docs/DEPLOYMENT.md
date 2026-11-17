# Deployment — production hardening, networking & scaling

Everything you need beyond `docker compose up -d`: image overrides and `.env` hardening, the RADIUS sidecar's database role, pre-built images on GHCR, reverse-proxy environment variables, a dedicated management VLAN (macvlan), unprivileged containers, and scaling/HA guidance. For remote-access proxy *examples* see [REVERSE-PROXY.md](REVERSE-PROXY.md).

## Image overrides & `.env`

The default `docker-compose.yml` is the end-user deployment: same services, env vars and volumes as the dev file — every locally-built service is pulled from GHCR instead. Overrides (`.env` or environment):

| Variable | Default | Effect |
|----------|---------|--------|
| `UNM_IMAGE_TAG` | `dev` | Image tag to pull — use a release tag like `v0.1.0` for stable deployments, or `nightly` for the latest pre-release build |
| `UNM_REGISTRY` | `ghcr.io/michaelkirgus/unifiednetworkmanager` | Registry prefix (self-mirroring) |
| `UNM_WEB_PORT` | `8080` | Host port the webapp is published on |

The **MCP server is not exposed to the host by default** — it carries an API token with full agent capabilities, so publishing it on all interfaces is a deliberate choice. If you need remote MCP access, add your own mapping (e.g. `UNM_MCP_PORT=8081`) behind auth or a reverse proxy.

For a production deployment, copy the annotated template to `.env` and change at least the values marked **MUST CHANGE** (`MASTER_KEY`, `CRYPTO_SALT`, `JWT_SECRET`, `POSTGRES_PASSWORD`, `PLUGIN_API_KEY`) — they are insecure dev defaults:

```bash
cp .env.example .env
# edit .env → set a strong MASTER_KEY (openssl rand -hex 32), CRYPTO_SALT, JWT_SECRET,
#              POSTGRES_PASSWORD, PLUGIN_API_KEY
docker compose up -d
```

Tear down with `docker compose down` (add `-v` to also remove the Postgres volume).

**Postgres is not published to the host** — api/mcp reach it over the internal compose network only. If you need psql-from-host, add a loopback-only mapping (`"127.0.0.1:5432:5432"`) rather than `"5432:5432"`. Note that `POSTGRES_USER/PASSWORD/DB` are applied when the data volume is first initialized; to rotate credentials on an existing deployment, run `ALTER USER <user> PASSWORD '<new>';` inside Postgres and set the same value in `.env`.

## RADIUS sidecar — least-privilege database role (managed Postgres)

The optional **unm-radius** service (FreeRADIUS for WiFi EAP-TLS + native accounting into Postgres) connects to the appliance DB with a dedicated, least-privilege role `unm_radius` — it can only write accounting rows (`radacct`) and read the revocation list (`revoked_serials`). The API creates this role at boot and stores its generated password in the `radius_db_credentials` table; the rendered FreeRADIUS config never carries the API's own credentials.

On **managed Postgres** (RDS, Hetzner Cloud, …) the `POSTGRES_USER` usually has no `CREATE ROLE` privilege. That is not fatal: the API logs a warning and RADIUS falls back to the API's own DB credentials until you create the role manually — as a privileged account of your database provider:

```sql
CREATE ROLE unm_radius LOGIN PASSWORD '<strong-password>' NOINHERIT NOSUPERUSER NOCREATEDB NOREPLICATION;
GRANT INSERT, UPDATE ON radacct TO unm_radius;
GRANT SELECT ON revoked_serials TO unm_radius;
GRANT SELECT ON radius_user_profiles TO unm_radius;
GRANT USAGE ON SEQUENCE radacct_RadAcctId_seq TO unm_radius;
```

(The API also attempts to (re-)apply these grants on every start, so upgrades that add tables pick up existing roles automatically; if your `unm` user lacks GRANT rights too, run them manually as shown above — the API logs a warning when it cannot.)

The API picks the role up on its next start: it adopts any pre-existing `unm_radius` role (the password you set there can be a placeholder — the API generates its own, stores it in `radius_db_credentials`, and renders that into the FreeRADIUS config). The grants above are idempotent; re-running them after an upgrade is harmless.

## Pre-built images (GHCR)

Every component is published to the [GitHub Container Registry](https://ghcr.io) after the plugin contract suite passes. All packages are set to **public** visibility on GHCR, so pulling needs no `docker login`. The standard `docker-compose.yml` (end-user deployment, no build step) is **generated** from `docker-compose.dev.yml` by `scripts/generate-registry-compose.cjs` — change the dev file and regenerate; never edit the generated one by hand. Image names follow `ghcr.io/michaelkirgus/unifiednetworkmanager/<service>`, where `<service>` is the compose service name (`api`, `webapp`, `mcp`, `unm-ca`, and every `*-plugin`):

```bash
docker pull ghcr.io/michaelkirgus/unifiednetworkmanager/api:dev
```

Tag scheme: **branch pushes** are tagged with the branch name (`main` → `dev`), and **release tags** (`v0.1.0`) additionally move `latest`. So `latest` always points at the newest stable release, never at dev-branch builds — pin `:latest` for stable deployments or a version tag to be explicit.

Two automated lanes sit on top of that (see `.github/workflows/docker-publish.yml`):

- **Stable releases** — pushing a strict semver tag publishes all images tagged with it *and* creates the matching GitHub Release (after the plugin contract suite passes):
  `git tag v0.2.0 && git push origin v0.2.0`
- **Nightly pre-releases** — a daily scheduled build of `main` (or manual dispatch) publishes images tagged `nightly-<YYYYMMDD>` plus rolling `nightly`, and creates a dated GitHub **pre-release**. Pre-releases never move `latest`.

## Reverse proxy environment variables

The supported way to reach UNM remotely is **TLS termination + auth at a reverse proxy** in front of the stack — see [REVERSE-PROXY.md](REVERSE-PROXY.md) for full nginx / Caddy / Cloudflare examples. Three env vars make it work:

| Variable | Default | Effect |
|----------|---------|--------|
| `UNM_TRUST_PROXY` | *(off)* | **Required behind any proxy.** Trusts `X-Forwarded-For` so rate limiting buckets on the **real client IP** instead of the proxy's address. Set to `1` for a single proxy hop, `N` for N hops, or a CIDR list / named policy (`loopback`, …). Without it, every proxied request is rejected with 500 — the rate limiter refuses untrusted `X-Forwarded-For` headers by design. |
| `UNM_CLIENT_IP_HEADER` | *(off)* | Explicit header carrying the client IP (e.g. Cloudflare's `CF-Connecting-IP`). Wins over `X-Forwarded-For`; only set it if the proxy is the sole path to the API. |
| `UNM_WEBAPP_API_URL` | `/v1` (relative) | The URL the *browser* uses for the API, baked into the webapp at build time. Pre-built images default to same-origin (`/v1`) — one public hostname serves UI + API, no CORS. Set an absolute URL only for cross-origin setups (e.g. dev: `http://localhost:3000/v1`); rebuild the webapp image after changing it. |

The recommended layout is **same-origin**: one public hostname serves the webapp and proxies `/v1/*` to the API, so there's no CORS configuration and the SSH-console WebSocket works with zero extra client setup — which is exactly what the pre-built images ship by default.

## Dedicated management VLAN (macvlan deployment)

For production you typically want every UNM container to be a first-class citizen of a dedicated management VLAN instead of hiding behind Docker's NAT bridge. All images built from this repository ship with an entrypoint wrapper (`scripts/docker-entrypoint.sh`) that installs a default route when the optional environment variable **`UNM_DEFAULT_GATEWAY`** is set — it is already wired into every service in `docker-compose.dev.yml`, and empty/unset means pure passthrough, so normal bridge deployments are unaffected.

1. Create the macvlan network once on the host (parent = your management NIC):
   ```bash
   docker network create -d macvlan \
     --subnet 192.168.50.0/24 --gateway 192.168.50.1 \
     -o parent=enp3s0 -o mode=bridge unm-vlan
   ```
   `mode=bridge` keeps host↔container reachability (plain macvlan blocks it by design — your healthchecks and curl-from-host debugging would break).
2. Set the gateway in `.env`: `UNM_DEFAULT_GATEWAY=192.168.50.1`
3. Uncomment the top-level `networks:` block in `docker-compose.dev.yml` (it documents itself) and give every service a static IP, e.g.
   ```yaml
   api:
     networks:
       default:            # keep → NAT stays as fallback for internet egress
       unm-vlan:
         ipv4_address: 192.168.50.10
   ```

Notes:
- **Hybrid vs macvlan-only.** Keeping the implicit `default` bridge attached means traffic to your VLAN goes out the macvlan interface (most-specific route) while everything else still NATs through the host. Dropping `default:` makes ALL egress flow via your gateway — which then needs upstream routing/NAT itself.
- **Service-name URLs keep working.** Docker's embedded DNS resolves names of containers sharing a user-defined network, macvlan included — so `ADVERTISED_ENDPOINT=http://file-repo-plugin:4080`, `UNM_API_URL=http://api:3000/v1` and the ACME directory default need no changes. Just don't mix service names and VLAN IPs for the same endpoint: plugin mTLS leaf certs get their SAN from the host of `ADVERTISED_ENDPOINT`, so URL and certificate must match.
- **Inter-container traffic transits the physical segment** on macvlan — expected for a management stack, but it shows up on the wire.
- The wrapper never blocks startup: if no suitable interface is found or the route cannot be written (missing `CAP_NET_ADMIN`), it logs to stderr and continues. `UNM_GW_IFACE` forces the interface instead of auto-detect (which skips `lo` and Docker's 172.16/12 bridge range).

## Unprivileged containers

Every UNM image runs its application as a dedicated unprivileged user **`app`** (uid/gid `1001`) by default — the entrypoint wrapper (`scripts/docker-entrypoint.sh`, PID 1) performs all root-only work first, then drops privileges via a dependency-free Node helper (`scripts/unm-privdrop.js`). The CA container already ran as its own non-root user; this extends that to the API, MCP server and every plugin.

What the wrapper does at boot (all steps best-effort — a failure logs to stderr and never blocks startup):
1. **Default gateway** — see [macvlan deployment](#dedicated-management-vlan-macvlan-deployment) above (`UNM_DEFAULT_GATEWAY`).
2. **Data-dir ownership** — chowns the paths listed in `UNM_CHOWN_PATHS` (set per service in `docker-compose.dev.yml`) to `1001:1001`, so persistent volumes created while running as root keep working after the drop.
3. **Privilege drop** — joins any host docker group (`UNM_DOCKER_GID`), then drops to `app` and re-execs the app with stdio inherited and SIGTERM/SIGINT forwarded (so `docker stop` stays graceful).

Environment variables (all wired into every service in `docker-compose.dev.yml`; set them in `.env`):

| Variable | Effect |
|----------|--------|
| `UNM_RUN_AS_ROOT=1` | Explicit opt-out: skip the privilege drop and run as root (e.g. for rollback). |
| `UNM_SKIP_CHOWN=1` | Skip the runtime data-dir chown entirely — use it for huge byte stores you pre-chowned once (`chown -R 1001:1001 <volume>`), so boot stays instant. |
| `UNM_DOCKER_GID=<gid>` | Join this host group (e.g. `id -g docker`) as a supplementary group of `app`, so a mounted `/var/run/docker.sock` (owned `root:<gid>`) is accessible after the drop — needed by the docker plugin's socket transport. |
| `UNM_DOCKER_UID=<uid>` | Run the app under this uid instead of 1001, e.g. to match an existing host user that owns bind-mounted data dirs. |

Notes:
- **Existing volumes.** If you upgrade a running deployment, your data volumes are still root-owned — on first boot after the switch the wrapper chowns them once (that's what `UNM_CHOWN_PATHS` is for). For large stores, stop the stack and pre-chown instead: `chown -R 1001:1001 /var/lib/docker/volumes/<unm-stack>_filerepo-plugin/_data`, then set `UNM_SKIP_CHOWN=1`.
- **Shared CA volume.** `/data/ca` is shared between the API (writes `ca.json`) and the CA container (`step`, uid 1000, owns its state DB). It is group-writable for gid 1001 with setgid in the CA image — no runtime chown needed or wanted there.
- **No extra capabilities.** The ICMP plugin's `ping` works unprivileged (busybox uses SOCK_DGRAM ICMP sockets); nothing in the stack needs `NET_ADMIN` except the optional macvlan default-route step, which degrades gracefully without it.

## Scaling & HA

The API is designed to run as **N replicas** behind a load balancer while exactly **one** of them runs the background workers. Election uses Postgres advisory locks (`api/src/workers/leader.ts`) — no Redis, no external coordinator:

- Each worker (telemetry polling, plan execution, log/telemetry retention, plugin self-metrics, plugin discovery) takes a non-blocking `pg_try_advisory_lock` at startup. The winner runs the loop; the others log *waiting for leadership* and serve HTTP only.
- **Failover is automatic**: if the leader dies (crash, OOM, `docker compose down`), Postgres frees its locks and every standby re-attempts within 15 s. A rolling deploy steps down gracefully on SIGTERM so handover takes seconds.
- All routes are stateless — jobs land in Postgres (`config_jobs`, `plans`), not process memory. The one exception is the **config-job worker**, which drains each instance's own in-process queue, so every replica runs it (it only picks up rows *its* routes enqueued).

**Overhead of HA-by-design on a single-replica deployment:** one extra `pg_try_advisory_lock` per worker at startup plus one verification query per minute — effectively zero. The lock rides on one dedicated pinned pool connection that is never returned to the idle list (node-postgres would destroy it after 5 min and silently drop session-scoped locks).

**Capacity guidance** (2 plugins/device, ~10 KB snapshots):

| Fleet | Notes |
|-------|-------|
| ≤ 50 devices | Defaults are fine. Retention is the only thing that matters long-term. |
| 50–150 devices | Fine as-is; watch plugin self-metrics (`inFlight`, event-loop lag) during poll beats. |
| 150–400+ devices | Raise `TELEMETRY_POLL_INTERVAL_MS` (60 s) and/or keep the concurrency cap; consider a second API replica for HA — polling load stays on one leader, HTTP scales out. |

The normalized inventory tables (`networks`, `hosts`, …) hold only current state and are swept at 24 h independently of telemetry retention.
