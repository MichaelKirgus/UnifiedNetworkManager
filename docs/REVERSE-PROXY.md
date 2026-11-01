# Running UNM behind a reverse proxy

UNM is an admin appliance — the README's top warning applies: never expose the
web UI to the public internet without additional authentication. The supported
remote-access pattern is **TLS termination + auth at a reverse proxy** (nginx,
Caddy, Traefik, Cloudflare Tunnel, …) in front of the stack. This document
covers what UNM needs from that proxy and how to configure both sides.

## What the API needs from your proxy

| Concern | Requirement |
|---|---|
| **Client IP** | Send `X-Forwarded-For` (standard) — or a dedicated header like Cloudflare's `CF-Connecting-IP`. UNM must be told to trust it: set `UNM_TRUST_PROXY` (see below). **This is required, not optional:** the rate limiter rejects every request carrying an untrusted `X-Forwarded-For` with HTTP 500 (`ERR_ERL_UNEXPECTED_X_FORWARDED_FOR`), so a proxy that sends the header but no `UNM_TRUST_PROXY` breaks all `/v1` traffic. |
| **WebSocket** | The SSH console (`/v1/devices/:id/console/ws`) is a WebSocket endpoint — your proxy must forward `Upgrade`/`Connection` headers for it. Both examples below do. |
| **Body size** | File uploads and filesystem writes carry base64 content; the API accepts up to ~12 MiB JSON. Set your proxy's body limit ≥ 15 MiB (nginx: `client_max_body_size`). |
| **Timeouts** | Long-running operations (plan execution, backups) can take minutes. Raise proxy read timeouts accordingly (the examples use 300 s). |

## UNM environment variables

Set these in `.env` next to the compose file (they flow into the `api` service):

```dotenv
# REQUIRED behind any reverse proxy: trust X-Forwarded-For so rate limiting
# sees real client IPs (and the API accepts proxied requests at all — see the
# table above). "1" = exactly one hop (a single reverse proxy) — the common
# case; N = N hops (e.g. load balancer + proxy); or a CIDR list / named policy,
# e.g. "10.0.0.0/8" or "loopback".
UNM_TRUST_PROXY=1

# Optional: explicit client-IP header instead of X-Forwarded-For.
# Cloudflare (and its Tunnel) sends CF-Connecting-IP — use that there.
# Only set this if the proxy is the SOLE path to the API; otherwise a client
# can forge the header and reset its own rate-limit bucket.
#UNM_CLIENT_IP_HEADER=CF-Connecting-IP
```

> **Webapp → API base URL.** The webapp's API base is compiled in at build time
> (`VITE_API_URL`). Pre-built images ship with the RELATIVE default `/v1` —
> same origin as the webapp itself. That means a standard `docker compose up -d`
> deployment already expects **one public hostname serving UI + API** (proxy
> `/v1/*` to the api container): no CORS configuration, and the SSH console
> WebSocket works with zero extra client setup.
>
> If you instead want separate origins (e.g. `unm.example.com` for the UI and
> `api.unm.example.com` for the API), build the webapp image yourself with an
> absolute base (`--build-arg VITE_API_URL=https://api.unm.example.com/v1`, or
> set `UNM_WEBAPP_API_URL` in the dev compose) and add the UI origin to
> `UNM_CORS_ORIGINS`. Pre-built GHCR images cannot be re-pointed at runtime.

## Example 1 — nginx (single host, same origin)

One hostname serves the webapp; `/v1/*` is proxied to the API container. The
SSH console WebSocket rides on the same location via the `Upgrade` headers.

```nginx
# /etc/nginx/conf.d/unm.conf
upstream unm_api { server 127.0.0.1:3000; }   # api host port (compose "3000:3000")
upstream unm_web { server 127.0.0.1:8080; }   # webapp host port (UNM_WEB_PORT)

server {
    listen 443 ssl http2;
    server_name unm.example.com;

    ssl_certificate     /etc/letsencrypt/live/unm.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/unm.example.com/privkey.pem;

    # ≥ the API's 12 MiB JSON limit, plus headroom for base64 + framing.
    client_max_body_size 20m;

    # --- API (JSON + SSH console WebSocket) -------------------------------
    location /v1/ {
        proxy_pass http://unm_api;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        # WebSocket support (SSH console):
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_read_timeout 300s;   # long-running ops: plans, backups
    }

    # --- Webapp (static bundle) -------------------------------------------
    location / {
        proxy_pass http://unm_web;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}

server {
    listen 80;
    server_name unm.example.com;
    return 301 https://$host$request_uri;
}
```

Matching `.env` (the pre-built webapp already uses same-origin `/v1`, so no
webapp variable is needed — just rebuild nothing, `docker compose up -d` works):

```dotenv
UNM_TRUST_PROXY=1
# Same-origin → no UNM_CORS_ORIGINS needed. WEBAUTHN_ORIGIN must be the public
# origin (passkeys are bound to it):
WEBAUTHN_RP_ID=unm.example.com
WEBAUTHN_ORIGIN=https://unm.example.com
```

> **WebAuthn note:** passkey enrollment binds to `WEBAUTHN_RP_ID` +
> `WEBAUTHN_ORIGIN`. If you change the public origin after enrolling, existing
> passkeys stop working — re-enroll them.

## Example 2 — Caddy (single host, same origin)

Caddy handles TLS automatically and forwards WebSocket upgrades by default:

```caddyfile
# /etc/caddy/Caddyfile
unm.example.com {
    encode gzip

    # API + SSH console WebSocket (WebSocket needs no extra config in Caddy).
    handle /v1/* {
        reverse_proxy 127.0.0.1:3000 {
            header_up X-Forwarded-For {remote_host}
        }
    }

    # Webapp static bundle.
    handle {
        reverse_proxy 127.0.0.1:8080
    }
}
```

`.env` is identical to the nginx example (`UNM_TRUST_PROXY=1`, public
`WEBAUTHN_*`) — same-origin `/v1` is already the pre-built webapp default.

## Example 3 — Cloudflare (Tunnel or proxied DNS)

Cloudflare terminates TLS at its edge and sends the real client IP in
**`CF-Connecting-IP`** (it also appends to `X-Forwarded-For`, but the edge IPs
are public and shared, so prefer the dedicated header):

```dotenv
# .env — Cloudflare-specific settings
UNM_TRUST_PROXY=1
UNM_CLIENT_IP_HEADER=CF-Connecting-IP
WEBAUTHN_RP_ID=unm.example.com
WEBAUTHN_ORIGIN=https://unm.example.com
```

With **Cloudflare Tunnel** (`cloudflared`) you don't publish any host ports at
all — the tunnel dials out to Cloudflare and forwards to `localhost:8080` /
`localhost:3000`. With a **proxied DNS record**, point the hostname at your
server's published webapp port and add an API route (e.g. a second hostname or
a path-based rule) for `/v1/*` → `localhost:3000`.

## Verifying it works

```bash
# 1. Rate limiting now buckets per client, not per proxy:
curl -s https://unm.example.com/v1/healthz          # 200 ok
# hammer an auth endpoint from two different machines → each gets its own
# 10/min budget instead of sharing one.

# 2. The API log line at startup confirms trust-proxy is active:
docker compose logs api | grep 'trust proxy'
#   [api] trust proxy enabled: 1 — client IPs are read from X-Forwarded-For …

# 3. SSH console still works (WebSocket through the proxy): open a device's
#    console in the webapp and confirm the terminal connects.
```

## Security checklist for proxied deployments

- [ ] `UNM_TRUST_PROXY` matches your actual hop count — too high lets upstream
      clients spoof `X-Forwarded-For`; too low reverts to proxy-IP bucketing.
- [ ] The API's host port (3000) is **not** reachable from the internet
      directly — only via the proxy. If it must be published, bind it to the
      proxy's interface (`"127.0.0.1:3000:3000"` when the proxy runs on the
      same host).
- [ ] `UNM_CLIENT_IP_HEADER` is only set if the proxy is the sole ingress.
- [ ] `WEBAUTHN_RP_ID` / `WEBAUTHN_ORIGIN` match the public origin exactly
      (scheme + host, no trailing slash).
- [ ] If you keep UI and API on separate origins: add the UI origin to
      `UNM_CORS_ORIGINS`.
- [ ] Consider additional auth at the proxy layer (OAuth2/OIDC, basic-auth, or
      an allow-listed IP range) — UNM's own 2FA protects accounts, but a proxy
      can block anonymous traffic entirely.
