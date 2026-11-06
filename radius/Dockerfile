# UNM RADIUS service — a RUNNABLE FreeRADIUS 3.x server for WiFi EAP-TLS.
# (The official freeradius/freeradius-server image is config-only: it ships no
# radiusd binary, only an empty raddb meant to be mounted elsewhere.)
#
# Layout contract (mirrors the unm-ca sidecar pattern — see api/src/radius/):
#   /data/radius  shared config volume with the UNM API. The API renders
#                 clients.conf, the eap/sql module instances, the EAP-TLS site,
#                 and the RADIUS server cert/key from global settings + CA state.
#                 This entrypoint copies them into /etc/freeradius/3.0 (owned by
#                 freerad) and SIGHUPs radiusd on change — hot-apply without a
#                 container restart.
#   /data/ca      the CA shared volume, mounted READ-ONLY. The entrypoint keeps
#                 root_ca.crt in sync from it into the local raddb so EAP-TLS
#                 validates client certs against UNM's own CA (no CRL endpoint
#                 exists on step-ca 0.30.x — revocation is enforced per-auth via
#                 the revoked_serials table, see api/src/radius/).
#
# Accounting writes go straight to UNM's Postgres through rlm_sql (postgresql
# dialect); the API applies the stock schema.sql at boot, so this image needs no
# DB tooling of its own.

FROM debian:trixie-slim

ENV DEBIAN_FRONTEND=noninteractive \
    FREERADIUS_DIR=/etc/freeradius/3.0 \
    RADIUS_CFG=/data/radius \
    CA_CFG=/data/ca

RUN apt-get update && apt-get install -y --no-install-recommends \
        freeradius \
        freeradius-postgresql \
        openssl \
        procps \
    && rm -rf /var/lib/apt/lists/*

# The shared volume is rendered by the UNM API (uid/gid 1001). Pre-create it so
# a fresh named volume inherits group-writable-for-1001 + setgid, exactly like
# ca/Dockerfile does for /data/ca. FreeRADIUS itself runs as `freerad` and only
# ever reads from the raddb — the entrypoint (root) copies rendered files in and
# fixes ownership before each start/reload.
# NOTE: Debian's addgroup rejects the short `-g` flag ("Option g is ambiguous")
# — use `--gid`. (The CA image uses Alpine, where `-g` works.)
RUN addgroup --gid 1001 unm \
    && mkdir -p "$RADIUS_CFG" /data/ca \
    && chown root:unm "$RADIUS_CFG" \
    && chmod 2775 "$RADIUS_CFG"

# Build context is the REPO ROOT (see docker-compose.yml `context: .`) — same as
# ca/Dockerfile, so paths are prefixed with radius/.
COPY radius/entrypoint.sh /entrypoint-unm.sh
RUN chmod 755 /entrypoint-unm.sh

# RADIUS auth + accounting (UDP; TCP variants for RFC 6614 clients).
EXPOSE 1812/udp 1813/udp 1812/tcp 1813/tcp

ENTRYPOINT ["/bin/sh", "/entrypoint-unm.sh"]
