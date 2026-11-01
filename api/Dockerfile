# Build context is the repository root (see docker-compose.yml) so that the
# shared openapi/ spec directory AND the @unm/plugin-sdk package can be copied
# alongside the api/ source.
FROM node:20-alpine

# Build tag baked in at image build time (CI sets UNM_BUILD_TAG to the branch or
# release tag; empty = local/dev build). Served by GET /v1/info → webapp UI.
ARG UNM_BUILD_TAG=
ENV UNM_BUILD_TAG=${UNM_BUILD_TAG}

WORKDIR /app

# Shared SDK — must exist BEFORE `cd api && npm install`: the api has a file:
# dependency on it (types-only), and npm links/copies from this path. Building
# it first also guarantees dist/ exists if anything ever requires() it.
COPY packages/plugin-sdk/package.json packages/plugin-sdk/tsconfig.json packages/plugin-sdk/
COPY packages/plugin-sdk/src/ packages/plugin-sdk/src/
RUN cd packages/plugin-sdk && npm install --legacy-peer-deps && npm run build

COPY api/package*.json ./api/
RUN cd api && npm install --legacy-peer-deps

COPY openapi ./openapi
COPY api ./api

RUN cd api && npm run build && npm prune --omit=dev --legacy-peer-deps
# Prune devDependencies (typescript, ts-node-dev, jest, @types/*): the build above
# already ran and nothing at runtime requires them — keeps images lean and free of
# dev-only vulnerable packages. NOTE: drizzle-kit is a RUNTIME dependency on purpose —
# src/schemaBootstrap.ts runs `drizzle-kit push` at container boot to bootstrap fresh
# databases and apply additive schema upgrades (production has no host-side setup.sh).

WORKDIR /app/api
EXPOSE 3000

# Unprivileged runtime user (uid/gid 1001) — the entrypoint wrapper drops to it.
# Pre-create persistent data dirs owned by `app` so fresh containers need no
# runtime chown; existing root-owned volumes are fixed at boot via UNM_CHOWN_PATHS.
RUN addgroup -g 1001 unm && adduser -u 1001 -G unm -D app \
    && mkdir -p /data/backups /data/file-repo /data/tls \
    && chown -R 1001:1001 /data/backups /data/file-repo /data/tls

# Privilege-drop helper — joins UNM_DOCKER_GID, drops to `app`, re-execs the app.
COPY scripts/unm-privdrop.js /usr/local/lib/unm-privdrop.js

# UNM entrypoint wrapper — macvlan gateway (UNM_DEFAULT_GATEWAY), data-dir chown
# (UNM_CHOWN_PATHS, skip via UNM_SKIP_CHOWN=1) and privilege drop to `app`
# (opt out with UNM_RUN_AS_ROOT=1). See scripts/docker-entrypoint.sh.
COPY scripts/docker-entrypoint.sh /usr/local/bin/unm-entrypoint.sh
RUN chmod +x /usr/local/bin/unm-entrypoint.sh
ENTRYPOINT ["/usr/local/bin/unm-entrypoint.sh"]

CMD ["npm", "start"]
