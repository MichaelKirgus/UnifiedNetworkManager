# Build context is the REPO ROOT (see docker-compose.yml `context: .`) so the
# shared @unm/plugin-sdk package can be copied in alongside this plugin.
FROM node:20-alpine

# Build tag baked in at image build time (CI sets UNM_BUILD_TAG to the branch or
# release tag; empty = local/dev build). Surfaced via /discover -> Plugins page.
ARG UNM_BUILD_TAG=
ENV UNM_BUILD_TAG=${UNM_BUILD_TAG}

WORKDIR /app

# Shared SDK (contract types + runtime helpers). The plugin's tsc build follows
# the file: link to compile against its sources; only dist/ is needed at run
# time, but the package's own node_modules must travel with it so require()
# resolves express/cors/bonjour-service from inside the copy.
COPY packages/plugin-sdk/package.json packages/plugin-sdk/tsconfig.json packages/plugin-sdk/
COPY packages/plugin-sdk/src/ packages/plugin-sdk/src/
RUN cd packages/plugin-sdk && npm install --legacy-peer-deps && npm run build

# Plugin: `npm install` links @unm/plugin-sdk → ../../packages/plugin-sdk.
COPY plugins/generic-ssh/package*.json plugins/generic-ssh/tsconfig.json plugins/generic-ssh/
RUN cd plugins/generic-ssh && npm install --legacy-peer-deps


COPY plugins/generic-ssh/src/ plugins/generic-ssh/src/
RUN cd plugins/generic-ssh && npm run build \
    && node -e "require('/app/plugins/generic-ssh/node_modules/@unm/plugin-sdk')" && npm prune --omit=dev --legacy-peer-deps
# Prune devDependencies (typescript, ts-node-dev, jest, @types/*): the build above
# already ran and nothing at runtime requires them — keeps images lean and free of
# dev-only vulnerable packages.

# Static icon assets served at /icons (proxied by the API's GET /plugins/:id/icon).
COPY plugins/generic-ssh/icons/ plugins/generic-ssh/icons/

# Run from the plugin dir so `main` (dist/src/index.js) and the file: link in
# node_modules resolve exactly like in local development.
# Static doc/license assets served at /assets/* (proxied by the API's
# GET /plugins/:id/asset) — referenced from discovery.deviceSupport. Separate
# COPYs: a multi-source COPY would flatten docs/ into the plugin root.
COPY plugins/generic-ssh/LICENSE.md plugins/generic-ssh/
COPY plugins/generic-ssh/docs/ plugins/generic-ssh/docs/

WORKDIR /app/plugins/generic-ssh

EXPOSE 4080

# Unprivileged runtime user (uid/gid 1001) — the entrypoint wrapper drops to it.
RUN addgroup -g 1001 unm && adduser -u 1001 -G unm -D app \
    && mkdir -p /data/tls && chown -R 1001:1001 /data/tls

# Privilege-drop helper — joins UNM_DOCKER_GID, drops to `app`, re-execs the app.
COPY scripts/unm-privdrop.js /usr/local/lib/unm-privdrop.js

# UNM entrypoint wrapper — macvlan gateway (UNM_DEFAULT_GATEWAY), data-dir chown
# (UNM_CHOWN_PATHS, skip via UNM_SKIP_CHOWN=1) and privilege drop to `app`
# (opt out with UNM_RUN_AS_ROOT=1). See scripts/docker-entrypoint.sh.
COPY scripts/docker-entrypoint.sh /usr/local/bin/unm-entrypoint.sh
RUN chmod +x /usr/local/bin/unm-entrypoint.sh
ENTRYPOINT ["/usr/local/bin/unm-entrypoint.sh"]

CMD ["npm", "start"]
