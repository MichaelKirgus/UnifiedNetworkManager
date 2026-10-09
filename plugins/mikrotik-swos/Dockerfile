# Build context is the REPO ROOT (see docker-compose.yml `context: .`) so the
# shared @unm/plugin-sdk package can be copied in alongside this plugin.
# Digest auth is pure node:crypto; no extra apk packages needed.
FROM node:20-alpine

# Build tag baked in at image build time (CI sets UNM_BUILD_TAG to the branch or
# release tag; empty = local/dev build). Surfaced via /discover -> Plugins page.
ARG UNM_BUILD_TAG=
ENV UNM_BUILD_TAG=${UNM_BUILD_TAG}

WORKDIR /app

# Shared SDK (contract types + runtime helpers). The plugin's tsc build follows
# the file: link to compile against its sources; only dist/ is needed at run
# time, but the package's own node_modules must travel with it so require()
# resolves express/cors/bonjour-service/axios from inside the copy.
COPY packages/plugin-sdk/package.json packages/plugin-sdk/tsconfig.json packages/plugin-sdk/
COPY packages/plugin-sdk/src/ packages/plugin-sdk/src/
RUN cd packages/plugin-sdk && npm install --legacy-peer-deps && npm run build

# Plugin: `npm install` links @unm/plugin-sdk → ../../packages/plugin-sdk.
COPY plugins/mikrotik-swos/package*.json plugins/mikrotik-swos/tsconfig.json plugins/mikrotik-swos/
RUN cd plugins/mikrotik-swos && npm install --legacy-peer-deps

COPY plugins/mikrotik-swos/src/ plugins/mikrotik-swos/src/
RUN cd plugins/mikrotik-swos && npm run build \
    && node -e "require('/app/plugins/mikrotik-swos/node_modules/@unm/plugin-sdk')"

# Static icon assets served at /icons (proxied by the API's GET /plugins/:id/icon).
COPY plugins/mikrotik-swos/icons/ plugins/mikrotik-swos/icons/

# Run from the plugin dir so `main` (dist/src/index.js) and the file: link in
# node_modules resolve exactly like in local development.
# Static doc/license assets served at /assets/* (proxied by the API's
# GET /plugins/:id/asset) — referenced from discovery.deviceSupport. Separate
# COPYs: a multi-source COPY would flatten docs/ into the plugin root.
COPY plugins/mikrotik-swos/LICENSE.md plugins/mikrotik-swos/
COPY plugins/mikrotik-swos/docs/ plugins/mikrotik-swos/docs/

WORKDIR /app/plugins/mikrotik-swos

EXPOSE 4080

CMD ["npm", "start"]
