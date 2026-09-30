# Build context is the REPO ROOT (see docker-compose.yml `context: .`) so the
# shared @unm/plugin-sdk package can be copied in alongside this plugin.
# The RouterOS REST API is plain HTTP(S) + Basic auth — no extra apk packages.
FROM node:20-alpine

WORKDIR /app

# Shared SDK (contract types + runtime helpers). The plugin's tsc build follows
# the file: link to compile against its sources; only dist/ is needed at run
# time, but the package's own node_modules must travel with it so require()
# resolves express/cors/bonjour-service from inside the copy.
COPY packages/plugin-sdk/package.json packages/plugin-sdk/tsconfig.json packages/plugin-sdk/
COPY packages/plugin-sdk/src/ packages/plugin-sdk/src/
RUN cd packages/plugin-sdk && npm install --legacy-peer-deps && npm run build

# Plugin: `npm install` links @unm/plugin-sdk → ../../packages/plugin-sdk.
COPY plugins/mikrotik-routeros/package*.json plugins/mikrotik-routeros/tsconfig.json plugins/mikrotik-routeros/
RUN cd plugins/mikrotik-routeros && npm install --legacy-peer-deps

COPY plugins/mikrotik-routeros/src/ plugins/mikrotik-routeros/src/
RUN cd plugins/mikrotik-routeros && npm run build \
    && node -e "require('/app/plugins/mikrotik-routeros/node_modules/@unm/plugin-sdk')"

# Static icon assets served at /icons (proxied by the API's GET /plugins/:id/icon).
COPY plugins/mikrotik-routeros/icons/ plugins/mikrotik-routeros/icons/

# Static doc/license assets served at /assets/* (proxied by the API's
# GET /plugins/:id/asset) — referenced from discovery.deviceSupport. Separate
# COPYs: a multi-source COPY would flatten docs/ into the plugin root.
COPY plugins/mikrotik-routeros/LICENSE.md plugins/mikrotik-routeros/
COPY plugins/mikrotik-routeros/docs/ plugins/mikrotik-routeros/docs/

# Run from the plugin dir so `main` (dist/src/index.js) and the file: link in
# node_modules resolve exactly like in local development.
WORKDIR /app/plugins/mikrotik-routeros

EXPOSE 4080

CMD ["npm", "start"]
