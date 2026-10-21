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
COPY plugins/generic-ipmi/package*.json plugins/generic-ipmi/tsconfig.json plugins/generic-ipmi/
RUN cd plugins/generic-ipmi && npm install --legacy-peer-deps


COPY plugins/generic-ipmi/src/ plugins/generic-ipmi/src/
RUN cd plugins/generic-ipmi && npm run build \
    && node -e "require('/app/plugins/generic-ipmi/node_modules/@unm/plugin-sdk')" && npm prune --omit=dev --legacy-peer-deps
# Prune devDependencies (typescript, ts-node-dev, @types/*): the build above
# already ran and nothing at runtime requires them — keeps images lean and free of
# dev-only vulnerable packages.

# Static doc/license assets served at /assets/* (proxied by the API's
# GET /plugins/:id/asset) — referenced from discovery.deviceSupport. Separate
# COPYs: a multi-source COPY would flatten docs/ into the plugin root.
COPY plugins/generic-ipmi/LICENSE.md plugins/generic-ipmi/
COPY plugins/generic-ipmi/docs/ plugins/generic-ipmi/docs/

# Run from the plugin dir so `main` (dist/src/index.js) and the file: link in
# node_modules resolve exactly like in local development.
WORKDIR /app/plugins/generic-ipmi

EXPOSE 4080

CMD ["npm", "start"]
