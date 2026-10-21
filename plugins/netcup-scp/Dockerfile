# Build context is the REPO ROOT (see docker-compose.yml `context: .`) so the
# shared @unm/plugin-sdk package can be copied in alongside this plugin.
FROM node:20-alpine

WORKDIR /app

# Shared SDK (contract types + runtime helpers). The plugin's tsc build follows
# the file: link to compile against its sources; only dist/ is needed at run
# time, but the package's own node_modules must travel with it so require()
# resolves express/cors/bonjour-service/axios from inside the copy.
COPY packages/plugin-sdk/package.json packages/plugin-sdk/tsconfig.json packages/plugin-sdk/
COPY packages/plugin-sdk/src/ packages/plugin-sdk/src/
RUN cd packages/plugin-sdk && npm install --legacy-peer-deps && npm run build

# Plugin: `npm install` links @unm/plugin-sdk → ../../packages/plugin-sdk.
COPY plugins/netcup-scp/package*.json plugins/netcup-scp/tsconfig.json plugins/netcup-scp/
RUN cd plugins/netcup-scp && npm install --legacy-peer-deps


COPY plugins/netcup-scp/src/ plugins/netcup-scp/src/
RUN cd plugins/netcup-scp && npm run build \
    && node -e "require('/app/plugins/netcup-scp/node_modules/@unm/plugin-sdk')" && npm prune --omit=dev --legacy-peer-deps
# Prune devDependencies (typescript, ts-node-dev, jest, @types/*): the build above
# already ran and nothing at runtime requires them — keeps images lean and free of
# dev-only vulnerable packages.

# Static doc/license assets served at /assets/* (proxied by the API's
# GET /plugins/:id/asset) — referenced from discovery.deviceSupport. Separate
# COPYs: a multi-source COPY would flatten docs/ into the plugin root.
COPY plugins/netcup-scp/LICENSE.md plugins/netcup-scp/
COPY plugins/netcup-scp/docs/ plugins/netcup-scp/docs/

# Run from the plugin dir so `main` (dist/src/index.js) and the file: link in
# node_modules resolve exactly like in local development.
WORKDIR /app/plugins/netcup-scp

EXPOSE 4080

# UNM entrypoint wrapper — optional macvlan default gateway (UNM_DEFAULT_GATEWAY);
# pure passthrough when the variable is unset. See scripts/docker-entrypoint.sh.
COPY scripts/docker-entrypoint.sh /usr/local/bin/unm-entrypoint.sh
RUN chmod +x /usr/local/bin/unm-entrypoint.sh
ENTRYPOINT ["/usr/local/bin/unm-entrypoint.sh"]

CMD ["npm", "start"]
