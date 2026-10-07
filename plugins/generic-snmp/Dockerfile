# Build context is the REPO ROOT (see docker-compose.yml `context: .`) so the
# shared @unm/snmp-client package can be copied in alongside this plugin.
FROM node:20-alpine

# No system packages needed: @unm/snmp-client speaks SNMP over native UDP via
# the `net-snmp` npm package (installed below with its own deps). Vendor MIBs
# are still expected in a mounted volume for manual debugging only.

WORKDIR /app

# Shared SDK (contract types + runtime helpers). The plugin's tsc build follows
# the file: link to compile against its sources; only dist/ is needed at run
# time, but the package's own node_modules must travel with it so require()
# resolves express/cors/bonjour-service/axios from inside the copy.
COPY packages/plugin-sdk/package.json packages/plugin-sdk/tsconfig.json packages/plugin-sdk/
COPY packages/plugin-sdk/src/ packages/plugin-sdk/src/
RUN cd packages/plugin-sdk && npm install --legacy-peer-deps && npm run build

# Shared transport package. Its runtime dep (the `net-snmp` UDP stack) is
# installed here and travels with the copy; the plugin's tsc build follows the
# file: symlink to compile against its sources.
COPY packages/snmp-client/package.json packages/snmp-client/tsconfig.json packages/snmp-client/
COPY packages/snmp-client/scripts/ packages/snmp-client/scripts/
COPY packages/snmp-client/src/ packages/snmp-client/src/
RUN cd packages/snmp-client && npm install --legacy-peer-deps && npm run build

# Plugin: `npm install` links @unm/snmp-client → ../../packages/snmp-client.
COPY plugins/generic-snmp/package*.json plugins/generic-snmp/tsconfig.json plugins/generic-snmp/
RUN cd plugins/generic-snmp && npm install --legacy-peer-deps

COPY plugins/generic-snmp/src/index.ts plugins/generic-snmp/src/metrics.ts plugins/generic-snmp/src/snmpClient.ts plugins/generic-snmp/src/
RUN cd plugins/generic-snmp && npm run build \
    && node -e "require('/app/plugins/generic-snmp/node_modules/@unm/snmp-client')"

# Run from the plugin dir so `main` (dist/src/index.js) and the file: symlink
# in node_modules resolve exactly like in local development.
# Static doc/license assets served at /assets/* (proxied by the API's
# GET /plugins/:id/asset) — referenced from discovery.deviceSupport. Separate
# COPYs: a multi-source COPY would flatten docs/ into the plugin root.
COPY plugins/generic-snmp/LICENSE.md plugins/generic-snmp/
COPY plugins/generic-snmp/docs/ plugins/generic-snmp/docs/

WORKDIR /app/plugins/generic-snmp

EXPOSE 4080

CMD ["npm", "start"]
