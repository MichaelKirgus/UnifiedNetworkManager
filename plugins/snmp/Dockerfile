# Build context is the REPO ROOT (see docker-compose.yml `context: .`) so the
# shared @unm/snmp-client package can be copied in alongside this plugin.
FROM node:20-alpine

# net-snmp provides the daemon + standard MIBs (SNMPv2-MIB, IF-MIB under
# /usr/share/snmp/mibs); net-snmp-tools provides the `snmpwalk` CLI used for
# all SNMP queries. Vendor MIBs are expected in a mounted volume (see
# docker-compose.yml).
RUN apk add --no-cache net-snmp net-snmp-tools

WORKDIR /app

# Shared SDK (contract types + runtime helpers). The plugin's tsc build follows
# the file: link to compile against its sources; only dist/ is needed at run
# time, but the package's own node_modules must travel with it so require()
# resolves express/cors/bonjour-service/axios from inside the copy.
COPY packages/plugin-sdk/package.json packages/plugin-sdk/tsconfig.json packages/plugin-sdk/
COPY packages/plugin-sdk/src/ packages/plugin-sdk/src/
RUN cd packages/plugin-sdk && npm install --legacy-peer-deps && npm run build

# Shared transport package (no runtime deps — only its dist/ is needed at run
# time; the plugin's tsc build follows the file: symlink to compile against it).
COPY packages/snmp-client/package.json packages/snmp-client/tsconfig.json packages/snmp-client/
COPY packages/snmp-client/src/index.ts packages/snmp-client/src/
RUN cd packages/snmp-client && npm install --legacy-peer-deps && npm run build

# Plugin: `npm install` links @unm/snmp-client → ../../packages/snmp-client.
COPY plugins/snmp/package*.json plugins/snmp/tsconfig.json plugins/snmp/
RUN cd plugins/snmp && npm install --legacy-peer-deps

COPY plugins/snmp/src/index.ts plugins/snmp/src/metrics.ts plugins/snmp/src/snmpClient.ts plugins/snmp/src/
RUN cd plugins/snmp && npm run build \
    && node -e "require('/app/plugins/snmp/node_modules/@unm/snmp-client')"

# Run from the plugin dir so `main` (dist/src/index.js) and the file: symlink
# in node_modules resolve exactly like in local development.
WORKDIR /app/plugins/snmp

EXPOSE 4080

CMD ["npm", "start"]
