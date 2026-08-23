# Build context is the REPO ROOT (see docker-compose.yml `context: .`) so the
# shared @unm/snmp-client package can be copied in alongside this plugin.
FROM node:20-alpine

# net-snmp provides the daemon + standard MIBs; net-snmp-tools provides the
# `snmpwalk` CLI used for all SNMP queries (via @unm/snmp-client). Vendor MIBs
# are expected in a mounted volume (see docker-compose.yml, /app/mibs).
RUN apk add --no-cache net-snmp net-snmp-tools

WORKDIR /app

# Shared transport package (no runtime deps — only its dist/ is needed at run
# time; the plugin's tsc build follows the file: symlink to compile against it).
COPY packages/snmp-client/package.json packages/snmp-client/tsconfig.json packages/snmp-client/
COPY packages/snmp-client/src/index.ts packages/snmp-client/src/
RUN cd packages/snmp-client && npm install --legacy-peer-deps && npm run build

# Plugin: `npm install` links @unm/snmp-client → ../../packages/snmp-client.
COPY plugins/lancom/package*.json plugins/lancom/tsconfig.json plugins/lancom/
RUN cd plugins/lancom && npm install --legacy-peer-deps

COPY plugins/lancom/src/index.ts plugins/lancom/src/lcosOids.ts plugins/lancom/src/lcosClient.ts plugins/lancom/src/metrics.ts plugins/lancom/src/
RUN cd plugins/lancom && npm run build \
    && node -e "require('/app/plugins/lancom/node_modules/@unm/snmp-client')"

# Run from the plugin dir so `main` (dist/src/index.js) and the file: symlink
# in node_modules resolve exactly like in local development.
WORKDIR /app/plugins/lancom

EXPOSE 4006

CMD ["npm", "start"]
