# Build context is the REPO ROOT (see docker-compose.yml `context: .`) so the
# shared @unm/snmp-client package can be copied in alongside this plugin.
FROM node:20-alpine

# net-snmp provides the daemon + standard MIBs; net-snmp-tools provides the
# snmpwalk/snmpget/snmpset CLIs used for all SNMP traffic (via @unm/snmp-client).
# Vendor MIBs are expected in a mounted volume (see docker-compose.yml, /app/mibs).
RUN apk add --no-cache net-snmp net-snmp-tools

WORKDIR /app

# Shared transport package (no runtime deps — only its dist/ is needed at run
# time; the plugin's tsc build follows the file: symlink to compile against it).
COPY packages/snmp-client/package.json packages/snmp-client/tsconfig.json packages/snmp-client/
COPY packages/snmp-client/src/index.ts packages/snmp-client/src/
RUN cd packages/snmp-client && npm install --legacy-peer-deps && npm run build

# Plugin: `npm install` links @unm/snmp-client → ../../packages/snmp-client.
COPY plugins/lancom-lcos/package*.json plugins/lancom-lcos/tsconfig.json plugins/lancom-lcos/
RUN cd plugins/lancom-lcos && npm install --legacy-peer-deps

COPY plugins/lancom-lcos/src/ plugins/lancom-lcos/src/
RUN cd plugins/lancom-lcos && npm run build \
    && node -e "require('/app/plugins/lancom-lcos/node_modules/@unm/snmp-client')"

# Static icon assets served at /icons (proxied by the API's GET /plugins/:id/icon).
COPY plugins/lancom-lcos/icons/ plugins/lancom-lcos/icons/

# Run from the plugin dir so `main` (dist/src/index.js) and the file: symlink
# in node_modules resolve exactly like in local development.
WORKDIR /app/plugins/lancom-lcos

EXPOSE 4008

CMD ["npm", "start"]
