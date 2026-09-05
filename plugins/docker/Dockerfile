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
COPY plugins/docker/package*.json plugins/docker/tsconfig.json plugins/docker/
RUN cd plugins/docker && npm install --legacy-peer-deps

COPY plugins/docker/src/ plugins/docker/src/
RUN cd plugins/docker && npm run build \
    && node -e "require('/app/plugins/docker/node_modules/@unm/plugin-sdk')"

# Run from the plugin dir so `main` (dist/src/index.js) and the file: link in
# node_modules resolve exactly like in local development.
WORKDIR /app/plugins/docker

EXPOSE 4080

CMD ["npm", "start"]
