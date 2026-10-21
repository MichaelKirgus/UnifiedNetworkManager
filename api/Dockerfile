# Build context is the repository root (see docker-compose.yml) so that the
# shared openapi/ spec directory AND the @unm/plugin-sdk package can be copied
# alongside the api/ source.
FROM node:20-alpine

# Build tag baked in at image build time (CI sets UNM_BUILD_TAG to the branch or
# release tag; empty = local/dev build). Served by GET /v1/info → webapp UI.
ARG UNM_BUILD_TAG=
ENV UNM_BUILD_TAG=${UNM_BUILD_TAG}

WORKDIR /app

# Shared SDK — must exist BEFORE `cd api && npm install`: the api has a file:
# dependency on it (types-only), and npm links/copies from this path. Building
# it first also guarantees dist/ exists if anything ever requires() it.
COPY packages/plugin-sdk/package.json packages/plugin-sdk/tsconfig.json packages/plugin-sdk/
COPY packages/plugin-sdk/src/ packages/plugin-sdk/src/
RUN cd packages/plugin-sdk && npm install --legacy-peer-deps && npm run build

COPY api/package*.json ./api/
RUN cd api && npm install --legacy-peer-deps

COPY openapi ./openapi
COPY api ./api

RUN cd api && npm run build && npm prune --omit=dev --legacy-peer-deps
# Prune devDependencies (typescript, ts-node-dev, jest, @types/*): the build above
# already ran and nothing at runtime requires them — keeps images lean and free of
# dev-only vulnerable packages.

WORKDIR /app/api
EXPOSE 3000

# UNM entrypoint wrapper — optional macvlan default gateway (UNM_DEFAULT_GATEWAY);
# pure passthrough when the variable is unset. See scripts/docker-entrypoint.sh.
COPY scripts/docker-entrypoint.sh /usr/local/bin/unm-entrypoint.sh
RUN chmod +x /usr/local/bin/unm-entrypoint.sh
ENTRYPOINT ["/usr/local/bin/unm-entrypoint.sh"]

CMD ["npm", "start"]
