# UNM MCP server — serves the API's OpenAPI operations as MCP tools over HTTP.
#   POST /mcp        production-safe (OpenAPI tools only)
#   POST /debug/mcp  extended debug (read-only SQL + plugin probes), keyed by MCP_DEBUG_KEY
# Build context is the REPO ROOT (see docker-compose.yml) so the OpenAPI spec —
# which the server reads at runtime to generate its tools — can be baked in.
FROM node:20-alpine

WORKDIR /app

# Shared SDK — must exist BEFORE `npm install`: mcp has a file: dependency on it
# (mTLS Stage 2 enrollment reuses startClientMtls). npm resolves the file: path
# RELATIVE TO THE DEPENDENT PACKAGE, so the layout must be
#   /app/packages/plugin-sdk   +   /app/mcp
# exactly like the repo root. Building the SDK first guarantees dist/ exists —
# npm copies it (with dist/) into mcp/node_modules during install.
COPY packages/plugin-sdk/package.json packages/plugin-sdk/tsconfig.json packages/plugin-sdk/
COPY packages/plugin-sdk/src/ packages/plugin-sdk/src/
RUN cd packages/plugin-sdk && npm install --legacy-peer-deps && npm run build

COPY mcp/package*.json ./mcp/
RUN cd mcp && npm install --legacy-peer-deps

COPY mcp/tsconfig.json ./mcp/
COPY mcp/src ./mcp/src
# The spec is resolved from here at runtime (UNM_OPENAPI_SPEC below).
COPY openapi/unified-network-manager.openapi.yaml /app/openapi/

RUN cd mcp && npm run build

WORKDIR /app/mcp

ENV MCP_PORT=3901 \
    UNM_OPENAPI_SPEC=/app/openapi/unified-network-manager.openapi.yaml

EXPOSE 3901

CMD ["npm", "start"]
