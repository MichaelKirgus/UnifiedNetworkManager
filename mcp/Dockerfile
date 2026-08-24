# UNM MCP server — serves the API's OpenAPI operations as MCP tools over HTTP.
#   POST /mcp        production-safe (OpenAPI tools only)
#   POST /debug/mcp  extended debug (read-only SQL + plugin probes), keyed by MCP_DEBUG_KEY
# Build context is the REPO ROOT (see docker-compose.yml) so the OpenAPI spec —
# which the server reads at runtime to generate its tools — can be baked in.
FROM node:20-alpine

WORKDIR /app

COPY mcp/package*.json ./
RUN npm install --legacy-peer-deps

COPY mcp/tsconfig.json ./
COPY mcp/src ./src
# The spec is resolved from here at runtime (UNM_OPENAPI_SPEC below).
COPY openapi/unified-network-manager.openapi.yaml /app/openapi/

RUN npm run build

ENV MCP_PORT=3901 \
    UNM_OPENAPI_SPEC=/app/openapi/unified-network-manager.openapi.yaml

EXPOSE 3901

CMD ["npm", "start"]
