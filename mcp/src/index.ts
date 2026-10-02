#!/usr/bin/env node
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { generateTools, resolveSpecPath } from './specTools.js';
import { buildDebugTools } from './debugTools.js';
import { createProdServer, createDebugServer } from './servers.js';
import { startHttpServer } from './httpServer.js';

/**
 * UnifiedNetworkManager MCP server.
 *
 * Two transports:
 *   - stdio (default): VS Code or any MCP client launches this process and it
 *     exposes the OpenAPI operations as tools on stdin/stdout.
 *       {
 *         "mcpServers": {
 *           "unm": {
 *             "command": "node",
 *             "args": ["/path/to/UnifiedNetworkManager/mcp/dist/index.js"],
 *             "env": { "UNM_API_TOKEN": "unm_…" }
 *           }
 *         }
 *       }
 *   - HTTP (when MCP_PORT is set, e.g. in the docker-compose `mcp` service):
 *     POST /mcp        — production-safe: OpenAPI tools only
 *     POST /debug/mcp  — extended debug: + read-only SQL + plugin probes
 *                        (requires Authorization: Bearer <MCP_DEBUG_KEY>)
 *
 * Environment:
 *   UNM_API_TOKEN      long-lived API token for the OpenAPI tools (required)
 *   UNM_API_BASE       default http://localhost:3000/v1
 *   UNM_TLS            "1" = enroll this server against the CA and talk to the
 *                      API's mTLS listener (:8443) + mTLS-live plugins. Off by
 *                      default — plain HTTP keeps working either way.
 *   UNM_API_TLS_BASE   mTLS base URL (default: UNM_API_BASE with https)
 *   MCP_PORT           set to enable HTTP mode (container uses 3901)
 *   MCP_DEBUG_KEY      bearer key gating /debug/mcp
 *   MCP_KEY            optional bearer key also gating /mcp
 *   DATABASE_URL       Postgres connection for the debug SQL tool
 *   PLUGIN_POLL_ENDPOINTS  comma-separated plugin endpoints for plugin_probe
 */

function main(): void {
  // mTLS Stage 2: importing ./mcpMtls.js starts the background CA enrollment
  // when UNM_TLS=1 (non-blocking; tools fall back to plain HTTP meanwhile).
  const specPath = resolveSpecPath();
  let tools;
  try {
    tools = generateTools(specPath);
  } catch (err) {
    console.error(`[unm-mcp] failed to load OpenAPI spec at ${specPath}:`, (err as Error).message);
    process.exit(1);
  }

  const debugTools = buildDebugTools();

  // HTTP mode (container): serve both endpoints on MCP_PORT.
  if (process.env.MCP_PORT) {
    startHttpServer({
      port: Number(process.env.MCP_PORT),
      createProdServer: () => createProdServer(tools),
      createDebugServer: () => createDebugServer(tools, debugTools),
      debugKey: process.env.MCP_DEBUG_KEY || undefined,
      mcpKey: process.env.MCP_KEY || undefined,
    });
    console.error(`[unm-mcp] ready (HTTP): ${tools.length} API tools + ${debugTools.length} debug tools from ${specPath}`);
    return;
  }

  // stdio mode (client-launched): production-safe tool set only.
  const server = createProdServer(tools);
  const transport = new StdioServerTransport();
  server.connect(transport).catch((err) => {
    console.error('[unm-mcp] transport error:', err);
    process.exit(1);
  });

  // Diagnostics go to stderr ONLY — stdout is the MCP protocol channel.
  console.error(`[unm-mcp] ready (stdio): ${tools.length} tools from ${specPath}`);
}

main();
