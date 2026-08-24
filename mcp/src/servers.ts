import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { GeneratedTool } from './specTools.js';
import type { DebugTool } from './debugTools.js';

const SERVER_INFO = { name: 'unified-network-manager', version: '0.1.0' };

/** Registers the OpenAPI-generated API tools on a server (shared by both endpoints). */
function registerApiTools(server: McpServer, tools: GeneratedTool[]): void {
  for (const tool of tools) {
    server.tool(tool.name, tool.description, tool.inputSchema, async (args: Record<string, unknown>) => {
      try {
        const result = await tool.execute(args);
        // Pretty-print JSON bodies when possible — agents read these as text.
        let contentText = result.bodyText;
        try {
          contentText = JSON.stringify(JSON.parse(result.bodyText), null, 2);
        } catch {
          /* not JSON — keep raw */
        }
        const prefix = result.status >= 400 ? `HTTP ${result.status} error\n` : '';
        return { content: [{ type: 'text' as const, text: `${prefix}${contentText}` }] };
      } catch (err) {
        return { content: [{ type: 'text' as const, text: `Request failed: ${(err as Error).message}` }], isError: true };
      }
    });
  }
}

/** Production-safe server: OpenAPI operations only (no direct DB access). */
export function createProdServer(tools: GeneratedTool[]): McpServer {
  const server = new McpServer(SERVER_INFO);
  registerApiTools(server, tools);
  return server;
}

/** Extended debug server: API tools + diagnostics (read-only SQL, plugin probes). */
export function createDebugServer(tools: GeneratedTool[], debugTools: DebugTool[]): McpServer {
  const server = new McpServer({ ...SERVER_INFO, name: 'unified-network-manager-debug' });
  registerApiTools(server, tools);
  for (const tool of debugTools) {
    server.tool(tool.name, tool.description, tool.inputSchema, tool.handler);
  }
  return server;
}
