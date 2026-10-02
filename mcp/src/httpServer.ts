import http from 'node:http';
import express from 'express';
import type { NextFunction, Request, Response } from 'express';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { renewMtls } from './mcpMtls.js';

export interface HttpMcpOptions {
  port: number;
  /** Factory for the production-safe server (OpenAPI tools only). */
  createProdServer: () => McpServer;
  /** Factory for the extended debug server (API + diagnostic tools). */
  createDebugServer: () => McpServer;
  /** Bearer key required on /debug/mcp. Enforced when set. */
  debugKey?: string;
  /** Optional bearer key that also gates the plain /mcp endpoint. */
  mcpKey?: string;
}

function bearerToken(req: Request): string | null {
  const header = req.headers.authorization;
  if (!header) return null;
  const match = /^Bearer\s+(.+)$/i.exec(header);
  return match ? match[1].trim() : null;
}

/**
 * Serves the MCP protocol over Streamable HTTP on two endpoints:
 *   POST /mcp        — production-safe (OpenAPI tools only)
 *   POST /debug/mcp  — extended debug (read-only SQL + plugin probes), keyed by MCP_DEBUG_KEY
 *
 * Stateless mode: a fresh server + transport per request, no session ids
 * (sessionIdGenerator: undefined) — every POST is independent, so the
 * container needs no session persistence.
 */
export function startHttpServer(opts: HttpMcpOptions): http.Server {
  const app = express();
  app.use(express.json());

  app.get('/healthz', (_req, res) => {
    res.status(200).json({ status: 'ok', endpoints: ['/mcp', '/debug/mcp'] });
  });

  // POST /tls/renew - force a fresh ACME enrollment for the MCP's own mTLS
  // identity (new leaf, same account) + rebuild the outbound dispatcher. The
  // API brokers this from its Plugins page (POST /plugins/:id/tls/renew).
  // Gated by the debug key — it's an operational action, not a data endpoint.
  app.post('/tls/renew', async (req: Request, res: Response) => {
    const key = bearerToken(req);
    if (!opts.debugKey || key !== opts.debugKey) {
      res.status(401).json({ error: 'unauthorized — /tls/renew requires the MCP_DEBUG_KEY bearer token' });
      return;
    }
    try {
      const result = await renewMtls();
      res.status(result.ok ? 200 : 502).json(result);
    } catch (err) {
      if (!res.headersSent) res.status(500).json({ ok: false, error: (err as Error).message });
    }
  });

  async function serveMcp(req: Request, res: Response, createServer: () => McpServer): Promise<void> {
    const server = createServer();
    const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
    await server.connect(transport);
    try {
      await transport.handleRequest(req, res, req.body);
    } finally {
      // Stateless — the request is done; release the per-request server.
      await server.close().catch(() => undefined);
    }
  }

  app.post('/mcp', (req, res) => {
    if (opts.mcpKey && bearerToken(req) !== opts.mcpKey) {
      res.status(401).json({ error: 'unauthorized — set the MCP_KEY bearer token' });
      return;
    }
    serveMcp(req, res, opts.createProdServer).catch((err) => {
      if (!res.headersSent) res.status(500).json({ error: (err as Error).message });
    });
  });

  app.post('/debug/mcp', (req, res) => {
    const key = bearerToken(req);
    if (!opts.debugKey || key !== opts.debugKey) {
      res.status(401).json({ error: 'unauthorized — /debug/mcp requires the MCP_DEBUG_KEY bearer token' });
      return;
    }
    serveMcp(req, res, opts.createDebugServer).catch((err) => {
      if (!res.headersSent) res.status(500).json({ error: (err as Error).message });
    });
  });

  // Malformed JSON bodies from clients → clean JSON-RPC parse error instead of an HTML stack trace.
  app.use((err: Error, _req: Request, res: Response, _next: NextFunction) => {
    if (res.headersSent) return;
    res.status(400).json({ jsonrpc: '2.0', id: null, error: { code: -32700, message: `Parse error: ${err.message}` } });
  });

  const server = app.listen(opts.port, () => {
    // Diagnostics to stderr — stdout is reserved for stdio mode.
    console.error(`[unm-mcp] HTTP MCP listening on :${opts.port} (POST /mcp, POST /debug/mcp)`);
  });
  return server;
}
