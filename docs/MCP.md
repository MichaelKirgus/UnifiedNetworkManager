# MCP server (AI agent access)

The `mcp/` service exposes the UNM API to AI agents via the [Model Context Protocol](https://modelcontextprotocol.io). It reads the OpenAPI spec at startup and turns every operation into a tool — new API endpoints appear automatically. The container serves two Streamable-HTTP endpoints on port **3901**:

| Endpoint | Purpose |
|----------|---------|
| `POST /mcp` | Production-safe: OpenAPI operations only. What an agent can do is controlled entirely by the permissions of its API token — create a scoped token (e.g. read-only) on the **Tokens** page and pass it as `UNM_API_TOKEN`. |
| `POST /debug/mcp` | Extended debug for diagnosing UNM itself: adds `query_database` (single read-only SELECT/WITH statement, max 200 rows) and `plugin_probe` (live `/healthz` + `/discover` of every plugin endpoint). Requires `Authorization: Bearer <MCP_DEBUG_KEY>`. |

**Environment variables:**

| Variable | Effect |
|----------|--------|
| `UNM_API_TOKEN` | Long-lived API token for the OpenAPI tools — **required**. Create it on the Tokens page (or `POST /v1/tokens`). |
| `UNM_API_BASE` | Base URL of the API. Defaults to `http://localhost:3000/v1`; the container uses `http://api:3000/v1`. |
| `MCP_DEBUG_KEY` | Bearer key gating `/debug/mcp` (default in compose: `dev-mcp-debug-key`). |
| `MCP_KEY` | Optional — when set, also gates the plain `/mcp` endpoint. |
| `DATABASE_URL` | Postgres connection used by the debug SQL tool only (same DB as the API; rendered from the same `POSTGRES_*` vars in compose). |

> **Privileged actions stay human.** Operations marked `x-2fa-required` in the spec (plan *execution*, retry, bulk-execute) are excluded from the MCP tool set — they need a 2FA-completed session. Plan *creation* is included: agents stage plans with `post_plans` / `post_plans_system`, humans execute them (or grant `token` in that user's `gateAmrs` on the Credential Policies page to let token sessions pass the gate).

**VS Code MCP client config** (remote/HTTP transport):

```jsonc
{
  "mcpServers": {
    "unm": {
      "url": "http://localhost:3901/mcp"
    },
    "unm-debug": {
      "url": "http://localhost:3901/debug/mcp",
      "headers": { "Authorization": "Bearer dev-mcp-debug-key" }
    }
  }
}
```

The same server also runs in **stdio mode** without Docker (client-launched, production-safe tools only): `node mcp/dist/index.js` with `UNM_API_TOKEN` set — no `MCP_PORT` needed.

> The MCP service is **not published to the host by default** in `docker-compose.yml` — it carries an API token with full agent capabilities. Expose it deliberately (e.g. `UNM_MCP_PORT=8081`) behind auth or a reverse proxy; see [DEPLOYMENT.md](DEPLOYMENT.md).
