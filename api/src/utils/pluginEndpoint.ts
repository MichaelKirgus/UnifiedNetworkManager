/**
 * Resolves a plugin endpoint to a URL the API can actually reach.
 *
 * Plugins advertise their endpoint using the Docker service name (e.g.
 * `http://opnsense-plugin:4080`) so the API *container* can reach them over the
 * compose network. But when the API runs on the HOST (the `setup.sh` dev
 * workflow — `ts-node-dev`), that service name does not resolve, and the
 * telemetry worker fails and marks devices `unknown`.
 *
 * The plugins publish their ports to the host for curl-from-host debugging, so
 * when the API is running outside Docker we rewrite the service host to
 * `localhost:<published port>`. When the API runs inside a container the
 * service name is left untouched.
 *
 * This is the single source of truth for "how do I reach a plugin" — every
 * call site (telemetry, config jobs, auth, secrets) goes through it.
 *
 * NO plugin catalog lives in this file: the service-name → host-port mapping is
 * read from the `PLUGIN_HOST_PORT_MAP` env var (`name:port,name:port,…`). The
 * dev bootstrap (setup.sh) builds that string from docker-compose.yml at start
 * time, so adding a third-party plugin never requires touching UNM code. With
 * the variable unset there is no rewrite — container deployments are
 * unaffected either way.
 */

/** Parses `name:port,name:port,…` into a lookup map (malformed entries dropped). */
function parseHostPortMap(raw: string | undefined): Record<string, number> {
  const out: Record<string, number> = {};
  for (const entry of (raw ?? '').split(',')) {
    const trimmed = entry.trim();
    if (!trimmed) continue;
    const idx = trimmed.lastIndexOf(':');
    if (idx <= 0) continue;
    const name = trimmed.slice(0, idx).trim();
    const port = Number(trimmed.slice(idx + 1));
    if (name && Number.isInteger(port) && port > 0 && port < 65536) out[name] = port;
  }
  return out;
}

/** True when the API is running on the host (not inside a Docker container). */
function isHostRuntime(): boolean {
  // The Docker API container sets NODE_ENV=production and runs as root with a
  // /app working dir. The host dev server (ts-node-dev) runs as the user.
  // The most reliable signal: the host dev workflow sets DEV_HOST=1, or we
  // detect the absence of the container's /app path.
  if (process.env.DEV_HOST === '1') return true;
  if (process.env.NODE_ENV === 'production') return false;
  // Fallback: containers run from /app; host dev runs from the repo's api/.
  try {
    return !process.cwd().startsWith('/app');
  } catch {
    return false;
  }
}

/**
 * Rewrites a plugin endpoint's host to `localhost` when the API is on the
 * host and the endpoint uses a service name present in PLUGIN_HOST_PORT_MAP.
 * Otherwise returns the endpoint unchanged.
 */
export function resolvePluginEndpoint(endpoint: string): string {
  if (!endpoint) return endpoint;
  if (!isHostRuntime()) return endpoint;
  try {
    const url = new URL(endpoint);
    const port = parseHostPortMap(process.env.PLUGIN_HOST_PORT_MAP)[url.hostname];
    if (port) {
      url.hostname = 'localhost';
      url.port = String(port);
      return url.toString().replace(/\/$/, '');
    }
    return endpoint;
  } catch {
    return endpoint;
  }
}
