/**
 * Resolves a plugin endpoint to a URL the API can actually reach.
 *
 * Plugins advertise their endpoint using the Docker service name (e.g.
 * `http://opnsense-plugin:4001`) so the API *container* can reach them over the
 * compose network. But when the API runs on the HOST (the `setup.sh` dev
 * workflow — `ts-node-dev`), that service name does not resolve, and the
 * telemetry worker fails and marks devices `unknown`.
 *
 * The plugins publish their ports to the host (4001/4002/4003), so when the
 * API is running outside Docker we rewrite the service host to `localhost`.
 * When the API runs inside a container the service name is left untouched.
 *
 * This is the single source of truth for "how do I reach a plugin" — every
 * call site (telemetry, config jobs, auth, secrets) goes through it.
 */

// Docker service name -> host-published port (from docker-compose.yml).
const SERVICE_HOST_PORTS: Record<string, number> = {
  'opnsense-plugin': 4001,
  'basic-auth-plugin': 4002,
  'secrets-provider-plugin': 4003,
  'icmp-plugin': 4004,
  'snmp-plugin': 4005,
  'lancom-lx-plugin': 4006,
  'swos-plugin': 4007,
  'lancom-lcos-plugin': 4008,
  'lancom-sx-plugin': 4009,
};

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
 * host and the endpoint uses a known Docker service name. Otherwise returns
 * the endpoint unchanged.
 */
export function resolvePluginEndpoint(endpoint: string): string {
  if (!endpoint) return endpoint;
  if (!isHostRuntime()) return endpoint;
  try {
    const url = new URL(endpoint);
    const port = SERVICE_HOST_PORTS[url.hostname];
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
