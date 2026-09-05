/**
 * Transport layer for the generic Docker monitoring plugin.
 *
 * Talks to the Docker Engine REST API (https://docs.docker.com/engine/api/)
 * over one of three transports, chosen per device via the `transport` option:
 *   - tcp    → http://<host>:<port>          (unauthenticated TCP, trusted LANs)
 *   - tls    → https://<host>:2376           (client-cert TLS; CA/cert/key come
 *                                             from a bound `dockerTls` secret slot)
 *   - socket → unix:///var/run/docker.sock   (daemon on the UNM host itself;
 *                                             the socket is mounted into this container)
 *   - auto   → try tcp first, then tls when a dockerTls slot is bound.
 *
 * The SDK provides no outbound-HTTP helper (its apiClient only talks back to
 * the UNM API), so — like plugins/opnsense/src/client/http.ts — we build our
 * own axios instance per transport and surface non-2xx as { ok:false } results
 * instead of throwing.
 */

import axios, { AxiosInstance } from 'axios';
import http from 'http';
import https from 'https';

/** Transport choice owned by this plugin via its `transport` option. */
export type DockerTransport = 'auto' | 'tcp' | 'tls' | 'socket';

/** TLS material from a bound `dockerTls` secret slot (PEM strings). */
export interface DockerTlsMaterial {
  ca?: string;
  cert?: string;
  key?: string;
}

export interface DockerClientOptions {
  /** Device management address — bare host or host:port. */
  host: string;
  transport: DockerTransport;
  /** TCP port (default 2375). TLS uses 2376 unless the host already carries a port. */
  tcpPort?: number;
  tlsPort?: number;
  /** Unix socket path for `socket` transport (inside THIS container). */
  localSocketPath?: string;
  tls?: DockerTlsMaterial | undefined;
  timeoutMs?: number;
}

export interface DockerApiResult<T = unknown> {
  ok: boolean;
  status: number;
  data: T;
  /** Transport actually used (useful for health detail in auto mode). */
  transportUsed?: 'tcp' | 'tls' | 'socket';
  error?: string;
}

const DEFAULT_TIMEOUT_MS = 8_000; // the API gives the whole poll a hard 10 s budget

/** Splits `host` into { host, port? } — tolerates bare hosts and explicit ports. */
function splitHostPort(host: string): { host: string; port?: number } {
  const h = (host ?? '').trim().replace(/\/+$/, '');
  if (!h) return { host: '' };
  // Strip a scheme if the user pasted one in.
  const bare = h.replace(/^https?:\/\//i, '');
  const lastColon = bare.lastIndexOf(':');
  const slashAfterColon = bare.indexOf('/', lastColon);
  if (lastColon > -1 && (slashAfterColon === -1 || lastColon < slashAfterColon)) {
    const maybePort = Number(bare.slice(lastColon + 1));
    if (Number.isInteger(maybePort) && maybePort > 0 && maybePort < 65536) {
      return { host: bare.slice(0, lastColon), port: maybePort };
    }
  }
  return { host: bare };
}

/** Builds the https.Agent for TLS transport from PEM material. */
function buildTlsAgent(tls: DockerTlsMaterial): https.Agent {
  const opts: https.AgentOptions = {};
  if (tls.ca) opts.ca = tls.ca;
  if (tls.cert) opts.cert = tls.cert;
  if (tls.key) opts.key = tls.key;
  // No rejectUnauthorized:false — a Docker TLS endpoint that fails verification
  // is a real misconfiguration we want surfaced, not silently accepted.
  return new https.Agent(opts);
}

/** One bound client for one transport. */
interface BoundClient {
  kind: 'tcp' | 'tls' | 'socket';
  axios?: AxiosInstance;
  socketPath?: string;
}

function buildBound(o: DockerClientOptions): BoundClient {
  const { host, port } = splitHostPort(o.host);
  if (!host) throw new Error('No target address — set the device management address.');

  switch (o.transport) {
    case 'socket': {
      const p = o.localSocketPath || '/var/run/docker.sock';
      return { kind: 'socket', socketPath: p };
    }
    case 'tls': {
      if (!o.tls?.ca && !o.tls?.cert) throw new Error('TLS transport selected but no dockerTls secret is bound to this device.');
      const tlsPort = port ?? o.tlsPort ?? 2376;
      return {
        kind: 'tls',
        axios: axios.create({
          baseURL: `https://${host}:${tlsPort}`,
          timeout: o.timeoutMs ?? DEFAULT_TIMEOUT_MS,
          validateStatus: () => true,
          httpsAgent: buildTlsAgent(o.tls ?? {}),
        }),
      };
    }
    case 'tcp':
    default: {
      const tcpPort = port ?? o.tcpPort ?? 2375;
      return {
        kind: 'tcp',
        axios: axios.create({
          baseURL: `http://${host}:${tcpPort}`,
          timeout: o.timeoutMs ?? DEFAULT_TIMEOUT_MS,
          validateStatus: () => true,
        }),
      };
    }
  }
}

/** Executes one GET against the Docker Engine API. Never throws for HTTP-level failures. */
async function get<T>(bound: BoundClient, path: string): Promise<DockerApiResult<T>> {
  try {
    if (bound.kind === 'socket') {
      // Unix-socket request via raw node http — keeps the plugin dependency-light
      // (no axios adapter package needed).
      const data = await new Promise<string>((resolve, reject) => {
        const req = http.request(
          { socketPath: bound.socketPath!, path, method: 'GET', timeout: DEFAULT_TIMEOUT_MS },
          (res) => {
            let body = '';
            res.on('data', (c) => (body += c));
            res.on('end', () => resolve(JSON.stringify({ status: res.statusCode ?? 0, body })));
          }
        );
        req.on('timeout', () => req.destroy(new Error(`socket request timed out after ${DEFAULT_TIMEOUT_MS} ms`)));
        req.on('error', reject);
        req.end();
      });
      const parsed = JSON.parse(data) as { status: number; body: string };
      let json: T;
      try {
        json = (parsed.body ? JSON.parse(parsed.body) : {}) as T;
      } catch {
        return { ok: false, status: parsed.status, data: undefined as unknown as T, transportUsed: 'socket', error: `non-JSON response from socket (${parsed.status})` };
      }
      return { ok: parsed.status >= 200 && parsed.status < 300, status: parsed.status, data: json, transportUsed: 'socket' };
    }

    const res = await bound.axios!.get<T>(path);
    return {
      ok: res.status >= 200 && res.status < 300,
      status: res.status,
      data: res.data as T,
      transportUsed: bound.kind === 'tls' ? 'tls' : 'tcp',
    };
  } catch (err) {
    return {
      ok: false,
      status: 0,
      data: undefined as unknown as T,
      transportUsed: bound.kind === 'tls' ? 'tls' : bound.kind === 'socket' ? 'socket' : 'tcp',
      error: err instanceof Error ? err.message : String(err),
    };
  }
}

/**
 * Runs one GET across the transports implied by `transport` (auto = tcp, then
 * tls when material is available) and returns the first success. Connection-
 * level failures on one transport fall through to the next; an HTTP error from
 * a reachable daemon is authoritative (no fallback — the daemon answered).
 */
export async function dockerGet<T>(o: DockerClientOptions, path: string): Promise<DockerApiResult<T>> {
  const attempts: BoundClient[] = [];
  if (o.transport === 'auto') {
    try {
      attempts.push(buildBound({ ...o, transport: 'tcp' }));
    } catch { /* no host — handled below */ }
    if (o.tls?.ca || o.tls?.cert) {
      try {
        attempts.push(buildBound({ ...o, transport: 'tls' }));
      } catch { /* missing material — skip tls leg */ }
    }
  } else {
    attempts.push(buildBound(o));
  }

  if (attempts.length === 0) return { ok: false, status: 0, data: undefined as unknown as T, error: 'No target address — set the device management address.' };

  let last: DockerApiResult<T> | null = null;
  for (const bound of attempts) {
    const r = await get<T>(bound, path);
    if (r.ok) return r;
    // A reachable daemon that answered with an HTTP error is authoritative.
    if (r.status >= 400 && r.status < 600) return r;
    last = r; // connection-level failure — try the next transport
  }
  return last ?? { ok: false, status: 0, data: undefined as unknown as T, error: 'no transports attempted' };
}

/** GET /containers/json?all=true — the full container list with network + mount detail. */
export function listContainers(o: DockerClientOptions): Promise<DockerApiResult<unknown[]>> {
  return dockerGet<unknown[]>(o, '/containers/json?all=true&limit=500');
}

/** GET /version — daemon version info (used for the device overview + health detail). */
export function engineVersion(o: DockerClientOptions): Promise<DockerApiResult<{ Version?: string; ApiVersion?: string; Os?: string; Arch?: string }>> {
  return dockerGet<{ Version?: string; ApiVersion?: string; Os?: string; Arch?: string }>(o, '/version');
}
