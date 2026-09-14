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
import type { DeviceApiResult } from '@unm/plugin-sdk';

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

/**
 * Result of one Docker Engine API call — the SDK's canonical device-API envelope
 * with `data` always present (the transport fills it even on failure) plus the
 * transport actually used in auto mode.
 */
export interface DockerApiResult<T = unknown> extends DeviceApiResult<T> {
  data: T;
  /** Transport actually used (useful for health detail in auto mode). */
  transportUsed?: 'tcp' | 'tls' | 'socket';
}

const DEFAULT_TIMEOUT_MS = 8_000; // the API gives the whole poll a hard 10 s budget

/** Timeout for mutating action calls (start/stop/restart/delete). Docker's
 * default stop grace period is 10 s — `docker stop` blocks until it elapses or
 * the container exits, so these need a longer budget than reads. The config-job
 * worker has no hard per-call deadline like /monitoring does. */
const ACTION_TIMEOUT_MS = 35_000;

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

/** HTTP verbs the Engine API needs. GET = reads; POST/DELETE = actions + image removal. */
export type DockerMethod = 'GET' | 'POST' | 'DELETE';

/** Executes one request against the Docker Engine API. Never throws for HTTP-level failures. */
async function request<T>(bound: BoundClient, method: DockerMethod, path: string, body?: unknown, timeoutMs = DEFAULT_TIMEOUT_MS): Promise<DockerApiResult<T>> {
  try {
    if (bound.kind === 'socket') {
      // Unix-socket request via raw node http — keeps the plugin dependency-light
      // (no axios adapter package needed).
      const payload = body !== undefined ? JSON.stringify(body) : null;
      const data = await new Promise<string>((resolve, reject) => {
        const req = http.request(
          { socketPath: bound.socketPath!, path, method, timeout: timeoutMs },
          (res) => {
            let bodyText = '';
            res.on('data', (c) => (bodyText += c));
            res.on('end', () => resolve(JSON.stringify({ status: res.statusCode ?? 0, body: bodyText })));
          }
        );
        req.on('timeout', () => req.destroy(new Error(`socket request timed out after ${timeoutMs} ms`)));
        req.on('error', reject);
        if (payload !== null) {
          req.setHeader('Content-Type', 'application/json');
          req.setHeader('Content-Length', Buffer.byteLength(payload));
          req.write(payload);
        }
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

    const res = await bound.axios!.request<T>({ method, url: path, timeout: timeoutMs, ...(body !== undefined ? { data: body } : {}) });
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
 * Runs one request across the transports implied by `transport` (auto = tcp,
 * then tls when material is available) and returns the first success.
 * Connection-level failures on one transport fall through to the next; an HTTP
 * error from a reachable daemon is authoritative (no fallback — it answered).
 */
export async function dockerRequest<T>(o: DockerClientOptions, method: DockerMethod, path: string, body?: unknown, timeoutMs = DEFAULT_TIMEOUT_MS): Promise<DockerApiResult<T>> {
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
    const r = await request<T>(bound, method, path, body, timeoutMs);
    if (r.ok) return r;
    // A reachable daemon that answered with an HTTP error is authoritative.
    if (r.status >= 400 && r.status < 600) return r;
    last = r; // connection-level failure — try the next transport
  }
  return last ?? { ok: false, status: 0, data: undefined as unknown as T, error: 'no transports attempted' };
}

/** GET convenience wrapper over dockerRequest. */
export function dockerGet<T>(o: DockerClientOptions, path: string): Promise<DockerApiResult<T>> {
  return dockerRequest<T>(o, 'GET', path);
}

/**
 * POST convenience wrapper (container start/stop/restart). Uses the LONGER
 * action timeout — `docker stop`/`restart` block for up to Docker's default
 * 10 s graceful-stop period before force-killing, so the read budget is too short.
 */
export function dockerPost<T = unknown>(o: DockerClientOptions, path: string): Promise<DockerApiResult<T>> {
  return dockerRequest<T>(o, 'POST', path, undefined, ACTION_TIMEOUT_MS);
}

/** DELETE convenience wrapper (container removal, image removal). Same longer action budget. */
export function dockerDelete<T = unknown>(o: DockerClientOptions, path: string): Promise<DockerApiResult<T>> {
  return dockerRequest<T>(o, 'DELETE', path, undefined, ACTION_TIMEOUT_MS);
}

/** GET /containers/json?all=true — the full container list with network + mount detail. */
export function listContainers(o: DockerClientOptions): Promise<DockerApiResult<unknown[]>> {
  return dockerGet<unknown[]>(o, '/containers/json?all=true&limit=500');
}

/** GET /images/json — the local image inventory (tags, sizes, dangling flag). */
export function listImages(o: DockerClientOptions): Promise<DockerApiResult<unknown[]>> {
  return dockerGet<unknown[]>(o, '/images/json?all=true');
}

/** GET /version — daemon version info (used for the device overview + health detail). */
export function engineVersion(o: DockerClientOptions): Promise<DockerApiResult<{ Version?: string; ApiVersion?: string; Os?: string; Arch?: string }>> {
  return dockerGet<{ Version?: string; ApiVersion?: string; Os?: string; Arch?: string }>(o, '/version');
}

/** GET /containers/{id}/stats?stream=false — one non-streaming stats sample. */
export function containerStats(o: DockerClientOptions, idOrName: string): Promise<DockerApiResult<Record<string, unknown>>> {
  return dockerGet<Record<string, unknown>>(o, `/containers/${encodeURIComponent(idOrName)}/stats?stream=false`);
}

/** GET /containers/json filtered by a compose project label — member resolution. */
export function listComposeMembers(o: DockerClientOptions, project: string): Promise<DockerApiResult<unknown[]>> {
  return dockerGet<unknown[]>(o, `/containers/json?all=true&filters=${encodeURIComponent(JSON.stringify({ label: [`com.docker.compose.project=${project}`] }))}`);
}

/**
 * GET /containers/{id}/logs — RAW byte stream (NOT JSON). With both stdout and
 * stderr requested the Engine returns multiplexed frames (8-byte header +
 * payload per line); with a single stream it's plain text. Returns the raw body
 * so the caller can demux (see demuxDockerLogs in actions.ts). Longer budget —
 * tailing large logs from a remote daemon can take a while.
 */
export async function containerLogsRaw(o: DockerClientOptions, idOrName: string, opts: { tail?: number; sinceSeconds?: number } = {}): Promise<DockerApiResult<Buffer>> {
  const q = new URLSearchParams();
  q.set('stdout', '1');
  q.set('stderr', '1');
  if (typeof opts.tail === 'number' && Number.isFinite(opts.tail)) q.set('tail', String(Math.max(1, Math.floor(opts.tail))));
  else q.set('all', '0'); // bounded by default — the caller passes tail explicitly
  if (typeof opts.sinceSeconds === 'number') q.set('since', String(Math.max(0, Math.floor(opts.sinceSeconds))));
  const path = `/containers/${encodeURIComponent(idOrName)}/logs?${q.toString()}`;

  // Build the transport list exactly like dockerRequest does.
  const attempts: BoundClient[] = [];
  if (o.transport === 'auto') {
    try { attempts.push(buildBound({ ...o, transport: 'tcp' })); } catch { /* no host */ }
    if (o.tls?.ca || o.tls?.cert) {
      try { attempts.push(buildBound({ ...o, transport: 'tls' })); } catch { /* missing material */ }
    }
  } else {
    attempts.push(buildBound(o));
  }
  if (attempts.length === 0) return { ok: false, status: 0, data: Buffer.alloc(0), error: 'No target address — set the device management address.' };

  const timeoutMs = 30_000;
  let last: DockerApiResult<Buffer> | null = null;
  for (const bound of attempts) {
    try {
      if (bound.kind === 'socket') {
        const { status, body } = await new Promise<{ status: number; body: Buffer }>((resolve, reject) => {
          const req = http.request({ socketPath: bound.socketPath!, path, method: 'GET', timeout: timeoutMs }, (res) => {
            const chunks: Buffer[] = [];
            res.on('data', (c: Buffer) => chunks.push(c));
            res.on('end', () => resolve({ status: res.statusCode ?? 0, body: Buffer.concat(chunks) }));
          });
          req.on('timeout', () => req.destroy(new Error(`socket request timed out after ${timeoutMs} ms`)));
          req.on('error', reject);
          req.end();
        });
        if (status >= 200 && status < 300) return { ok: true, status, data: body, transportUsed: 'socket' };
        // Daemon error bodies are JSON ({message}) — surface the message.
        let msg = `HTTP ${status}`;
        try { const j = JSON.parse(body.toString('utf8')); if (j && typeof j.message === 'string') msg = j.message; } catch { /* not JSON */ }
        return { ok: false, status, data: Buffer.alloc(0), transportUsed: 'socket', error: msg };
      }
      const res = await bound.axios!.request<Buffer>({ method: 'GET', url: path, timeout: timeoutMs, responseType: 'arraybuffer' });
      if (res.status >= 200 && res.status < 300) {
        return { ok: true, status: res.status, data: Buffer.isBuffer(res.data) ? res.data : Buffer.from(res.data as ArrayBuffer), transportUsed: bound.kind === 'tls' ? 'tls' : 'tcp' };
      }
      // A reachable daemon that answered with an HTTP error is authoritative.
      if (res.status >= 400 && res.status < 600) {
        return { ok: false, status: res.status, data: Buffer.alloc(0), transportUsed: bound.kind === 'tls' ? 'tls' : 'tcp', error: `HTTP ${res.status}` };
      }
    } catch (err) {
      last = { ok: false, status: 0, data: Buffer.alloc(0), transportUsed: bound.kind === 'tls' ? 'tls' : 'socket', error: err instanceof Error ? err.message : String(err) };
    }
  }
  return last ?? { ok: false, status: 0, data: Buffer.alloc(0), error: 'no transports attempted' };
}
