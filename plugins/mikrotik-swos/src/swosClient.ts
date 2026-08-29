/**
 * SwOS / SwOS Lite HTTP transport + wire codec.
 *
 * Re-implements (in TypeScript, without using the python-mikrotik-swos module)
 * the protocol described in that project's SWOS_API.md:
 *  - Plain HTTP with **Digest authentication** (MD5). Node's global fetch has
 *    no digest support, so the challenge/response dance is implemented here.
 *  - Endpoints are `.b` files returning JavaScript-object notation with hex
 *    values: `{i01:0x03ff,i0a:['506f727431'],...}` (SwOS Lite) or
 *    `{en:1023,nm:['506f727431'],...}` (SwOS — descriptive field names).
 *  - Writes are POSTs with `Content-Type: text/plain` of the SAME notation,
 *    using ONLY writable fields; per-port settings must send complete arrays.
 *
 * Wire-format rules that break naive implementations (all enforced here):
 *  - Scalars/bitmasks need EVEN-length hex (`0x03ff`, never `0x3ff`).
 *  - Array integers use fixed 2-digit hex (`0x02`, never `0x0002`).
 *  - Strings are ASCII encoded as hex pairs inside single quotes.
 *  - IP addresses are LITTLE-ENDIAN (192.168.88.1 → 0x0158a8c0).
 */

import http from 'http';
import https from 'https';
import { URL } from 'url';
import { createHash } from 'crypto';

// --- Wire codec -----------------------------------------------------------------

/** A parsed SwOS value: number, hex string, or array of either. */
export type SwosScalar = number | string;
export type SwosArray = SwosScalar[];
/** Parsed response body — object (most endpoints) or array of objects (vlan.b). */
export type SwosData = Record<string, unknown> | unknown[];

function md5(input: string): string {
  return createHash('md5').update(input, 'utf8').digest('hex');
}

/** Decode a hex-encoded ASCII string ('506f727431' → 'Port1'). */
export function decodeHexString(hex: unknown): string {
  if (typeof hex !== 'string') return '';
  const clean = hex.trim();
  if (!/^[0-9a-fA-F]*$/.test(clean) || clean.length % 2 !== 0) return typeof hex === 'string' ? hex : '';
  try {
    return Buffer.from(clean, 'hex').toString('latin1');
  } catch {
    return String(hex);
  }
}

/** Encode an ASCII string to the wire hex form ('Port1' → '506f727431'). */
export function encodeHexString(text: string): string {
  // SwOS strings are ASCII; latin1 keeps arbitrary bytes intact.
  return Buffer.from(text, 'latin1').toString('hex');
}

/** Decode a hex MAC ('48a98a1954b4' → '48:a9:8a:19:54:b4'). Passes through anything else. */
export function decodeMac(hex: unknown): string {
  if (typeof hex !== 'string') return '';
  const clean = hex.trim().toLowerCase();
  if (/^[0-9a-f]{12}$/.test(clean)) {
    return clean.replace(/([0-9a-f]{2})(?=[0-9a-f])/g, '$1:').slice(0, 17);
  }
  // Already colon-formatted (or unexpected) — normalize separators.
  if (/^([0-9a-f]{2}[:-]){5}[0-9a-f]{2}$/.test(clean)) return clean.replace(/-/g, ':');
  return String(hex ?? '');
}

/** Decode a little-endian IP integer (SwOS byte order: first octet in the LSB). */
export function decodeIpLe(value: unknown): string {
  const n = typeof value === 'number' ? Math.max(0, Math.floor(value)) : Number(value);
  if (!Number.isFinite(n) || n <= 0) return '';
  return `${n & 0xff}.${(n >> 8) & 0xff}.${(n >> 16) & 0xff}.${(n >> 24) & 0xff}`;
}

/** Encode an IPv4 address to the little-endian integer SwOS expects. */
export function encodeIpLe(ip: string): number {
  const parts = ip.trim().split('.');
  if (parts.length !== 4) throw new Error(`Invalid IP address: ${ip}`);
  let value = 0;
  for (let i = 0; i < 4; i++) {
    const octet = Number(parts[i]);
    if (!Number.isInteger(octet) || octet < 0 || octet > 255) throw new Error(`Invalid IP address: ${ip}`);
    value |= octet << (8 * i); // little-endian: first octet in the low byte
  }
  return value;
}

/** Port bitmask → list of 1-based port numbers. */
export function decodePortMask(mask: unknown, numPorts: number): number[] {
  const m = typeof mask === 'number' ? Math.max(0, Math.floor(mask)) : Number(mask) || 0;
  const ports: number[] = [];
  // Arithmetic bit test — JS bitwise ops wrap at 32 bits and would misreport
  // ports > 32 (e.g. a 64-port mask).
  for (let i = 0; i < numPorts; i++) if (Math.floor(m / 2 ** i) % 2 === 1) ports.push(i + 1);
  return ports;
}

/** List of 1-based port numbers → bitmask. */
export function encodePortMask(portNumbers: number[], maxPorts?: number): number {
  let mask = 0;
  for (const p of portNumbers) {
    if (!Number.isInteger(p) || p < 1) throw new Error(`Invalid port number: ${p}`);
    if (maxPorts !== undefined && p > maxPorts) throw new Error(`Port ${p} exceeds the switch's ${maxPorts} ports`);
    mask |= 1 << (p - 1);
  }
  return mask;
}

/** Even-length hex for scalars/bitmasks: 0 → '0x00', 255 → '0x00ff', 1023 → '0x03ff'. */
function formatHexScalar(value: number): string {
  let h = Math.max(0, Math.floor(value)).toString(16);
  if (h.length % 2 !== 0) h = `0${h}`;
  return `0x${h}`;
}

/** Format one value for a POST body: arrays use 2-digit hex ints, scalars even-length. */
export function formatPostValue(value: SwosScalar | SwosArray): string {
  if (Array.isArray(value)) {
    const items = value.map((v) => (typeof v === 'number' ? `0x${Math.max(0, Math.floor(v)).toString(16).padStart(2, '0')}` : `'${v}'`));
    return `[${items.join(',')}]`;
  }
  if (typeof value === 'number') return formatHexScalar(value);
  return `'${value}'`;
}

/** Build a POST body from an object of fields: `{i01:0x03ff,i0a:['506f727431']}`. */
export function buildPostData(fields: Record<string, SwosScalar | SwosArray>): string {
  const pairs = Object.entries(fields).map(([k, v]) => `${k}:${formatPostValue(v)}`);
  return `{${pairs.join(',')}}`;
}

/** Build a POST body for an array of objects (VLAN table): `[{...},{...}]`. */
export function buildPostArray(objects: Record<string, SwosScalar | SwosArray>[]): string {
  const objs = objects.map((o) => `{${Object.entries(o).map(([k, v]) => `${k}:${formatPostValue(v)}`).join(',')}}`);
  return `[${objs.join(',')}]`;
}

/**
 * Parse the JS-object notation responses. Mirrors the reference parser:
 * hex numbers → decimal, single quotes → double, bare keys quoted — then JSON.parse.
 * Safe because quoted values are pure [0-9a-f] (no colons, no literal 'x'), so
 * neither substitution can touch string contents.
 */
export function parseSwos(text: string): SwosData {
  let t = text.trim();
  if (!t) throw new Error('Empty response body');
  t = t.replace(/0x([0-9a-fA-F]+)/g, (_m, h: string) => String(parseInt(h, 16)));
  t = t.replace(/'/g, '"');
  t = t.replace(/([a-zA-Z_][a-zA-Z0-9_]*):/g, '"$1":');
  try {
    return JSON.parse(t) as SwosData;
  } catch (err) {
    throw new Error(`Unparseable SwOS response: ${(err as Error).message}`);
  }
}

// --- Digest-authenticated HTTP client ---------------------------------------------

export interface SwosCredentials {
  username: string;
  password: string;
}

/** Raised when the switch rejects our credentials (401 after a full digest exchange). */
export class SwosAuthError extends Error {
  constructor(message = 'SwOS authentication failed — check the assigned username/password secret') {
    super(message);
    this.name = 'SwosAuthError';
  }
}

interface DigestChallenge {
  realm: string;
  nonce: string;
  opaque?: string;
  qop?: string[]; // e.g. ['auth'] or ['auth', 'auth-int']
  algorithm?: string;
}

function parseDigestChallenge(header: string): DigestChallenge | null {
  const params = new Map<string, string>();
  // Strip the "Digest" scheme prefix first — otherwise the first parameter is
  // parsed as key "digest realm" and the challenge looks malformed.
  for (const part of header.replace(/^Digest\s+/i, '').split(',')) {
    const eq = part.indexOf('=');
    if (eq < 0) continue;
    const key = part.slice(0, eq).trim().toLowerCase();
    let val = part.slice(eq + 1).trim();
    if (val.startsWith('"') && val.endsWith('"')) val = val.slice(1, -1);
    params.set(key, val);
  }
  if (!params.has('realm') || !params.has('nonce')) return null;
  const qopRaw = params.get('qop');
  return {
    realm: params.get('realm')!,
    nonce: params.get('nonce')!,
    opaque: params.get('opaque'),
    qop: qopRaw ? qopRaw.split(';').map((s) => s.trim()).filter(Boolean) : undefined,
    algorithm: params.get('algorithm'),
  };
}

/**
 * Minimal SwOS HTTP client with manual Digest (MD5) authentication.
 * One instance per management address; safe to create per request — the digest
 * exchange costs one extra round-trip only on the first call of a process.
 */
export class SwosClient {
  private readonly baseUrl: string;
  private readonly username: string;
  private readonly password: string;
  private readonly timeoutMs: number;

  /**
   * Per-client request queue. The embedded web server cannot handle CONCURRENT
   * digest exchanges — parallel requests get ECONNRESET or a spurious 401 even
   * though the same requests succeed one after another (verified live on a
   * CRS309: 10 parallel GETs → resets/401, sequential → all OK). Every request
   * still uses its own fresh connection; this only serializes them.
   */
  private requestChain: Promise<unknown> = Promise.resolve();

  private enqueue<T>(fn: () => Promise<T>): Promise<T> {
    const next = this.requestChain.then(fn, fn);
    // Keep the chain alive even if a request fails — later requests must not be rejected.
    this.requestChain = next.catch(() => undefined);
    return next;
  }

  /**
   * @param address bare host ("192.168.88.1") or full URL ("http://…"). SwOS Lite
   *                is HTTP-only; an explicit https:// scheme is honored when given.
   */
  constructor(address: string, credentials: SwosCredentials, timeoutMs = 4000) {
    const trimmed = (address ?? '').trim().replace(/\/+$/, '');
    this.baseUrl = trimmed.includes('://') ? trimmed : `http://${trimmed}`;
    if (!this.baseUrl) throw new Error('No management address');
    this.username = credentials?.username ?? '';
    this.password = credentials?.password ?? '';
    this.timeoutMs = timeoutMs;
  }

  get base(): string {
    return this.baseUrl;
  }

  /** GET a `.b` endpoint and parse the response. */
  async get(endpoint: string): Promise<SwosData> {
    const res = await this.rawRequest('GET', `/${endpoint}`);
    if (res.status < 200 || res.status >= 300) throw new Error(`HTTP ${res.status} from ${endpoint}`);
    const text = res.body.toString('utf8');
    if (!text || !text.trim()) throw new Error(`Empty response from ${endpoint} (feature may be unsupported)`);
    return parseSwos(text);
  }

  /** GET an endpoint as raw bytes (backup.swb). */
  async getRaw(endpoint: string): Promise<Buffer> {
    const res = await this.rawRequest('GET', `/${endpoint}`);
    if (res.status < 200 || res.status >= 300) throw new Error(`HTTP ${res.status} from ${endpoint}`);
    return res.body;
  }

  /** POST a pre-built wire body (text/plain). Returns the response text. */
  async post(endpoint: string, body: string): Promise<string> {
    const res = await this.rawRequest('POST', `/${endpoint}`, body);
    if (res.status < 200 || res.status >= 300) throw new Error(`HTTP ${res.status} from POST ${endpoint}`);
    return res.body.toString('utf8').trim();
  }

  // --- internals -----------------------------------------------------------------

  /**
   * One HTTP request over a FRESH connection. Deliberately NOT global fetch:
   * undici pools connections and injects extra headers (accept-language,
   * sec-fetch-mode, user-agent: node, …) — the SwOS embedded web server rejects
   * digest responses on reused/pooled sockets with 401 even when the response
   * hash is correct (verified live against a CRS309: identical header via raw
   * node:http → 200, via fetch → 401). `Connection: close` forces one socket per
   * request; only the minimal header set is sent.
   */
  private httpRequest(method: 'GET' | 'POST', path: string, headers: Record<string, string>, body?: string): Promise<{ status: number; headers: http.IncomingHttpHeaders; body: Buffer }> {
    return new Promise((resolve, reject) => {
      let u: URL;
      try {
        u = new URL(this.baseUrl + path);
      } catch (err) {
        reject(new Error(`SwOS request failed (${method} ${path}): bad URL`));
        return;
      }
      const lib = u.protocol === 'https:' ? https : http;
      const reqHeaders: Record<string, string> = { ...headers };
      if (body !== undefined) {
        reqHeaders['Content-Length'] = String(Buffer.byteLength(body, 'utf8'));
      }
      reqHeaders.Connection = 'close';

      let settled = false;
      const finish = (fn: () => void) => {
        if (!settled) {
          settled = true;
          fn();
        }
      };

      const req = lib.request(
        u,
        { method, headers: reqHeaders },
        (res) => {
          const chunks: Buffer[] = [];
          res.on('data', (c: Buffer) => chunks.push(c));
          res.on('end', () => finish(() => resolve({ status: res.statusCode ?? 0, headers: res.headers, body: Buffer.concat(chunks) })));
        }
      );
      req.setTimeout(this.timeoutMs, () => {
        finish(() => {
          req.destroy();
          reject(new Error(`SwOS request timed out after ${this.timeoutMs} ms (${method} ${path})`));
        });
      });
      req.on('error', (err) => finish(() => reject(new Error(`SwOS request failed (${method} ${path}): ${err.message}`))));
      if (body !== undefined) req.write(body);
      req.end();
    });
  }

  private rawRequest(
    method: 'GET' | 'POST',
    path: string,
    body?: string
  ): Promise<{ status: number; headers: http.IncomingHttpHeaders; body: Buffer }> {
    return this.enqueue(() => this.rawRequestOnce(method, path, body));
  }

  private async rawRequestOnce(
    method: 'GET' | 'POST',
    path: string,
    body?: string
  ): Promise<{ status: number; headers: http.IncomingHttpHeaders; body: Buffer }> {
    let challenge: DigestChallenge | null = null;
    let attempts = 0;
    for (;;) {
      const headers: Record<string, string> = {};
      if (body !== undefined) headers['Content-Type'] = 'text/plain';
      if (challenge) {
        headers.Authorization = this.buildDigestHeader(method, path, challenge, body ?? '');
      }
      let res: { status: number; headers: http.IncomingHttpHeaders; body: Buffer };
      try {
        res = await this.httpRequest(method, path, headers, body);
      } catch (err) {
        throw err instanceof Error ? err : new Error(String(err));
      }

      if (res.status === 401) {
        const www = String(res.headers['www-authenticate'] ?? '');
        attempts++;
        if (!www || !www.toLowerCase().startsWith('digest')) throw new SwosAuthError();
        challenge = parseDigestChallenge(www);
        if (!challenge) throw new SwosAuthError();
        // A second 401 with a fresh nonce means the first response was stale — retry once.
        if (attempts > 2) throw new SwosAuthError();
        continue;
      }

      return res;
    }
  }

  private buildDigestHeader(method: string, path: string, c: DigestChallenge, body: string): string {
    const ha1 = md5(`${this.username}:${c.realm}:${this.password}`);
    const ha2 = md5(`${method}:${path}`);

    const parts = [`username="${this.username}"`, `realm="${c.realm}"`, `nonce="${c.nonce}"`, `uri="${path}"`];
    if (c.opaque) parts.push(`opaque="${c.opaque}"`);

    let response: string;
    if (c.qop && c.qop.length > 0) {
      const qop = c.qop.includes('auth') ? 'auth' : c.qop[0];
      const nc = '00000001';
      const cnonce = md5(`${Date.now()}:${Math.random()}`).slice(0, 16);
      if (qop === 'auth-int') {
        response = md5(`${ha1}:${c.nonce}:${nc}:${cnonce}:auth-int:${md5(`${ha2}:${md5(body)}`)}`);
      } else {
        response = md5(`${ha1}:${c.nonce}:${nc}:${cnonce}:${qop}:${ha2}`);
      }
      // nc and qop are RFC tokens — they must NOT be quoted. Real SwOS devices
      // reject `qop="auth"` / `nc="00000001"` (verified against a CSS309; curl's
      // unquoted form is what the firmware accepts). cnonce IS quoted.
      parts.push(`cnonce="${cnonce}"`, `nc=${nc}`, `qop=${qop}`);
    } else {
      response = md5(`${ha1}:${c.nonce}:${ha2}`);
    }

    parts.push(`response="${response}"`);
    return `Digest ${parts.join(', ')}`;
  }
}
