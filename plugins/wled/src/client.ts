/**
 * WLED device client — LAN-only HTTP(S) to a single WLED controller.
 *
 * This module talks ONLY to the device itself (its management address). It never
 * opens outbound internet connections: firmware downloads and the GitHub release
 * feed go through UNM's web-fetch broker instead (see updates.ts / actions.ts),
 * so this plugin stays egress-agnostic like every other UNM component.
 *
 * WLED speaks plain HTTP on port 80 by default (overridable via the `httpPort`
 * option). The JSON API is documented at https://wled.me/wiki/api/ — the fields
 * we read are source-verified against wled/WLED:
 *   GET /json/info → { name, ver, vid, cn, release, arch, freeheap, uptime,
 *                      wifi{rssi,signal,channel,band,bssid}, leds{count,fps,pwr},
 *                      mac, ip }
 */

import http from 'http';
import https from 'https';
import { resolveEndpointCandidates } from '@unm/plugin-sdk';

/** Canonical result envelope for one device call (mirrors the SDK's DeviceApiResult). */
export interface WledResult<T = unknown> {
  ok: boolean;
  status: number;
  data?: T;
  error?: string;
}

export interface WledClientOptions {
  /** The device management address (bare host[:port] or explicit http(s):// URL). */
  address: string;
  /** Transport policy — 'http' is the WLED default. */
  transport?: 'auto' | 'http' | 'https';
  /** Plain-HTTP port applied to bare addresses without an explicit port (default 80). */
  httpPort?: number;
  /** Per-request timeout in ms. */
  timeoutMs: number;
}

/** Resolves the ordered candidate base URLs for a WLED device address. */
export function wledCandidates(opts: Pick<WledClientOptions, 'address' | 'transport' | 'httpPort'>): string[] {
  const t = opts.transport ?? 'http';
  return resolveEndpointCandidates(opts.address, {
    transport: t,
    ports: { httpPort: opts.httpPort ?? 80 },
  });
}

/** Splits a base URL into the node request options (host/port/path). */
function splitBase(base: string, path: string): { host: string; port: number; scheme: 'http' | 'https'; path: string } {
  const u = new URL(base);
  return {
    host: u.hostname,
    port: u.port ? Number(u.port) : (u.protocol === 'https:' ? 443 : 80),
    scheme: (u.protocol === 'https:' ? 'https' : 'http') as 'http' | 'https',
    path,
  };
}

/**
 * Issues one HTTP request against the FIRST candidate that answers. A network-
 * level failure on a candidate falls through to the next; an HTTP-level outcome
 * (any status) is final for that candidate and returned as-is. Resolves null when
 * every candidate fails at the transport layer.
 */
async function request<T>(
  opts: WledClientOptions,
  method: string,
  path: string,
  body?: Buffer | string,
  headers?: Record<string, string>
): Promise<WledResult<T>> {
  const candidates = wledCandidates(opts);
  if (candidates.length === 0) return { ok: false, status: 0, error: 'No candidate endpoints for address' };

  let lastError = '';
  for (const base of candidates) {
    const target = splitBase(base, path);
    const lib = target.scheme === 'https' ? https : http;
    const result = await new Promise<WledResult<T> | null>((resolve) => {
      let settled = false;
      const finish = (r: WledResult<T> | null): void => {
        if (!settled) {
          settled = true;
          resolve(r);
        }
      };

      let req: http.ClientRequest;
      try {
        req = lib.request(
          {
            host: target.host,
            port: target.port,
            path: target.path,
            method,
            headers: { 'User-Agent': 'UnifiedNetworkManager/0.1 (wled plugin)', ...(body ? { 'Content-Length': String(Buffer.byteLength(body)) } : {}), ...headers },
            // WLED boxes may present a self-signed cert when TLS is enabled — accept it;
            // the point of this client is to reach the device, not to judge its chain.
            rejectUnauthorized: false,
          },
          (res) => {
            const chunks: Buffer[] = [];
            res.on('data', (c: Buffer) => chunks.push(c));
            res.on('end', () => {
              const raw = Buffer.concat(chunks);
              const status = res.statusCode ?? 0;
              if (status < 200 || status >= 300) {
                finish({ ok: false, status, error: `HTTP ${status}: ${raw.toString('utf8').slice(0, 512)}` });
                return;
              }
              let data: T | undefined;
              if (raw.length > 0) {
                try {
                  data = JSON.parse(raw.toString('utf8')) as T;
                } catch {
                  // Non-JSON success body (e.g. /update's "Update successful!") — keep raw text.
                  data = raw.toString('utf8') as unknown as T;
                }
              }
              finish({ ok: true, status, data });
            });
          },
        );
      } catch {
        finish(null);
        return;
      }

      const timer = setTimeout(() => {
        try {
          req.destroy(new Error(`request timed out after ${opts.timeoutMs} ms`));
        } catch {
          /* already closed */
        }
      }, opts.timeoutMs);
      req.on('error', (err) => {
        clearTimeout(timer);
        lastError = err.message;
        finish(null); // transport failure — try the next candidate
      });
      if (body !== undefined) req.write(body);
      req.end();
    });

    if (result !== null) return result; // an HTTP-level answer is final
  }
  return { ok: false, status: 0, error: lastError || 'no endpoint answered' };
}

/** The parsed /json/info payload (only the fields UNM consumes). */
export interface WledInfo {
  name?: string;
  ver?: string;
  vid?: number;
  cn?: string; // core name, e.g. "Niji"
  release?: string; // board variant, e.g. "ESP32" — matches the firmware asset suffix
  repo?: string; // GitHub repo of this firmware (default "wled/WLED") — source of update rows
  arch?: string; // e.g. "esp32", "esp8266"
  freeheap?: number; // bytes
  uptime?: number; // seconds (rollover-safe)
  wifi?: { rssi?: number; signal?: number; channel?: number; band?: string; bssid?: string };
  leds?: { count?: number; fps?: number; pwr?: number };
  mac?: string;
  ip?: string;
}

/** GET /json/info — the single source of truth for monitoring + update rows. */
export function getInfo(opts: WledClientOptions): Promise<WledResult<WledInfo>> {
  return request<WledInfo>(opts, 'GET', '/json/info');
}

/** Plain GET against an arbitrary path (e.g. /update?revert). */
export function get(opts: WledClientOptions, path: string): Promise<WledResult<unknown>> {
  return request(opts, 'GET', path);
}

/** POST a JSON body to a path (e.g. /json/cfg with {"id":{"name":…}} or /json state). */
export function postJson(opts: WledClientOptions, path: string, body: Record<string, unknown>): Promise<WledResult<unknown>> {
  return request(opts, 'POST', path, JSON.stringify(body), { 'Content-Type': 'application/json' });
}

/**
 * Builds a multipart/form-data body. `file` (when present) is the firmware blob;
 * extra form fields ride along as plain parts (e.g. the optional PIN).
 */
export function buildMultipart(fields: Record<string, string>, file?: { name: string; filename: string; contentType: string; data: Buffer }): { body: Buffer; contentType: string } {
  const boundary = `----wledunm${Date.now().toString(16)}${Math.floor(Math.random() * 0xffff).toString(16)}`;
  const parts: Buffer[] = [];
  for (const [k, v] of Object.entries(fields)) {
    if (v === undefined || v === '') continue;
    parts.push(Buffer.from(`--${boundary}\r\nContent-Disposition: form-data; name="${k}"\r\n\r\n${v}\r\n`));
  }
  if (file) {
    parts.push(
      Buffer.from(
        `--${boundary}\r\nContent-Disposition: form-data; name="${file.name}"; filename="${file.filename}"\r\nContent-Type: ${file.contentType}\r\n\r\n`
      )
    );
    parts.push(file.data);
    parts.push(Buffer.from('\r\n'));
  }
  parts.push(Buffer.from(`--${boundary}--\r\n`));
  return { body: Buffer.concat(parts), contentType: `multipart/form-data; boundary=${boundary}` };
}

/** POST a multipart form (firmware upload to /update, or any file field). */
export function postMultipart(opts: WledClientOptions, path: string, fields: Record<string, string>, file?: { name: string; filename: string; contentType: string; data: Buffer }): Promise<WledResult<unknown>> {
  const mp = buildMultipart(fields, file);
  return request(opts, 'POST', path, mp.body, { 'Content-Type': mp.contentType });
}
