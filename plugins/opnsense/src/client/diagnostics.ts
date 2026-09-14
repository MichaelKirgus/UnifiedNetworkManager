import { AxiosInstance } from 'axios';
import * as https from 'https';
import * as http from 'http';
import { basicAuthHeader, insecureHttpsAgent } from '@unm/plugin-sdk';
import { get, post, OpnsenseApiResult, resolveBase, OpnsenseCredentials, OpnsensePorts, OpnsenseTransport } from './http';

/**
 * Diagnostics module: interface names/statistics, neighbor tables (ARP/NDP)
 * and the CPU usage SSE stream. These power /monitoring; they are moved here
 * unchanged in behavior so monitoring keeps working while the rest of the
 * plugin moves to the client library.
 */

/** GET /api/diagnostics/interface/get_interface_names — configured interface names/details. */
export function getInterfaces(client: AxiosInstance): Promise<OpnsenseApiResult> {
  return get(client, '/api/diagnostics/interface/get_interface_names');
}

/** GET /api/diagnostics/interface/get_interface_statistics — per-interface byte counters + MACs. */
export function getInterfaceStats(client: AxiosInstance): Promise<OpnsenseApiResult> {
  return get(client, '/api/diagnostics/interface/get_interface_statistics');
}

/**
 * POST /api/diagnostics/interface/search_arp/ — ARP table (IPv4 neighbors).
 * The web UI uses the POST "search" endpoint (GET /getArp returns 403).
 */
export function getArpTable(client: AxiosInstance, query?: Record<string, unknown>): Promise<OpnsenseApiResult> {
  return post(client, '/api/diagnostics/interface/search_arp/', query ?? {});
}

/** POST /api/diagnostics/interface/search_ndp/ — NDP table (IPv6 neighbors). */
export function getNdpTable(client: AxiosInstance, query?: Record<string, unknown>): Promise<OpnsenseApiResult> {
  return post(client, '/api/diagnostics/interface/search_ndp/', query ?? {});
}

/**
 * Reads a single CPU-usage sample from OPNsense's Server-Sent Events stream.
 *
 * The dashboard's CPU graph polls `GET /api/diagnostics/cpu_usage/stream`,
 * which emits one `event: message` frame per second with a shape like:
 *   { "total": 11, "user": 3, "nice": 0, "sys": 7, "intr": 1, "idle": 88 }
 * where `total` is the percentage of CPU in use (100 - idle).
 *
 * This helper opens the stream, captures the first complete sample, and closes
 * the connection — so a poll takes ~1s and never hangs. Returns `undefined`
 * when the appliance doesn't expose the endpoint (older firmware).
 */
export async function getCpuUsage(
  host: string,
  credentials: OpnsenseCredentials,
  transport?: OpnsenseTransport,
  ports?: OpnsensePorts
): Promise<{ total: number; user: number; sys: number; intr: number; idle: number } | undefined> {
  const base = resolveBase(host, transport, ports);
  if (!base) return undefined;
  const isHttps = base.startsWith('https://');
  const lib = isHttps ? https : http;
  const url = new URL(`${base}/api/diagnostics/cpu_usage/stream`);

  return new Promise((resolve) => {
    let settled = false;
    const finish = (v: { total: number; user: number; sys: number; intr: number; idle: number } | undefined) => {
      if (settled) return;
      settled = true;
      req.destroy();
      resolve(v);
    };

    const req = lib.request(
      url,
      {
        method: 'GET',
        headers: {
          Authorization: basicAuthHeader(credentials.apiKey, credentials.apiSecret),
          Accept: 'text/event-stream',
        },
        // OPNsense presents a self-signed cert — accept it (shared SDK agent).
        ...(isHttps ? { agent: insecureHttpsAgent() } : {}),
      },
      (res) => {
        const code = res.statusCode ?? 0;
        if (code < 200 || code >= 300) {
          res.resume();
          finish(undefined);
          return;
        }
        let buffer = '';
        res.on('data', (chunk: Buffer) => {
          buffer += chunk.toString('utf8');
          const dataLine = buffer.split('\n').find((l) => l.startsWith('data:'));
          if (dataLine) {
            try {
              const parsed = JSON.parse(dataLine.slice(5).trim()) as Record<string, unknown>;
              const num = (k: string) => (typeof parsed[k] === 'number' ? (parsed[k] as number) : 0);
              finish({ total: num('total'), user: num('user'), sys: num('sys'), intr: num('intr'), idle: num('idle') });
            } catch {
              /* keep reading */
            }
          }
        });
        res.on('end', () => finish(undefined));
        res.on('error', () => finish(undefined));
      }
    );
    req.on('error', () => finish(undefined));
    // Hard cap: a poll must never hang.
    req.setTimeout(4000, () => finish(undefined));
    req.end();
  });
}
