import axios, { AxiosInstance } from 'axios';
import { Agent as HttpsAgent } from 'https';

export interface OpnsenseApiResult<T = unknown> {
  ok: boolean;
  status: number;
  data: T;
}

// OPNsense appliances almost always present a self-signed TLS certificate.
// Rejecting it (axios default) makes every poll fail with "self-signed
// certificate" and the device stays offline. Use an agent that accepts it.
const httpsAgent = new HttpsAgent({ rejectUnauthorized: false });

async function request<T = unknown>(
  method: 'get' | 'post',
  url: string,
  host: string,
  apiKey: string,
  apiSecret: string,
  body?: unknown
): Promise<OpnsenseApiResult<T>> {
  const response = await axios.request<T>({
    method,
    url: `${host.replace(/\/$/, '')}${url}`,
    auth: {
      username: apiKey,
      password: apiSecret,
    },
    data: body,
    timeout: 10_000,
    validateStatus: () => true,
    httpsAgent,
  });
  return {
    ok: response.status >= 200 && response.status < 300,
    status: response.status,
    data: response.data,
  };
}

/**
 * Fetches high-level system status (uptime, version, load) from OPNsense.
 * GET /api/core/system/status
 */
export function getSystemStatus(host: string, apiKey: string, apiSecret: string): Promise<OpnsenseApiResult> {
  return request('get', '/api/core/system/status', host, apiKey, apiSecret);
}

/**
 * Fetches system resource usage (memory total/used in bytes).
 * GET /api/diagnostics/system/system_resources
 */
export function getSystemResources(host: string, apiKey: string, apiSecret: string): Promise<OpnsenseApiResult> {
  return request('get', '/api/diagnostics/system/system_resources', host, apiKey, apiSecret);
}

/**
 * Fetches system information (hostname, versions).
 * GET /api/diagnostics/system/system_information
 */
export function getSystemInformation(host: string, apiKey: string, apiSecret: string): Promise<OpnsenseApiResult> {
  return request('get', '/api/diagnostics/system/system_information', host, apiKey, apiSecret);
}

/**
 * Fetches the configured interface names/details.
 * GET /api/diagnostics/interface/get_interface_names
 */
export function getInterfaces(host: string, apiKey: string, apiSecret: string): Promise<OpnsenseApiResult> {
  return request('get', '/api/diagnostics/interface/get_interface_names', host, apiKey, apiSecret);
}

/**
 * Fetches per-interface traffic statistics (byte counters).
 * GET /api/diagnostics/interface/get_interface_statistics
 */
export function getInterfaceStats(host: string, apiKey: string, apiSecret: string): Promise<OpnsenseApiResult> {
  return request('get', '/api/diagnostics/interface/get_interface_statistics', host, apiKey, apiSecret);
}

/**
 * Fetches the ARP table (IPv4 neighbors). The web UI uses a POST "search" endpoint
 * (GET /getArp returns 403). Shape:
 *   { total, rowCount, current, rows: [{ mac, ip, intf, manufacturer, intf_description, ... }] }
 * POST /api/diagnostics/interface/search_arp/
 */
export function getArpTable(host: string, apiKey: string, apiSecret: string): Promise<OpnsenseApiResult> {
  return request('post', '/api/diagnostics/interface/search_arp/', host, apiKey, apiSecret, {});
}

/**
 * Fetches the NDP table (IPv6 neighbors).
 *   { total, rowCount, current, rows: [{ mac, ip, intf, manufacturer, ... }] }
 * POST /api/diagnostics/interface/search_ndp/
 */
export function getNdpTable(host: string, apiKey: string, apiSecret: string): Promise<OpnsenseApiResult> {
  return request('post', '/api/diagnostics/interface/search_ndp/', host, apiKey, apiSecret, {});
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
  apiKey: string,
  apiSecret: string
): Promise<{ total: number; user: number; sys: number; intr: number; idle: number } | undefined> {
  const https = require('https');
  const http = require('http');
  const base = host.replace(/\/$/, '');
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
          Authorization: `Basic ${Buffer.from(`${apiKey}:${apiSecret}`).toString('base64')}`,
          Accept: 'text/event-stream',
        },
        // OPNsense presents a self-signed cert — accept it.
        rejectUnauthorized: false,
      },
      (res: any) => {
        if (res.statusCode < 200 || res.statusCode >= 300) {
          res.resume();
          finish(undefined);
          return;
        }
        let buffer = '';
        res.on('data', (chunk: Buffer) => {
          buffer += chunk.toString('utf8');
          const dataLine = buffer.split('\n').find((l: string) => l.startsWith('data:'));
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

/**
 * Applies a configuration change. OPNsense laughts a single generic
 * "apply config" endpoint, so this reference implementation targets the
 * firmware/config reconfigure endpoint used to activate pending changes.
 * Real deployments would branch on the requested action/payload shape to
 * call the appropriate OPNsense module endpoint (e.g. firewall rules,
 * interface settings, etc.).
 * POST /api/core/firmware/status
 */
export function applyConfig(payload: unknown, host: string, apiKey: string, apiSecret: string): Promise<OpnsenseApiResult> {
  return request('post', '/api/core/firmware/status', host, apiKey, apiSecret, payload);
}
