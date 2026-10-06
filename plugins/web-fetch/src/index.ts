/**
 * UNM web-fetch service (capability `webFetch`).
 *
 * A GLOBAL service plugin (no device assignment, no credentials): it downloads
 * files and web content from the internet ON BEHALF of UNM. The API's GeoIP
 * worker calls POST /fetch to pull database files (MMDB/CSV) into the central
 * file repository; any future feature that needs outbound web data can reuse
 * the same endpoint.
 *
 * Why a plugin at all: in enterprise environments plain egress TLS is often
 * not allowed — every request must go through an egress proxy server, and the
 * API container may live on a network segment WITHOUT internet access while a
 * small box WITH access sits elsewhere. By pushing the outbound HTTP into its
 * own plugin (deployed wherever egress exists), UNM's core stays agnostic of
 * proxies/egress: the API only ever talks to this plugin over the compose
 * network, and this plugin does the internet hop — plain or through a proxy
 * with CONNECT tunneling for HTTPS targets.
 *
 * Contract (POST /fetch):
 *   body  { url, proxyUrl?, timeoutMs?, maxBytes?, extract?: 'auto'|'tar.gz'|'zip', headers? }
 *   resp  raw octet-stream of the downloaded (and optionally extracted) bytes;
 *         metadata rides in response headers:
 *           x-webfetch-status          — origin HTTP status code
 *           x-webfetch-content-type    — origin Content-Type
 *           x-webfetch-extracted-from  — archive member name, when extraction ran
 *   errors are JSON { error } with a meaningful status (502 upstream failure /
 *   bad content, 504 timeout). The caller (the API broker) streams the body
 *   straight into file-repo's PUT /store — nothing is buffered end-to-end.
 *
 * Extraction: GeoIP vendors ship archives (MaxMind .tar.gz, IP2Location LITE
 * .zip) around a single database file. `extract` pulls the FIRST *.mmdb or
 * *.csv member out of the archive; 'auto' sniffs the magic bytes (gzip →
 * tar.gz, PK\x03\x04 → zip) and falls back to raw passthrough for plain files
 * (dp-ip CSV, ipinfo mmdb-lite). Only matching members are ever written to
 * disk — everything else in the archive is skipped.
 */

import fs from 'fs';
import fsp from 'fs/promises';
import os from 'os';
import path from 'path';
import { randomUUID } from 'crypto';
import axios, { AxiosError, type AxiosProxyConfig } from 'axios';
import tar from 'tar';
import unzipper from 'unzipper';
import type { Health, MetricDescriptor } from '@unm/plugin-sdk';
import {
  createPluginLogger,
  createPluginServer,
  requirePluginKey,
  resolvePluginIdentity,
} from '@unm/plugin-sdk';

export const PLUGIN_UUID = '00000000-0000-4000-8000-0000000013';
export const PLUGIN_NAME = 'Web Fetch (Internet Egress)';

const identity = resolvePluginIdentity({
  uuid: PLUGIN_UUID,
  name: PLUGIN_NAME,
  version: '0.1.0',
  vendors: ['unm'],
  // No device-facing capabilities — this is a pull-based egress service. The
  // API's plugin-metrics worker still polls GET /metrics (SDK auto-mounted)
  // for runtime health; the custom gauges below carry fetch stats.
  capabilities: ['webFetch'],
});

// ── Runtime configuration (env — global service, no per-device settings) ────

/** Default egress proxy (empty = direct connection). Per-request `proxyUrl` wins. */
const DEFAULT_PROXY_URL = (process.env.WEBFETCH_PROXY_URL ?? '').trim();
/** Default request timeout in ms when the caller does not pass one. */
const DEFAULT_TIMEOUT_MS = Math.max(5_000, Number(process.env.WEBFETCH_TIMEOUT_MS ?? 120_000));
/** Hard ceiling for a single download (default 512 MiB — GeoIP DBs are <100 MiB). */
const MAX_BYTES_CEILING = Math.max(1_048_576, Number(process.env.WEBFETCH_MAX_BYTES ?? 512 * 1024 * 1024));

/** Hop-by-hop / request-defining headers a caller must never override. */
const FORBIDDEN_HEADERS = new Set(['host', 'content-length', 'connection', 'proxy-authorization']);

interface FetchRequest {
  url: string;
  proxyUrl?: string;
  timeoutMs?: number;
  maxBytes?: number;
  extract?: 'auto' | 'tar.gz' | 'zip';
  headers?: Record<string, string>;
}

const stats = {
  fetchesTotal: 0,
  fetchFailuresTotal: 0,
  bytesFetchedTotal: 0,
  lastFetchMs: null as number | null,
};

// ── Metric descriptors (rendered on the Plugins page) ───────────────────────

const METRIC_DESCRIPTORS: MetricDescriptor[] = [
  { key: 'webfetch.fetchesTotal', label: 'Fetches (total)', type: 'number', visualization: 'text', group: 'Web Fetch' },
  { key: 'webfetch.fetchFailuresTotal', label: 'Failed fetches (total)', type: 'number', visualization: 'text', group: 'Web Fetch' },
  { key: 'webfetch.bytesFetchedTotal', label: 'Bytes fetched (total)', type: 'number', visualization: 'plot', group: 'Web Fetch', color: '#3b82f6' },
];

const server = createPluginServer({
  identity,
  logTag: 'web-fetch-plugin',
  discovery: {
    requiredSecretType: null,
    metrics: METRIC_DESCRIPTORS,
    options: [],
  },
  selfMetricsExtra: () => ({
    webfetchFetchesTotal: stats.fetchesTotal,
    webfetchFetchFailuresTotal: stats.fetchFailuresTotal,
    webfetchBytesFetchedTotal: stats.bytesFetchedTotal,
    webfetchLastFetchMs: stats.lastFetchMs ?? 0,
  }),
});

// Structured logs shipped to the API (boot errors, fetch failures).
const logger = createPluginLogger(identity);

/** Normalizes a proxy URL string into axios's AxiosProxyConfig (axios tunnels CONNECT for https targets). */
function normalizeProxy(raw: string | undefined): AxiosProxyConfig | undefined {
  const value = (raw ?? '').trim();
  if (!value) return undefined;
  let u: URL;
  try {
    u = new URL(value);
  } catch {
    throw Object.assign(new Error(`Invalid proxyUrl: ${value}`), { status: 400 });
  }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') {
    throw Object.assign(new Error(`Unsupported proxy protocol: ${u.protocol}`), { status: 400 });
  }
  const cfg: AxiosProxyConfig = {
    host: u.hostname,
    port: Number(u.port) || (u.protocol === 'https:' ? 443 : 80),
    protocol: u.protocol.replace(/:$/, ''),
  };
  if (u.username || u.password) cfg.auth = { username: decodeURIComponent(u.username), password: decodeURIComponent(u.password) };
  return cfg;
}

/** Sanitizes caller-supplied headers — hop-by-hop and identity headers are dropped. */
function sanitizeHeaders(headers: Record<string, string> | undefined): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(headers ?? {})) {
    if (FORBIDDEN_HEADERS.has(k.toLowerCase())) continue;
    if (typeof v === 'string') out[k] = v;
  }
  return out;
}

/** Sniffs the archive kind from magic bytes. */
function sniffArchive(buf: Buffer): 'tar.gz' | 'zip' | null {
  if (buf.length >= 2 && buf[0] === 0x1f && buf[1] === 0x8b) return 'tar.gz'; // gzip
  if (buf.length >= 4 && buf[0] === 0x50 && buf[1] === 0x4b && buf[2] === 0x03 && buf[3] === 0x04) return 'zip';
  return null;
}

/** The database file we care about inside an archive (first match wins). */
function isDatabaseMember(name: string): boolean {
  const lower = name.toLowerCase();
  return lower.endsWith('.mmdb') || lower.endsWith('.csv');
}

/**
 * Streams a response body into a temp file, enforcing the byte ceiling on
 * chunked responses too (maxContentLength only fires when Content-Length is
 * known). Returns the path + received size.
 */
async function downloadToTempFile(stream: fs.ReadStream, tmpDir: string, maxBytes: number): Promise<{ archivePath: string; received: number }> {
  const archivePath = path.join(tmpDir, 'download');
  let received = 0;
  await new Promise<void>((resolve, reject) => {
    const out = fs.createWriteStream(archivePath);
    // pipe() does the actual writing (with backpressure); this listener only
    // counts bytes so chunked responses without Content-Length are bounded too.
    stream.on('data', (chunk: string | Buffer) => {
      received += Buffer.isBuffer(chunk) ? chunk.length : Buffer.byteLength(chunk);
      if (received > maxBytes) {
        out.destroy();
        stream.destroy();
        reject(Object.assign(new Error(`Response exceeds maxBytes (${maxBytes})`), { status: 502 }));
      }
    });
    stream.on('error', reject);
    out.on('finish', resolve);
    out.on('error', reject);
    stream.pipe(out, { end: true });
  });
  return { archivePath, received };
}

/** Pipes a local file into the HTTP response as octet-stream. */
function streamFileToResponse(res: import('express').Response, filePath: string): void {
  const fileStream = fs.createReadStream(filePath);
  fileStream.pipe(res);
  fileStream.on('error', () => {
    if (!res.headersSent) res.status(502).json({ error: 'Failed to stream the download' });
    else res.destroy();
  });
}

/**
 * Extracts the first *.mmdb / *.csv member from a downloaded archive into a
 * fresh temp dir (only matching members are written) and returns its path.
 */
async function extractMember(archivePath: string, kind: 'tar.gz' | 'zip', outDir: string): Promise<string> {
  if (kind === 'tar.gz') {
    await tar.extract({
      file: archivePath,
      cwd: outDir,
      filter: (name) => isDatabaseMember(name),
    });
  } else {
    const dir = await unzipper.Open.file(archivePath);
    // Regular entries report type 'File' (folders are 'Directory') — skip dirs.
    const member = dir.files.find((f) => f.type !== 'Directory' && isDatabaseMember(f.path));
    if (!member) throw new Error('No .mmdb/.csv member found in zip archive');
    // Open.file() entries expose buffer()/stream(), not extract() — write it.
    const data = await member.buffer();
    await fsp.writeFile(path.join(outDir, path.basename(member.path)), data);
  }

  // Walk the (tiny) output dir for the extracted database file.
  const found: string[] = [];
  async function walk(dirPath: string): Promise<void> {
    for (const entry of await fsp.readdir(dirPath, { withFileTypes: true })) {
      const full = path.join(dirPath, entry.name);
      if (entry.isDirectory()) await walk(full);
      else if (isDatabaseMember(entry.name)) found.push(full);
    }
  }
  await walk(outDir);
  if (found.length === 0) throw new Error('No .mmdb/.csv member found in archive');
  return found[0];
}

/**
 * POST /fetch — download `url` (plain or via proxy), optionally extract the
 * database file from an archive, and stream the bytes back as octet-stream.
 */
server.app.post('/fetch', requirePluginKey, async (req, res) => {
  const body = req.body as FetchRequest;
  let tmpDir: string | null = null;

  try {
    // ── Validate + clamp inputs ────────────────────────────────────────────
    if (!body?.url || typeof body.url !== 'string') throw Object.assign(new Error('Missing url'), { status: 400 });
    let target: URL;
    try {
      target = new URL(body.url);
    } catch {
      throw Object.assign(new Error(`Invalid url: ${body.url}`), { status: 400 });
    }
    if (target.protocol !== 'http:' && target.protocol !== 'https:') {
      throw Object.assign(new Error(`Unsupported protocol: ${target.protocol}`), { status: 400 });
    }

    const proxy = normalizeProxy(body.proxyUrl ?? DEFAULT_PROXY_URL);
    const timeoutMs = Math.min(Math.max(5_000, Number(body.timeoutMs) || DEFAULT_TIMEOUT_MS), 3_600_000);
    const maxBytes = Math.min(Number(body.maxBytes) > 0 ? Number(body.maxBytes) : MAX_BYTES_CEILING, MAX_BYTES_CEILING);
    const extract: 'auto' | 'tar.gz' | 'zip' = body.extract === 'tar.gz' || body.extract === 'zip' ? body.extract : 'auto';

    // ── Download (streamed; byte-counted so chunked responses are bounded too) ──
    let response;
    try {
      response = await axios.get<fs.ReadStream>(body.url, {
        responseType: 'stream',
        timeout: timeoutMs,
        proxy: proxy ?? false,
        maxContentLength: maxBytes, // rejects early when Content-Length is known
        headers: sanitizeHeaders(body.headers),
        validateStatus: (s) => s >= 200 && s < 300,
      });
    } catch (e) {
      const ax = e as AxiosError;
      if (ax.response) {
        stats.fetchFailuresTotal += 1;
        throw Object.assign(new Error(`Upstream returned HTTP ${ax.response.status}`), { status: 502 });
      }
      if (ax.code === 'ECONNABORTED' || ax.code === 'ETIMEDOUT') {
        stats.fetchFailuresTotal += 1;
        throw Object.assign(new Error(`Fetch timed out after ${timeoutMs} ms`), { status: 504 });
      }
      if (ax.code === 'ERR_BAD_RESPONSE') {
        stats.fetchFailuresTotal += 1;
        throw Object.assign(new Error(`Response exceeds maxBytes (${maxBytes})`), { status: 502 });
      }
      // Proxy CONNECT failures, DNS errors, refused connections — all surface here.
      stats.fetchFailuresTotal += 1;
      logger.warn(`Fetch failed for ${body.url}: ${ax.message ?? String(e)}`);
      throw Object.assign(new Error(`Fetch failed: ${ax.message ?? String(e)}`), { status: 502 });
    }

    const originStatus = response.status;
    const contentType = String(response.headers['content-type'] ?? 'application/octet-stream');
    const stream = response.data as unknown as fs.ReadStream;

    // Buffer to a temp file — extraction needs the whole archive, and even the
    // plain-file path is bounded by maxBytes (GeoIP DBs are <100 MiB).
    tmpDir = await fsp.mkdtemp(path.join(os.tmpdir(), `webfetch-${randomUUID()}`));
    const { archivePath, received } = await downloadToTempFile(stream, tmpDir, maxBytes);

    // Decide: plain file (passthrough) or archive (extract the DB member).
    let kind: 'tar.gz' | 'zip' | null;
    if (extract === 'auto') kind = sniffArchive(fs.readFileSync(archivePath).subarray(0, 4));
    else kind = extract;

    let payloadPath = archivePath; // default: the raw download itself
    let extractedFrom: string | undefined;
    if (kind) {
      const outDir = path.join(tmpDir, 'extracted');
      await fsp.mkdir(outDir, { recursive: true });
      try {
        payloadPath = await extractMember(archivePath, kind, outDir);
        extractedFrom = path.basename(payloadPath);
      } catch (e) {
        stats.fetchFailuresTotal += 1;
        throw Object.assign(new Error((e as Error).message), { status: 502 });
      }
    }

    stats.fetchesTotal += 1;
    stats.bytesFetchedTotal += received;
    stats.lastFetchMs = Date.now();
    res.status(200);
    res.setHeader('Content-Type', 'application/octet-stream');
    res.setHeader('x-webfetch-status', String(originStatus));
    res.setHeader('x-webfetch-content-type', contentType);
    if (extractedFrom) res.setHeader('x-webfetch-extracted-from', extractedFrom);
    streamFileToResponse(res, payloadPath);
  } catch (err) {
    const e = err as Error & { status?: number };
    const status = e.status ?? 500;
    if (!res.headersSent) res.status(status).json({ error: e.message });
    else res.destroy();
  } finally {
    if (tmpDir) await fsp.rm(tmpDir, { recursive: true, force: true }).catch(() => undefined);
  }
});

/** POST /monitoring — no device-facing work; reports fetch-service health. */
server.app.post('/monitoring', (_req, res) => {
  const metrics: Record<string, unknown> = {
    'webfetch.fetchesTotal': stats.fetchesTotal,
    'webfetch.fetchFailuresTotal': stats.fetchFailuresTotal,
    'webfetch.bytesFetchedTotal': stats.bytesFetchedTotal,
  };
  res.status(200).json({
    collectedAt: new Date().toISOString(),
    health: (stats.fetchFailuresTotal > 0 ? 'warning' : 'ok') as Health,
    metrics,
    metricDescriptors: METRIC_DESCRIPTORS,
  });
});

server.listen().catch((err) => {
  // eslint-disable-next-line no-console
  console.error('[web-fetch] failed to start HTTP server:', err.message);
  process.exit(1);
});
