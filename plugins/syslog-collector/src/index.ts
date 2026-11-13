/**
 * Syslog collector plugin — RFC 5424 + BSD syslog ingest for the UNM security-events feature.
 *
 * A GLOBAL service plugin (no device assignment, no credentials): it listens on
 * UDP and TCP port 514 for syslog messages pushed by network devices (firewalls,
 * routers, switches), parses each line (RFC 5424 or BSD — sniffed per line),
 * maps the syslog severity onto UNM's four log levels, extracts src/dst IPs from
 * well-known vendor message shapes and pushes normalized batches to the UNM
 * API's internal POST /plugin/security-events endpoint. The API resolves each
 * row's deviceId from its hostname (hosts table first, then devices) — this
 * plugin stays device-agnostic.
 *
 * Backpressure model: the UDP/TCP receive path NEVER blocks on the API. Parsed
 * rows go into a bounded in-memory queue; overflow drops the OLDEST rows
 * (counted + surfaced via self-metrics). Pushes are fire-and-forget with one
 * retry — same semantics as the flow-collector plugin and the SDK's log pipeline.
 */

import crypto from 'crypto';
import dgram from 'dgram';
import net from 'net';
import path from 'path';
import {
  Health,
  MetricDescriptor,
  createPluginLogger,
  createPluginServer,
  resolvePluginIdentity,
} from '@unm/plugin-sdk';
import axios from 'axios';
import { SYSLOG_COLLECTOR_DEVICE_SUPPORT } from './deviceSupport';
import { extractVendorIps } from './vendorParsers';
import { parseSyslogLine } from './syslogParser';

export const PLUGIN_UUID = '00000000-0000-4000-8000-0000000013';
export const PLUGIN_NAME = 'Syslog Collector (RFC5424/BSD)';

/**
 * Multi-instance support: set `PLUGIN_INSTANCE_ID` (e.g. "site-a") to run
 * several collectors — each advertises a distinct identity (`<uuid>:<id>`) so
 * the API registers them as separate plugins and attributes events per
 * collector. Unset = single instance.
 */
const identity = resolvePluginIdentity({
  uuid: PLUGIN_UUID,
  name: PLUGIN_NAME,
  description:
    'Push-based syslog ingest service — devices forward RFC5424/BSD syslog to this collector (UDP/TCP 514); it is not assigned to devices.',
  version: '0.1.0',
  vendors: ['generic'],
  capabilities: ['logIngestion'],
});

// ── Runtime configuration (env — global service, no per-device settings) ────

const SYSLOG_PORT = Math.max(1, Math.min(65_535, Number(process.env.SYSLOG_PORT ?? 514)));
const UDP_ENABLED = process.env.SYSLOG_UDP !== '0';
const TCP_ENABLED = process.env.SYSLOG_TCP !== '0';
const PUSH_INTERVAL_MS = Math.max(500, Number(process.env.SYSLOG_PUSH_INTERVAL_MS ?? 2_000));
const MAX_QUEUE_EVENTS = Math.max(1_000, Number(process.env.SYSLOG_MAX_QUEUE_EVENTS ?? 50_000));
const PUSH_BATCH_SIZE = 5_000; // API caps requests at 5k rows
const MAX_LINE_CHARS = 65_536;

// ── Metric descriptors (rendered on the Plugins page) ───────────────────────

const METRIC_DESCRIPTORS: MetricDescriptor[] = [
  { key: 'syslog.messagesPerSec', label: 'Messages received/s', type: 'number', visualization: 'plot', group: 'Syslog', color: '#3b82f6', summary: true },
  { key: 'syslog.eventsEmittedPerSec', label: 'Events emitted/s', type: 'number', visualization: 'plot', group: 'Syslog' },
  { key: 'syslog.droppedEventsTotal', label: 'Dropped events (total)', type: 'number', visualization: 'text', group: 'Syslog' },
  { key: 'syslog.queueDepth', label: 'Push queue depth', type: 'number', visualization: 'plot', group: 'Syslog', color: '#f59e0b' },
  { key: 'syslog.pushesTotal', label: 'Push batches (total)', type: 'number', visualization: 'text', group: 'Syslog' },
  { key: 'syslog.pushFailuresTotal', label: 'Failed pushes (total)', type: 'number', visualization: 'text', group: 'Syslog' },
];

// Pre-wired app: cors + json + /healthz + /discover (+ static icons, mDNS on
// listen) come from @unm/plugin-sdk. Custom gauges ride on GET /metrics via
// selfMetricsExtra (polled by the API's plugin-metrics worker).
const server = createPluginServer({
  identity,
  logTag: 'syslog-collector-plugin',
  iconsDir: path.join(__dirname, '../../icons'),
  // Static doc/license assets served at /assets/* (proxied by the API's
  // GET /plugins/:id/asset) — referenced from discovery.deviceSupport.
  assetsDir: path.join(__dirname, '../..'),
  discovery: {
    requiredSecretType: null,
    metrics: METRIC_DESCRIPTORS,
    options: [],
    iconUrl: '/icons/syslog-collector.svg',
    // License/help/docs metadata for UNM's Plugins page (see ./deviceSupport.ts).
    deviceSupport: SYSLOG_COLLECTOR_DEVICE_SUPPORT,
  },
  selfMetricsExtra: () => ({
    syslogMessagesPerSec: stats.messagesPerSec,
    syslogEventsEmittedPerSec: stats.eventsEmittedPerSec,
    syslogDroppedEventsTotal: stats.droppedEventsTotal,
    syslogQueueDepth: pushQueue.length,
    syslogPushesTotal: stats.pushesTotal,
    syslogPushFailuresTotal: stats.pushFailuresTotal,
  }),
});

// Structured logs shipped to the API (boot errors, socket failures).
const logger = createPluginLogger(identity);

/** POST /monitoring — no device-facing work; reports collector health. */
server.app.post('/monitoring', (_req, res) => {
  const metrics: Record<string, unknown> = {
    'syslog.messagesPerSec': stats.messagesPerSec,
    'syslog.eventsEmittedPerSec': stats.eventsEmittedPerSec,
    'syslog.droppedEventsTotal': stats.droppedEventsTotal,
    'syslog.queueDepth': pushQueue.length,
    'syslog.pushesTotal': stats.pushesTotal,
    'syslog.pushFailuresTotal': stats.pushFailuresTotal,
  };
  res.status(200).json({
    collectedAt: new Date().toISOString(),
    health: (stats.droppedEventsTotal > 0 ? 'warning' : 'ok') as Health,
    metrics,
    metricDescriptors: METRIC_DESCRIPTORS,
  });
});

// ── Line parsing lives in ./syslogParser (+ vendor IP extraction) ───────────

/** One normalized security-event row (push wire shape — see POST /plugin/security-events). */
interface SecurityEventRow {
  tsMs: number;
  level: 'debug' | 'info' | 'warn' | 'error';
  severity: string;
  facility: string;
  hostname: string;
  appname: string | null;
  srcIp: string | null;
  dstIp: string | null;
  message: string;
  /** Stable dedup key — sha1(hostname|tsMs|message); the API ignores re-sends. */
  vendorEventId: string;
}

const stats = {
  messagesReceivedTotal: 0,
  eventsEmittedTotal: 0,
  droppedEventsTotal: 0,
  parseErrorsTotal: 0,
  pushesTotal: 0,
  pushFailuresTotal: 0,
  lastPushAt: null as string | null,
  messagesPerSec: 0,
  eventsEmittedPerSec: 0,
};

/** Bounded push queue (oldest dropped on overflow). */
const pushQueue: SecurityEventRow[] = [];

function enqueue(row: SecurityEventRow): void {
  pushQueue.push(row);
  stats.eventsEmittedTotal += 1;
  const overflow = pushQueue.length - MAX_QUEUE_EVENTS;
  if (overflow > 0) {
    pushQueue.splice(0, overflow);
    stats.droppedEventsTotal += overflow;
  }
}

/** Parse one received line and enqueue the normalized row. */
function handleLine(line: string): void {
  const parsed = parseSyslogLine(line);
  if (!parsed) {
    stats.parseErrorsTotal += 1;
    return;
  }
  // BSD syslog carries NO timezone — stamps are interpreted in the collector's
  // local zone (SYSLOG_TZ). When that doesn't match the sender's zone, parsed
  // stamps land in the FUTURE. A stamp more than 5 minutes ahead is a broken
  // clock / TZ mismatch; clamp to now so rows stay inside "now"-anchored query
  // windows and can never poison automation watermarks (which advance
  // monotonically over tsMs). RFC5424 lines carry explicit offsets — only
  // genuinely skewed clocks hit this.
  if (parsed.tsMs > Date.now() + 300_000) parsed.tsMs = Date.now();
  const ips = extractVendorIps(parsed.message);
  enqueue({
    tsMs: parsed.tsMs,
    level: parsed.level,
    severity: parsed.severity,
    facility: parsed.facility,
    hostname: parsed.hostname,
    appname: parsed.appname || null,
    srcIp: ips?.srcIp ?? null,
    dstIp: ips?.dstIp ?? null,
    message: parsed.message,
    vendorEventId: crypto.createHash('sha1').update(`${parsed.hostname}|${parsed.tsMs}|${parsed.message}`).digest('hex'),
  });
}

// ── UDP socket (RFC 5424 + BSD — sniffed per line) ──────────────────────────

function startUdpSocket(): void {
  const sock = dgram.createSocket({ type: 'udp4', reuseAddr: true });
  // Large receive buffer — syslog bursts are the norm, not the exception.
  try { sock.setRecvBufferSize(8 * 1024 * 1024); } catch { /* best effort */ }

  sock.on('message', (msg) => {
    const text = msg.toString('utf8');
    // A datagram normally carries one line, but multi-line payloads happen.
    for (const line of text.split('\n')) {
      if (line.trim() === '') continue;
      stats.messagesReceivedTotal += 1;
      handleLine(line);
    }
  });
  sock.on('error', (err) => {
    logger.error(`syslog UDP socket error on :${SYSLOG_PORT}`, { context: { error: err.message } });
  });

  sock.bind(SYSLOG_PORT, () => {
    // eslint-disable-next-line no-console
    console.log(`[syslog-collector] syslog listener live on udp/${SYSLOG_PORT}`);
  });
}

// ── TCP server (newline-delimited; some senders prefer reliable transport) ──

function startTcpServer(): void {
  const srv = net.createServer((socket: net.Socket) => {
    let buf = '';
    socket.setEncoding('utf8');
    socket.on('data', (chunk: string) => {
      buf += chunk;
      // Runaway guard — a sender that never emits newlines must not grow memory.
      if (buf.length > MAX_LINE_CHARS * 2) {
        stats.parseErrorsTotal += 1;
        buf = '';
        return;
      }
      let idx: number;
      while ((idx = buf.indexOf('\n')) !== -1) {
        const line = buf.slice(0, idx).replace(/\r$/, '');
        buf = buf.slice(idx + 1);
        if (line.trim() === '') continue;
        stats.messagesReceivedTotal += 1;
        handleLine(line);
      }
    });
    socket.on('error', () => { /* client disconnects are normal — don't crash */ });
  });

  srv.on('error', (err) => {
    logger.error(`syslog TCP server error on :${SYSLOG_PORT}`, { context: { error: err.message } });
  });

  srv.listen(SYSLOG_PORT, () => {
    // eslint-disable-next-line no-console
    console.log(`[syslog-collector] syslog listener live on tcp/${SYSLOG_PORT}`);
  });
}

// ── Push pipeline (fire-and-forget batches to POST /plugin/security-events) ─

const api = axios.create({
  baseURL: (process.env.UNM_API_URL ?? 'http://localhost:3000/v1').replace(/\/+$/, ''),
  timeout: 5_000,
  headers: process.env.PLUGIN_API_KEY ? { 'x-plugin-api-key': process.env.PLUGIN_API_KEY } : undefined,
});

async function pushBatch(rows: SecurityEventRow[]): Promise<void> {
  const body = { pluginId: identity.effectiveUuid, events: rows };
  try {
    await api.post('/plugin/security-events', body);
    stats.pushesTotal += 1;
    stats.lastPushAt = new Date().toISOString();
  } catch (err) {
    // One retry after a short pause — then drop the batch (counted).
    await new Promise((r) => setTimeout(r, 500));
    try {
      await api.post('/plugin/security-events', body);
      stats.pushesTotal += 1;
      stats.lastPushAt = new Date().toISOString();
    } catch {
      stats.pushFailuresTotal += 1;
      logger.warn(`Dropped syslog batch of ${rows.length} events (API unreachable)`);
    }
  }
}

function startPushLoop(): void {
  setInterval(() => {
    if (pushQueue.length === 0) return;
    const batch = pushQueue.splice(0, PUSH_BATCH_SIZE);
    void pushBatch(batch);
  }, PUSH_INTERVAL_MS);

  // Periodic rate computation for self-metrics (1 Hz).
  let lastMessages = stats.messagesReceivedTotal;
  let lastEvents = stats.eventsEmittedTotal;
  setInterval(() => {
    stats.messagesPerSec = Math.max(0, stats.messagesReceivedTotal - lastMessages);
    stats.eventsEmittedPerSec = Math.max(0, stats.eventsEmittedTotal - lastEvents);
    lastMessages = stats.messagesReceivedTotal;
    lastEvents = stats.eventsEmittedTotal;
  }, 1_000);
}

// ── Boot ────────────────────────────────────────────────────────────────────

if (UDP_ENABLED) startUdpSocket();
if (TCP_ENABLED) startTcpServer();
startPushLoop();

server.listen().catch((err: Error) => {
  // eslint-disable-next-line no-console
  console.error('[syslog-collector] failed to start HTTP server:', err.message);
  process.exit(1);
});
