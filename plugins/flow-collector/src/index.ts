/**
 * Flow collector plugin — sFlow (v1) receiver for the UNM Flows feature.
 *
 * A GLOBAL service plugin (no device assignment, no credentials): it listens on
 * UDP for flow samples pushed by network devices (LANCOM LX, OPNsense, …),
 * parses them, PRE-AGGREGATES them in-process into per-window
 * (srcIp,dstIp,proto) tuples and pushes compact batches to the UNM API's
 * internal POST /plugin/flows endpoint. The API enqueues the rows; a
 * leader-gated worker persists + enriches + rolls them up (see
 * api/src/workers/flows.ts). Pre-aggregation here is what keeps the volume
 * manageable: tens of millions of raw samples/day become ~1-10M tuples.
 *
 * Backpressure model: the UDP receive path NEVER blocks on the API. Parsed
 * tuples go into a bounded in-memory queue; overflow drops the OLDEST tuples
 * (counted + surfaced via self-metrics). Pushes are fire-and-forget with one
 * retry — same semantics as the SDK's log pipeline.
 *
 * v1 protocol support: sFlow v1 (sampled packets + flow records, IPv4/IPv6).
 * NetFlow v5/v9/IPFIX arrive in a follow-up phase behind the same tuple
 * normalization (see plan).
 */

import dgram from 'dgram';
import path from 'path';
import {
  Health,
  MetricDescriptor,
  createPluginLogger,
  createPluginServer,
  resolvePluginIdentity,
} from '@unm/plugin-sdk';
import axios from 'axios';
import { parseSflowDatagram } from './sflowParser';

export const PLUGIN_UUID = '00000000-0000-4000-8000-0000000012';
export const PLUGIN_NAME = 'Flow Collector (sFlow)';

/**
 * Multi-instance support: set `PLUGIN_INSTANCE_ID` (e.g. "site-a") to run
 * several collectors — each advertises a distinct identity (`<uuid>:<id>`) so
 * the API registers them as separate plugins and attributes tuples per
 * collector. Unset = single instance.
 */
const identity = resolvePluginIdentity({
  uuid: PLUGIN_UUID,
  name: PLUGIN_NAME,
  version: '0.1.0',
  vendors: ['generic'],
  // No device-facing capabilities — this is a push-based ingest service. The
  // API's plugin-metrics worker still polls GET /metrics (SDK auto-mounted)
  // for its runtime health; the custom gauges below carry collector stats.
  capabilities: [],
});

// ── Runtime configuration (env — global service, no per-device settings) ────

const SFLOW_PORT = Math.max(1, Math.min(65_535, Number(process.env.SFLOW_PORT ?? 6343)));
const AGG_WINDOW_MS = Math.max(1_000, Number(process.env.FLOW_AGG_WINDOW_MS ?? 5_000)); // pre-agg window
const PUSH_INTERVAL_MS = Math.max(1_000, Number(process.env.FLOW_PUSH_INTERVAL_MS ?? 3_000));
const MAX_QUEUE_TUPLES = Math.max(1_000, Number(process.env.FLOW_MAX_QUEUE_TUPLES ?? 50_000));
const PUSH_BATCH_SIZE = 20_000; // API caps requests at 20k samples

// ── Metric descriptors (rendered on the Plugins page) ───────────────────────

const METRIC_DESCRIPTORS: MetricDescriptor[] = [
  { key: 'flow.samplesPerSec', label: 'Samples received/s', type: 'number', visualization: 'plot', group: 'Flow', color: '#3b82f6', summary: true },
  { key: 'flow.tuplesPerSec', label: 'Aggregated tuples/s', type: 'number', visualization: 'plot', group: 'Flow' },
  { key: 'flow.droppedTuplesTotal', label: 'Dropped tuples (total)', type: 'number', visualization: 'text', group: 'Flow' },
  { key: 'flow.queueDepth', label: 'Push queue depth', type: 'number', visualization: 'plot', group: 'Flow', color: '#f59e0b' },
  { key: 'flow.pushesTotal', label: 'Push batches (total)', type: 'number', visualization: 'text', group: 'Flow' },
  { key: 'flow.pushFailuresTotal', label: 'Failed pushes (total)', type: 'number', visualization: 'text', group: 'Flow' },
];

// Pre-wired app: cors + json + /healthz + /discover (+ static icons, mDNS on
// listen) come from @unm/plugin-sdk. Custom gauges ride on GET /metrics via
// selfMetricsExtra (polled by the API's plugin-metrics worker).
const server = createPluginServer({
  identity,
  logTag: 'flow-collector-plugin',
  iconsDir: path.join(__dirname, '../../icons'),
  discovery: {
    requiredSecretType: null,
    metrics: METRIC_DESCRIPTORS,
    options: [],
    iconUrl: '/icons/flow-collector.svg',
  },
  selfMetricsExtra: () => ({
    flowSamplesPerSec: stats.samplesPerSec,
    flowTuplesPerSec: stats.tuplesPerSec,
    flowDroppedTuplesTotal: stats.droppedTuplesTotal,
    flowQueueDepth: pushQueue.length,
    flowPushesTotal: stats.pushesTotal,
    flowPushFailuresTotal: stats.pushFailuresTotal,
  }),
});

// Structured logs shipped to the API (boot errors, socket failures).
const logger = createPluginLogger(identity);

/** POST /monitoring — no device-facing work; reports collector health. */
server.app.post('/monitoring', (_req, res) => {
  const metrics: Record<string, unknown> = {
    'flow.samplesPerSec': stats.samplesPerSec,
    'flow.tuplesPerSec': stats.tuplesPerSec,
    'flow.droppedTuplesTotal': stats.droppedTuplesTotal,
    'flow.queueDepth': pushQueue.length,
    'flow.pushesTotal': stats.pushesTotal,
    'flow.pushFailuresTotal': stats.pushFailuresTotal,
  };
  res.status(200).json({
    collectedAt: new Date().toISOString(),
    health: (stats.droppedTuplesTotal > 0 ? 'warning' : 'ok') as Health,
    metrics,
    metricDescriptors: METRIC_DESCRIPTORS,
  });
});

// ── sFlow v1 parsing ────────────────────────────────────────────────────────
// Reference: RFC 3176 (sFlow v5 wire format is "sFlow" — the protocol version
// field in the header is 1 for the original and 5 for the current; both share
// the same record layout we parse here).

/** One normalized flow tuple (pre-aggregation input + push wire shape). */
interface FlowTuple {
  ts: string; // window-start ISO instant
  srcIp: string;
  dstIp: string;
  proto: number;
  bytes: number;
  packets: number;
  sampleCount: number;
  sampleRate: number;
}

/** Aggregation map key. */
type TupleKey = string; // `${src}|${dst}|${proto}`

const stats = {
  samplesReceivedTotal: 0,
  tuplesEmittedTotal: 0,
  droppedTuplesTotal: 0,
  parseErrorsTotal: 0,
  pushesTotal: 0,
  pushFailuresTotal: 0,
  lastPushAt: null as string | null,
  samplesPerSec: 0,
  tuplesPerSec: 0,
};

// Rolling pre-aggregation window.
let windowStartMs = Date.now();
let windowTuples = new Map<TupleKey, FlowTuple>();

/** Bounded push queue (oldest dropped on overflow). */
const pushQueue: FlowTuple[] = [];

function addSample(srcIp: string, dstIp: string, proto: number, bytes: number, packets: number, sampleRate: number): void {
  const key = `${srcIp}|${dstIp}|${proto}`;
  let t = windowTuples.get(key);
  if (!t) {
    t = { ts: new Date(windowStartMs).toISOString(), srcIp, dstIp, proto, bytes: 0, packets: 0, sampleCount: 0, sampleRate };
    windowTuples.set(key, t);
  }
  t.bytes += bytes;
  t.packets += packets;
  t.sampleCount += 1;
  if (sampleRate > t.sampleRate) t.sampleRate = sampleRate;
}

/** Flush the current window into the push queue. */
function flushWindow(): void {
  if (windowTuples.size === 0) return;
  for (const t of windowTuples.values()) {
    pushQueue.push(t);
    stats.tuplesEmittedTotal += 1;
  }
  const overflow = pushQueue.length - MAX_QUEUE_TUPLES;
  if (overflow > 0) {
    pushQueue.splice(0, overflow);
    stats.droppedTuplesTotal += overflow;
  }
  windowTuples = new Map();
  windowStartMs = Date.now();
}

// ── sFlow datagram parsing lives in ./sflowParser (pure module, unit-tested) ─

// ── UDP socket (sFlow) ──────────────────────────────────────────────────────

function startSflowSocket(): void {
  const sock = dgram.createSocket({ type: 'udp4', reuseAddr: true });
  // Large receive buffer — flow bursts are the norm, not the exception.
  try { sock.setRecvBufferSize(8 * 1024 * 1024); } catch { /* best effort */ }

  sock.on('message', (msg) => {
    stats.samplesReceivedTotal += 1;
    for (const f of parseSflowDatagram(msg)) {
      addSample(f.srcIp, f.dstIp, f.proto, f.bytes, f.packets, f.sampleRate);
    }
  });
  sock.on('error', (err) => {
    logger.error(`sFlow UDP socket error on :${SFLOW_PORT}`, { context: { error: err.message } });
  });

  sock.bind(SFLOW_PORT, () => {
    // eslint-disable-next-line no-console
    console.log(`[flow-collector] sFlow listener live on udp/${SFLOW_PORT}`);
  });
}

// ── Push pipeline (fire-and-forget batches to POST /plugin/flows) ───────────

const api = axios.create({
  baseURL: (process.env.UNM_API_URL ?? 'http://localhost:3000/v1').replace(/\/+$/, ''),
  timeout: 5_000,
  headers: process.env.PLUGIN_API_KEY ? { 'x-plugin-api-key': process.env.PLUGIN_API_KEY } : undefined,
});

async function pushBatch(rows: FlowTuple[]): Promise<void> {
  const body = {
    pluginId: identity.effectiveUuid,
    samples: rows.map((t) => ({ s: t.srcIp, d: t.dstIp, p: t.proto, b: t.bytes, k: t.packets, n: t.sampleCount, r: t.sampleRate, ts: t.ts })),
  };
  try {
    await api.post('/plugin/flows', body);
    stats.pushesTotal += 1;
    stats.lastPushAt = new Date().toISOString();
  } catch (err) {
    // One retry after a short pause — then drop the batch (counted).
    await new Promise((r) => setTimeout(r, 500));
    try {
      await api.post('/plugin/flows', body);
      stats.pushesTotal += 1;
      stats.lastPushAt = new Date().toISOString();
    } catch {
      stats.pushFailuresTotal += 1;
      logger.warn(`Dropped flow batch of ${rows.length} tuples (API unreachable)`);
    }
  }
}

function startPushLoop(): void {
  setInterval(() => {
    if (pushQueue.length === 0) return;
    // Flush the window first so in-flight samples join this push.
    flushWindow();
    const batch = pushQueue.splice(0, PUSH_BATCH_SIZE);
    void pushBatch(batch);
  }, PUSH_INTERVAL_MS);

  // Periodic rate computation for self-metrics (1 Hz).
  let lastSamples = stats.samplesReceivedTotal;
  let lastTuples = stats.tuplesEmittedTotal;
  setInterval(() => {
    stats.samplesPerSec = Math.max(0, stats.samplesReceivedTotal - lastSamples);
    stats.tuplesPerSec = Math.max(0, stats.tuplesEmittedTotal - lastTuples);
    lastSamples = stats.samplesReceivedTotal;
    lastTuples = stats.tuplesEmittedTotal;
  }, 1_000);

  // Window flush timer (independent of the push loop so tuples age out even
  // when the queue is empty).
  setInterval(() => {
    if (Date.now() - windowStartMs >= AGG_WINDOW_MS) flushWindow();
  }, Math.min(1_000, AGG_WINDOW_MS));
}

// ── Boot ────────────────────────────────────────────────────────────────────

startSflowSocket();
startPushLoop();

server.listen().catch((err: Error) => {
  // eslint-disable-next-line no-console
  console.error('[flow-collector] failed to start HTTP server:', err.message);
  process.exit(1);
});
