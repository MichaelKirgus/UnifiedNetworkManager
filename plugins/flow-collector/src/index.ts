/**
 * Flow collector plugin — sFlow + NetFlow v5/v9 receiver for the UNM Flows feature.
 *
 * A GLOBAL service plugin (no device assignment, no credentials): it listens on
 * UDP for flow samples pushed by network devices (LANCOM LX, OPNsense, …),
 * parses them (sFlow v1/5 or NetFlow v5/v9 — sniffed per datagram),
 * PRE-AGGREGATES them in-process into per-window
 * (srcIp,dstIp,proto) tuples and pushes compact batches to the UNM API's
 * internal POST /plugin/flows endpoint. The API enqueues the rows; a
 * leader-gated worker persists + enriches + rolls them up (see
 * api/src/workers/flows.ts). Pre-aggregation here is what keeps the volume
 * manageable: tens of millions of raw samples/day become ~1-10M tuples.
 *
 * Multi-exporter dedup: several devices on the path (distribution switch,
 * core switch, router) all export the SAME flow. Every one of them sees ~100%
 * of its packets, so summing all exporters would overcount ×N. The window
 * therefore accumulates per (tuple, exporter) and at flush keeps only the
 * BEST OBSERVATION — the agent with the highest estimated bytes (reported ×
 * sampling rate, comparable across different rates; an agent whose port was
 * down part of the window has fewer bytes and loses). `agentCount` records how
 * many distinct exporters saw the tuple so the UI can show where dedup kicked
 * in. Caveat: with ECMP/LACP path-splitting no single exporter sees 100%, so
 * best-observation is then an undercount — still far closer than ×N overcount.
 *
 * Backpressure model: the UDP receive path NEVER blocks on the API. Parsed
 * tuples go into a bounded in-memory queue; overflow drops the OLDEST tuples
 * (counted + surfaced via self-metrics). Pushes are fire-and-forget with one
 * retry — same semantics as the SDK's log pipeline.
 *
 * Protocol support: sFlow v1/5 (sampled packets + flow records, IPv4/IPv6)
 * and NetFlow v5/v9 (RFC 3954; v9 templates cached per SourceID).
 * IPFIX arrives in a follow-up phase behind the same tuple normalization.
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
import { FLOW_COLLECTOR_DEVICE_SUPPORT } from './deviceSupport';
import axios from 'axios';
import { parseFlowDatagram } from './dispatch';

export const PLUGIN_UUID = '00000000-0000-4000-8000-0000000012';
export const PLUGIN_NAME = 'Flow Collector (sFlow/NetFlow)';

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
  { key: 'flow.multiObservedTuples', label: 'Multi-observed tuples (deduped, total)', type: 'number', visualization: 'text', group: 'Flow' },
];

// Pre-wired app: cors + json + /healthz + /discover (+ static icons, mDNS on
// listen) come from @unm/plugin-sdk. Custom gauges ride on GET /metrics via
// selfMetricsExtra (polled by the API's plugin-metrics worker).
const server = createPluginServer({
  identity,
  logTag: 'flow-collector-plugin',
  iconsDir: path.join(__dirname, '../../icons'),
  // Static doc/license assets served at /assets/* (proxied by the API's
  // GET /plugins/:id/asset) — referenced from discovery.deviceSupport.
  assetsDir: path.join(__dirname, '../..'),
  discovery: {
    requiredSecretType: null,
    metrics: METRIC_DESCRIPTORS,
    options: [],
    iconUrl: '/icons/flow-collector.svg',
    // License/help/docs metadata for UNM's Plugins page (see ./deviceSupport.ts).
    deviceSupport: FLOW_COLLECTOR_DEVICE_SUPPORT,
  },
  selfMetricsExtra: () => ({
    flowSamplesPerSec: stats.samplesPerSec,
    flowTuplesPerSec: stats.tuplesPerSec,
    flowDroppedTuplesTotal: stats.droppedTuplesTotal,
    flowQueueDepth: pushQueue.length,
    flowPushesTotal: stats.pushesTotal,
    flowPushFailuresTotal: stats.pushFailuresTotal,
    flowMultiObservedTuples: stats.multiObservedTuplesTotal,
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
    'flow.multiObservedTuples': stats.multiObservedTuplesTotal,
  };
  res.status(200).json({
    collectedAt: new Date().toISOString(),
    health: (stats.droppedTuplesTotal > 0 ? 'warning' : 'ok') as Health,
    metrics,
    metricDescriptors: METRIC_DESCRIPTORS,
  });
});

// ── Datagram parsing lives in ./sflowParser, ./netflowParser, ./dispatch ───
// sFlow: RFC 3176. NetFlow v5: Cisco legacy format. NetFlow v9: RFC 3954.

/** One normalized flow tuple (pre-aggregation input + push wire shape). */
interface FlowTuple {
  ts: string; // window-start ISO instant
  srcIp: string;
  dstIp: string;
  proto: number;
  srcPort: number;
  dstPort: number;
  bytes: number;
  packets: number;
  sampleCount: number;
  sampleRate: number;
  /** Exporter that contributed the (deduplicated) counters — best observation. */
  agentIp: string;
  /** How many distinct exporters observed this tuple in the window (>1 = deduped). */
  agentCount: number;
}

/** Aggregation map key. */
type TupleKey = string; // `${src}|${dst}|${proto}|${sp}|${dp}`

/** Per-agent counters for one tuple within the current window. */
interface AgentAccum {
  bytes: number;
  packets: number;
  sampleCount: number;
  sampleRate: number;
}

const stats = {
  samplesReceivedTotal: 0,
  tuplesEmittedTotal: 0,
  droppedTuplesTotal: 0,
  parseErrorsTotal: 0,
  pushesTotal: 0,
  pushFailuresTotal: 0,
  multiObservedTuplesTotal: 0,
  lastPushAt: null as string | null,
  samplesPerSec: 0,
  tuplesPerSec: 0,
};

// Rolling pre-aggregation window — per tuple, per EXPORTER (see the module
// header for why the flush keeps only the best observation).
let windowStartMs = Date.now();
let windowTuples = new Map<TupleKey, Map<string, AgentAccum>>();

/** Bounded push queue (oldest dropped on overflow). */
const pushQueue: FlowTuple[] = [];

function addSample(srcIp: string, dstIp: string, proto: number, srcPort: number, dstPort: number, bytes: number, packets: number, sampleRate: number, agentIp: string): void {
  const key = `${srcIp}|${dstIp}|${proto}|${srcPort}|${dstPort}`;
  let agents = windowTuples.get(key);
  if (!agents) {
    agents = new Map();
    windowTuples.set(key, agents);
  }
  let a = agents.get(agentIp);
  if (!a) {
    a = { bytes: 0, packets: 0, sampleCount: 0, sampleRate };
    agents.set(agentIp, a);
  }
  a.bytes += bytes;
  a.packets += packets;
  a.sampleCount += 1;
  if (sampleRate > a.sampleRate) a.sampleRate = sampleRate;
}

/** Flush the current window into the push queue. */
function flushWindow(): void {
  if (windowTuples.size === 0) return;
  for (const [key, agents] of windowTuples) {
    // Best-observation dedup — see module header: keep the agent with the
    // highest ESTIMATED bytes (reported × rate; comparable across different
    // sampling rates), count how many exporters saw the tuple.
    let bestIp = '';
    let bestAcc: AgentAccum | null = null;
    for (const [ip, acc] of agents) {
      if (!bestAcc || acc.bytes * acc.sampleRate > bestAcc.bytes * bestAcc.sampleRate) {
        bestIp = ip;
        bestAcc = acc;
      }
    }
    const [srcIp, dstIp, protoStr, spStr, dpStr] = key.split('|');
    pushQueue.push({
      ts: new Date(windowStartMs).toISOString(),
      srcIp,
      dstIp,
      proto: Number(protoStr),
      srcPort: Number(spStr),
      dstPort: Number(dpStr),
      bytes: bestAcc!.bytes,
      packets: bestAcc!.packets,
      sampleCount: bestAcc!.sampleCount,
      sampleRate: bestAcc!.sampleRate,
      agentIp: bestIp,
      agentCount: agents.size,
    });
    stats.tuplesEmittedTotal += 1;
    if (agents.size > 1) stats.multiObservedTuplesTotal += 1;
  }
  const overflow = pushQueue.length - MAX_QUEUE_TUPLES;
  if (overflow > 0) {
    pushQueue.splice(0, overflow);
    stats.droppedTuplesTotal += overflow;
  }
  windowTuples = new Map();
  windowStartMs = Date.now();
}

// ── UDP socket (sFlow + NetFlow v5/v9 — sniffed per datagram) ───────────────

function startSflowSocket(): void {
  const sock = dgram.createSocket({ type: 'udp4', reuseAddr: true });
  // Large receive buffer — flow bursts are the norm, not the exception.
  try { sock.setRecvBufferSize(8 * 1024 * 1024); } catch { /* best effort */ }

  sock.on('message', (msg, rinfo) => {
    stats.samplesReceivedTotal += 1;
    // NetFlow carries no in-payload exporter identity — the UDP source IS it.
    for (const f of parseFlowDatagram(msg, rinfo.address)) {
      // f.agentIp = sFlow header agent address or the UDP source (NetFlow).
      addSample(f.srcIp, f.dstIp, f.proto, f.srcPort, f.dstPort, f.bytes, f.packets, f.sampleRate, f.agentIp);
    }
  });
  sock.on('error', (err) => {
    logger.error(`sFlow UDP socket error on :${SFLOW_PORT}`, { context: { error: err.message } });
  });

  sock.bind(SFLOW_PORT, () => {
    // eslint-disable-next-line no-console
    console.log(`[flow-collector] flow listener (sFlow/NetFlow v5/v9) live on udp/${SFLOW_PORT}`);
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
    // a = agentIp (best-observation exporter), ac = distinct-exporter count.
    samples: rows.map((t) => ({ s: t.srcIp, d: t.dstIp, p: t.proto, sp: t.srcPort, dp: t.dstPort, b: t.bytes, k: t.packets, n: t.sampleCount, r: t.sampleRate, ts: t.ts, a: t.agentIp, ac: t.agentCount })),
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
