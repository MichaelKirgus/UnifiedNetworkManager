/**
 * Topology graph builder — pure functions that turn normalized inventory rows
 * (+ the latest telemetry snapshots for port detail) into a device graph with
 * PHYSICAL links (inferred from switch MAC tables, LACP partners and tunnels)
 * and LOGICAL segments (merged networks / VLANs). No DB access here: the route
 * loads the inputs, this module computes. Everything is hash-map based —
 * O(devices + mac entries), no pairwise device comparisons — so it stays fast
 * at 100+ devices with thousands of MAC-table entries.
 */

import { mergeNetworkRows } from '../routes/networks';

// ---------- input shapes (the route maps DB rows into these) ----------

export interface TopoDeviceInput {
  id: string;
  name: string;
  status: string;
  siteId: string | null;
  managementAddress: string;
}

export interface TopoNetworkRow {
  deviceId: string;
  pluginId: string;
  name: string;
  ip: string;
  prefix: number | null;
  version: string | null;
  vlanId: number | null;
  mac: string | null;
  status: string | null;
  collectedAt: string;
}

export interface TopoHostRow {
  deviceId: string;
  pluginId: string;
  mac: string;
  ip: string;
  source: string;
  hostname: string | null;
  intf: string | null;
  lastSeenAt: string;
}

export interface TopoTunnelRow {
  deviceId: string;
  name: string;
  type: string;
  peerAddress: string;
  localAddress: string;
  status: string;
}

export interface TopoDeviceIp {
  deviceId: string;
  address: string;
}

/** One latest telemetry snapshot per device+plugin assignment (metrics parsed). */
export interface TopoSnapshot {
  deviceId: string;
  pluginId: string;
  metrics: Record<string, unknown>;
}

// ---------- output shapes (serialized by GET /topology) ----------

/** A physical port as reported by the latest snapshot of one device. */
export interface TopologyPort {
  name: string;
  linkUp?: 'up' | 'down';
  speed?: string | null;
  /** access | trunk | hybrid (switches that report it). */
  mode?: string | null;
  pvid?: number | null;
  /** VLANs traversing this port — drives the per-VLAN edge coloring. */
  vlans: number[];
  mac?: string | null;
}

export type TopologyNode =
  | {
      id: string;
      kind: 'device';
      name: string;
      status: string;
      siteId: string | null;
      managementAddress: string;
      ports: TopologyPort[];
      /** VLAN ids this device participates in (from its networks rows). */
      vlans: number[];
    }
  | { id: string; kind: 'segment'; label: string; vlanId: number | null; subnets: string[] }
  | { id: string; kind: 'host'; mac: string; hostname: string | null; ips: string[] }
  /** Unmanaged tunnel far end (public IP / FQDN) — drawn so site-to-site
   * tunnels stay visible even when the peer device is not in UNM. */
  | { id: string; kind: 'remote'; label: string };

export type TopologyEdge =
  | {
      id: string;
      source: string;
      target: string;
      kind: 'cable';
      /** Evidence the link was inferred from. */
      via: 'mac-table' | 'lacp';
      portA?: string | null;
      portB?: string | null;
      /** VLANs traversing the observing port (trunk coloring); empty = unknown. */
      vlans: number[];
    }
  | { id: string; source: string; target: string; kind: 'tunnel'; type: string; status: string | null }
  | { id: string; source: string; target: string; kind: 'membership'; vlanId: number | null };

export interface TopologyInput {
  devices: TopoDeviceInput[];
  networks: TopoNetworkRow[];
  hosts: TopoHostRow[];
  tunnels: TopoTunnelRow[];
  deviceIps: TopoDeviceIp[];
  snapshots: TopoSnapshot[];
  /** When true, end-hosts (ARP/MAC-table entries) are added as nodes. */
  includeHosts?: boolean;
}

export interface TopologyResult {
  nodes: TopologyNode[];
  edges: TopologyEdge[];
}

// ---------- small helpers ----------

/** Normalizes a MAC for comparison: lowercase hex only (separators stripped). */
function normMac(mac: string | null | undefined): string | null {
  if (!mac) return null;
  const hex = mac.replace(/[^0-9a-f]/gi, '').toLowerCase();
  return hex.length >= 6 ? hex : null;
}

function toInt(v: unknown): number | null {
  if (typeof v === 'number' && Number.isFinite(v)) return Math.trunc(v);
  if (typeof v === 'string') {
    const n = parseInt(v, 10);
    if (Number.isFinite(n) && String(n) === v.trim()) return n;
  }
  return null;
}

function strOrNull(v: unknown): string | null {
  return typeof v === 'string' && v !== '' ? v : null;
}

/**
 * Normalizes an endpoint address to a bare IP literal for device matching:
 * strips IPv6 brackets + port ("[2003::1]:51820"), CIDR prefixes
 * ("10.1.2.21/30") and splits comma-separated lists (dual-stack rows).
 * Returns [] when nothing IP-like remains (FQDNs, empty strings).
 */
export function normalizeAddress(addr: string | null | undefined): string[] {
  if (!addr) return [];
  const out = new Set<string>();
  for (let part of addr.split(',')) {
    part = part.trim();
    if (!part) continue;
    // "[2003::5]:51820" → "2003::5" — bracketed v6 with optional trailing :port.
    const b = /^\[(.+)\](?::\d+)?$/.exec(part);
    if (b) part = b[1];
    const slash = part.indexOf('/');
    if (slash !== -1) part = part.slice(0, slash); // CIDR prefix
    if (/^[0-9a-fA-F.:]+$/.test(part)) out.add(part.toLowerCase());
  }
  return Array.from(out);
}

/** Expands a VLAN list like "1,10-13" into [1, 10, 11, 12, 13]. */
export function expandVlanList(s: unknown): number[] {
  if (typeof s !== 'string' || !s.trim() || s.trim() === '-') return [];
  const out = new Set<number>();
  for (const part of s.split(',')) {
    const p = part.trim();
    const range = /^(\d+)\s*-\s*(\d+)$/.exec(p);
    if (range) {
      const a = Number(range[1]);
      const b = Number(range[2]);
      for (let v = Math.min(a, b); v <= Math.max(a, b); v++) out.add(v);
    } else if (/^\d+$/.test(p)) {
      out.add(Number(p));
    }
  }
  return Array.from(out).sort((a, b) => a - b);
}

/**
 * Parses per-port detail from one snapshot's metrics. Detection is by metric
 * SHAPE (not plugin id), so it keeps working if plugins are renamed:
 *   - lancom-sx style:  `ports.table` [{name, linkUp, speedStatus, vlanModeLabel, pvid, allowedVlans}]
 *   - mikrotik-swos:    `switch.portStats` + `vlans.perPort`
 *   - lancom-lx style:  `lan.ports` [{name, linkUp, speedLabel, mac}]
 */
function parsePorts(metrics: Record<string, unknown>): TopologyPort[] {
  const pt = metrics['ports.table'];
  if (Array.isArray(pt)) {
    return pt
      .filter((r): r is Record<string, unknown> => !!r && typeof r === 'object')
      .map((o) => {
        const pvid = toInt(o.pvid);
        const mode = strOrNull(o.vlanModeLabel);
        let vlans: number[];
        if (mode === 'access') {
          vlans = pvid !== null ? [pvid] : [];
        } else {
          const allowed = expandVlanList(o.allowedVlans);
          vlans = allowed.length > 0 ? allowed : pvid !== null ? [pvid] : [];
        }
        return {
          name: String(o.name ?? ''),
          linkUp: o.linkUp === 'up' || o.linkUp === 'down' ? (o.linkUp as 'up' | 'down') : undefined,
          speed: strOrNull(o.speedStatus),
          mode,
          pvid,
          vlans,
        };
      })
      .filter((p) => p.name !== '');
  }

  const stats = metrics['switch.portStats'];
  if (Array.isArray(stats)) {
    const perPort = Array.isArray(metrics['vlans.perPort'])
      ? (metrics['vlans.perPort'] as Record<string, unknown>[])
      : [];
    return stats
      .filter((r): r is Record<string, unknown> => !!r && typeof r === 'object')
      .map((o) => {
        const name = String(o.port ?? '');
        const pp = perPort.find((x) => x && typeof x === 'object' && String(x.port) === name);
        const vlans: number[] = [];
        if (pp) {
          const d = toInt(pp.defaultVlanId);
          const f = toInt(pp.forceVlanId);
          if (d !== null) vlans.push(d);
          if (f !== null && !vlans.includes(f)) vlans.push(f);
        }
        return { name, vlans };
      })
      .filter((p) => p.name !== '');
  }

  const lp = metrics['lan.ports'];
  if (Array.isArray(lp)) {
    return lp
      .filter((r): r is Record<string, unknown> => !!r && typeof r === 'object')
      .map((o) => ({
        name: String(o.name ?? ''),
        linkUp: o.linkUp === 'up' || o.linkUp === 'down' ? (o.linkUp as 'up' | 'down') : undefined,
        speed: strOrNull(o.speedLabel),
        vlans: [] as number[],
        mac: strOrNull(o.mac) ?? null,
      }))
      .filter((p) => p.name !== '');
  }

  return [];
}

/** Per-device port lookup: lowercased port name → ports. Built ONCE so the
 * per-host-row matching below is O(1) instead of scanning every port — that
 * keeps cable inference linear at scale (thousands of MAC rows × many ports). */
type PortIndex = Map<string, TopologyPort[]>;

function buildPortIndex(ports: TopologyPort[]): PortIndex {
  const idx: PortIndex = new Map();
  for (const p of ports) {
    const k = p.name.toLowerCase();
    let list = idx.get(k);
    if (!list) {
      list = [];
      idx.set(k, list);
    }
    list.push(p);
  }
  return idx;
}

/**
 * Finds the port(s) matching an observed interface name via the index. Exact
 * match first; then LAG members — SwOS reports bond ports as "port 4+5" in its
 * MAC table while `switch.portStats` lists the individual member ports ("4",
 * "5"), so a host seen on the bond inherits the VLANs of ALL its members. A
 * numeric tail fallback covers single tokens like "port 4" vs port name "4".
 */
function matchPorts(idx: PortIndex | undefined, intf: string): TopologyPort[] {
  if (!idx) return [];
  const i = intf.toLowerCase();
  const exact = idx.get(i);
  if (exact) return exact;
  // Single token — try its numeric tail ("port 4" → "4").
  const num = i.replace(/^[^0-9]*/, '');
  if (num !== '' && num !== i) {
    const m = idx.get(num);
    if (m) return m;
  }
  // LAG: union of all member ports.
  const parts = i.split('+').map((s) => s.trim()).filter(Boolean);
  if (parts.length < 2) return [];
  const out: TopologyPort[] = [];
  for (const part of parts) {
    let m = idx.get(part);
    if (!m) {
      const pn = part.replace(/^[^0-9]*/, '');
      if (pn !== '' && pn !== part) m = idx.get(pn);
    }
    if (m) out.push(...m);
  }
  return out;
}

/** Normalizes a vlan-prefixed interface name for comparison: "vlan0100" ≡ "vlan100"
 * (OPNsense zero-pads its ARP intf names, the networks table does not). */
function normVlanIface(name: string): string {
  const m = /^(vlan)(\d+)$/i.exec(name.trim());
  return m ? `vlan${Number(m[2])}` : name.toLowerCase();
}

/** True when an observed interface name matches any of the given names (exact, LAG-aware or vlan-zero-pad-tolerant). */
function ifaceMatchesAny(intf: string, names: string[]): boolean {
  const i = intf.toLowerCase();
  const ni = normVlanIface(i);
  for (const n of names) {
    if (n === i || normVlanIface(n) === ni) return true;
  }
  for (const part of i.split('+').map((s) => s.trim()).filter(Boolean)) {
    const np = normVlanIface(part);
    for (const n of names) {
      if (part === n || np === normVlanIface(n)) return true;
      const num = part.replace(/^[^0-9]*/, '');
      if (num !== '' && num === n) return true;
    }
  }
  return false;
}

/** Union of VLANs across a set of matched ports, deduped + sorted. */
function vlansOf(ports: TopologyPort[]): number[] {
  const set = new Set<number>();
  for (const p of ports) for (const v of p.vlans) set.add(v);
  return Array.from(set).sort((a, b) => a - b);
}

/** LACP partner hints from one snapshot (port + partner system MAC). */
function parseLagPartners(metrics: Record<string, unknown>): Array<{ port: string; partnerMac: string | null }> {
  const out: Array<{ port: string; partnerMac: string | null }> = [];
  const sx = metrics['lag.members']; // lancom-sx: partnerSystemId / partnerPort
  if (Array.isArray(sx)) {
    for (const r of sx) {
      if (!r || typeof r !== 'object') continue;
      const o = r as Record<string, unknown>;
      out.push({ port: String(o.port ?? ''), partnerMac: strOrNull(o.partnerSystemId) });
    }
  }
  const swos = metrics['lag.ports']; // mikrotik-swos: partnerMac
  if (Array.isArray(swos)) {
    for (const r of swos) {
      if (!r || typeof r !== 'object') continue;
      const o = r as Record<string, unknown>;
      out.push({ port: String(o.port ?? ''), partnerMac: strOrNull(o.partnerMac) });
    }
  }
  return out;
}

/** One physical host while being merged (pre-response shape). */
interface HostAccum {
  mac: string; // normalized
  displayMac: string;
  hostname: string | null;
  ips: Set<string>;
  lastSeenAt: string;
  /** Where this MAC was observed (device + interface) — drives segment placement. */
  observedOn: Array<{ deviceId: string; intf: string }>;
  observedKeys: Set<string>;
}

// ---------- the builder ----------

export function buildTopologyGraph(input: TopologyInput): TopologyResult {
  const nodes: TopologyNode[] = [];
  const edges: TopologyEdge[] = [];
  let edgeSeq = 0;
  const nextEdgeId = () => `e${++edgeSeq}`;

  // MAC normalization is called from several loops over the SAME strings —
  // memoize per build so each raw value is normalized exactly once.
  const macNormCache = new Map<string, string | null>();
  const normMacMemo = (mac: string | null | undefined): string | null => {
    if (!mac) return null;
    let v = macNormCache.get(mac);
    if (v === undefined) {
      v = normMac(mac);
      macNormCache.set(mac, v);
    }
    return v;
  };

  // --- per-device port detail (merged across the device's snapshots) -------
  const portsByDevice = new Map<string, TopologyPort[]>();
  for (const s of input.snapshots) {
    const parsed = parsePorts(s.metrics);
    if (parsed.length === 0) continue;
    const existing = portsByDevice.get(s.deviceId) ?? [];
    // First snapshot with port data wins per port name (deterministic).
    for (const p of parsed) {
      if (!existing.some((e) => e.name === p.name)) existing.push(p);
    }
    portsByDevice.set(s.deviceId, existing);
  }
  // O(1) port-name lookup per device — the cable/host loops below match
  // thousands of observed interface names against these.
  const portIndexes = new Map<string, PortIndex>();
  for (const [devId, ports] of portsByDevice) portIndexes.set(devId, buildPortIndex(ports));

  // --- device identity MACs: which interface on which device owns this MAC --
  const macToInterface = new Map<string, { deviceId: string; iface: string }>();
  const registerMac = (mac: string | null, deviceId: string, iface: string) => {
    const n = normMacMemo(mac);
    if (!n || !iface) return;
    if (!macToInterface.has(n)) macToInterface.set(n, { deviceId, iface });
  };
  for (const r of input.networks) registerMac(r.mac, r.deviceId, r.name);
  for (const h of input.hosts) {
    if (h.source === 'self' && h.intf) registerMac(h.mac, h.deviceId, h.intf);
  }
  // Port MACs too (e.g. LANCOM AP ports only report them there) — reuse the
  // already-parsed per-device list instead of re-parsing every snapshot.
  for (const [devId, ports] of portsByDevice) {
    for (const p of ports) if (p.mac) registerMac(p.mac, devId, p.name);
  }

  // --- IP → device map (tunnel endpoint resolution) -------------------------
  const ipToDevice = new Map<string, string>();
  const registerIps = (addr: string | null | undefined, deviceId: string) => {
    for (const ip of normalizeAddress(addr)) {
      if (!ipToDevice.has(ip)) ipToDevice.set(ip, deviceId);
    }
  };
  for (const d of input.devices) registerIps(d.managementAddress, d.id);
  for (const r of input.deviceIps) registerIps(r.address, r.deviceId);
  for (const n of input.networks) registerIps(n.ip, n.deviceId);

  // --- device nodes ----------------------------------------------------------
  const vlansByDevice = new Map<string, Set<number>>();
  for (const n of input.networks) {
    if (n.vlanId === null) continue;
    let set = vlansByDevice.get(n.deviceId);
    if (!set) {
      set = new Set();
      vlansByDevice.set(n.deviceId, set);
    }
    set.add(n.vlanId);
  }
  for (const d of input.devices) {
    nodes.push({
      id: `device:${d.id}`,
      kind: 'device',
      name: d.name,
      status: d.status,
      siteId: d.siteId,
      managementAddress: d.managementAddress,
      ports: portsByDevice.get(d.id) ?? [],
      vlans: Array.from(vlansByDevice.get(d.id) ?? []).sort((a, b) => a - b),
    });
  }

  // --- physical cable edges from MAC-table / ARP observations ----------------
  // "MAC X (owned by device B's interface Y) was seen on port P of device A"
  // ⇒ cable A:P ↔ B:Y. One port seeing several devices emits one edge each —
  // a hub or miswire stays visible instead of being collapsed away.
  const cableKeys = new Set<string>();
  const cableEdgesByPairPort = new Map<string, TopologyEdge & { kind: 'cable' }>();
  // Trunk VLANs per observing port — cached because real MAC tables hold
  // hundreds of rows on the SAME port (e.g. "port 4+5" with 600 entries).
  const portVlanCache = new Map<string, number[]>();
  const portVlansFor = (devId: string, intf: string): number[] => {
    const k = `${devId}|${intf.toLowerCase()}`;
    let v = portVlanCache.get(k);
    if (!v) {
      v = vlansOf(matchPorts(portIndexes.get(devId), intf));
      portVlanCache.set(k, v);
    }
    return v;
  };
  for (const h of input.hosts) {
    if (!h.intf) continue;
    const n = normMacMemo(h.mac);
    if (!n) continue;
    const target = macToInterface.get(n);
    if (!target || target.deviceId === h.deviceId) continue; // self-loop / own table
    const a = `device:${h.deviceId}`;
    const b = `device:${target.deviceId}`;
    const key = `${a}|${b}|${h.intf.toLowerCase()}|${(target.iface || '').toLowerCase()}`;
      if (cableKeys.has(key)) continue;
      cableKeys.add(key);
      // Trunk coloring: VLANs traversing the OBSERVING port(s), when known.
      // Runs once per unique cable — dedup above skips the hundreds of
      // duplicate rows real MAC tables hold on a single port.
    const edgeVlans = portVlansFor(h.deviceId, h.intf);
    const edge: TopologyEdge & { kind: 'cable' } = {
      id: nextEdgeId(),
      source: a,
      target: b,
      kind: 'cable',
      via: 'mac-table',
      portA: h.intf,
      portB: target.iface || null,
      vlans: edgeVlans,
    };
    edges.push(edge);
    cableEdgesByPairPort.set(key, edge);
  }

  // --- LACP partner hints upgrade/add bond edges ------------------------------
  for (const s of input.snapshots) {
    const partners = parseLagPartners(s.metrics);
    if (partners.length === 0) continue;
    for (const p of partners) {
      const n = normMacMemo(p.partnerMac);
      if (!n || !p.port) continue;
      const target = macToInterface.get(n);
      if (!target || target.deviceId === s.deviceId) continue;
      const a = `device:${s.deviceId}`;
      const b = `device:${target.deviceId}`;
      // If we already drew the same physical link from MAC-table evidence,
      // upgrade it instead of drawing a duplicate line.
      const key = `${a}|${b}|${p.port.toLowerCase()}|${(target.iface || '').toLowerCase()}`;
      const existing = cableEdgesByPairPort.get(key);
      if (existing) {
        existing.via = 'lacp';
        continue;
      }
      edges.push({
        id: nextEdgeId(),
        source: a,
        target: b,
        kind: 'cable',
        via: 'lacp',
        portA: p.port,
        portB: target.iface || null,
        vlans: vlansOf(matchPorts(portIndexes.get(s.deviceId), p.port)),
      });
    }
  }

  // --- tunnel edges (overlay links) --------------------------------------------
  // Endpoints are normalized first — plugins store "[2003::1]:51820" peers and
  // "10.1.2.21/30" local addresses. A managed device on EITHER end is enough to
  // draw the link; an unmanaged far end (public IP / FQDN) becomes a small
  // 'remote' node so site-to-site tunnels stay visible.
  const resolveAddr = (addr: string): { deviceId?: string; raw: string } => {
    for (const ip of normalizeAddress(addr)) {
      const d = ipToDevice.get(ip);
      if (d) return { deviceId: d, raw: addr };
    }
    // No managed device owns any address in this field — keep the first
    // normalized literal as the remote label.
    const ips = normalizeAddress(addr);
    return { raw: ips[0] ?? addr.trim() };
  };
  const remoteNodesAdded = new Set<string>();
  for (const t of input.tunnels) {
    const local = resolveAddr(t.localAddress);
    const peer = resolveAddr(t.peerAddress);
    if (!local.deviceId && !peer.deviceId) continue; // neither end known → not drawable
    let source: string;
    let target: string;
    if (local.deviceId && peer.deviceId) {
      if (local.deviceId === peer.deviceId) continue; // self-tunnel
      source = `device:${local.deviceId}`;
      target = `device:${peer.deviceId}`;
    } else {
      const managed = local.deviceId ?? peer.deviceId!;
      const remoteRaw = local.deviceId ? peer.raw : local.raw;
      if (!remoteRaw) continue;
      source = `device:${managed}`;
      target = `remote:${remoteRaw.toLowerCase()}`;
      if (!remoteNodesAdded.has(target)) {
        remoteNodesAdded.add(target);
        nodes.push({ id: target, kind: 'remote', label: `${t.type} → ${remoteRaw}` });
      }
    }
    edges.push({
      id: nextEdgeId(),
      source,
      target,
      kind: 'tunnel',
      type: t.type,
      status: t.status || null,
    });
  }

  // --- logical segments (merged networks) -------------------------------------
  const merged = mergeNetworkRows(input.networks as never);
  for (const m of merged) {
    // Skip single-device groups without a VLAN — those are just one interface
    // with no cross-device meaning (e.g. an isolated SVI).
    if (m.devices.length < 2 && m.vlanId === null) continue;
    const segKey = `segment:${m.key}`;
    nodes.push({ id: segKey, kind: 'segment', label: m.name, vlanId: m.vlanId, subnets: m.subnets });
    for (const d of m.devices) {
      edges.push({
        id: nextEdgeId(),
        source: `device:${d.deviceId}`,
        target: segKey,
        kind: 'membership',
        vlanId: m.vlanId,
      });
    }
  }

  // --- end-hosts (optional) ----------------------------------------------------
  if (input.includeHosts) {
    const acc = new Map<string, HostAccum>();
    for (const h of input.hosts) {
      const n = normMacMemo(h.mac);
      if (!n) continue;
      let a = acc.get(n);
      if (!a) {
        a = { mac: n, displayMac: h.mac, hostname: null, ips: new Set(), lastSeenAt: '', observedOn: [], observedKeys: new Set() };
        acc.set(n, a);
      }
      // DHCP rows carry the best hostname; first non-null wins otherwise.
      if (!a.hostname && h.hostname) a.hostname = h.hostname;
      if (h.ip !== '') a.ips.add(h.ip);
      if (h.lastSeenAt > a.lastSeenAt) a.lastSeenAt = h.lastSeenAt;
      if (h.intf) {
        const k = `${h.deviceId}|${h.intf.toLowerCase()}`;
        if (!a.observedKeys.has(k)) {
          a.observedKeys.add(k);
          a.observedOn.push({ deviceId: h.deviceId, intf: h.intf });
        }
      }
    }

    // Per-segment placement data for host matching.
    interface SegmentPlacement {
      segKey: string;
      vlanId: number | null;
      /** deviceId -> lowercased member interface names (from the networks table). */
      memberIfaces: Map<string, Set<string>>;
    }
    const placements: SegmentPlacement[] = [];
    for (const m of merged) {
      if (m.devices.length < 2 && m.vlanId === null) continue; // same filter as above
      const memberIfaces = new Map<string, Set<string>>();
      for (const d of m.devices) {
        let set = memberIfaces.get(d.deviceId);
        if (!set) {
          set = new Set();
          memberIfaces.set(d.deviceId, set);
        }
        for (const iface of d.interfaces) set.add(iface.toLowerCase());
      }
      placements.push({ segKey: `segment:${m.key}`, vlanId: m.vlanId, memberIfaces });
    }

    // Precise VLAN → segment mapping per device: "interface X on device D
    // carries VLAN vid AND belongs to segment S" ⇒ a host observed on D's
    // vlan<vid> interface joins S. Built from the networks rows' per-interface
    // vlanId (member-level — group-level vlanId is null for mixed groups).
    const ifaceVlans = new Map<string, Set<number>>();
    for (const n of input.networks) {
      if (n.vlanId === null || !n.name) continue;
      const k = `${n.deviceId}|${n.name.toLowerCase()}`;
      let set = ifaceVlans.get(k);
      if (!set) {
        set = new Set();
        ifaceVlans.set(k, set);
      }
      set.add(n.vlanId);
    }
    const vlanSegments = new Map<string, Map<number, Set<string>>>(); // deviceId -> vid -> segKeys
    for (const sm of placements) {
      for (const [devId, ifaces] of sm.memberIfaces) {
        for (const iface of ifaces) {
          const vids = ifaceVlans.get(`${devId}|${iface}`);
          if (!vids) continue;
          let byVid = vlanSegments.get(devId);
          if (!byVid) {
            byVid = new Map();
            vlanSegments.set(devId, byVid);
          }
          for (const vid of vids) {
            let segs = byVid.get(vid);
            if (!segs) {
              segs = new Set();
              byVid.set(vid, segs);
            }
            segs.add(sm.segKey);
          }
        }
      }
    }

    const MAX_HOSTS_PER_SEGMENT = 50; // ARP tables can hold hundreds of entries
    const hostNodesAdded = new Set<string>();
    // Sort ONCE (newest first) — the per-segment cap below keeps newest hosts.
    const sortedHosts = Array.from(acc.values()).sort((x, y) => (y.lastSeenAt > x.lastSeenAt ? 1 : -1));

    // Reverse index: `${deviceId}|${iface}` -> segments that contain it. Built
    // once so host placement is O(hosts × observations), NOT O(segments × hosts).
    const ifaceSegments = new Map<string, Set<string>>();
    for (const sm of placements) {
      for (const [devId, ifaces] of sm.memberIfaces) {
        for (const iface of ifaces) {
          const k = `${devId}|${iface}`;
          let set = ifaceSegments.get(k);
          if (!set) {
            set = new Set();
            ifaceSegments.set(k, set);
          }
          set.add(sm.segKey);
        }
      }
    }

    // Memoized per (device, interface): real MAC tables hold hundreds of
    // hosts on the SAME port — evaluating it once covers all of them.
    const obsCache = new Map<string, Set<string>>();
    /** Which segments does one observation point place a host into? */
    const segmentsForObservation = (obs: { deviceId: string; intf: string }): Set<string> => {
      const ck = `${obs.deviceId}|${obs.intf.toLowerCase()}`;
      const cached = obsCache.get(ck);
      if (cached) return cached;
      const out = new Set<string>();
      // 1) The observing interface is itself a member of some segment(s).
      const direct = ifaceSegments.get(`${obs.deviceId}|${obs.intf.toLowerCase()}`);
      if (direct) for (const s of direct) out.add(s);
      // LAG-aware: "port 4+5" matches member ports "4" and "5" separately.
      if (out.size === 0 && obs.intf.includes('+')) {
        for (const part of obs.intf.split('+').map((s) => s.trim()).filter(Boolean)) {
          const p = ifaceSegments.get(`${obs.deviceId}|${part.toLowerCase()}`);
          if (p) for (const s of p) out.add(s);
        }
      }
      // 2) A port on the device carries a VLAN that belongs to segment(s)
      //    (trunk/access data from the latest snapshot — covers SwOS bonds).
      //    Ambiguity guard: a MAC learned on a trunk with MANY allowed VLANs
      //    could belong to any of them — placing it into all would be noise,
      //    so only ports carrying ≤8 VLANs qualify.
      const byVid = vlanSegments.get(obs.deviceId);
      if (byVid) {
        const vids = portVlansFor(obs.deviceId, obs.intf); // cached union
        if (vids.length > 0 && vids.length <= 8) {
          for (const vid of vids) {
            const segs = byVid.get(vid);
            if (segs) for (const s of segs) out.add(s);
          }
        }
      }
      // 3) VLAN-named interface heuristic: "vlan0100" on a device whose member
      //    interfaces carry VLAN 100 in some segment (e.g. OPNsense vlan
      //    interfaces, whose ARP intf names differ from their IP interface
      //    names and are zero-padded).
      if (/^vlan/i.test(obs.intf)) {
        const m = /^vlan0*(\d+)$/i.exec(obs.intf.trim());
        if (m) {
          const segs = byVid?.get(Number(m[1]));
          if (segs) for (const s of segs) out.add(s);
        }
      }
      obsCache.set(ck, out);
      return out;
    };

    // Place each host once; the per-segment cap is enforced in newest-first order.
    const placedPerSegment = new Map<string, number>();
    const vlanBySegKey = new Map(placements.map((p) => [p.segKey, p.vlanId]));
    for (const a of sortedHosts) {
      const segs = new Set<string>();
      for (const o of a.observedOn) {
        for (const s of segmentsForObservation(o)) segs.add(s);
      }
      if (segs.size === 0) continue;
      const hostId = `host:${a.mac}`;
      if (!hostNodesAdded.has(hostId)) {
        hostNodesAdded.add(hostId);
        nodes.push({
          id: hostId,
          kind: 'host',
          mac: a.displayMac,
          hostname: a.hostname,
          ips: Array.from(a.ips).sort((x, y) => (x.includes(':') === y.includes(':') ? x.localeCompare(y) : x.includes(':') ? 1 : -1)),
        });
      }
      for (const segKey of segs) {
        const placed = placedPerSegment.get(segKey) ?? 0;
        if (placed >= MAX_HOSTS_PER_SEGMENT) continue;
        placedPerSegment.set(segKey, placed + 1);
        edges.push({ id: nextEdgeId(), source: hostId, target: segKey, kind: 'membership', vlanId: vlanBySegKey.get(segKey) ?? null });
      }
    }
  }

  return { nodes, edges };
}
