/**
 * Unified OpenWRT data-path facade.
 *
 * One Backend per request resolves HOW to reach the appliance once, then every
 * collector routes through it:
 *
 *   mode 'auto'  → probe LuCI (ubus-over-HTTP); use it for ubus-backed sources,
 *                  SSH fills everything else (/proc stats, uci config, ARP...).
 *   mode 'luci'  → HTTP only; shell-only sources are omitted (best-effort
 *                  contract: an absent key never wipes stored rows).
 *   mode 'ssh'   → shell only.
 *
 * Key insight: the `ubus call` CLI exists on every OpenWRT box, so SSH mode can
 * read the SAME structured data LuCI reads (system board, network interface
 * dump, service list) — the two transports are interchangeable for ubus-backed
 * sources and differ only in what a shell adds (/proc, uci, wg show, df).
 *
 * Transport state is cached per host (TTL + in-flight dedupe) so N concurrent
 * polls share one LuCI probe; the resolved LuciClient/SshBackend instances are
 * reused across polls (sessions persist — no re-login per cycle).
 */

import type { CertificateRow, SshCredentials } from '@unm/plugin-sdk';
import { createLuciClient, resolveLuciCandidates } from './luciClient';
import type { LuciClient, LuciResult } from './luciClient';
import { SshBackend, parseUciShow, uciSectionsByType, uciOpt, resolveOpenWrtSshCredentials } from './sshBackend';
import type {
  BoardInfo,
  FilesystemRow,
  FirewallRuleRow,
  HostRow,
  InventorySnapshot,
  NetworkRow,
  OpenWrtPorts,
  OpenWrtTransportMode,
  RouteRow,
  ServiceRow,
  TransportState,
  TunnelRow,
  WifiSsidRow,
} from '../types';

const STATE_TTL_MS = 5 * 60_000; // re-probe transport state every 5 min per host
const LUCI_PROBE_TIMEOUT_MS = 4_000;

interface HostState {
  at: number;
  state: TransportState;
  luci: LuciClient | null;
  ssh: SshBackend | null;
}

/** Per-host resolved transport (module-level, survives across polls). */
const hostStates = new Map<string, HostState>();
/** In-flight probes — concurrent polls share one resolution. */
const inFlight = new Map<string, Promise<HostState>>();

export interface BackendOptions {
  /** Management address as stored (may carry scheme/port). */
  address: string;
  /** Decrypted assignment credentials (primary + bound slots). */
  credentials?: Record<string, unknown> | null;
  mode: OpenWrtTransportMode;
  ports: OpenWrtPorts;
  sshPort: number;
  /** Optional diagnostic sink for transport-level failures (container logs / UNM log shipping). */
  log?: (level: 'info' | 'warn', message: string) => void;
}

/** The per-request facade. Obtain via Backend.create() — never construct directly. */
export class Backend {
  private constructor(
    readonly address: string,
    readonly host: string,
    readonly state: TransportState,
    private readonly luciClient: LuciClient | null,
    private readonly sshBackend: SshBackend | null,
    private readonly logFn?: (level: 'info' | 'warn', message: string) => void
  ) {}

  /** The LuCI client (null when unavailable / not used in this mode). */
  get luci(): LuciClient | null {
    return this.luciClient;
  }

  /** The SSH backend (null when no usable credential or mode forbids it). */
  get ssh(): SshBackend | null {
    return this.sshBackend;
  }

  // --- Transport resolution -------------------------------------------------

  static async create(opts: BackendOptions): Promise<Backend> {
    const host = bareHost(opts.address);
    if (!host) throw new Error(`Unparseable management address "${opts.address}"`);

    const key = `${host}|${opts.mode}`;
    const cached = hostStates.get(key);
    if (cached && Date.now() - cached.at < STATE_TTL_MS) {
      return new Backend(opts.address, host, cached.state, cached.luci, cached.ssh, opts.log);
    }
    let pending = inFlight.get(key);
    if (!pending) {
      pending = resolveHostState(host, opts).finally(() => inFlight.delete(key));
      inFlight.set(key, pending);
    }
    const resolved = await pending;
    return new Backend(opts.address, host, resolved.state, resolved.luci, resolved.ssh, opts.log);
  }

  /** Drops the cached transport state for a host (after auth failures etc.). */
  static invalidate(address: string): void {
    const host = bareHost(address);
    if (!host) return;
    for (const k of [...hostStates.keys()]) {
      if (k.startsWith(`${host}|`)) hostStates.delete(k);
    }
  }

  // --- ubus-over-anything helper --------------------------------------------

  /** Calls one ubus method via LuCI HTTP when available, else `ubus call` over SSH. */
  private async ubus<T = unknown>(service: string, member: string, path?: string, params?: Record<string, unknown>): Promise<LuciResult<T>> {
    if (this.luciClient) {
      return this.luciClient.callUbus<T>(service, member, path, params);
    }
    if (!this.sshBackend) return { ok: false, status: 0, error: 'no transport available' };
    const args = [service, member];
    if (path !== undefined) args.push(path);
    let json = '{}';
    try {
      json = JSON.stringify(params ?? {});
    } catch {
      /* keep '{}' */
    }
    // ubus call <service> <member> [<path>] [json-params] — params are a single
    // shell-quoted argument; empty object when none.
    const cmd = `ubus call ${args.map((a) => `'${a.replace(/'/g, "'\\''")}'`).join(' ')} '${json.replace(/'/g, "'\\''")}'`;
    const r = await this.sshBackend.exec(cmd).catch(() => null);
    if (!r || r.code !== 0) {
      // Surface the failure once per host+method (custom firmware builds may
      // restrict or rename ubus — the caller falls back to file/uci reads).
      const errText = r ? `exit=${r.code} stderr="${r.stderr.trim().slice(0, 200)}"` : 'exec threw';
      this.logFn?.('warn', `[${this.host}] ubus-over-ssh ${service}.${member} failed: ${errText}`);
      return { ok: false, status: 0, error: `ubus call ${service}.${member} failed${r ? `: ${r.stderr.trim().slice(0, 200)}` : ''}` };
    }
    try {
      const parsed = JSON.parse(r.stdout) as unknown[] | Record<string, unknown>;
      if (Array.isArray(parsed)) return { ok: true, status: 200, data: (parsed[0] ?? parsed) as T };
      return { ok: true, status: 200, data: parsed as T };
    } catch {
      return { ok: false, status: 0, error: `ubus call ${service}.${member}: unparseable output` };
    }
  }

  // --- Data sources (the matrix) --------------------------------------------

  /** Board/system identity — LuCI `system board`, else SSH release file + uci. */
  async boardInfo(): Promise<BoardInfo | null> {
    const r = await this.ubus<Record<string, unknown>>('system', 'board');
    if (r.ok && r.data) {
      const d = r.data;
      return {
        hostname: str(d['hostname']) ?? '',
        model: str(d['model']) ?? '',
        board: str(d['board']) ?? '',
        release: str(d['release']) ?? '',
        revision: str(d['revision']),
        uptimeSeconds: num(d['uptime']),
      };
    }
    // SSH fallback (also used when LuCI is down in auto mode).
    if (!this.sshBackend) return null;
    const sections = await this.sshBackend.runSections([
      { name: 'release', cmd: "cat /etc/openwrt_release 2>/dev/null" },
      // Custom firmware builds often drop the stock release script — try the
      // bare version files, POSIX os-release (PRETTY_NAME), and /etc/banner.
      { name: 'versionfile', cmd: "cat /etc/openwrt_version 2>/dev/null; cat /etc/version 2>/dev/null; grep -E '^(PRETTY_NAME|VERSION)=' /etc/os-release 2>/dev/null; head -1 /etc/banner 2>/dev/null" },
      { name: 'hostname', cmd: "uci get system.@system[0].hostname 2>/dev/null" },
      { name: 'uptime', cmd: 'awk "{print int($1)}" /proc/uptime' },
    ]).catch(() => new Map<string, string>());

    // Release/version — custom firmware builds vary the layout, so try several:
    //   DISTRIB_DESCRIPTION='OpenWrt 23.05.x-...' (stock) → keep the whole string
    //   PRETTY_NAME / VERSION from /etc/os-release (modern OpenWrt + derivatives)
    //   bare version file (/etc/openwrt_version: "rXXXXX-Y")
    // Quote-tolerant: stock builds use single quotes, some derivatives double.
    const RELEASE_RE = /DISTRIB_DESCRIPTION=["']([^"']+)["']/;
    const releaseRaw = sections.get('release') ?? '';
    let release = '';
    for (const line of releaseRaw.split('\n')) {
      const m = line.match(RELEASE_RE);
      if (m) { release = m[1]; break; }
    }
    if (!release) {
      for (const rawLine of (sections.get('versionfile') ?? '').split('\n')) {
        const line = rawLine.trim();
        if (!line) continue;
        // "PRETTY_NAME=OpenWrt 23.05" / "VERSION=..." → strip the key prefix.
        const kv = line.match(/^(?:PRETTY_NAME|VERSION)=(.*)$/);
        release = (kv ? kv[1] : line).trim();
        if (release) break;
      }
    }
    const hostname = (sections.get('hostname') ?? '').trim();
    const uptime = Number((sections.get('uptime') ?? '0').trim());
    if (!release && !hostname) return null;
    return {
      hostname: hostname || this.host,
      model: release ? release.replace(/^OpenWrt\s+/i, '') : '',
      board: '',
      release,
      revision: null,
      uptimeSeconds: Number.isFinite(uptime) && uptime > 0 ? uptime : null,
    };
  }

  /** CPU usage % (from /proc/stat delta) + load averages — SSH only. */
  async cpuLoad(): Promise<{ percent: number | null; load1: number | null; load5: number | null; load15: number | null }> {
    if (!this.sshBackend) return { percent: null, load1: null, load5: null, load15: null };
    const sections = await this.sshBackend.runSections([
      { name: 'stat', cmd: "head -1 /proc/stat" },
      { name: 'loadavg', cmd: 'cat /proc/loadavg' },
    ]).catch(() => new Map<string, string>());

    let percent: number | null = null;
    const statLine = sections.get('stat') ?? '';
    // cpu  user nice system idle iowait irq softirq steal ...
    if (/^cpu\s+/.test(statLine)) {
      percent = this.cpuPercentFromStat(statLine);
    }

    let load1: number | null = null, load5: number | null = null, load15: number | null = null;
    const lm = (sections.get('loadavg') ?? '').match(/^([\d.]+)\s+([\d.]+)\s+([\d.]+)/);
    if (lm) {
      load1 = Number(lm[1]);
      load5 = Number(lm[2]);
      load15 = Number(lm[3]);
    }
    return { percent, load1, load5, load15 };
  }

  /** Per-host /proc/stat busy-time baselines (module-level). */
  private statBaselines = new Map<string, { total: number; idle: number; at: number }>();

  private cpuPercentFromStat(statLine: string): number | null {
    const m = statLine.match(/^cpu\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)/);
    if (!m) return null;
    const user = Number(m[1]), nice = Number(m[2]), system = Number(m[3]), idle = Number(m[4]);
    const total = user + nice + system + idle;
    const now = Date.now();
    const prev = this.statBaselines.get(this.host);
    this.statBaselines.set(this.host, { total, idle, at: now });
    if (!prev || now <= prev.at) return null; // first sample — no delta yet
    const dTotal = total - prev.total;
    const dIdle = idle - prev.idle;
    if (dTotal <= 0) return null; // counter reset/wrap
    return Math.max(0, Math.min(100, Math.round(((dTotal - dIdle) / dTotal) * 100)));
  }

  /** Memory from /proc/meminfo — SSH only. */
  async memory(): Promise<{ used: number | null; total: number | null; percent: number | null }> {
    if (!this.sshBackend) return { used: null, total: null, percent: null };
    const r = await this.sshBackend.exec('cat /proc/meminfo').catch(() => null);
    if (!r || r.code !== 0) return { used: null, total: null, percent: null };
    const fields: Record<string, number> = {};
    for (const line of r.stdout.split('\n')) {
      const m = line.match(/^(\w+):\s+(\d+)\s*kB/);
      if (m) fields[m[1]] = Number(m[2]) * 1024;
    }
    const total = fields['MemTotal'] ?? null;
    const available = fields['MemAvailable'];
    const used = total !== null && available !== undefined ? total - available : null;
    const percent = total && used !== null ? Math.round((used / total) * 100) : null;
    return { used, total, percent };
  }

  /** Configured interfaces + IPs — LuCI `network.interface dump`, else SSH ubus. */
  async networks(): Promise<NetworkRow[]> {
    const r = await this.ubus<Record<string, Record<string, unknown>>>('network', 'interface', 'dump');
    if (r.ok && r.data) return parseInterfaceDump(r.data);

    // SSH fallback: ubus over shell + MACs from /sys. If the ubus dump is empty
    // (custom firmware builds may restrict/rename it), fall back to `ip addr` —
    // iproute2 ships on every OpenWRT box and needs no ubus at all.
    if (!this.sshBackend) return [];
    const sections = await this.sshBackend.runSections([
      { name: 'dump', cmd: 'ubus call network interface dump 2>/dev/null' },
      { name: 'ipaddr', cmd: "ip -4 addr show 2>/dev/null" },
      { name: 'macs', cmd: "for i in /sys/class/net/*; do n=$(basename $i); a=$(cat $i/address 2>/dev/null); [ -n \"$a\" ] && echo \"$n $a\"; done" },
    ]).catch(() => new Map<string, string>());

    let dump: Record<string, Record<string, unknown>> = {};
    try {
      const parsed = JSON.parse(sections.get('dump') ?? '{}');
      if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) dump = parsed as Record<string, Record<string, unknown>>;
    } catch { /* empty */ }

    const macs = new Map<string, string>();
    for (const line of (sections.get('macs') ?? '').split('\n')) {
      const [n, a] = line.trim().split(/\s+/);
      if (n && a) macs.set(n, a.toLowerCase());
    }

    // `ip addr` fallback when ubus gave nothing: one row per interface with an IPv4.
    if (Object.keys(dump).length === 0) {
      const rows: NetworkRow[] = [];
      let current: string | null = null;
      for (const line of (sections.get('ipaddr') ?? '').split('\n')) {
        const ifm = line.match(/^\d+:\s+(\S+)@/); // "2: eth0@if3:"
        if (ifm) { current = ifm[1]; continue; }
        const ifPlain = line.match(/^\d+:\s+(\S+):/); // "1: lo:"
        if (ifPlain) { current = ifPlain[1]; continue; }
        if (!current) continue;
        const inetM = line.trim().match(/^inet\s+(\S+)\/(\d+)/);
        if (!inetM) continue;
        rows.push({ name: current, ip: inetM[1], prefix: Number(inetM[2]), version: 'v4', vlanId: null, mac: macs.get(current) ?? null, status: 'up' });
      }
      return rows;
    }

    return Object.entries(dump).map(([name, d]) => {
      const row: NetworkRow = { name, ip: null, prefix: null, version: 'v4', vlanId: null, mac: null, status: d['up'] ? 'up' : 'down' };
      const ipv4 = Array.isArray(d['ipv4_address']) ? (d['ipv4_address'] as unknown[]) : [];
      if (ipv4.length > 0) {
        const first = String(ipv4[0]);
        row.ip = first.split('/')[0];
        row.prefix = first.includes('/') ? Number(first.split('/')[1]) : null;
        row.version = 'v4';
      } else if (Array.isArray(d['ipv6_address']) && (d['ipv6_address'] as unknown[]).length > 0) {
        const first = String((d['ipv6_address'] as unknown[])[0]);
        row.ip = first.split('/')[0];
        row.prefix = first.includes('/') ? Number(first.split('/')[1]) : null;
        row.version = 'v6';
      }
      // VLAN id from the device name (eth0.100 → 100).
      const vm = String(d['device'] ?? '').match(/\.(\d+)$/);
      if (vm) row.vlanId = Number(vm[1]);
      const dev = String(d['device'] ?? '');
      if (dev && macs.has(dev)) row.mac = macs.get(dev) ?? null;
      return row;
    });
  }

  /** Per-interface traffic counters — LuCI `network.interface@X status`, else SSH /sys. */
  async traffic(): Promise<Record<string, { rx: number; tx: number }>> {
    const out: Record<string, { rx: number; tx: number }> = {};

    if (this.luciClient) {
      // One dump gives us the interface list; per-interface status carries ibytes/obytes.
      const r = await this.ubus<Record<string, Record<string, unknown>>>('network', 'interface', 'dump');
      if (r.ok && r.data) {
        for (const name of Object.keys(r.data)) {
          const s = await this.luciClient.callUbus<Record<string, unknown>>('network', 'interface', `@${name}`, {}, 4_000);
          if (!s.ok || !s.data) continue;
          const rx = num(s.data['ibytes']);
          const tx = num(s.data['obytes']);
          if (rx !== null && tx !== null && (rx > 0 || tx > 0)) out[name] = { rx, tx };
        }
      }
      return out;
    }

    if (!this.sshBackend) return out;
    const r = await this.sshBackend.exec(
      "for i in /sys/class/net/*; do n=$(basename $i); [ -f \"$i/statistics/rx_bytes\" ] && echo \"$n $(cat $i/statistics/rx_bytes) $(cat $i/statistics/tx_bytes)\"; done"
    ).catch(() => null);
    if (!r || r.code !== 0) return out;
    for (const line of r.stdout.split('\n')) {
      const [name, rxS, txS] = line.trim().split(/\s+/);
      if (!name) continue;
      const rx = Number(rxS), tx = Number(txS);
      if (Number.isFinite(rx) && Number.isFinite(tx) && (rx > 0 || tx > 0)) out[name] = { rx, tx };
    }
    return out;
  }

  /** ARP + NDP neighbor tables — SSH only (/proc/net/arp + ip -6 neigh). */
  async neighbors(): Promise<{ arp: HostRow[]; ndp: HostRow[] }> {
    if (!this.sshBackend) return { arp: [], ndp: [] };
    const sections = await this.sshBackend.runSections([
      { name: 'arp', cmd: 'cat /proc/net/arp 2>/dev/null' },
      { name: 'ndp', cmd: "ip -6 neigh show 2>/dev/null" },
    ]).catch(() => new Map<string, string>());

    const arp: HostRow[] = [];
    for (const line of (sections.get('arp') ?? '').split('\n').slice(1)) {
      // IP address HW type Flags HW address Mask Device
      const parts = line.trim().split(/\s+/);
      if (parts.length < 6) continue;
      const [ip, , flags, mac] = parts;
      if (!mac || mac === '00:00:00:00:00:00' || !/^\d/.test(ip)) continue;
      arp.push({ mac: mac.toLowerCase(), ip, hostname: null, manufacturer: null, intf: parts[7] ?? null });
    }

    const ndp: HostRow[] = [];
    for (const line of (sections.get('ndp') ?? '').split('\n')) {
      // 2001:db8::1 dev eth0 lladdr aa:bb:... REACHABLE
      const m = line.match(/^(\S+)\s+dev\s+(\S+)\s+lladdr\s+([0-9a-f:]+)/i);
      if (!m) continue;
      ndp.push({ mac: m[3].toLowerCase(), ip: m[1], hostname: null, manufacturer: null, intf: m[2] });
    }
    return { arp, ndp };
  }

  /** Active DHCP leases — SSH only (/tmp/dhcp.leases + uci static mappings). */
  async dhcpLeases(): Promise<HostRow[]> {
    if (!this.sshBackend) return [];
    const sections = await this.sshBackend.runSections([
      { name: 'leases', cmd: 'cat /tmp/dhcp.leases 2>/dev/null' },
      { name: 'static', cmd: "uci show dhcp 2>/dev/null" },
    ]).catch(() => new Map<string, string>());

    const rows = new Map<string, HostRow>(); // keyed by mac — static mappings win on hostname/ip
    for (const line of (sections.get('leases') ?? '').split('\n')) {
      // -1  aa:bb:cc:dd:ee:ff  192.168.1.50  host  01:aa:...
      const parts = line.trim().split(/\s+/);
      if (parts.length < 3) continue;
      const [expiry, mac, ip, hostname] = parts;
      if (!mac || !ip) continue;
      rows.set(mac.toLowerCase(), {
        mac: mac.toLowerCase(),
        ip,
        hostname: hostname && hostname !== '?' ? hostname : null,
        manufacturer: null,
        intf: null,
        expiry: expiry === '-1' ? null : new Date(Number(expiry) * 1000).toISOString(),
      });
    }

    // Static mappings (uci dhcp .name=host / .ip=... pairs) enrich hostnames.
    const staticTree = parseUciShow(sections.get('static') ?? '');
    for (const [key, options] of Object.entries(staticTree['dhcp'] ?? {})) {
      if (!key.startsWith('@host[') && !key.startsWith('@map[')) continue;
      const mac = uciOpt(options, 'mac');
      const ip = uciOpt(options, 'ip');
      const hostname = uciOpt(options, 'name') ?? uciOpt(options, 'hostname');
      if (!mac) continue;
      const k = mac.toLowerCase();
      const existing = rows.get(k);
      if (existing) {
        if (hostname) existing.hostname = hostname;
        if (ip && !existing.ip) existing.ip = ip;
      } else if (ip) {
        rows.set(k, { mac: k, ip, hostname: hostname ?? null, manufacturer: null, intf: null });
      }
    }
    return [...rows.values()];
  }

  /** Routes — LuCI mode derives from the interface dump; SSH uses `ip route`. */
  async routes(): Promise<RouteRow[]> {
    if (this.luciClient) {
      const r = await this.ubus<Record<string, Record<string, unknown>>>('network', 'interface', 'dump');
      if (!r.ok || !r.data) return [];
      const rows: RouteRow[] = [];
      for (const [name, d] of Object.entries(r.data)) {
        const gw = str(d['gateway']);
        const ipv4 = Array.isArray(d['ipv4_address']) ? ((d['ipv4_address'] as unknown[]) as string[]) : [];
        if (gw) rows.push({ destination: '0.0.0.0/0', gateway: gw, protocol: 'static', distance: null, metric: null, mtu: num(d['mtu']), status: d['up'] ? 'active' : 'inactive', extra: { interface: name } });
        for (const cidr of ipv4) {
          rows.push({ destination: String(cidr), gateway: undefined, protocol: 'connected', distance: null, metric: null, mtu: num(d['mtu']), status: d['up'] ? 'active' : 'inactive', extra: { interface: name } });
        }
      }
      return rows;
    }

    if (!this.sshBackend) return [];
    const r = await this.sshBackend.exec('ip route show 2>/dev/null').catch(() => null);
    if (!r || r.code !== 0) return [];
    const rows: RouteRow[] = [];
    for (const line of r.stdout.split('\n')) {
      // default via 192.168.1.1 dev eth0  /  192.168.1.0/24 dev br-lan proto kernel scope link src 192.168.1.1
      const m = line.trim().match(/^(default|(\S+))\s+(?:via\s+(\S+)\s+)?dev\s+(\S+)/);
      if (!m) continue;
      rows.push({
        destination: m[1] === 'default' ? '0.0.0.0/0' : m[2],
        gateway: m[3],
        protocol: /proto kernel/.test(line) ? 'connected' : /proto static/.test(line) || (m[3] && m[1] !== 'default') ? 'static' : 'other',
        distance: null,
        metric: null,
        mtu: null,
        status: 'active',
        extra: { interface: m[4] },
      });
    }
    return rows;
  }

  /** Firewall rules (fw4 = nftables) — uci show firewall over SSH only. */
  async firewallRules(): Promise<FirewallRuleRow[] | null> {
    if (!this.sshBackend) return null; // luci-only mode: omit (keep previous rows)
    const r = await this.sshBackend.exec('uci show firewall 2>/dev/null').catch(() => null);
    if (!r || r.code !== 0) return null;
    try {
      return parseFirewallUci(r.stdout);
    } catch {
      return null; // malformed — keep previous rows (null = "collection failed")
    }
  }

  /** Wireless SSIDs — LuCI hostapd ubus when present, else uci config over SSH. */
  async wifiSsids(): Promise<WifiSsidRow[]> {
    if (this.luciClient) {
      const r = await this.luciClient.callUbus<Record<string, unknown>>('hostapd', 'status');
      if (r.ok && r.data) return parseHostapdStatus(r.data);
    }
    if (!this.sshBackend) return [];
    const r = await this.sshBackend.exec('uci show wireless 2>/dev/null').catch(() => null);
    if (!r || r.code !== 0) return [];
    return parseWirelessUci(r.stdout);
  }

  /** Tunnels (WireGuard/OpenVPN/PPPoE/GRE) — SSH only. */
  async tunnels(): Promise<TunnelRow[]> {
    if (!this.sshBackend) return [];
    const sections = await this.sshBackend.runSections([
      { name: 'wg', cmd: "command -v wg >/dev/null && wg show all 2>/dev/null || true" },
      { name: 'uci', cmd: 'uci show network 2>/dev/null' },
    ]).catch(() => new Map<string, string>());

    const rows = new Map<string, TunnelRow>();

    // WireGuard: config sections (proto=wireguard) + live `wg show all` state.
    const netTree = parseUciShow(sections.get('uci') ?? '');
    for (const [key, options] of Object.entries(netTree['network'] ?? {})) {
      if (!key.startsWith('@interface[')) continue;
      const proto = uciOpt(options, 'proto');
      let type: string | null = null;
      if (proto === 'wireguard') type = 'wireguard';
      else if (proto === 'openvpn') type = 'openvpn';
      else if (proto === 'pppoe' || proto === 'pppoa') type = 'pppoe';
      else if (proto === 'gre' || proto === 'ipip') type = 'gre';
      if (!type) continue;

      const name = uciOpt(options, 'name') ?? key;
      const device = uciOpt(options, 'device');
      const peer = uciOpt(options, 'peeraddr') ?? uciOpt(options, 'remote');
      const rows4: string[] = [];
      for (const [opt, v] of Object.entries(options)) {
        if (/^ip4addr$/.test(opt) || /^option\.ip4addr\[\d+\]$/.test(opt)) rows4.push(v);
      }
      rows.set(name, {
        name,
        type,
        peerAddress: peer ?? undefined,
        localAddress: undefined,
        subnet: rows4[0] ?? null,
        status: 'unknown',
        uptimeSeconds: null,
        lastHandshakeSeconds: null,
        interfaceName: device ?? undefined,
        extra: {},
      });
    }

    // Live WireGuard state (handshake age + peer endpoint).
    const wgOut = sections.get('wg') ?? '';
    let currentIface: string | null = null;
    for (const line of wgOut.split('\n')) {
      const ifaceM = line.match(/^interface\s+(\S+)/);
      if (ifaceM) {
        currentIface = ifaceM[1];
        continue;
      }
      if (!currentIface) continue;
      // Find the config row bound to this device.
      const row = [...rows.values()].find((t) => t.interfaceName === currentIface);
      if (!row) continue;
      const peerM = line.match(/^peer:\s+(\S+)/);
      if (peerM && !line.includes('last handshake')) {
        // The "public key:" line follows the endpoint in wg show output.
      }
      const hsM = line.match(/last handshake:\s+([\d]+) seconds ago/);
      if (hsM && row) row.lastHandshakeSeconds = Number(hsM[1]);
    }

    return [...rows.values()];
  }

  /** Running services — ubus `service list` over either transport. */
  async services(): Promise<ServiceRow[]> {
    const r = await this.ubus<Record<string, Record<string, unknown>>>('service', 'list');
    if (r.ok && r.data) {
      return Object.entries(r.data).map(([name, d]) => ({
        name,
        enabled: !!d['enabled'],
        running: !!d['running'],
        pid: num(d['pid']),
      }));
    }
    return [];
  }

  /** Filesystems — SSH only (df -k + overlay). */
  async filesystems(): Promise<FilesystemRow[]> {
    if (!this.sshBackend) return [];
    const r = await this.sshBackend.exec('df -kT 2>/dev/null').catch(() => null);
    if (!r || r.code !== 0) return [];
    const rows: FilesystemRow[] = [];
    for (const line of r.stdout.split('\n').slice(1)) {
      // Filesystem Type 1K-blocks Used Available Use% Mounted on
      const parts = line.trim().split(/\s+/);
      if (parts.length < 7) continue;
      const [fs, type, sizeS, usedS, availS, , mount] = parts;
      rows.push({
        name: fs,
        type,
        sizeBytes: Number(sizeS) * 1024 || null,
        usedBytes: Number(usedS) * 1024 || null,
        availBytes: Number(availS) * 1024 || null,
        mountpoint: mount,
      });
    }
    return rows;
  }

  /** Full inventory snapshot (15-min cadence). */
  async collectInventory(certificates: CertificateRow[]): Promise<InventorySnapshot> {
    const [board, networks, neighborsRes, leases, routes, tunnels, wifi, firewall, services, filesystems] = await Promise.all([
      this.boardInfo().catch(() => null),
      this.networks().catch(() => [] as NetworkRow[]),
      this.neighbors().catch(() => ({ arp: [], ndp: [] })),
      this.dhcpLeases().catch(() => [] as HostRow[]),
      this.routes().catch(() => [] as RouteRow[]),
      this.tunnels().catch(() => [] as TunnelRow[]),
      this.wifiSsids().catch(() => [] as WifiSsidRow[]),
      this.firewallRules(), // null on failure — load-bearing (keep previous rows)
      this.services().catch(() => [] as ServiceRow[]),
      this.filesystems().catch(() => [] as FilesystemRow[]),
    ]);

    return {
      collectedAt: new Date().toISOString(),
      board,
      networks,
      arp: neighborsRes.arp,
      ndp: neighborsRes.ndp,
      dhcpLeases: leases,
      routes,
      tunnels,
      wifiSsids: wifi,
      firewallRules: firewall,
      services,
      filesystems,
      certificates,
    };
  }
}

// ---------------------------------------------------------------------------
// Host-state resolution (the auto-negotiation)
// ---------------------------------------------------------------------------

async function resolveHostState(host: string, opts: BackendOptions): Promise<HostState> {
  const report: string[] = [];
  let luci: LuciClient | null = null;
  let ssh: SshBackend | null = null;

  // SSH availability (needed in auto + ssh modes).
  if (opts.mode !== 'luci') {
    const creds: SshCredentials | undefined = resolveOpenWrtSshCredentials(opts.credentials);
    if (creds) {
      ssh = new SshBackend(host, opts.sshPort, creds);
      report.push(`ssh:${host}:${opts.sshPort} (user ${creds.username})`);
    } else {
      report.push('ssh: no usable credential bound');
    }
  }

  // LuCI availability (needed in auto + luci modes).
  if (opts.mode !== 'ssh') {
    const creds = resolveOpenWrtSshCredentials(opts.credentials);
    const username = typeof opts.credentials?.['username'] === 'string' ? (opts.credentials['username'] as string) : creds?.username ?? 'root';
    const password = typeof opts.credentials?.['password'] === 'string' ? (opts.credentials['password'] as string) : creds?.password;

    if (!password) {
      report.push('luci: no username/password available');
    } else {
      for (const base of resolveLuciCandidates(opts.address, opts.ports)) {
        const client = createLuciClient(base, username, password);
        try {
          const ok = await withTimeout(client.probe(), LUCI_PROBE_TIMEOUT_MS);
          if (ok) {
            luci = client;
            report.push(`luci:${base}`);
            break;
          }
        } catch {
          /* try next candidate */
        }
      }
      if (!luci) report.push('luci: not reachable on any candidate endpoint');
    }
  }

  // Forced-mode validation.
  let mode = opts.mode;
  if (opts.mode === 'luci' && !luci) {
    throw new Error("Transport is forced to 'luci' but no LuCI web UI was reachable — check the device runs LuCI and the httpsPort/httpPort options are correct.");
  }

  const state: TransportState = {
    mode,
    luciBaseUrl: luci ? luci.baseUrl : null,
    sshAvailable: !!ssh,
    report,
  };

  return { at: Date.now(), state, luci, ssh };
}

/** Promise timeout wrapper (probe budget). */
function withTimeout<T>(p: Promise<T>, ms: number): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const t = setTimeout(() => reject(new Error('timeout')), ms);
    p.then((v) => { clearTimeout(t); resolve(v); }, (e) => { clearTimeout(t); reject(e); });
  });
}

/** Bare hostname from a management address (strips scheme/port/brackets). */
export function bareHost(address: string): string | null {
  const raw = String(address ?? '').trim();
  if (!raw) return null;
  try {
    const u = new URL(raw.includes('://') ? raw : `https://${raw}`);
    return u.hostname.replace(/^\[|\]$/g, '') || null;
  } catch {
    return raw.split('/')[0].split(':')[0] || null;
  }
}

// ---------------------------------------------------------------------------
// Parsers (ubus / proc / uci output → row shapes)
// ---------------------------------------------------------------------------

function str(v: unknown): string | undefined {
  return typeof v === 'string' && v.length > 0 ? v : undefined;
}

function num(v: unknown): number | null {
  const n = typeof v === 'number' ? v : Number(v);
  return Number.isFinite(n) ? n : null;
}

/** Parses `ubus call network interface dump` → NetworkRow[]. */
export function parseInterfaceDump(dump: Record<string, Record<string, unknown>>): NetworkRow[] {
  const rows: NetworkRow[] = [];
  for (const [name, d] of Object.entries(dump)) {
    if (!d || typeof d !== 'object') continue;
    const row: NetworkRow = { name, ip: null, prefix: null, version: 'v4', vlanId: null, mac: null, status: d['up'] ? 'up' : 'down' };
    const ipv4 = Array.isArray(d['ipv4_address']) ? ((d['ipv4_address'] as unknown[]) as string[]) : [];
    if (ipv4.length > 0) {
      row.ip = ipv4[0].split('/')[0];
      row.prefix = ipv4[0].includes('/') ? Number(ipv4[0].split('/')[1]) : null;
      row.version = 'v4';
    } else if (Array.isArray(d['ipv6_address']) && (d['ipv6_address'] as unknown[]).length > 0) {
      const first = String((d['ipv6_address'] as unknown[])[0]);
      row.ip = first.split('/')[0];
      row.prefix = first.includes('/') ? Number(first.split('/')[1]) : null;
      row.version = 'v6';
    }
    const vm = str(d['device'])?.match(/\.(\d+)$/);
    if (vm) row.vlanId = Number(vm[1]);
    rows.push(row);
  }
  return rows;
}

/** Parses `ubus call hostapd status` → WifiSsidRow[] (best-effort). */
export function parseHostapdStatus(data: Record<string, unknown>): WifiSsidRow[] {
  const rows: WifiSsidRow[] = [];
  // Shape varies by version — accept both a flat map and an array of ifaces.
  const entries = Array.isArray(data) ? (data as unknown[]) : Object.values(data);
  for (const e of entries) {
    if (!e || typeof e !== 'object') continue;
    const d = e as Record<string, unknown>;
    const ssid = str(d['ssid']) ?? str(d['essid']);
    if (!ssid) continue;
    rows.push({
      name: ssid,
      band: /5g|ac|ax/i.test(String(d['ifname'] ?? d['device'] ?? '')) ? '5g' : '2g',
      channel: num(d['channel']),
      bssid: str(d['bssid']) ?? null,
      encryption: str(d['encryption']) ?? (d['wpa'] || d['ieee80211w'] ? 'wpa' : 'none'),
      vlanId: num(d['vlan']),
      ifc: str(d['ifname']) ?? str(d['device']) ?? null,
    });
  }
  return rows;
}

/** Parses `uci show wireless` → WifiSsidRow[] (config-level SSIDs). */
export function parseWirelessUci(text: string): WifiSsidRow[] {
  const tree = parseUciShow(text);
  const rows: WifiSsidRow[] = [];
  for (const [key, options] of Object.entries(tree['wireless'] ?? {})) {
    if (!key.startsWith('@wifi-iface[')) continue;
    const ssid = uciOpt(options, 'ssid');
    if (!ssid) continue;
    // Band from the radio reference (radio0 → 2g typically).
    const radioRef = uciOpt(options, 'device') ?? '';
    rows.push({
      name: ssid,
      band: /radio[1-9]/.test(radioRef) ? '5g' : '2g',
      channel: num(uciOpt(options, 'channel')),
      bssid: null,
      encryption: uciOpt(options, 'encryption') ?? (uciOpt(options, 'key') ? 'wpa' : 'none'),
      vlanId: num(uciOpt(options, 'network')?.match(/\.(\d+)$/)?.[1]),
      ifc: radioRef || null,
    });
  }
  return rows;
}

/** Parses `uci show firewall` → unified FirewallRuleRow[] (fw4). */
export function parseFirewallUci(text: string): FirewallRuleRow[] {
  const tree = parseUciShow(text);
  const fw = tree['firewall'] ?? {};
  const rows: FirewallRuleRow[] = [];

  // Zones (for scope + default policy context).
  const zones: Record<string, { name: string; input?: string }> = {};
  for (const [key, options] of Object.entries(fw)) {
    if (!key.startsWith('@zone[')) continue;
    zones[key] = { name: uciOpt(options, 'name') ?? key, input: uciOpt(options, 'input') };
  }

  // Filter rules.
  const ruleSections = uciSectionsByType(fw, 'rule');
  ruleSections.forEach(({ key, options }, i) => {
    const srcZone = uciOpt(options, 'src_zone');
    const dstZone = uciOpt(options, 'dest_zone');
    rows.push({
      ruleType: 'filter',
      vendorRuleId: `fw4:${key}`,
      position: i + 1,
      protocol: (uciOpt(options, 'proto') ?? 'all').toLowerCase(),
      sourceIp: uciOpt(options, 'src_ip') ?? (srcZone ? zones[srcZone]?.name : undefined) ?? '',
      destIp: uciOpt(options, 'dest_ip') ?? (dstZone ? zones[dstZone]?.name : undefined) ?? '',
      sourcePort: uciOpt(options, 'src_port') ?? null,
      destPort: uciOpt(options, 'dest_port') ?? null,
      action: (uciOpt(options, 'target') ?? 'ACCEPT').toUpperCase() === 'DROP' ? 'deny' : (uciOpt(options, 'target') ?? '').toUpperCase() === 'REJECT' ? 'other' : 'allow',
      enabled: uciOpt(options, 'enabled') !== '0',
      description: uciOpt(options, 'name') ?? '',
      scope: srcZone && dstZone ? `${zones[srcZone]?.name ?? srcZone} → ${zones[dstZone]?.name ?? dstZone}` : (srcZone || dstZone || ''),
      ipVersion: (uciOpt(options, 'family') ?? 'ipv4').includes('6') ? 'v6' : 'v4',
      extra: { src_zone: srcZone ?? null, dest_zone: dstZone ?? null },
    });
  });

  // NAT rules (port forwards = dnat; masquerade = snat).
  const natSections = uciSectionsByType(fw, 'redirect');
  for (const { key, options } of natSections) {
    rows.push({
      ruleType: 'dnat',
      vendorRuleId: `fw4:${key}`,
      position: 0,
      protocol: (uciOpt(options, 'proto') ?? 'all').toLowerCase(),
      sourceIp: uciOpt(options, 'src_ip') ?? '',
      destIp: uciOpt(options, 'dest_ip') ?? '',
      sourcePort: null,
      destPort: uciOpt(options, 'dest_port') ?? null,
      action: 'allow',
      enabled: uciOpt(options, 'enabled') !== '0',
      description: uciOpt(options, 'name') ?? `→ ${uciOpt(options, 'target') ?? ''}`,
      scope: uciOpt(options, 'src_dip') ? `${uciOpt(options, 'src_dip')} → ${uciOpt(options, 'target')}` : '',
      ipVersion: (uciOpt(options, 'family') ?? 'ipv4').includes('6') ? 'v6' : 'v4',
      extra: { target: uciOpt(options, 'target') ?? null },
    });
  }

  const masqSections = uciSectionsByType(fw, 'masq');
  for (const { key, options } of masqSections) {
    rows.push({
      ruleType: 'snat',
      vendorRuleId: `fw4:${key}`,
      position: 0,
      protocol: 'all',
      sourceIp: uciOpt(options, 'src_ip') ?? '',
      destIp: '',
      sourcePort: null,
      destPort: null,
      action: 'allow',
      enabled: uciOpt(options, 'enabled') !== '0',
      description: uciOpt(options, 'name') ?? 'masquerade',
      scope: (() => {
        const src = uciOpt(options, 'src');
        return src ? `${zones[src]?.name ?? src} → ${uciOpt(options, 'out') ?? ''}` : '';
      })(),
      ipVersion: (uciOpt(options, 'family') ?? 'ipv4').includes('6') ? 'v6' : 'v4',
      extra: {},
    });
  }

  return rows;
}
