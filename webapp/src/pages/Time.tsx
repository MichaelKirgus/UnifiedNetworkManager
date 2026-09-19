import { useEffect, useMemo, useRef, useState, type MouseEvent as ReactMouseEvent } from 'react';
import { useQueries, useQuery } from '@tanstack/react-query';
import clsx from 'clsx';
import { ChevronDown, ChevronUp, Clock } from 'lucide-react';
import { Layout } from '../components/Layout';
import { DataTable, type DataTableColumn } from '../components/DataTable';
import { api, DeviceTimeRow } from '../api/client';
import { useTimeFormat } from '../utils/time';

/** The `system.deviceTime` blob a plugin emits (telemetry or live probe). */
interface ProbeDeviceTime {
  localIso?: string;
  timezone?: string | null;
  utcOffsetMinutes?: number | null;
  epochMs?: number | null;
}

/** The `system.ntpServed` blob the generic-ntp plugin emits (telemetry or live probe). */
interface ProbeNtpServed {
  timeUtc?: string;
  epochMs?: number | null;
  stratum?: number | null;
  referenceId?: string | null;
}

/** One device as rendered on this page — telemetry baseline merged with the
 * freshest live probe (when its plugin supports the 'deviceTime' / 'ntpServed'
 * probe keys). Carries BOTH clocks: the device's own system time AND the time it
 * serves over NTP (they can differ). */
interface TimeRowView {
  deviceId: string;
  name: string;
  managementAddress: string;
  /** Device's local wall clock (ISO, may carry an offset) — display as-is. */
  localIso: string | null;
  timezone: string | null;
  utcOffsetMinutes: number | null;
  /** Stable clock offset in ms — device instant MINUS the reading's own timestamp
   * (telemetry: pre-computed by the API; live probe: measured against its
   * collectedAt). Positive = device ahead. Null = not computable. Unlike a
   * drift-vs-now value this does NOT grow with staleness. */
  driftMs: number | null;
  /** True when the freshest reading came from a live probe (< 15 s old). */
  live: boolean;
  collectedAt: string | null;

  // --- NTP-served time (distinct from the device's own clock) -----------------
  /** UTC wall clock served by the device's NTP service (ISO "…Z"). */
  ntpTimeUtc: string | null;
  /** Stratum of the source (1 = reference clock … 15 = unsynchronized). */
  ntpStratum: number | null;
  /** Reference ID (dotted IPv4 for stratum ≤ 1, else a tag like "GOOG"). */
  ntpReferenceId: string | null;
  /** Stable offset of the SERVED instant vs UNM — same semantics as driftMs. */
  ntpDriftMs: number | null;
  /** True when the freshest NTP reading came from a live probe (< 15 s old). */
  ntpLive: boolean;
}

/** One short-cycle probe target: which plugin + which key to poll every few seconds. */
interface ProbeTarget {
  deviceId: string;
  pluginId: string;
  /** 'deviceTime' (system clock) or 'ntpServed' (NTP-served time). */
  kind: 'deviceTime' | 'ntpServed';
}

/** Drift magnitude → color class (green = NTP-tight, amber = off by < 1 min, red beyond). */
function driftTextClass(ms: number): string {
  const abs = Math.abs(ms);
  if (abs < 1_000) return 'text-success-fg';
  if (abs < 60_000) return 'text-warning-fg';
  return 'text-danger-fg';
}

/** Drift magnitude → bar/dot color (token, for the span chart). */
function driftBarColor(ms: number): string {
  const abs = Math.abs(ms);
  if (abs < 1_000) return 'rgb(var(--status-ok))';
  if (abs < 60_000) return 'rgb(var(--status-warn))';
  return 'rgb(var(--status-critical))';
}

/** Signed human drift: "+23 ms", "−1.25 s", "+4m 07s", "−1d 3h". */
function fmtDrift(ms: number | null): string {
  if (ms === null) return '—';
  const abs = Math.abs(ms);
  const sign = ms >= 0 ? '+' : '−';
  if (abs < 1_000) return `${sign}${Math.round(abs)} ms`;
  if (abs < 60_000) return `${sign}${(abs / 1_000).toFixed(2)} s`;
  if (abs < 3_600_000) {
    const m = Math.floor(abs / 60_000);
    const s = Math.round((abs % 60_000) / 1_000);
    return `${sign}${m}m ${String(s).padStart(2, '0')}s`;
  }
  if (abs < 86_400_000) {
    const h = Math.floor(abs / 3_600_000);
    const m = Math.round((abs % 3_600_000) / 60_000);
    return `${sign}${h}h ${String(m).padStart(2, '0')}m`;
  }
  const d = Math.floor(abs / 86_400_000);
  const h = Math.round((abs % 86_400_000) / 3_600_000);
  return `${sign}${d}d ${h}h`;
}

/** Fixed-offset minutes → "+02:00" label. */
function fmtOffset(mins: number): string {
  const sign = mins >= 0 ? '+' : '−';
  const a = Math.abs(mins);
  return `${sign}${String(Math.floor(a / 60)).padStart(2, '0')}:${String(a % 60).padStart(2, '0')}`;
}

/** "just now" / "42 s ago" / "3 m ago" / "5 h ago". */
function fmtAge(iso: string | null, nowMs: number): string {
  if (!iso) return 'never';
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return 'unknown';
  const s = Math.max(0, Math.round((nowMs - t) / 1_000));
  if (s < 5) return 'just now';
  if (s < 60) return `${s} s ago`;
  if (s < 3_600) return `${Math.floor(s / 60)} m ago`;
  if (s < 86_400) return `${Math.floor(s / 3_600)} h ago`;
  return `${Math.floor(s / 86_400)} d ago`;
}

/** Wall-clock part ("HH:MM:SS") + date part of a device localIso, shown as-is. */
function wallClockParts(localIso: string | null): { time: string; date: string } {
  if (!localIso) return { time: '—', date: '' };
  const t = localIso.slice(11, 19);
  const d = localIso.slice(0, 10);
  return { time: /^\d{2}:\d{2}(:\d{2})?$/.test(t) ? t : '—', date: /^\d{4}-\d{2}-\d{2}$/.test(d) ? d : '' };
}

/** Pick a "nice" half-range (seconds) so the span axis shows ≤ 5 ticks per side. */
function niceHalfRange(maxAbsMs: number): number {
  const secs = Math.max(2, maxAbsMs / 1_000); // never tighter than ±2 s
  for (const r of [2, 5, 10, 30, 60, 300, 900, 3_600, 21_600, 86_400, 604_800]) {
    if (secs <= r) return r;
  }
  return 2_592_000; // ±3 d — beyond this the clock is simply broken
}

export default function Time() {
  // The UNM reference clock in the header follows the user's display zone.
  // Device clocks below intentionally stay in THEIR OWN zones — that is what
  // drift comparison is about (a device showing a different wall time IS the point).
  const { formatTime, formatDate } = useTimeFormat();
  // Telemetry baseline: the API reads each device's latest `system.deviceTime`
  // metric and pre-computes drift. Poll at the telemetry cadence (30 s).
  const timeQuery = useQuery({
    queryKey: ['device-time'],
    queryFn: () => api.deviceTime(),
    refetchInterval: 30_000,
  });

  // Ticking "now" — drift is recomputed against the local clock every second so
  // values stay fresh between polls (both clocks advance at the same rate).
  const [nowMs, setNowMs] = useState(() => Date.now());
  useEffect(() => {
    const t = setInterval(() => setNowMs(Date.now()), 1_000);
    return () => clearInterval(t);
  }, []);

  // --- Live probes (short-cycle, capability 'probe') -------------------------
  // Devices whose latest snapshot came from a probe-capable plugin get a live
  // `deviceTime` probe every few seconds — the freshest possible drift. Plugins
  // without the key simply omit it and we keep serving the telemetry value.
  const pluginsQuery = useQuery({ queryKey: ['plugins'], queryFn: api.plugins });
  const probePluginIds = useMemo(
    () => new Set((pluginsQuery.data ?? []).filter((p) => (p.capabilities ?? []).includes('probe')).map((p) => p.id)),
    [pluginsQuery.data],
  );

  // One target per (device, plugin, clock-kind): the system clock via its
  // `pluginId` + 'deviceTime' key, and the NTP-served time via its `ntpPluginId`
  // + 'ntpServed' key. A device watched by both an OS-capable AND the NTP plugin
  // gets TWO targets — each kind refreshes independently every few seconds.
  const probeTargets = useMemo(() => {
    const seen = new Set<string>();
    const out: ProbeTarget[] = [];
    for (const r of timeQuery.data?.devices ?? []) {
      if (r.pluginId && probePluginIds.has(r.pluginId)) {
        const k = `${r.deviceId}|${r.pluginId}|deviceTime`;
        if (!seen.has(k)) { seen.add(k); out.push({ deviceId: r.deviceId, pluginId: r.pluginId, kind: 'deviceTime' }); }
      }
      if (r.ntpPluginId && probePluginIds.has(r.ntpPluginId)) {
        const k = `${r.deviceId}|${r.ntpPluginId}|ntpServed`;
        if (!seen.has(k)) { seen.add(k); out.push({ deviceId: r.deviceId, pluginId: r.ntpPluginId, kind: 'ntpServed' }); }
      }
    }
    return out;
  }, [timeQuery.data, probePluginIds]);

  const probeResults = useQueries({
    queries: probeTargets.map((t) => ({
      queryKey: ['device-probe', t.deviceId, t.kind],
      queryFn: () => api.deviceProbe(t.deviceId, [t.kind === 'ntpServed' ? 'ntpServed' : 'deviceTime'], t.pluginId),
      refetchInterval: 5_000,
      // Short-cycle live data — a failed poll is retried by the NEXT interval tick;
      // React Query's default retry storm only floods devices whose probe can't work.
      retry: false,
      staleTime: 0,
      gcTime: 30_000,
    })),
  });

  // deviceId → freshest live reading (only when < 15 s old), with the probe's
  // own collectedAt so drift can be measured against that instant. One map per
  // clock kind — they come from different plugins/rows and must not mix.
  const [liveClockByDevice, liveNtpByDevice] = useMemo(() => {
    const clocks = new Map<string, { dt: ProbeDeviceTime; atMs: number }>();
    const ntps = new Map<string, { ntp: ProbeNtpServed; atMs: number }>();
    probeTargets.forEach((t, i) => {
      const res = probeResults[i];
      if (!res?.data) return;
      const atMs = Date.parse(res.data.probe.collectedAt);
      if (Number.isNaN(atMs) || Date.now() - atMs >= 15_000) return;
      if (t.kind === 'deviceTime') {
        const dt = res.data.probe.metrics['system.deviceTime'];
        if (dt && typeof dt === 'object' && typeof (dt as ProbeDeviceTime).localIso === 'string') {
          clocks.set(t.deviceId, { dt: dt as ProbeDeviceTime, atMs });
        }
      } else {
        const ntp = res.data.probe.metrics['system.ntpServed'];
        if (ntp && typeof ntp === 'object' && typeof (ntp as ProbeNtpServed).timeUtc === 'string') {
          ntps.set(t.deviceId, { ntp: ntp as ProbeNtpServed, atMs });
        }
      }
    });
    return [clocks, ntps] as const;
  }, [probeTargets, probeResults]);

  // Merge telemetry baseline + live probes into render rows. Drift is the STABLE
  // clock offset: for a live probe we measure deviceEpoch − probeInstant here;
  // otherwise we use the API's pre-computed value (deviceEpoch − readingInstant).
  // The NTP-served columns follow the same pattern from their own baseline/probe.
  const rows: TimeRowView[] = useMemo(() => {
    const out: TimeRowView[] = [];
    for (const r of timeQuery.data?.devices ?? []) {
      const live = liveClockByDevice.get(r.deviceId);
      let driftMs: number | null = typeof r.driftMs === 'number' && Number.isFinite(r.driftMs) ? r.driftMs : null;
      if (live) {
        const epochMs = typeof live.dt.epochMs === 'number' && Number.isFinite(live.dt.epochMs) ? live.dt.epochMs : null;
        driftMs = epochMs !== null ? epochMs - live.atMs : null;
      }

      // NTP-served: telemetry baseline, overridden by a fresh live probe.
      const liveNtp = liveNtpByDevice.get(r.deviceId);
      let ntpTimeUtc: string | null = r.ntpAvailable ? (r.ntpTimeUtc ?? null) : null;
      let ntpStratum: number | null = r.ntpAvailable ? (r.ntpStratum ?? null) : null;
      let ntpReferenceId: string | null = r.ntpAvailable ? (r.ntpReferenceId ?? null) : null;
      let ntpDriftMs: number | null = typeof r.ntpDriftMs === 'number' && Number.isFinite(r.ntpDriftMs) ? r.ntpDriftMs : null;
      if (liveNtp) {
        ntpTimeUtc = liveNtp.ntp.timeUtc ?? ntpTimeUtc;
        ntpStratum = typeof liveNtp.ntp.stratum === 'number' ? liveNtp.ntp.stratum : ntpStratum;
        ntpReferenceId = liveNtp.ntp.referenceId ?? ntpReferenceId;
        const epochMs = typeof liveNtp.ntp.epochMs === 'number' && Number.isFinite(liveNtp.ntp.epochMs) ? liveNtp.ntp.epochMs : null;
        if (epochMs !== null) ntpDriftMs = epochMs - liveNtp.atMs;
      }

      out.push({
        deviceId: r.deviceId,
        name: r.name,
        managementAddress: r.managementAddress,
        localIso: live?.dt.localIso ?? r.localIso ?? null,
        timezone: (live?.dt.timezone ?? null) || r.timezone || null,
        utcOffsetMinutes: live?.dt.utcOffsetMinutes ?? r.utcOffsetMinutes ?? null,
        driftMs,
        live: !!live,
        collectedAt: r.collectedAt ?? null,
        ntpTimeUtc,
        ntpStratum,
        ntpReferenceId,
        ntpDriftMs,
        ntpLive: !!liveNtp,
      });
    }
    return out;
  }, [timeQuery.data, liveClockByDevice, liveNtpByDevice]);

  const driftOf = (deviceId: string): number | null => {
    const row = rows.find((r) => r.deviceId === deviceId);
    return row?.driftMs ?? null;
  };

  const ntpDriftOf = (deviceId: string): number | null => {
    const row = rows.find((r) => r.deviceId === deviceId);
    return row?.ntpDriftMs ?? null;
  };

  /** "HH:MM:SS" of a UTC ISO instant ("…Z") — the served time, shown as-is. */
  function ntpWallClock(iso: string | null): string {
    if (!iso) return '—';
    const t = iso.slice(11, 19);
    return /^\d{2}:\d{2}(:\d{2})?$/.test(t) ? t : '—';
  }

  /** Stratum → short label: 1 "ref clock", 2–6 numeric, 0/15 "unsync". */
  function stratumLabel(s: number | null): string {
    if (s === null || s === undefined) return '—';
    if (s === 0 || s === 15) return `S${s} unsync`;
    if (s === 1) return 'S1 ref clock';
    return `S${s}`;
  }

  // Span-chart geometry: half-range in ms + per-row position.
  const span = useMemo(() => {
    let maxAbs = 0;
    for (const r of rows) if (r.driftMs !== null) maxAbs = Math.max(maxAbs, Math.abs(r.driftMs));
    const halfMs = niceHalfRange(maxAbs) * 1_000;
    return { halfMs };
  }, [rows]);

  // Shared hover state: table rows and span-chart rows highlight each other.
  const [hoveredDevice, setHoveredDevice] = useState<string | null>(null);

  // Splitter layout: device table (top) vs drift-span view (bottom). Each side
  // can be collapsed so the other takes the full height; while both are open the
  // divider is draggable — same pattern as the WiFi page.
  const [spanOpen, setSpanOpen] = useState(true);
  const [tablePct, setTablePct] = useState(52);
  const vSplitRef = useRef<HTMLDivElement>(null);
  const vDragCleanup = useRef<(() => void) | null>(null);

  useEffect(() => () => { vDragCleanup.current?.(); }, []);

  const startVDrag = (e: ReactMouseEvent) => {
    e.preventDefault();
    const el = vSplitRef.current;
    if (!el) return;
    const rect = el.getBoundingClientRect();
    const move = (ev: globalThis.MouseEvent) => {
      const pct = ((ev.clientY - rect.top) / rect.height) * 100;
      setTablePct(Math.min(75, Math.max(25, pct)));
    };
    const up = () => {
      window.removeEventListener('mousemove', move);
      window.removeEventListener('mouseup', up);
      document.body.style.cursor = '';
      document.body.style.userSelect = '';
      vDragCleanup.current = null;
    };
    window.addEventListener('mousemove', move);
    window.addEventListener('mouseup', up);
    document.body.style.cursor = 'row-resize';
    document.body.style.userSelect = 'none';
    vDragCleanup.current = up;
  };

  const columns: DataTableColumn<TimeRowView>[] = [
    {
      header: 'Device',
      key: 'name',
      width: 210,
      render: (row) => (
        <div className="flex flex-col">
          <span className="font-medium text-foreground">{row.name}</span>
          <span className="font-mono text-[11px] text-faint">{row.managementAddress}</span>
        </div>
      ),
    },
    {
      header: 'Local time',
      key: 'localIso',
      width: 150,
      exportValue: (row) => row.localIso ?? '',
      render: (row) => {
        const { time, date } = wallClockParts(row.localIso);
        return (
          <div className="flex items-center gap-2">
            {time === '—' ? (
              <span className="text-faint">—</span>
            ) : (
              <span className="font-mono text-sm tabular-nums">{time}</span>
            )}
            {date && <span className="font-mono text-[10px] text-faint">{date}</span>}
            {row.live && (
              <span title="Live probe (< 15 s old)" className="h-1.5 w-1.5 shrink-0 rounded-full bg-success-fg" />
            )}
          </div>
        );
      },
    },
    {
      header: 'Timezone',
      key: 'timezone',
      width: 160,
      exportValue: (row) => row.timezone ?? (row.utcOffsetMinutes !== null ? fmtOffset(row.utcOffsetMinutes) : ''),
      render: (row) =>
        row.timezone ? (
          <span className="rounded bg-muted px-1.5 py-0.5 text-xs text-secondary">{row.timezone}</span>
        ) : row.utcOffsetMinutes !== null ? (
          <span className="font-mono text-xs text-secondary" title="Fixed offset — no IANA zone reported">
            {fmtOffset(row.utcOffsetMinutes)} fixed
          </span>
        ) : (
          <span className="text-faint">—</span>
        ),
    },
    {
      header: 'Drift vs UNM',
      key: 'drift',
      width: 130,
      sortAccessor: (row) => driftOf(row.deviceId) ?? Number.MAX_SAFE_INTEGER,
      exportValue: (row) => fmtDrift(driftOf(row.deviceId)),
      render: (row) => {
        const d = driftOf(row.deviceId);
        if (d === null) return <span className="text-faint" title="No resolvable instant — plugin reports no zone/offset">—</span>;
        return (
          <span className={clsx('font-mono text-sm tabular-nums', driftTextClass(d))} title={d >= 0 ? 'Device clock is ahead of UNM' : 'Device clock is behind UNM'}>
            {fmtDrift(d)}
          </span>
        );
      },
    },
    // --- NTP-served time: the instant this device transmits to its clients.
    // Kept SEPARATE from "Local time" on purpose — a box can serve accurate NTP
    // while its own wall clock is off (or vice versa). Hidden by default so the
    // page stays compact for fleets without NTP servers; toggle via column menu.
    {
      header: 'NTP served (UTC)',
      key: 'ntpTimeUtc',
      width: 150,
      hiddenByDefault: true,
      exportValue: (row) => row.ntpTimeUtc ?? '',
      render: (row) => {
        if (!row.ntpTimeUtc) return <span className="text-faint">—</span>;
        return (
          <div className="flex items-center gap-2" title={`Served over NTP — ${row.ntpReferenceId ?? 'unknown reference'}`}>
            <span className="font-mono text-sm tabular-nums">{ntpWallClock(row.ntpTimeUtc)}</span>
            {row.ntpLive && (
              <span title="Live probe (< 15 s old)" className="h-1.5 w-1.5 shrink-0 rounded-full bg-success-fg" />
            )}
          </div>
        );
      },
    },
    {
      header: 'NTP stratum',
      key: 'ntpStratum',
      width: 120,
      hiddenByDefault: true,
      exportValue: (row) => row.ntpReferenceId ?? '',
      render: (row) => {
        if (!row.ntpTimeUtc) return <span className="text-faint">—</span>;
        const ref = row.ntpReferenceId;
        return (
          <div className="flex flex-col" title={ref ? `Reference ID: ${ref}` : undefined}>
            <span className="font-mono text-xs tabular-nums">{stratumLabel(row.ntpStratum)}</span>
            {ref && <span className="truncate font-mono text-[10px] text-faint">{ref}</span>}
          </div>
        );
      },
    },
    {
      header: 'NTP drift vs UNM',
      key: 'ntpDrift',
      width: 130,
      hiddenByDefault: true,
      sortAccessor: (row) => ntpDriftOf(row.deviceId) ?? Number.MAX_SAFE_INTEGER,
      exportValue: (row) => fmtDrift(ntpDriftOf(row.deviceId)),
      render: (row) => {
        const d = ntpDriftOf(row.deviceId);
        if (!row.ntpTimeUtc || d === null) return <span className="text-faint">—</span>;
        return (
          <span className={clsx('font-mono text-sm tabular-nums', driftTextClass(d))} title={d >= 0 ? 'Served time is ahead of UNM' : 'Served time is behind UNM'}>
            {fmtDrift(d)}
          </span>
        );
      },
    },
    {
      header: 'Source / age',
      key: 'collectedAt',
      width: 150,
      render: (row) => (
        <span className="text-xs text-secondary">
          {row.live ? 'live probe' : 'telemetry'} · {fmtAge(row.collectedAt, nowMs)}
        </span>
      ),
    },
  ];

  // "reporting" = the device's plugin read a wall clock (localIso present), even
  // when drift isn't resolvable (zone-less SNMP devices show time but no offset).
  const availableCount = rows.filter((r) => r.localIso !== null).length;
  const ahead = rows.filter((r) => (r.driftMs ?? 1) > 0).length;
  const behind = rows.filter((r) => (r.driftMs ?? 1) < 0).length;
  // NTP-served coverage — how many devices transmit a time over their NTP service.
  const ntpCount = rows.filter((r) => r.ntpTimeUtc !== null).length;

  // Span-chart tick marks: −half, −half/2, 0, +half/2, +half.
  const ticks = [-span.halfMs, -span.halfMs / 2, 0, span.halfMs / 2, span.halfMs];

  return (
    <Layout title="Time">
      {/* Full-height column: table / drift-span split by a horizontal splitter. */}
      <div className="flex h-full min-h-0 flex-col">
        {timeQuery.isLoading && <p className="shrink-0 text-sm text-muted-foreground">Loading device clocks...</p>}
        {timeQuery.isError && (
          <p className="shrink-0 text-sm text-danger-fg">Failed to load device time: {(timeQuery.error as Error).message}</p>
        )}

        {/* Header strip — UNM's own clock (the reference) + coverage summary. */}
        <div className="mb-2 flex shrink-0 items-center gap-4 rounded-lg border border-border bg-card px-4 py-2.5">
          <span className="flex items-center gap-2 text-sm font-semibold text-secondary">
            <Clock size={16} className="text-muted-foreground" />
            UNM clock
          </span>
          <span className="font-mono text-lg tabular-nums text-foreground">{formatTime(nowMs)}</span>
          <span className="font-mono text-[11px] text-faint">{formatDate(nowMs)}</span>
          <span className="ml-auto flex items-center gap-3 text-xs text-secondary">
            <span>{availableCount} of {rows.length} devices reporting</span>
            <span className="text-success-fg">{ahead} ahead</span>
            <span className="text-danger-fg">{behind} behind</span>
            {ntpCount > 0 && (
              <span title="Devices serving time over their NTP/SNTP service" className="rounded bg-muted px-1.5 py-0.5">
                {ntpCount} serve NTP
              </span>
            )}
          </span>
        </div>

        <div ref={vSplitRef} className="flex min-h-0 flex-1 flex-col">
          {/* Device table (top) — fixed share of the page height while the span
              view is open; when collapsed it takes everything. */}
          <div
            className={clsx('min-h-0 pr-1', !spanOpen && 'flex-1')}
            style={{ height: spanOpen ? `${tablePct}%` : undefined }}
          >
            <DataTable<TimeRowView>
              columns={columns}
              rows={rows}
              rowKey={(row) => row.deviceId}
              storageKey="time"
              autoRefresh={{ intervalMs: 30_000, queries: [timeQuery] }}
              fillHeight
              searchPlaceholder="Search devices…"
              emptyMessage="No device clocks reported yet — plugins that can read a wall clock (OPNsense, TrueNAS, RouterOS, OpenWrt, LANCOM) populate this view within a poll cycle."
              onRowHover={(row) => setHoveredDevice(row ? row.deviceId : null)}
            />
          </div>

          {/* Horizontal splitter between table and drift-span view. */}
          {spanOpen && (
            <div
              role="separator"
              aria-orientation="horizontal"
              onMouseDown={startVDrag}
              className="group relative -my-1 h-3 shrink-0 cursor-row-resize"
              title="Drag to resize — or collapse the drift view for full table height"
            >
              <div className="absolute inset-x-0 top-1/2 h-px -translate-y-1/2 bg-muted transition-colors group-hover:bg-accent-hover" />
              <div className="absolute left-1/2 top-1/2 flex h-3 w-8 -translate-x-1/2 -translate-y-1/2 items-center justify-center">
                <span className="h-1 w-6 rounded-full bg-status-neutral transition-colors group-hover:bg-accent-hover" />
              </div>
            </div>
          )}

          {/* Drift-span view (bottom) — one row per device: a bar from the UNM
              center line to the device's clock position. Right = ahead, left =
              behind; color encodes magnitude. The header stays mounted when
              collapsed so it can be re-opened. */}
          <div className={clsx('shrink-0 min-h-0 pl-1', spanOpen && 'flex-1')}>
            <div className="flex h-full min-h-0 flex-col rounded-lg border border-border bg-card">
              <button
                type="button"
                onClick={() => setSpanOpen((o) => !o)}
                className="flex w-full shrink-0 items-center justify-between px-4 py-3 text-left"
                aria-expanded={spanOpen}
              >
                <span className="flex items-center gap-2 text-sm font-semibold text-secondary">
                  <Clock size={16} className="text-muted-foreground" />
                  Drift span — device clocks vs UNM
                </span>
                {spanOpen ? <ChevronDown size={18} className="text-faint" /> : <ChevronUp size={18} className="text-faint" />}
              </button>

              {spanOpen && (
                <div className="flex min-h-0 flex-1 flex-col border-t border-border p-4">
                  {/* Legend: color scale + direction hint. */}
                  <div className="mb-3 flex shrink-0 items-center gap-4 text-[11px] text-secondary">
                    <span className="flex items-center gap-1.5"><span className="h-2 w-2 rounded-full bg-status-ok" /> &lt; 1 s</span>
                    <span className="flex items-center gap-1.5"><span className="h-2 w-2 rounded-full bg-status-warn" /> &lt; 1 min</span>
                    <span className="flex items-center gap-1.5"><span className="h-2 w-2 rounded-full bg-status-critical" /> ≥ 1 min</span>
                    <span className="ml-auto text-faint">← behind UNM · center = UNM clock · ahead of UNM →</span>
                  </div>

                  {/* Axis header — tick labels aligned with the row grid below. */}
                  <div className="mb-1 flex shrink-0 items-center gap-3">
                    <div className="w-40 shrink-0" />
                    <div className="relative h-4 min-w-0 flex-1">
                      {ticks.map((v) => (
                        <span
                          key={v}
                          className="absolute -translate-x-1/2 font-mono text-[10px] tabular-nums text-faint"
                          style={{ left: `${50 + (v / span.halfMs) * 50}%` }}
                        >
                          {fmtDrift(v)}
                        </span>
                      ))}
                    </div>
                    <div className="w-[92px] shrink-0" />
                  </div>

                  {/* One row per device (scrolls internally when the pane is short). */}
                  <div className="min-h-0 flex-1 overflow-y-auto">
                    {rows.length === 0 && <p className="py-4 text-center text-xs text-faint">No devices yet.</p>}
                    {rows.map((row) => {
                      const d = driftOf(row.deviceId);
                      // Position of the marker: 50% + signed fraction of the half-range.
                      const posPct = d === null ? null : Math.min(98, Math.max(2, 50 + (d / span.halfMs) * 50));
                      const dimmed = hoveredDevice !== null && hoveredDevice !== row.deviceId;
                      return (
                        <div
                          key={row.deviceId}
                          className="flex items-center gap-3 border-b border-border/40 py-1 last:border-b-0"
                          onMouseEnter={() => setHoveredDevice(row.deviceId)}
                          onMouseLeave={() => setHoveredDevice(null)}
                        >
                          <div className={clsx('w-40 shrink-0 truncate text-xs transition-opacity duration-150', dimmed && 'opacity-30')} title={`${row.name} (${row.managementAddress})`}>
                            {row.name}
                          </div>
                          <div className="relative h-4 min-w-0 flex-1">
                            {/* Center line = UNM's own clock. */}
                            <div className="absolute inset-y-0 left-1/2 w-px -translate-x-1/2 bg-border" />
                            {d !== null && posPct !== null ? (
                              <>
                                {/* Bar from center to the device position — direction = sign. */}
                                <div
                                  className="absolute top-1/2 h-0.5 -translate-y-1/2 transition-opacity duration-150"
                                  style={{
                                    left: posPct >= 50 ? '50%' : `${posPct}%`,
                                    width: `${Math.abs(posPct - 50)}%`,
                                    background: driftBarColor(d),
                                    opacity: dimmed ? 0.25 : 1,
                                  }}
                                />
                                {/* Marker dot at the device's clock position. */}
                                <div
                                  className="absolute top-1/2 h-2 w-2 -translate-x-1/2 -translate-y-1/2 rounded-full transition-opacity duration-150"
                                  style={{ left: `${posPct}%`, background: driftBarColor(d), opacity: dimmed ? 0.25 : 1 }}
                                />
                              </>
                            ) : (
                              <span className="absolute inset-y-0 left-1/2 -translate-x-1/2 text-[10px] leading-4 text-faint">no clock data</span>
                            )}
                          </div>
                          <div className={clsx('w-[92px] shrink-0 text-right font-mono text-xs tabular-nums transition-opacity duration-150', dimmed && 'opacity-30')}>
                            {d === null ? <span className="text-faint">—</span> : (
                              <span className={driftTextClass(d)}>{fmtDrift(d)}</span>
                            )}
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </Layout>
  );
}
