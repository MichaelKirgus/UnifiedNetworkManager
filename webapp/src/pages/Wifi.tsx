import { useEffect, useRef, useState, type MouseEvent as ReactMouseEvent } from 'react';
import { useQuery } from '@tanstack/react-query';
import clsx from 'clsx';
import { ChevronDown, ChevronUp, Wifi as WifiIcon } from 'lucide-react';
import { Layout } from '../components/Layout';
import { DataTable, DataTableColumn } from '../components/DataTable';
import { DeviceChip } from '../components/DeviceChip';
import { api, WifiBandView, WifiNeighborRef, WifiSsidGroup } from '../api/client';

/** Color scale for airtime utilization (green → amber → red). */
function utilColor(pct: number | null): string {
  if (pct === null) return 'text-faint';
  if (pct < 30) return 'text-success-fg';
  if (pct < 70) return 'text-warning-fg';
  return 'text-danger-fg';
}

/** Bar fill for airtime utilization (green → amber → red). */
function utilBarColor(pct: number | null): string {
  if (pct === null) return 'rgb(var(--status-neutral))'; // no data
  if (pct < 30) return 'rgb(var(--status-ok))';
  if (pct < 70) return 'rgb(var(--status-warn))';
  return 'rgb(var(--status-critical))';
}

/** Pick a tick step so the axis shows at most ~14 labels. */
function tickStep(span: number): number {
  for (const s of [1, 2, 5, 10, 20]) if (span / s <= 14) return s;
  return 50;
}

/** Stable per-SSID hues (scanner style): each network gets its own color so
 * bars are identifiable WITHOUT text labels on top of them. The index into this
 * palette comes from the SSID's position in the sorted name list, so colors are
 * deterministic across renders and bands. */
const HUES = [210, 340, 150, 25, 270, 90, 180, 300, 45, 120, 230, 355];
function ssidHue(name: string, allNames: string[]): number {
  const idx = allNames.indexOf(name);
  return HUES[(idx < 0 ? 0 : idx) % HUES.length];
}

/** Default channel axis ranges per band (used when the data is sparse). */
const BAND_DEFAULTS: Record<string, { min: number; max: number; label: string }> = {
  '2.4': { min: 1, max: 14, label: '2.4 GHz' },
  '5': { min: 36, max: 165, label: '5 GHz' },
  '6': { min: 1, max: 233, label: '6 GHz' },
};

/** inSSIDer-style band panel: ONE bar per channel (height = airtime
 * utilization), a noise-floor line at the bottom, and colored dots for own
 * SSIDs at their channel position. Hovering an SSID (legend/table/dot) dims
 * every channel that does NOT carry it. */
function BandPanel({
  view,
  allNames,
  hoveredSsid,
  onHover,
}: {
  view: WifiBandView;
  /** Sorted list of ALL SSID names — used for stable per-SSID colors. */
  allNames: string[];
  hoveredSsid: string | null;
  onHover: (ssid: string | null) => void;
}) {
  // The axis ALWAYS spans the full standard band range (like a real scanner) —
  // shrinking it to only the in-use channels would pin two SSIDs on ch 1 and
  // ch 5 to opposite edges of the panel. Only EXPAND when a channel lies
  // outside the default range (e.g. DFS edge channels, 6 GHz).
  const def = BAND_DEFAULTS[view.band] ?? { min: 1, max: 255, label: view.band };
  const min = Math.min(def.min, view.minChannel ?? def.min);
  const max = Math.max(def.max, view.maxChannel ?? def.max);
  const span = max - min;

  // Which own SSIDs sit on each channel (for hover dimming of bars).
  const ssidsOnChannel = new Map<number, Set<string>>();
  for (const m of view.markers) {
    let set = ssidsOnChannel.get(m.channel);
    if (!set) { set = new Set(); ssidsOnChannel.set(m.channel, set); }
    set.add(m.name);
  }

  const leftPct = (ch: number): string => `${((ch - min) / span) * 100}%`;
  const step = tickStep(span);
  const ticks: number[] = [];
  for (let ch = Math.ceil(min / step) * step; ch <= max; ch += step) ticks.push(ch);

  const empty = view.channels.length === 0 && view.markers.length === 0;

  return (
    <div className="rounded-lg border border-border bg-card p-3">
      <div className="mb-1 flex items-center justify-between">
        <span className="text-sm font-semibold text-secondary">{def.label}</span>
        <span className="flex items-center gap-3 text-xs text-faint">
          {view.noiseFloorDbm !== null && view.noiseFloorDbm !== undefined && (
            <span title="Noisiest radio noise floor on this band" className="font-mono">noise {Math.round(view.noiseFloorDbm)} dBm</span>
          )}
          <span>{view.markers.length > 0 ? `${view.markers.length} network${view.markers.length === 1 ? '' : 's'} · ` : ''}ch {min}–{max}</span>
        </span>
      </div>
      <div className="relative h-32 w-full">
        {empty && (
          <div className="flex h-full items-center justify-center text-xs text-faint">—</div>
        )}
        {/* Airtime gridlines — bar area = 76px above the axis (bottom-5). */}
        {[0, 50, 100].map((v) => (
          <div key={v} className="absolute left-0 right-0" style={{ bottom: 20 + (v / 100) * 76 }}>
            <div className="h-px bg-muted" />
            <span className="absolute -top-1.5 left-0 text-[9px] font-mono text-faint">{v}%</span>
          </div>
        ))}
        {/* One bar per channel — height ∝ airtime utilization (worst case across devices). */}
        {view.channels.map((c) => {
          const util: number | null = c.utilizationPct ?? null;
          const h = util === null ? 8 : Math.max(8, (util / 100) * 76);
          const names = ssidsOnChannel.get(c.channel);
          const dimmed = hoveredSsid !== null && !(names?.has(hoveredSsid));
          return (
            <div
              key={c.channel}
              className={clsx('absolute bottom-5 w-4 rounded-t transition-opacity duration-150', dimmed && 'opacity-25')}
              style={{ left: leftPct(c.channel), transform: 'translateX(-50%)', height: h, background: utilBarColor(util) }}
              title={`ch ${c.channel}${util !== null ? ` · airtime ${Math.round(util * 10) / 10}%` : ''}${names?.size ? `\n${[...names].join(', ')}` : ''}`}
            />
          );
        })}
        {/* Own-SSID markers — colored dots in a lane above the bars. */}
        {view.markers.map((m) => (
          <div
            key={`${m.name}-${m.channel}`}
            className={clsx('absolute h-2.5 w-2.5 -translate-x-1/2 rounded-full border border-white shadow-sm transition-opacity duration-150', hoveredSsid !== null && m.name !== hoveredSsid && 'opacity-20')}
            style={{ left: leftPct(m.channel), bottom: 20 + 76 + 4, background: `hsl(${ssidHue(m.name, allNames)}, 65%, 45%)` }}
            title={`${m.name} — ch ${m.channel}`}
            onMouseEnter={() => onHover(m.name)}
            onMouseLeave={() => onHover(null)}
          />
        ))}
        {/* Noise floor line (annotation — dBm is not on the % axis). */}
        {view.noiseFloorDbm !== null && view.noiseFloorDbm !== undefined && !empty && (
          <div className="absolute left-0 right-0 border-t border-dashed border-status-warn/70" style={{ bottom: 21 }}>
            <span className="absolute -top-3.5 right-0 text-[9px] font-mono text-warning-fg">noise {Math.round(view.noiseFloorDbm)} dBm</span>
          </div>
        )}
        {/* Channel axis + ticks */}
        <div className="absolute bottom-0 left-0 right-0 h-px bg-muted" />
        {ticks.map((ch) => (
          <div key={ch} className="absolute -bottom-4 -translate-x-1/2 text-[9px] font-mono text-faint" style={{ left: leftPct(ch) }}>
            {ch}
          </div>
        ))}
      </div>
    </div>
  );
}

/** Neighbor networks seen by device scan engines (inSSIDer's network list). */
function NeighborList({ neighbors }: { neighbors: WifiNeighborRef[] }) {
  const MAX_SHOWN = 30;
  const shown = neighbors.slice(0, MAX_SHOWN);
  return (
    <div className="flex h-full flex-col rounded-lg border border-border bg-card p-3">
      <div className="mb-2 flex items-center justify-between">
        <span className="text-sm font-semibold text-secondary">Neighbor networks</span>
        <span className="text-xs text-faint">{neighbors.length} seen by your devices</span>
      </div>
      {shown.length === 0 ? (
        <p className="m-auto text-xs text-faint">No neighbor scan data yet — LANCOM LX APs populate this within a poll cycle.</p>
      ) : (
        <ul className="-my-1 min-h-0 flex-1 divide-y divide-border overflow-y-auto">
          {shown.map((n) => {
            const dbm = n.signalDbm ?? null;
            // Map -90…-30 dBm onto a 4–100% bar width.
            const pct = dbm === null ? 0 : Math.max(4, Math.min(100, ((dbm + 90) / 60) * 100));
            const color = dbm === null ? 'bg-muted' : dbm >= -55 ? 'bg-status-ok' : dbm >= -70 ? 'bg-status-warn' : 'bg-status-critical';
            return (
              <li key={`${n.deviceId}-${n.bssid}`} className="flex items-center gap-2 py-1.5" title={`BSSID ${n.bssid}${n.siteName ? ` · site ${n.siteName}` : ''} — seen by ${n.deviceName ?? n.managementAddress ?? 'unknown device'}`}>
                <div className="h-1.5 w-16 shrink-0 overflow-hidden rounded bg-muted">
                  <div className={`h-full ${color}`} style={{ width: `${pct}%` }} />
                </div>
                <span className={clsx('w-40 truncate text-xs', n.ssid ? 'font-medium text-secondary' : 'italic text-faint')}>
                  {n.ssid || `hidden (${n.bssid.slice(-5)})`}
                </span>
                <span className="whitespace-nowrap rounded bg-muted px-1.5 py-0.5 font-mono text-[10px] text-secondary">
                  {n.band || '—'}G · ch {n.channel ?? '?'}
                </span>
                <span className="w-12 shrink-0 text-right font-mono text-[10px] text-muted-foreground">{dbm !== null ? `${Math.round(dbm)} dBm` : '—'}</span>
                <span className="min-w-0 flex-1 truncate text-right text-[10px] text-faint">{n.deviceName ?? n.managementAddress ?? ''}</span>
              </li>
            );
          })}
        </ul>
      )}
      {neighbors.length > MAX_SHOWN && (
        <p className="mt-2 text-center text-[10px] text-faint">+{neighbors.length - MAX_SHOWN} more (weakest signals hidden)</p>
      )}
    </div>
  );
}

export default function Wifi() {
  // The API polls plugins every 30s and upserts the WiFi inventory — refresh at
  // the same cadence so client counts / airtime track live state.
  const wifiQuery = useQuery({
    queryKey: ['wifi'],
    queryFn: () => api.wifi(),
    refetchInterval: 30_000,
  });

  // Shared hover state: table rows and spectrum bars both set it; the non-matching
  // SSIDs dim in the diagram while something is hovered.
  const [hoveredSsid, setHoveredSsid] = useState<string | null>(null);
  const [spectrumOpen, setSpectrumOpen] = useState(true);

  // Splitter layout: band diagrams (left) vs neighbor list (right). Each side can
  // be collapsed so the other takes the full width; while both are open the
  // divider is draggable.
  const [bandsOpen, setBandsOpen] = useState(true);
  const [neighborsOpen, setNeighborsOpen] = useState(true);
  const [splitPct, setSplitPct] = useState(68);
  const splitRef = useRef<HTMLDivElement>(null);
  const dragCleanup = useRef<(() => void) | null>(null);

  // Horizontal splitter: SSID table (top) vs spectrum view (bottom). The table
  // gets a fixed share of the page height; collapsing the spectrum below gives
  // it back to the table.
  const [tablePct, setTablePct] = useState(50);
  const vSplitRef = useRef<HTMLDivElement>(null);
  const vDragCleanup = useRef<(() => void) | null>(null);

  useEffect(() => () => { dragCleanup.current?.(); vDragCleanup.current?.(); }, []);

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

  const startDrag = (e: ReactMouseEvent) => {
    e.preventDefault();
    const el = splitRef.current;
    if (!el) return;
    const rect = el.getBoundingClientRect();
    const move = (ev: globalThis.MouseEvent) => {
      const pct = ((ev.clientX - rect.left) / rect.width) * 100;
      setSplitPct(Math.min(75, Math.max(25, pct)));
    };
    const up = () => {
      window.removeEventListener('mousemove', move);
      window.removeEventListener('mouseup', up);
      document.body.style.cursor = '';
      document.body.style.userSelect = '';
      dragCleanup.current = null;
    };
    window.addEventListener('mousemove', move);
    window.addEventListener('mouseup', up);
    document.body.style.cursor = 'col-resize';
    document.body.style.userSelect = 'none';
    dragCleanup.current = up;
  };

  const overview = wifiQuery.data;
  const groups: WifiSsidGroup[] = overview?.ssids ?? [];
  const bands: WifiBandView[] = overview?.bands ?? [];
  const neighbors: WifiNeighborRef[] = overview?.neighbors ?? [];

  // Sorted name list drives the stable per-SSID color palette (same order in
  // legend and all band panels).
  const allSsidNames = groups.map((g) => g.name).sort();

  const columns: DataTableColumn<WifiSsidGroup>[] = [
    {
      header: 'SSID',
      key: 'name',
      width: 200,
      render: (row) => <span className="font-medium text-foreground">{row.name}</span>,
    },
    {
      header: 'Channels',
      key: 'channels',
      width: 220,
      exportValue: (row) => row.channels.map((c) => `ch ${c.channel ?? '?'} (${c.band || '?'})`).join(', '),
      render: (row) => (
        <div className="flex flex-wrap gap-1">
          {row.channels.length === 0 && <span className="text-faint">—</span>}
          {row.channels.map((c, i) => (
            <span key={i} className="whitespace-nowrap rounded bg-muted px-1.5 py-0.5 font-mono text-[11px] text-secondary">
              ch {c.channel ?? '?'} · {c.band || '—'}G
            </span>
          ))}
        </div>
      ),
    },
    {
      header: 'Security',
      key: 'security',
      width: 150,
      render: (row) =>
        row.security.length > 0 ? (
          <span className="rounded bg-accent-indigo/60 px-1.5 py-0.5 text-xs font-medium text-accent-indigo-fg">{row.security.join(' · ')}</span>
        ) : (
          <span className="text-faint">—</span>
        ),
    },
    {
      // Only set by the API when the VLAN id is unique across ALL rows of this SSID.
      header: 'VLAN',
      key: 'vlanId',
      width: 80,
      render: (row) =>
        row.vlanId !== null && row.vlanId !== undefined ? (
          <span className="rounded bg-muted px-1.5 py-0.5 font-mono text-xs text-secondary">{row.vlanId}</span>
        ) : (
          <span className="text-faint">—</span>
        ),
    },
    {
      header: 'Clients',
      key: 'clientCount',
      width: 90,
      sortAccessor: (row) => row.clientCount,
      render: (row) => <span className="font-mono text-sm">{row.clientCount}</span>,
    },
    {
      header: 'Airtime (mean / max)',
      key: 'airtimeMaxPct',
      width: 170,
      sortAccessor: (row) => row.airtimeMaxPct ?? -1,
      render: (row) => {
        if (row.airtimeMeanPct === null || row.airtimeMeanPct === undefined) return <span className="text-faint">—</span>;
        const mean = Math.round(row.airtimeMeanPct * 10) / 10;
        const max = row.airtimeMaxPct ?? mean;
        return (
          <span className={`font-mono text-xs ${utilColor(max)}`}>
            {mean}% / {Math.round(max * 10) / 10}%
          </span>
        );
      },
    },
    {
      header: 'Devices',
      key: 'devices',
      width: 280,
      exportValue: (row) => row.devices.map((d) => `${d.deviceName ?? '?'} [${d.interfaces.join(',')}]`).join('; '),
      render: (row) => (
        <div className="flex flex-col gap-1">
          {row.devices.length === 0 && <span className="text-faint">—</span>}
          {row.devices.map((d) => (
            <DeviceChip
              key={d.deviceId}
              deviceName={d.deviceName}
              managementAddress={d.managementAddress}
              pluginName={d.pluginName}
              siteName={d.siteName}
              interfaces={d.interfaces}
            />
          ))}
        </div>
      ),
    },
  ];

  return (
    <Layout title="WiFi">
      {/* Full-height column: table / spectrum split by a horizontal splitter —
          collapsing the spectrum gives its space back to the table instead of
          leaving it empty below. */}
      <div className="flex h-full min-h-0 flex-col">
        {wifiQuery.isLoading && <p className="shrink-0 text-sm text-muted-foreground">Loading WiFi networks...</p>}
        {wifiQuery.isError && (
          <p className="shrink-0 text-sm text-danger-fg">Failed to load WiFi data: {(wifiQuery.error as Error).message}</p>
        )}

        <div ref={vSplitRef} className="flex min-h-0 flex-1 flex-col">
          {/* SSID table (top) — fixed share of the page height while the spectrum is
              open; when collapsed it takes everything left of the header card. */}
          <div
            className={clsx('min-h-0', !spectrumOpen && 'flex-1')}
            style={{ height: spectrumOpen ? `${tablePct}%` : undefined }}
          >
            <DataTable<WifiSsidGroup>
              columns={columns}
              rows={groups}
              rowKey={(row) => row.name}
              storageKey="wifi"
              autoRefresh={{ intervalMs: 30_000, queries: [wifiQuery] }}
              fillHeight
              searchPlaceholder="Search SSIDs…"
              emptyMessage="No WiFi networks reported yet — devices with built-in radios (LANCOM LX APs, LCOS routers) populate this view within a poll cycle."
              onRowHover={(row) => setHoveredSsid(row ? row.name : null)}
            />
          </div>

          {/* Horizontal splitter between table and spectrum view. */}
          {spectrumOpen && (
            <div
              role="separator"
              aria-orientation="horizontal"
              onMouseDown={startVDrag}
              className="group relative -my-1 h-3 shrink-0 cursor-row-resize"
              title="Drag to resize — or collapse the spectrum view for full table height"
            >
              <div className="absolute inset-x-0 top-1/2 h-px -translate-y-1/2 bg-muted transition-colors group-hover:bg-accent-hover" />
              <div className="absolute left-1/2 top-1/2 flex h-3 w-8 -translate-x-1/2 -translate-y-1/2 items-center justify-center">
                <span className="h-1 w-6 rounded-full bg-status-neutral transition-colors group-hover:bg-accent-hover" />
              </div>
            </div>
          )}

          {/* Spectrum view (bottom) — takes the remaining height; each column
              inside scrolls independently so nothing spills out of the card.
              The header stays mounted when collapsed so it can be re-opened. */}
          <div className={clsx('shrink-0 min-h-0', spectrumOpen && 'flex-1')}>
            {/* Collapsible spectrum view — all three bands, WiFi-scanner style.
                The header (with its toggle) stays mounted when collapsed so the
                view can be re-opened; only the content below it is conditional. */}
            <div className="flex h-full min-h-0 flex-col rounded-lg border border-border bg-card">
              <button
                type="button"
                onClick={() => setSpectrumOpen((o) => !o)}
                className="flex w-full shrink-0 items-center justify-between px-4 py-3 text-left"
                aria-expanded={spectrumOpen}
              >
                <span className="flex items-center gap-2 text-sm font-semibold text-secondary">
                  <WifiIcon size={16} className="text-muted-foreground" />
                  Spectrum view — all bands
                </span>
                {/* Expanded panel → chevron points DOWN (click collapses it);
                    collapsed → UP (click expands). */}
                {spectrumOpen ? <ChevronDown size={18} className="text-faint" /> : <ChevronUp size={18} className="text-faint" />}
              </button>
          {spectrumOpen && (
            <div className="flex min-h-0 flex-1 flex-col border-t border-border p-4">
              {/* Legend: one swatch per SSID (same colors as the marker dots).
                  Hovering a legend entry highlights that SSID in ALL bands. The
                  column toggles live here too, so they stay reachable even when
                  there is no data yet. */}
              <div className="mb-3 flex shrink-0 flex-wrap items-center gap-x-4 gap-y-1">
                {groups.map((g) => (
                  <span
                    key={g.name}
                    className="flex cursor-default items-center gap-1.5 text-xs text-secondary"
                    onMouseEnter={() => setHoveredSsid(g.name)}
                    onMouseLeave={() => setHoveredSsid(null)}
                  >
                    <span
                      className={clsx('h-2.5 w-2.5 rounded-full transition-opacity duration-150', hoveredSsid !== null && hoveredSsid !== g.name && 'opacity-30')}
                      style={{ background: `hsl(${ssidHue(g.name, allSsidNames)}, 65%, 45%)` }}
                    />
                    {g.name}
                  </span>
                ))}
                <span className="ml-auto flex items-center gap-1">
                  <button
                    type="button"
                    onClick={() => setBandsOpen((o) => !o)}
                    title={bandsOpen ? 'Collapse the band diagrams' : 'Show the band diagrams'}
                    aria-label={bandsOpen ? 'Collapse the band diagrams' : 'Show the band diagrams'}
                    className={clsx('rounded px-1.5 py-0.5 text-[11px] font-medium', bandsOpen ? 'bg-muted text-secondary' : 'text-faint hover:bg-muted')}
                  >
                    {bandsOpen ? '▸ Diagrams' : '◂ Diagrams'}
                  </button>
                  <button
                    type="button"
                    onClick={() => setNeighborsOpen((o) => !o)}
                    title={neighborsOpen ? 'Collapse the neighbor list' : 'Show the neighbor list'}
                    aria-label={neighborsOpen ? 'Collapse the neighbor list' : 'Show the neighbor list'}
                    className={clsx('rounded px-1.5 py-0.5 text-[11px] font-medium', neighborsOpen ? 'bg-muted text-secondary' : 'text-faint hover:bg-muted')}
                  >
                    {neighborsOpen ? 'Neighbors ▸' : '◂ Neighbors'}
                  </button>
                </span>
              </div>
              <div ref={splitRef} className="flex min-h-0 flex-1 items-stretch">
                {/* Band diagrams (left) — scrolls internally when the pane is short. */}
                {bandsOpen && (
                  <div
                    className="min-w-0 flex-col gap-3 overflow-y-auto"
                    style={{ display: 'flex', width: neighborsOpen ? `${splitPct}%` : '100%' }}
                  >
                    {bands.map((b) => (
                      <BandPanel key={b.band} view={b} allNames={allSsidNames} hoveredSsid={hoveredSsid} onHover={setHoveredSsid} />
                    ))}
                  </div>
                )}
                {/* Draggable splitter — only when both columns are open */}
                {bandsOpen && neighborsOpen && (
                  <div
                    role="separator"
                    aria-orientation="vertical"
                    onMouseDown={startDrag}
                    className="group relative -mx-1.5 my-0 w-3 shrink-0 cursor-col-resize"
                    title="Drag to resize — or collapse a column above for full width"
                  >
                    <div className="absolute inset-y-0 left-1/2 w-px -translate-x-1/2 bg-muted transition-colors group-hover:bg-accent-hover" />
                    <div className="absolute inset-y-0 left-1/2 flex w-3 -translate-x-1/2 items-center justify-center">
                      <span className="h-8 w-1 rounded-full bg-status-neutral transition-colors group-hover:bg-accent-hover" />
                    </div>
                  </div>
                )}
                {/* Neighbor list (right) */}
                {neighborsOpen && (
                  <div className="min-w-0 flex-1">
                    <NeighborList neighbors={neighbors} />
                  </div>
                )}
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
