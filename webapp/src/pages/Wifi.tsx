import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import clsx from 'clsx';
import { ChevronDown, ChevronUp, Wifi as WifiIcon } from 'lucide-react';
import { Layout } from '../components/Layout';
import { DataTable, DataTableColumn } from '../components/DataTable';
import { DeviceChip } from '../components/DeviceChip';
import { api, WifiBandView, WifiSsidGroup } from '../api/client';

/** Color scale for airtime utilization (green → amber → red). */
function utilColor(pct: number | null): string {
  if (pct === null) return 'text-slate-400';
  if (pct < 30) return 'text-emerald-700';
  if (pct < 70) return 'text-amber-600';
  return 'text-red-600';
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

/** One WiFi-scanner-style band panel: a horizontal channel axis with one bar
 * per SSID×channel entry. Bar height ∝ airtime utilization; hovering an SSID
 * (here or in the table above) dims every other SSID's bars. */
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

  // Group entries by channel so co-channel SSIDs sit side by side instead of
  // stacking on top of each other.
  const byChannel = new Map<number, typeof view.entries>();
  for (const e of view.entries) {
    let arr = byChannel.get(e.channel);
    if (!arr) { arr = []; byChannel.set(e.channel, arr); }
    arr.push(e);
  }

  return (
    <div className="rounded-lg border border-slate-200 bg-white p-3">
      <div className="mb-1 flex items-center justify-between">
        <span className="text-sm font-semibold text-slate-700">{def.label}</span>
        <span className="text-xs text-slate-400">
          {view.entries.length > 0 ? `${view.entries.length} network${view.entries.length === 1 ? '' : 's'} · ch ${min}–${max}` : 'no networks on this band'}
        </span>
      </div>
      <div className="relative h-28 w-full">
        {view.entries.length === 0 && (
          <div className="flex h-full items-center justify-center text-xs text-slate-300">—</div>
        )}
        {/* Airtime gridlines (bar area = 76px above the axis, bars sit on bottom-5). */}
        {[0, 50, 100].map((v) => (
          <div key={v} className="absolute left-0 right-0" style={{ bottom: 20 + (v / 100) * 76 }}>
            <div className="h-px bg-slate-100" />
            <span className="absolute -top-1.5 left-0 text-[9px] font-mono text-slate-300">{v}%</span>
          </div>
        ))}
        {[...byChannel.entries()].map(([channel, entries]) => {
          const leftPct = ((channel - min) / span) * 100;
          return (
            <div key={channel} className="absolute bottom-5 flex items-end gap-px" style={{ left: `${leftPct}%`, transform: 'translateX(-50%)' }}>
              {entries.map((e, i) => {
                const dimmed = hoveredSsid !== null && e.name !== hoveredSsid;
                const util: number | null = e.utilizationPct ?? null;
                const h = util === null ? 12 : Math.max(12, (util / 100) * 76);
                return (
                  <div
                    key={`${e.name}-${i}`}
                    className={clsx('w-3.5 rounded-t transition-opacity duration-150', dimmed && 'opacity-20')}
                    style={{ height: h, background: `hsl(${ssidHue(e.name, allNames)}, 65%, 45%)` }}
                    title={`${e.name} — ch ${channel}${util !== null ? ` · airtime ${util}%` : ''}`}
                    onMouseEnter={() => onHover(e.name)}
                    onMouseLeave={() => onHover(null)}
                  />
                );
              })}
            </div>
          );
        })}
        {/* Channel axis */}
        <div className="absolute bottom-0 left-0 right-0 h-px bg-slate-200" />
        <div className="absolute -bottom-4 left-0 text-[10px] font-mono text-slate-400">{min}</div>
        <div className="absolute -bottom-4 right-0 text-[10px] font-mono text-slate-400">{max}</div>
      </div>
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

  const overview = wifiQuery.data;
  const groups: WifiSsidGroup[] = overview?.ssids ?? [];
  const bands: WifiBandView[] = overview?.bands ?? [];

  // Sorted name list drives the stable per-SSID color palette (same order in
  // legend and all band panels).
  const allSsidNames = groups.map((g) => g.name).sort();

  const columns: DataTableColumn<WifiSsidGroup>[] = [
    {
      header: 'SSID',
      key: 'name',
      width: 200,
      render: (row) => <span className="font-medium text-slate-800">{row.name}</span>,
    },
    {
      header: 'Channels',
      key: 'channels',
      width: 220,
      exportValue: (row) => row.channels.map((c) => `ch ${c.channel ?? '?'} (${c.band || '?'})`).join(', '),
      render: (row) => (
        <div className="flex flex-wrap gap-1">
          {row.channels.length === 0 && <span className="text-slate-400">—</span>}
          {row.channels.map((c, i) => (
            <span key={i} className="whitespace-nowrap rounded bg-slate-100 px-1.5 py-0.5 font-mono text-[11px] text-slate-600">
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
          <span className="rounded bg-indigo-50 px-1.5 py-0.5 text-xs font-medium text-indigo-700">{row.security.join(' · ')}</span>
        ) : (
          <span className="text-slate-400">—</span>
        ),
    },
    {
      // Only set by the API when the VLAN id is unique across ALL rows of this SSID.
      header: 'VLAN',
      key: 'vlanId',
      width: 80,
      render: (row) =>
        row.vlanId !== null && row.vlanId !== undefined ? (
          <span className="rounded bg-slate-100 px-1.5 py-0.5 font-mono text-xs text-slate-700">{row.vlanId}</span>
        ) : (
          <span className="text-slate-400">—</span>
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
        if (row.airtimeMeanPct === null || row.airtimeMeanPct === undefined) return <span className="text-slate-400">—</span>;
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
          {row.devices.length === 0 && <span className="text-slate-400">—</span>}
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
    <Layout>
      <div className="mb-4">
        <h1 className="text-xl font-bold text-slate-900">WiFi</h1>
        <p className="mt-1 text-sm text-slate-500">
          All SSIDs across your devices, grouped by name — channels, security, VLAN and the devices broadcasting each network.
          Hover a row (or a bar below) to highlight that SSID in the spectrum view.
        </p>
      </div>

      {wifiQuery.isLoading && <p className="text-sm text-slate-500">Loading WiFi networks...</p>}
      {wifiQuery.isError && (
        <p className="text-sm text-red-600">Failed to load WiFi data: {(wifiQuery.error as Error).message}</p>
      )}

      <div className="flex flex-col gap-4">
        <DataTable<WifiSsidGroup>
          columns={columns}
          rows={groups}
          rowKey={(row) => row.name}
          storageKey="wifi"
          searchPlaceholder="Search SSIDs…"
          emptyMessage="No WiFi networks reported yet — devices with built-in radios (LANCOM LX APs, LCOS routers) populate this view within a poll cycle."
          onRowHover={(row) => setHoveredSsid(row ? row.name : null)}
        />

        {/* Collapsible spectrum view — all three bands, WiFi-scanner style. */}
        <div className="rounded-lg border border-slate-200 bg-white">
          <button
            type="button"
            onClick={() => setSpectrumOpen((o) => !o)}
            className="flex w-full items-center justify-between px-4 py-3 text-left"
            aria-expanded={spectrumOpen}
          >
            <span className="flex items-center gap-2 text-sm font-semibold text-slate-700">
              <WifiIcon size={16} className="text-slate-500" />
              Spectrum view — all bands
            </span>
            {spectrumOpen ? <ChevronUp size={18} className="text-slate-400" /> : <ChevronDown size={18} className="text-slate-400" />}
          </button>
          {spectrumOpen && (
            <div className="flex flex-col gap-3 border-t border-slate-100 p-4">
              {/* Legend: one swatch per SSID (same colors as the bars). Hovering a
                  legend entry highlights that SSID's bars in ALL bands. */}
              {groups.length > 0 && (
                <div className="flex flex-wrap gap-x-4 gap-y-1">
                  {groups.map((g) => (
                    <span
                      key={g.name}
                      className="flex cursor-default items-center gap-1.5 text-xs text-slate-600"
                      onMouseEnter={() => setHoveredSsid(g.name)}
                      onMouseLeave={() => setHoveredSsid(null)}
                    >
                      <span
                        className={clsx('h-2.5 w-2.5 rounded-sm transition-opacity duration-150', hoveredSsid !== null && hoveredSsid !== g.name && 'opacity-30')}
                        style={{ background: `hsl(${ssidHue(g.name, allSsidNames)}, 65%, 45%)` }}
                      />
                      {g.name}
                    </span>
                  ))}
                </div>
              )}
              {bands.map((b) => (
                <BandPanel key={b.band} view={b} allNames={allSsidNames} hoveredSsid={hoveredSsid} onHover={setHoveredSsid} />
              ))}
            </div>
          )}
        </div>
      </div>
    </Layout>
  );
}
