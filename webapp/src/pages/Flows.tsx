import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Activity, Globe, Radio, ArrowLeftRight, Server, X } from 'lucide-react';
import { Layout } from '../components/Layout';
import { DataTable, DataTableColumn } from '../components/DataTable';
import { formatBytes, formatNumber } from '../components/formatMetric';
import { can } from '../auth/permissions';
import { api, FlowTalker, FlowInternetDevice, FlowInternetCountry, FlowPair, FlowPortRow, FlowNetworkRow } from '../api/client';

/** Well-known L4 port names for the port-stats tables (0 = no transport header). */
const PORT_NAMES: Record<number, string> = {
  0: '—', 53: 'DNS', 67: 'DHCP', 68: 'DHCP', 80: 'HTTP', 123: 'NTP', 443: 'HTTPS',
  445: 'SMB', 465: 'SMTPS', 587: 'Submission', 993: 'IMAPS', 995: 'POP3S', 1433: 'MSSQL',
  2049: 'NFS', 2222: 'SSH-alt', 3000: 'Web-3000', 3389: 'RDP', 5000: 'UPnP/RTSP', 5355: 'mDNS',
  6343: 'sFlow', 8080: 'HTTP-alt', 8443: 'HTTPS-alt', 12345: 'NetFlow', 1900: 'SSDP',
};

/** IANA protocol numbers → short names for the port tables. */
const PROTO_NAMES: Record<number, string> = {
  1: 'ICMP', 6: 'TCP', 17: 'UDP', 41: 'IPv6', 47: 'GRE', 50: 'ESP', 58: 'ICMPv6', 89: 'OSPF',
};

function portLabel(port: number): string {
  return PORT_NAMES[port] ? `${port} (${PORT_NAMES[port]})` : String(port);
}

/** Time-range presets (v1: presets only — the API resolves `from`/`to`). */
const TIME_RANGES = [
  { value: '1h', label: 'Last hour' },
  { value: '24h', label: 'Last 24 hours' },
  { value: '7d', label: 'Last 7 days' },
  { value: '30d', label: 'Last 30 days' },
] as const;

type TimeRange = (typeof TIME_RANGES)[number]['value'];

const RANGE_MS: Record<TimeRange, number> = {
  '1h': 60 * 60 * 1000,
  '24h': 24 * 60 * 60 * 1000,
  '7d': 7 * 24 * 60 * 60 * 1000,
  '30d': 30 * 24 * 60 * 60 * 1000,
};

/** Minimal inline SVG sparkline — no chart lib needed for a single series. */
function Sparkline({ values, width = 160, height = 32 }: { values: number[]; width?: number; height?: number }) {
  if (values.length < 2) return null;
  const min = Math.min(...values);
  const max = Math.max(...values);
  const span = max - min || 1;
  const stepX = width / (values.length - 1);
  const points = values
    .map((v, i) => `${(i * stepX).toFixed(1)},${(height - 2 - ((v - min) / span) * (height - 4)).toFixed(1)}`)
    .join(' ');
  return (
    <svg width={width} height={height} className="block" aria-hidden="true">
      <polyline points={points} fill="none" stroke="rgb(var(--accent-solid))" strokeWidth="1.5" strokeLinejoin="round" />
    </svg>
  );
}

/** Classification pill for a talker IP (internal vs internet/unknown). */
function ClassPill({ internal }: { internal: boolean }) {
  return (
    <span
      className={`inline-flex rounded px-1.5 py-0.5 text-xs font-medium uppercase ${
        internal ? 'bg-accent-teal text-accent-teal-fg' : 'bg-muted text-secondary'
      }`}
    >
      {internal ? 'internal' : 'external'}
    </span>
  );
}

function orDash(v?: string | null): string {
  return v && v.trim() !== '' ? v : '—';
}

/** ISO-3166 alpha-2 → flag emoji (regional indicators), e.g. "US" → 🇺🇸. */
function flagEmoji(code: string | null | undefined): string {
  if (!code || code.length !== 2) return '';
  const upper = code.toUpperCase();
  if (!/^[A-Z]{2}$/.test(upper)) return '';
  try {
    return String.fromCodePoint(...[...upper].map((c) => 0x1F1E6 + c.charCodeAt(0) - 65));
  } catch {
    return '';
  }
}

/** GeoIP location cell — "City, 🇺🇸 United States" or a faint dash. */
function LocationCell({ row }: { row: FlowTalker }) {
  const city = row.city?.trim() || null;
  const countryName = row.countryName?.trim() || null;
  if (!city && !countryName) return <span className="text-faint">—</span>;
  const flag = flagEmoji(row.countryCode);
  return (
    <span className="truncate text-xs" title={[city, `${flag} ${countryName}`.trim()].filter(Boolean).join(', ')}>
      {city && <>{city}{countryName ? ', ' : ''}</>}
      {countryName && <>
        {flag && <span className="mr-1">{flag}</span>}
        {countryName}
      </>}
    </span>
  );
}

/** Country cell for the per-country egress table — "🇺🇸 US" or a faint dash. */
function CountryCell({ row }: { row: FlowInternetCountry }) {
  const code = row.countryCode?.trim() || null;
  if (!code) return <span className="text-faint">—</span>;
  const flag = flagEmoji(code);
  return (
    <span className="flex items-center gap-1.5 text-xs" title={code}>
      {flag && <span>{flag}</span>}
      <span className="font-medium uppercase">{code}</span>
    </span>
  );
}

/**
 * Flows — sFlow/NetFlow traffic visibility. Shows who talks to the internet and
 * which devices talk to each other, aggregated from flow-collector plugin
 * samples (5-minute / hourly rollups). Gated by `flows:read`.
 */
export default function Flows() {
  const [range, setRange] = useState<TimeRange>('24h');
  // Site filter — '' = all sites. Options come from /sites (gated on sites:read).
  const [siteId, setSiteId] = useState('');
  // Port drilldown — click a talker IP to scope the port tables to that host.
  const [drillIp, setDrillIp] = useState<string | null>(null);

  // The `from` bound is computed at fetch time so "last hour" keeps sliding as
  // the page refetches. Rollups land every 5 minutes — refresh on that cadence.
  const windowParams = () => {
    const to = new Date();
    const from = new Date(Date.now() - RANGE_MS[range]);
    return { from: from.toISOString(), to: to.toISOString() };
  };
  // Every flow query shares the site filter (null = no filter).
  const siteParam = () => (siteId || undefined);

  const sitesQuery = useQuery({ queryKey: ['sites'], queryFn: () => api.sites(), enabled: can('sites:read') });

  const talkersQuery = useQuery({
    queryKey: ['flows', 'top-talkers', range, siteId],
    queryFn: () => api.flowsTopTalkers({ ...windowParams(), limit: 20, siteId: siteParam() }),
    refetchInterval: 60_000,
  });
  const internetQuery = useQuery({
    queryKey: ['flows', 'internet', range, siteId],
    queryFn: () => api.flowsInternet({ ...windowParams(), siteId: siteParam() }),
    refetchInterval: 60_000,
  });
  const pairsQuery = useQuery({
    queryKey: ['flows', 'pairs', range, siteId],
    queryFn: () => api.flowsPairs({ ...windowParams(), limit: 20, siteId: siteParam() }),
    refetchInterval: 60_000,
  });
  // Internet egress over time — the page's headline chart. Hourly buckets for
  // multi-day ranges keep the point count sane; 5-minute otherwise.
  const seriesQuery = useQuery({
    queryKey: ['flows', 'timeseries', range, siteId],
    queryFn: () => api.flowsTimeseries({ ...windowParams(), bucket: range === '7d' || range === '30d' ? '1h' : '5m', class: 'internet', siteId: siteParam() }),
    refetchInterval: 60_000,
  });
  // Port usage — top source/destination ports (optionally scoped to one host).
  const portsQuery = useQuery({
    queryKey: ['flows', 'ports', range, siteId, drillIp],
    queryFn: () => api.flowsPorts({ ...windowParams(), limit: 15, ip: drillIp ?? undefined, siteId: siteParam() }),
    refetchInterval: 60_000,
  });
  // Traffic per inventoried network (name + VLAN) — the "which networks" view.
  const networksQuery = useQuery({
    queryKey: ['flows', 'networks', range, siteId],
    queryFn: () => api.flowsNetworks({ ...windowParams(), limit: 20, siteId: siteParam() }),
    refetchInterval: 60_000,
  });
  const collectorsQuery = useQuery({
    queryKey: ['flows', 'collectors'],
    queryFn: () => api.flowCollectors(),
    refetchInterval: 30_000,
  });

  const talkerColumns: DataTableColumn<FlowTalker>[] = [
    {
      header: 'IP',
      key: 'ip',
      width: 170,
      exportValue: (row) => row.hostname ? `${row.ip} (${row.hostname})` : row.ip,
      render: (row) => (
        <div className="flex flex-col">
          {/* Clickable → scopes the port tables to this host (drilldown). */}
          <button
            type="button"
            onClick={() => setDrillIp(drillIp === row.ip ? null : row.ip)}
            title={`Show ports for ${row.ip}`}
            className={`text-left font-mono text-xs hover:underline ${drillIp === row.ip ? 'text-accent-solid' : ''}`}
          >
            {row.ip}
          </button>
          {row.hostname && (
            <span
              className="truncate text-[11px] text-faint"
              title={row.hostnameSource === 'reverse-dns' ? `${row.hostname} (reverse DNS)` : row.hostname}
            >
              {row.hostname}
              {row.hostnameSource === 'reverse-dns' && <span className="ml-1 opacity-60">(rDNS)</span>}
            </span>
          )}
        </div>
      ),
    },
    {
      header: 'Class',
      key: 'internal',
      width: 90,
      sortAccessor: (row) => (row.internal ? 1 : 0),
      render: (row) => <ClassPill internal={row.internal} />,
    },
    {
      header: 'Device',
      key: 'deviceName',
      width: 200,
      exportValue: (row) => row.deviceName ?? '',
      render: (row) => (row.deviceName ? <span className="text-sm">{row.deviceName}</span> : <span className="text-faint">—</span>),
    },
    {
      header: 'Network / VLAN',
      key: 'networkName',
      width: 150,
      exportValue: (row) => row.networkName ? `${row.networkName}${row.vlanId != null ? ` (VLAN ${row.vlanId})` : ''}` : '',
      render: (row) => (row.networkName || row.vlanId != null ? (
        <span className="text-xs">
          {row.networkName ?? '—'}
          {row.vlanId != null && <span className="ml-1 rounded bg-muted px-1 py-0.5 text-[10px] font-medium">{row.vlanId}</span>}
        </span>
      ) : (
        <span className="text-faint">—</span>
      )),
    },
    {
      // GeoIP location for external talkers — city + country from the active
      // database file (Settings → GeoIP). Empty while no DB is configured.
      header: 'Location',
      key: 'countryCode',
      width: 180,
      exportValue: (row) => [row.city, row.countryName].filter(Boolean).join(', '),
      sortAccessor: (row) => row.countryCode ?? '',
      render: (row) => <LocationCell row={row} />,
    },
    {
      header: 'Est. Bytes',
      key: 'estBytes',
      width: 120,
      sortAccessor: (row) => row.estBytes,
      render: (row) => <span className="font-mono text-xs">{formatBytes(row.estBytes)}</span>,
    },
    {
      // Multi-exporter dedup indicator — >1 means several devices on the path
      // exported this traffic and it was collapsed to one best observation.
      header: 'Observed by',
      key: 'observedBy',
      width: 100,
      sortAccessor: (row) => row.observedBy,
      render: (row) => (row.observedBy > 1 ? (
        <span className="rounded bg-accent-sky px-1.5 py-0.5 text-[10px] font-medium" title={`Seen by ${row.observedBy} exporters — deduplicated to the best observation`}>
          {row.observedBy}×
        </span>
      ) : (
        <span className="text-faint">—</span>
      )),
    },
    {
      header: 'Reported',
      key: 'reportedBytes',
      width: 120,
      hiddenByDefault: true,
      sortAccessor: (row) => row.reportedBytes,
      render: (row) => <span className="font-mono text-xs">{formatBytes(row.reportedBytes)}</span>,
    },
  ];

  const internetColumns: DataTableColumn<FlowInternetDevice>[] = [
    {
      header: 'Device',
      key: 'deviceName',
      width: 240,
      render: (row) => <span className="font-medium text-foreground">{orDash(row.deviceName)}</span>,
    },
    {
      header: 'Egress to Internet',
      key: 'estBytes',
      width: 160,
      sortAccessor: (row) => row.estBytes,
      render: (row) => <span className="font-mono text-xs">{formatBytes(row.estBytes)}</span>,
    },
    {
      header: 'Distinct Destinations',
      key: 'distinctDestinations',
      width: 160,
      sortAccessor: (row) => row.distinctDestinations,
      render: (row) => <span className="font-mono text-xs">{formatNumber(row.distinctDestinations)}</span>,
    },
  ];

  // Country aggregation over the stored GeoIP codes — only shown when a
  // database has resolved at least one destination.
  const countryColumns: DataTableColumn<FlowInternetCountry>[] = [
    {
      header: 'Country',
      key: 'countryCode',
      width: 160,
      sortAccessor: (row) => row.countryCode ?? '',
      render: (row) => <CountryCell row={row} />,
    },
    {
      header: 'Egress to Internet',
      key: 'estBytes',
      width: 160,
      sortAccessor: (row) => row.estBytes,
      render: (row) => <span className="font-mono text-xs">{formatBytes(row.estBytes)}</span>,
    },
    {
      header: 'Distinct Destinations',
      key: 'distinctDestinations',
      width: 160,
      sortAccessor: (row) => row.distinctDestinations,
      render: (row) => <span className="font-mono text-xs">{formatNumber(row.distinctDestinations)}</span>,
    },
  ];

  // Busiest host on one side of a pair — the actual container/VM behind the device.
  const topHostCell = (ip: string | null | undefined, host: string | null | undefined) => (
    ip ? (
      <span className="text-[11px] text-faint">
        {host && <span title={host}>{host}</span>}
        {!host && <span className="font-mono">{ip}</span>}
      </span>
    ) : null
  );

  const pairColumns: DataTableColumn<FlowPair>[] = [
    {
      header: 'Source',
      key: 'srcName',
      width: 240,
      render: (row) => (
        <div className="flex flex-col">
          <span className="font-medium text-foreground">{orDash(row.srcName)}</span>
          {topHostCell(row.srcTopIp, row.srcTopHost)}
        </div>
      ),
    },
    {
      header: 'Destination',
      key: 'dstName',
      width: 240,
      render: (row) => (
        <div className="flex flex-col">
          <span className="font-medium text-foreground">{orDash(row.dstName)}</span>
          {topHostCell(row.dstTopIp, row.dstTopHost)}
        </div>
      ),
    },
    {
      header: 'Est. Bytes',
      key: 'estBytes',
      width: 140,
      sortAccessor: (row) => row.estBytes,
      render: (row) => <span className="font-mono text-xs">{formatBytes(row.estBytes)}</span>,
    },
    {
      header: 'Distinct IP Pairs',
      key: 'distinctPairs',
      width: 140,
      sortAccessor: (row) => row.distinctPairs,
      render: (row) => <span className="font-mono text-xs">{formatNumber(row.distinctPairs)}</span>,
    },
  ];

  // Port tables share one column shape — the direction only changes the header.
  const portColumns = (direction: 'Source' | 'Destination'): DataTableColumn<FlowPortRow>[] => [
    {
      header: `${direction} Port`,
      key: 'port',
      width: 160,
      sortAccessor: (row) => row.port,
      render: (row) => <span className="font-mono text-xs">{portLabel(row.port)}</span>,
    },
    {
      header: 'Proto',
      key: 'proto',
      width: 80,
      sortAccessor: (row) => row.proto,
      render: (row) => <span className="text-xs">{PROTO_NAMES[row.proto] ?? `#${row.proto}`}</span>,
    },
    {
      header: 'Est. Bytes',
      key: 'estBytes',
      width: 120,
      sortAccessor: (row) => row.estBytes,
      render: (row) => <span className="font-mono text-xs">{formatBytes(row.estBytes)}</span>,
    },
  ];

  const networkColumns: DataTableColumn<FlowNetworkRow>[] = [
    {
      header: 'Network',
      key: 'name',
      width: 260,
      exportValue: (row) => row.subnets?.length ? `${row.name} (${row.subnets.join(', ')})` : row.name,
      render: (row) => (
        <div className="flex flex-col">
          {row.name === '(external)' ? (
            <span className="w-fit rounded bg-muted px-1.5 py-0.5 text-xs font-medium">External</span>
          ) : (
            <span className={row.name === '(unknown)' ? 'text-faint' : 'font-medium text-foreground'}>{row.name}</span>
          )}
          {row.subnets && row.subnets.length > 0 && (
            <span className="mt-0.5 flex flex-wrap gap-1">
              {row.subnets.slice(0, 3).map((s) => (
                <span key={s} className="rounded bg-muted px-1 py-0.5 font-mono text-[10px]">{s}</span>
              ))}
              {row.subnets.length > 3 && <span className="text-[10px] text-faint">+{row.subnets.length - 3}</span>}
            </span>
          )}
        </div>
      ),
    },
    {
      header: 'VLAN',
      key: 'vlanId',
      width: 80,
      sortAccessor: (row) => row.vlanId ?? -1,
      render: (row) => (row.vlanId != null ? <span className="rounded bg-muted px-1.5 py-0.5 text-xs font-medium">{row.vlanId}</span> : <span className="text-faint">—</span>),
    },
    {
      header: 'Inbound',
      key: 'dstEstBytes',
      width: 120,
      sortAccessor: (row) => row.dstEstBytes,
      render: (row) => <span className="font-mono text-xs">{formatBytes(row.dstEstBytes)}</span>,
    },
    {
      header: 'Outbound',
      key: 'srcEstBytes',
      width: 120,
      sortAccessor: (row) => row.srcEstBytes,
      render: (row) => <span className="font-mono text-xs">{formatBytes(row.srcEstBytes)}</span>,
    },
    {
      header: 'Total',
      key: 'estBytes',
      width: 120,
      sortAccessor: (row) => row.estBytes,
      render: (row) => <span className="font-mono text-xs">{formatBytes(row.estBytes)}</span>,
    },
  ];

  const seriesValues = (seriesQuery.data?.points ?? []).map((p) => p.estBytes);
  const topSource = talkersQuery.data?.sources[0];
  const topPair = pairsQuery.data?.pairs[0];
  const collectors = collectorsQuery.data?.collectors ?? [];
  const ingest = collectorsQuery.data?.ingest;

  return (
    <Layout title="Flows">
      {/* Filter bar — time-range preset + site filter. */}
      <div className="mb-3 flex shrink-0 items-center gap-2">
        <select
          className="w-full max-w-xs rounded-md border border-border px-2.5 py-1.5 text-sm"
          value={range}
          onChange={(e) => setRange(e.target.value as TimeRange)}
        >
          {TIME_RANGES.map((r) => (
            <option key={r.value} value={r.value}>
              {r.label}
            </option>
          ))}
        </select>
        {can('sites:read') && (
          <select
            className="w-full max-w-xs rounded-md border border-border px-2.5 py-1.5 text-sm"
            value={siteId}
            onChange={(e) => setSiteId(e.target.value)}
          >
            <option value="">All sites</option>
            {(sitesQuery.data ?? []).map((s) => (
              <option key={s.id} value={s.id}>
                {s.name}
              </option>
            ))}
          </select>
        )}
        {/* Port drilldown indicator — set by clicking a talker IP. */}
        {drillIp && (
          <button
            type="button"
            onClick={() => setDrillIp(null)}
            className="flex items-center gap-1 rounded-md border border-border bg-card px-2 py-1.5 text-xs hover:bg-muted"
            title="Clear port drilldown"
          >
            ports for <span className="font-mono">{drillIp}</span>
            <X size={12} />
          </button>
        )}
      </div>

      {/* Summary strip — internet egress total, top talker, busiest pair. */}
      {internetQuery.data && (
        <div className="mb-3 flex shrink-0 flex-wrap items-center gap-x-6 gap-y-1 rounded-lg border border-border bg-card px-4 py-2 text-xs">
          <span className="flex items-center gap-2 text-secondary">
            <Globe size={13} className="text-accent-solid" />
            {formatBytes(internetQuery.data.total.estBytes)} to internet ·{' '}
            {formatNumber(internetQuery.data.total.distinctDestinations)} destinations
          </span>
          {topSource && (
            <span className="flex items-center gap-2 text-secondary">
              <Radio size={13} className="text-muted-foreground" />
              top talker:{' '}
              <span className="font-mono">
                {topSource.ip}
                {topSource.hostname ? ` (${topSource.hostname})` : ''}
              </span>{' '}
              ({formatBytes(topSource.estBytes)})
            </span>
          )}
          {topPair && (
            <span className="flex items-center gap-2 text-secondary">
              <ArrowLeftRight size={13} className="text-muted-foreground" />
              busiest pair: {orDash(topPair.srcName)} → {orDash(topPair.dstName)} ({formatBytes(topPair.estBytes)})
            </span>
          )}
        </div>
      )}

      {/* Internet egress over time — headline chart. */}
      <div className="mb-3 shrink-0 rounded-lg border border-border bg-card px-4 py-2">
        <p className="text-xs font-medium text-secondary">Internet egress over time</p>
        {seriesQuery.isLoading && <p className="mt-1 text-sm text-muted-foreground">Loading…</p>}
        {!seriesQuery.isLoading && seriesValues.length > 0 && (
          <div className="flex items-end gap-4">
            <Sparkline values={seriesValues} width={560} height={48} />
            <span className="font-mono text-xs text-secondary">{formatBytes(Math.max(...seriesValues))} peak</span>
          </div>
        )}
        {!seriesQuery.isLoading && seriesValues.length > 0 && Math.max(...seriesValues) === 0 && (
          <p className="mt-1 text-sm text-faint">No internet egress in this window.</p>
        )}
      </div>

      {/* Internet egress per device. */}
      {internetQuery.data && (
        <DataTable
          columns={internetColumns}
          rows={internetQuery.data.perDevice}
          rowKey={(row) => row.deviceId}
          storageKey="flows-internet"
          searchPlaceholder="Search devices…"
          emptyMessage="No internet egress recorded in this window — start the flow-collector plugin and point an sFlow or NetFlow exporter at it."
        />
      )}

      {/* Internet egress per country — from the stored GeoIP codes (Settings →
       *  GeoIP). Hidden entirely until a database has resolved ≥1 destination. */}
      {internetQuery.data?.perCountry && internetQuery.data.perCountry.length > 0 && (
        <div className="mt-3">
          <p className="mb-2 text-xs font-medium text-secondary">Internet egress by country</p>
          <DataTable
            columns={countryColumns}
            rows={internetQuery.data.perCountry}
            rowKey={(row) => `c|${row.countryCode ?? 'unknown'}`}
            storageKey="flows-internet-countries"
            searchPlaceholder="Search countries…"
            emptyMessage="No country data yet — fetch a GeoIP database (Settings → GeoIP)."
          />
        </div>
      )}

      {/* Top talkers — sources and destinations side by side. */}
      <div className="mt-3 grid shrink-0 grid-cols-1 gap-3 xl:grid-cols-2">
        {talkersQuery.data && (
          <DataTable
            columns={talkerColumns}
            rows={talkersQuery.data.sources}
            rowKey={(row) => `s|${row.ip}`}
            storageKey="flows-talkers-src"
            searchPlaceholder="Search source IPs…"
            emptyMessage="No traffic recorded in this window."
          />
        )}
        {talkersQuery.data && (
          <DataTable
            columns={talkerColumns}
            rows={talkersQuery.data.destinations}
            rowKey={(row) => `d|${row.ip}`}
            storageKey="flows-talkers-dst"
            searchPlaceholder="Search destination IPs…"
            emptyMessage="No traffic recorded in this window."
          />
        )}
      </div>

      {/* Port usage — most used L4 ports, source and destination. */}
      <div className="mt-3 shrink-0 rounded-lg border border-border bg-card px-4 py-2">
        <p className="flex items-center gap-2 text-xs font-medium text-secondary">
          <Activity size={13} /> Port usage{drillIp ? (
            <>
              {' '}for <span className="font-mono">{drillIp}</span>
              <button type="button" onClick={() => setDrillIp(null)} className="text-faint hover:text-foreground" title="Clear drilldown">
                <X size={12} />
              </button>
            </>
          ) : (
            ' — click a talker IP to drill down'
          )}
        </p>
        {portsQuery.isLoading && <p className="mt-1 text-sm text-muted-foreground">Loading…</p>}
        {!portsQuery.isLoading && portsQuery.data && (
          <div className="mt-2 grid grid-cols-1 gap-3 xl:grid-cols-2">
            <DataTable
              columns={portColumns('Source')}
              rows={portsQuery.data.sourcePorts}
              rowKey={(row) => `s|${row.port}|${row.proto}`}
              storageKey="flows-ports-src"
              emptyMessage="No source ports recorded in this window."
            />
            <DataTable
              columns={portColumns('Destination')}
              rows={portsQuery.data.destinationPorts}
              rowKey={(row) => `d|${row.port}|${row.proto}`}
              storageKey="flows-ports-dst"
              emptyMessage="No destination ports recorded in this window."
            />
          </div>
        )}
      </div>

      {/* Traffic per network — which documented networks the traffic lives on. */}
      <div className="mt-3 shrink-0 rounded-lg border border-border bg-card px-4 py-2">
        <p className="flex items-center gap-2 text-xs font-medium text-secondary">
          <Globe size={13} /> Traffic per network
        </p>
        {networksQuery.isLoading && <p className="mt-1 text-sm text-muted-foreground">Loading…</p>}
        {!networksQuery.isLoading && networksQuery.data && (
          <DataTable
            columns={networkColumns}
            rows={networksQuery.data.networks}
            rowKey={(row) => `${row.name}|${row.vlanId ?? ''}`}
            storageKey="flows-networks"
            searchPlaceholder="Search networks…"
            emptyMessage="No network context recorded in this window — document your networks (Networks page) to see per-network traffic."
          />
        )}
      </div>

      {/* Device-to-device pairs. */}
      {pairsQuery.data && (
        <DataTable
          columns={pairColumns}
          rows={pairsQuery.data.pairs}
          rowKey={(row) => `${row.srcDeviceId}|${row.dstDeviceId}`}
          storageKey="flows-pairs"
          searchPlaceholder="Search device pairs…"
          emptyMessage="No internal device-to-device traffic recorded in this window."
        />
      )}

      {/* Collector health — live plugin stats + API ingest queue. */}
      <div className="mt-3 shrink-0 rounded-lg border border-border bg-card px-4 py-2">
        <p className="flex items-center gap-2 text-xs font-medium text-secondary">
          <Server size={13} /> Collectors &amp; ingest
        </p>
        {collectorsQuery.isLoading && <p className="mt-1 text-sm text-muted-foreground">Loading…</p>}
        {!collectorsQuery.isLoading && collectors.length === 0 && (
          <p className="mt-1 text-sm text-faint">No flow-collector plugins registered — add one via the Plugins page.</p>
        )}
        {collectors.map((c) => (
          <div key={c.id} className="mt-1 flex flex-wrap items-center gap-x-4 gap-y-0.5 text-xs">
            <span className={`font-medium ${c.reachable ? 'text-success-fg' : 'text-danger-fg'}`}>
              {orDash(c.name)} ({c.reachable ? 'online' : 'offline'})
            </span>
            <span className="font-mono text-secondary">{formatNumber(c.samplesPerSec, 'samples/s')}</span>
            <span className="font-mono text-secondary">queue {formatNumber(c.queueDepth)}</span>
            <span className={`font-mono ${c.droppedTuplesTotal > 0 ? 'text-warning-fg' : 'text-secondary'}`}>
              dropped {formatNumber(c.droppedTuplesTotal)}
            </span>
          </div>
        ))}
        {ingest && (
          <p className="mt-1 text-xs text-faint">
            API ingest queue: depth {formatNumber(ingest.queueDepth)} · enqueued {formatNumber(ingest.enqueuedTotal)} · dropped{' '}
            {formatNumber(ingest.droppedTotal)} · inserted {formatNumber(ingest.insertedTotal)}
            {ingest.lastError && <span className="text-danger-fg"> · last error: {ingest.lastError}</span>}
          </p>
        )}
      </div>
    </Layout>
  );
}
