import { useEffect, useMemo, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Layout } from '../components/Layout';
import { DataTable, DataTableColumn } from '../components/DataTable';
import { DeviceChip } from '../components/DeviceChip';
import { TimeRangeFilter, resolveTimeRangeIso, type TimeRangeValue } from '../components/TimeRangeFilter';
import { ALL_PAGES, useServerTable } from '../components/useServerTable';
import { api, FirewallEventRow, FirewallEventsResponse } from '../api/client';
import { useTimeFormat } from '../utils/time';

/** Verdict pill — pass green, block red, NAT actions slate. */
const ACTION_STYLES: Record<FirewallEventRow['action'], string> = {
  pass: 'bg-success text-success-fg',
  block: 'bg-danger text-danger-fg',
  rdr: 'bg-accent-indigo text-accent-indigo-fg',
  nat: 'bg-accent-teal text-accent-teal-fg',
  binat: 'bg-accent-purple text-accent-purple-fg',
  unknown: 'bg-muted text-secondary',
};

function ActionBadge({ action }: { action: FirewallEventRow['action'] }) {
  return (
    <span className={`inline-flex rounded px-1.5 py-0.5 text-xs font-medium uppercase ${ACTION_STYLES[action] ?? ACTION_STYLES.unknown}`}>
      {action}
    </span>
  );
}

/** "—" for empty/unknown values (the API stores '' for unknown). */
function orDash(v?: string | null): string {
  return v && v.trim() !== '' ? v : '—';
}

/** Combines an address with its port for compact display ("10.0.0.5:443"). */
function addrPort(addr?: string, port?: number | null): string {
  const a = (addr ?? '').trim();
  if (!a) return '—';
  return typeof port === 'number' && port > 0 ? `${a}:${port}` : a;
}

/** Action filter chips — the summary counts double as the chip labels. */
const ACTION_FILTERS = [
  { value: '', label: 'All', key: null },
  { value: 'block', label: 'Blocked', key: 'blocked' as const },
  { value: 'pass', label: 'Passed', key: 'passed' as const },
  { value: 'other', label: 'NAT', key: 'other' as const },
] as const;

/**
 * Firewall event log — which traffic is allowed and which is blocked. Rows are
 * pushed by plugins from their appliance's firewall log (OPNsense today) via the
 * API's internal POST /plugin/firewall-events endpoint and kept for
 * FIREWALL_EVENT_RETENTION_DAYS (default 7). Gated by `firewall:read` — same
 * permission as the Firewall rules page.
 */
export default function FirewallEvents() {
  const { formatDateTime } = useTimeFormat();
  const [action, setAction] = useState('');
  const [deviceId, setDeviceId] = useState('');
  // Filter-bar search draft — debounced into the table's committed `q` below.
  const [searchDraft, setSearchDraft] = useState('');
  const [range, setRange] = useState<TimeRangeValue>('1h');

  // Options for the device filter select.
  const devicesQuery = useQuery({ queryKey: ['devices'], queryFn: api.devices });

  // Page-owned filters; any change resets the table to page 1 (hook behavior).
  const extra = useMemo(() => ({ action, deviceId, range }), [action, deviceId, range]);

  // Server-side pagination — rows are fetched per page by the API. The `from`
  // bound is computed at fetch time so "last hour" keeps sliding on refetch.
  // The response's summary (per-action counts over the FULL window/filters)
  // rides along via TData and feeds the action chips below.
  const table = useServerTable<{ action: string; deviceId: string; range: TimeRangeValue }, FirewallEventRow, FirewallEventsResponse & { total: number }>({
    fetcher: async (p) => {
      // Relative presets slide with the current time; custom ranges are absolute.
      const { from, to } = resolveTimeRangeIso(p.range);
      const res = await api.firewallEvents({
        from,
        to,
        deviceId: p.deviceId || undefined,
        action: (p.action || undefined) as 'pass' | 'block' | 'rdr' | 'nat' | 'binat' | 'other' | undefined,
        search: p.q,
        page: p.pageSize === ALL_PAGES ? undefined : p.page,
        pageSize: p.pageSize === ALL_PAGES ? undefined : p.pageSize,
        all: p.pageSize === ALL_PAGES || undefined,
        sort: p.sort?.key === 'tsMs' ? 'tsMs' : undefined,
        dir: p.sort?.dir,
      });
      return { ...res, total: res.total ?? 0 };
    },
    extra,
    storageKey: 'firewall-events',
  });

  // Debounce the filter-bar search into the committed server query (300 ms).
  useEffect(() => {
    const t = setTimeout(() => table.setQ(searchDraft.trim()), 300);
    return () => clearTimeout(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [searchDraft]);

  const devices = useMemo(() => (devicesQuery.data ?? []).slice().sort((a, b) => a.name.localeCompare(b.name)), [devicesQuery.data]);
  const summary = table.data?.summary;

  const columns: DataTableColumn<FirewallEventRow>[] = [
    {
      header: 'Time',
      key: 'tsMs',
      width: 170,
      sortAccessor: (row) => row.tsMs ?? Date.parse(row.ts),
      render: (row) => <span className="font-mono text-xs">{formatDateTime((row.tsMs ? new Date(row.tsMs).toISOString() : row.ts))}</span>,
    },
    {
      header: 'Action',
      key: 'action',
      width: 90,
      sortable: false, // server only sorts by tsMs
      render: (row) => <ActionBadge action={row.action} />,
    },
    {
      header: 'Device',
      key: 'deviceName',
      width: 220,
      sortable: false,
      exportValue: (row) => row.deviceName ?? '',
      render: (row) =>
        row.deviceId ? (
          <DeviceChip deviceName={row.deviceName} managementAddress={null} pluginName={row.pluginName} siteName={row.siteName} interfaces={[]} />
        ) : (
          <span className="text-xs text-faint">—</span>
        ),
    },
    {
      header: 'Interface',
      key: 'interfaceName',
      width: 100,
      sortable: false,
      render: (row) => <span className="font-mono text-xs">{orDash(row.interfaceName)}</span>,
    },
    {
      // Source → destination in one cell — the core question this page answers.
      header: 'Source → Destination',
      key: 'srcIp',
      width: 300,
      sortable: false,
      exportValue: (row) => `${orDash(row.srcIp)} → ${orDash(row.dstIp)}`,
      render: (row) => (
        <span className="font-mono text-xs">
          {addrPort(row.srcIp, row.srcPort)} <span className="text-faint">→</span> {addrPort(row.dstIp, row.dstPort)}
        </span>
      ),
    },
    {
      header: 'Proto',
      key: 'proto',
      width: 70,
      sortable: false,
      render: (row) => <span className="text-xs uppercase">{orDash(row.proto)}</span>,
    },
    {
      // The matched rule's description — the "why" of allow/block.
      header: 'Rule',
      key: 'ruleName',
      width: 240,
      sortable: false,
      render: (row) =>
        row.ruleName && row.ruleName.trim() !== '' ? (
          <span className="text-xs text-secondary">{row.ruleName}</span>
        ) : (
          <span className="text-faint">—</span>
        ),
    },
    {
      header: 'Reason',
      key: 'reason',
      width: 180,
      sortable: false,
      render: (row) => <span className="text-xs text-muted-foreground">{orDash(row.reason)}</span>,
    },
  ];

  return (
    <Layout title="Firewall Events">

      {/* Filter bar */}
      <div className="mb-4 grid grid-cols-1 gap-3 rounded-md border border-border bg-card p-3 shadow-sm sm:grid-cols-5">
        <div>
          <label className="mb-1 block text-xs font-medium text-secondary">Action</label>
          <div className="flex flex-wrap gap-1.5">
            {ACTION_FILTERS.map((f) => (
              <button
                key={f.value}
                type="button"
                onClick={() => setAction(f.value)}
                className={`rounded-md border px-2 py-1 text-xs font-medium ${
                  action === f.value ? 'border-info bg-info/10 text-info-fg' : 'border-border text-secondary hover:bg-muted'
                }`}
              >
                {f.label}
                {summary && f.key !== null && (
                  <span className="ml-1 font-mono text-[10px] opacity-70">{summary[f.key].toLocaleString()}</span>
                )}
              </button>
            ))}
          </div>
        </div>
        <div>
          <label className="mb-1 block text-xs font-medium text-secondary">Device</label>
          <select className="w-full rounded-md border border-border px-2.5 py-1.5 text-sm" value={deviceId} onChange={(e) => setDeviceId(e.target.value)}>
            <option value="">All devices</option>
            {devices.map((d) => (
              <option key={d.id} value={d.id}>
                {d.name}
              </option>
            ))}
          </select>
        </div>
        <TimeRangeFilter label="Time range" value={range} onChange={setRange} />
        <div className="sm:col-span-2">
          <label className="mb-1 block text-xs font-medium text-secondary">Search</label>
          <input
            type="text"
            className="w-full rounded-md border border-border px-2.5 py-1.5 text-sm"
            placeholder="Source/destination IP or rule name…"
            value={searchDraft}
            onChange={(e) => setSearchDraft(e.target.value)}
          />
        </div>
      </div>

      {table.isError && (
        <p className="text-sm text-danger-fg">Failed to load firewall events: {table.error?.message}</p>
      )}
      <DataTable
        columns={columns}
        rows={table.data?.rows ?? []}
        rowKey={(row) => row.id}
        storageKey="firewall-events"
        isFetching={table.isFetching}
        showSearch={false} // the filter bar above owns search (debounced into table.q)
        onSearch={table.setQ}
        externalSearch={table.q || null}
        serverPagination={{
          total: table.data?.total ?? 0,
          page: table.page,
          pageSize: table.pageSize,
          onPageChange: table.setPage,
          onPageSizeChange: table.setPageSize,
          // pageSizeOptions omitted → global `tablePageSizeOptions` setting + built-in "All".
          sort: table.sort,
          onSortChange: table.setSort,
        }}
        autoRefresh={{ intervalMs: 30_000, queries: [table] }}
        emptyMessage="No firewall events in this range yet — assign an OPNsense plugin to a device and wait for the next poll (logging must be enabled on the appliance)."
      />
    </Layout>
  );
}
