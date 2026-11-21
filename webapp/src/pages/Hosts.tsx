import { useMemo, useRef } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Layout } from '../components/Layout';
import { DataTable, DataTableColumn } from '../components/DataTable';
import { ALL_PAGES, useServerTable } from '../components/useServerTable';
import { DeviceChip } from '../components/DeviceChip';
import { IpGroupChips } from '../components/IpGroups';
import { formatBytes } from '../components/formatMetric';
import { api, HostRow } from '../api/client';
import { can } from '../auth/permissions';
import { useTimeFormat } from '../utils/time';

/** Fixed window for the traffic column — matches what the header advertises. */
const TRAFFIC_WINDOW_MS = 24 * 60 * 60 * 1000;

/** One host's traffic totals over the window (null = no flows observed). */
interface HostTraffic {
  sent: number;
  received: number;
}

/** One host's firewall-state view across all of its addresses.
 * `open` is null when no stateful device tracks this host; churn fields are
 * null when the window had no walk with a baseline (first walk after start). */
interface HostStates {
  open: number | null;
  created24h: number | null;
  destroyed24h: number | null;
}

/** Color-coded pill for one discovery source; a merged host shows all of its sources. */
function SourceBadges({ sources }: { sources: HostRow['sources'] }) {
  const cls = (s: string) =>
    s === 'dhcp'
      ? 'bg-success text-success-fg'
      : s === 'ndp'
        ? 'bg-accent-purple text-accent-purple-fg'
        : s === 'wlan'
          ? 'bg-warning text-warning-fg'
          : s === 'self'
            ? 'bg-muted text-secondary'
            : s === 'vm'
              ? 'bg-accent-indigo text-accent-indigo-fg'
              : 'bg-info text-info-fg';
  return (
    <span className="flex flex-wrap gap-1">
      {sources.map((s) => (
        <span key={s} className={`inline-flex rounded px-1.5 py-0.5 text-xs font-medium uppercase ${cls(s)}`}>
          {s}
        </span>
      ))}
    </span>
  );
}

export default function Hosts() {
  const { formatDateTime } = useTimeFormat();

  // Server-side pagination — rows are fetched per page by the API (the merge
  // into one row per MAC happens server-side; sort + slice apply to the merged
  // list). Rows are upserted by the telemetry worker (30s poll) — the hook's
  // default 30s refetch keeps the view tracking live neighbor/lease tables.
  const table = useServerTable<object, HostRow>({
    fetcher: async (p) => {
      // Only mac/hostname/lastSeenAt are server-sortable columns — anything else
      // (e.g. stale persisted state) falls back to the API's default order.
      const k = p.sort?.key;
      const res = await api.hosts({
        q: p.q,
        page: p.pageSize === ALL_PAGES ? undefined : p.page,
        pageSize: p.pageSize === ALL_PAGES ? undefined : p.pageSize,
        all: p.pageSize === ALL_PAGES || undefined,
        sort: k === 'mac' || k === 'hostname' || k === 'lastSeenAt' ? k : undefined,
        dir: p.sort?.dir,
      });
      // Paged mode always returns the envelope; guard for safety.
      return Array.isArray(res) ? { rows: res, total: res.length } : { rows: res.rows, total: res.total };
    },
    extra: useMemo(() => ({}), []),
    storageKey: 'hosts',
  });

  // Debounce the table's built-in quick search into the committed server query (300 ms).
  const qTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  function onSearchInput(v: string) {
    if (qTimer.current) clearTimeout(qTimer.current);
    qTimer.current = setTimeout(() => table.setQ(v.trim()), 300);
  }

  // Traffic over the last 24h per endpoint IP — summed across each host's
  // addresses below. Rollups land every 5 minutes; refresh on that cadence.
  const trafficQuery = useQuery({
    queryKey: ['flows', 'inventory'],
    queryFn: () => {
      const to = new Date();
      return api.flowsInventory({ from: new Date(Date.now() - TRAFFIC_WINDOW_MS).toISOString(), to: to.toISOString() });
    },
    enabled: can('flows:read'),
    refetchInterval: 300_000,
  });

  const trafficByIp = useMemo(() => {
    const map = new Map<string, HostTraffic>();
    for (const r of trafficQuery.data?.perIp ?? []) {
      map.set(r.ip, { sent: Number(r.srcEstBytes), received: Number(r.dstEstBytes) });
    }
    return map;
  }, [trafficQuery.data]);

  // Per-endpoint firewall state snapshots (open now + created/destroyed over
  // the last 24h). Walks run at a slow cadence on the devices (default 15 min),
  // so refresh on that order — not every 30 s.
  const statesQuery = useQuery({
    queryKey: ['hostStates'],
    queryFn: () => api.hostStates({ windowHours: 24 }),
    enabled: can('hosts:read'),
    refetchInterval: 300_000,
  });

  const statesByIp = useMemo(() => {
    // One endpoint address may be tracked by several devices — sum them.
    const map = new Map<string, { open: number; created: number | null; destroyed: number | null }>();
    for (const r of statesQuery.data?.rows ?? []) {
      let e = map.get(r.hostIp);
      if (!e) {
        e = { open: 0, created: null, destroyed: null };
        map.set(r.hostIp, e);
      }
      e.open += r.openStates;
      // Null churn = no baseline in the window — skip it (never count as 0).
      if (r.createdWindow !== null) e.created = (e.created ?? 0) + r.createdWindow;
      if (r.destroyedWindow !== null) e.destroyed = (e.destroyed ?? 0) + r.destroyedWindow;
    }
    return map;
  }, [statesQuery.data]);

  const hostStates = (row: HostRow): HostStates | null => {
    let open = 0;
    let created: number | null = null;
    let destroyed: number | null = null;
    for (const ip of row.ips) {
      const s = statesByIp.get(ip);
      if (!s) continue;
      open += s.open;
      if (s.created !== null) created = (created ?? 0) + s.created;
      if (s.destroyed !== null) destroyed = (destroyed ?? 0) + s.destroyed;
    }
    return open > 0 || created !== null || destroyed !== null ? { open, created24h: created, destroyed24h: destroyed } : null;
  };

  const hostTraffic = (row: HostRow): HostTraffic | null => {
    let sent = 0;
    let received = 0;
    for (const ip of row.ips) {
      const t = trafficByIp.get(ip);
      if (!t) continue;
      sent += t.sent;
      received += t.received;
    }
    return sent > 0 || received > 0 ? { sent, received } : null;
  };

  const columns: DataTableColumn<HostRow>[] = [
    {
      header: 'MAC',
      key: 'mac',
      width: 150,
      render: (row) => <span className="font-mono text-xs">{row.mac}</span>,
    },
    {
      // Merged host: one row per MAC with all its addresses (IPv4 first).
      header: 'IPs',
      key: 'ips',
      width: 200,
      exportValue: (row) => row.ips.join(' '),
      render: (row) => <IpGroupChips ips={row.ips} />,
      sortable: false, // server sorts by mac/hostname/lastSeenAt only
    },
    {
      header: 'Hostname',
      key: 'hostname',
      render: (row) => row.hostname ?? <span className="text-faint">—</span>,
    },
    {
      header: 'Source',
      key: 'sources',
      width: 120,
      exportValue: (row) => row.sources.join(' '),
      render: (row) => <SourceBadges sources={row.sources} />,
      sortable: false,
    },
    {
      header: 'Manufacturer',
      key: 'manufacturer',
      render: (row) => row.manufacturer ?? <span className="text-faint">—</span>,
      sortable: false,
    },
    {
      // Every device+plugin that observed this MAC, with the interface(s) seen on.
      header: 'Devices',
      key: 'devices',
      width: 320,
      exportValue: (row) => row.devices.map((d) => `${d.deviceName ?? '?'}[${d.interfaces.join(',')}]`).join('; '),
      render: (row) => (
        <div className="flex flex-wrap gap-1">
          {row.devices.map((d) => (
            <DeviceChip
              key={`${d.deviceId}|${d.pluginId}`}
              deviceName={d.deviceName}
              managementAddress={d.managementAddress}
              pluginName={d.pluginName}
              siteName={d.siteName}
              interfaces={d.interfaces}
            />
          ))}
        </div>
      ),
      sortable: false,
    },
    {
      header: 'Lease expiry',
      key: 'expiry',
      width: 180,
      sortable: false, // not a server sort field
      render: (row) => (row.expiry ? formatDateTime(row.expiry) : <span className="text-faint">—</span>),
    },
    {
      header: 'Last seen',
      key: 'lastSeenAt',
      width: 180,
      sortAccessor: (row) => new Date(row.lastSeenAt).getTime(),
      render: (row) => formatDateTime(row.lastSeenAt),
    },
    {
      // Flow-collector traffic over the last 24h — estimated bytes sent/received
      // across ALL of the host's addresses. "—" when no flows were observed.
      header: 'Traffic (24h)',
      key: 'traffic',
      width: 170,
      sortable: false, // client-side enrichment — not a server sort field
      exportValue: (row) => {
        const t = hostTraffic(row);
        return t ? `${t.sent} sent / ${t.received} received` : '';
      },
      render: (row) => {
        const t = hostTraffic(row);
        if (!t) return <span className="text-faint">—</span>;
        return (
          <div className="flex flex-col leading-tight" title={`Last 24h — sent ${formatBytes(t.sent)}, received ${formatBytes(t.received)}`}>
            <span className="font-mono text-xs"><span className="text-faint">↑</span> {formatBytes(t.sent)}</span>
            <span className="font-mono text-xs"><span className="text-faint">↓</span> {formatBytes(t.received)}</span>
          </div>
        );
      },
    },
    {
      // Firewall state-table view from the devices' periodic full walks: open
      // states now + created/destroyed over the last 24h, summed across ALL of
      // the host's addresses. "—" when no stateful device tracks this host (or
      // per-host tracking is disabled on every observing device).
      header: 'States',
      key: 'states',
      width: 170,
      sortable: false, // client-side enrichment — not a server sort field
      exportValue: (row) => {
        const s = hostStates(row);
        if (!s) return '';
        return `${s.open} open / ${s.created24h ?? '—'} created / ${s.destroyed24h ?? '—'} destroyed (24h)`;
      },
      render: (row) => {
        const s = hostStates(row);
        if (!s) return <span className="text-faint">—</span>;
        return (
          <div className="flex flex-col leading-tight" title={`Open states now: ${s.open} — created/destroyed over the last 24h`}>
            <span className="font-mono text-xs"><span className="text-faint">open</span> {s.open}</span>
            <span className="font-mono text-xs">
              <span className="text-success">+{s.created24h ?? '—'}</span>{' '}
              <span className="text-danger">−{s.destroyed24h ?? '—'}</span>
              <span className="text-faint"> (24h)</span>
            </span>
          </div>
        );
      },
    },
  ];

  return (
    <Layout title="Hosts">

      {table.isError && (
        <p className="text-sm text-danger-fg">Failed to load hosts: {table.error?.message}</p>
      )}

      <DataTable
        columns={columns}
        rows={table.data?.rows ?? []}
        rowKey={(row) => row.mac}
        storageKey="hosts"
        isFetching={table.isFetching}
        searchPlaceholder="Search hosts…"
        onSearch={onSearchInput}
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
        emptyMessage="No hosts discovered yet — assign a plugin (e.g. OPNsense) to a device and wait for the next poll."
      />
    </Layout>
  );
}
