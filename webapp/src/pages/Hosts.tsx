import { useQuery } from '@tanstack/react-query';
import { Layout } from '../components/Layout';
import { DataTable, DataTableColumn } from '../components/DataTable';
import { api, HostRow } from '../api/client';

/** Color-coded pill for one discovery source; a merged host shows all of its sources. */
function SourceBadges({ sources }: { sources: HostRow['sources'] }) {
  const cls = (s: string) =>
    s === 'dhcp'
      ? 'bg-emerald-100 text-emerald-700'
      : s === 'ndp'
        ? 'bg-purple-100 text-purple-700'
        : s === 'wlan'
          ? 'bg-amber-100 text-amber-700'
          : 'bg-blue-100 text-blue-700';
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
  // Rows are upserted by the API's telemetry worker (30s poll) — refresh at
  // the same cadence so the view tracks live neighbor/lease tables.
  const hostsQuery = useQuery({
    queryKey: ['hosts'],
    queryFn: () => api.hosts(),
    refetchInterval: 30_000,
  });

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
      render: (row) => (
        <span className="flex flex-wrap gap-1">
          {row.ips.map((ip) => (
            <span key={ip} className={`font-mono text-xs ${ip.includes(':') ? 'text-purple-700' : ''}`}>
              {ip}
            </span>
          ))}
        </span>
      ),
    },
    {
      header: 'Hostname',
      key: 'hostname',
      render: (row) => row.hostname ?? <span className="text-slate-400">—</span>,
    },
    {
      header: 'Source',
      key: 'sources',
      width: 120,
      exportValue: (row) => row.sources.join(' '),
      render: (row) => <SourceBadges sources={row.sources} />,
    },
    {
      header: 'Manufacturer',
      key: 'manufacturer',
      render: (row) => row.manufacturer ?? <span className="text-slate-400">—</span>,
    },
    {
      header: 'Interface',
      key: 'intf',
      width: 120,
      render: (row) => row.intf ?? <span className="text-slate-400">—</span>,
    },
    {
      header: 'Lease expiry',
      key: 'expiry',
      width: 180,
      sortAccessor: (row) => (row.expiry ? new Date(row.expiry).getTime() : null),
      render: (row) => (row.expiry ? new Date(row.expiry).toLocaleString() : <span className="text-slate-400">—</span>),
    },
    {
      header: 'Last seen',
      key: 'lastSeenAt',
      width: 180,
      sortAccessor: (row) => new Date(row.lastSeenAt).getTime(),
      render: (row) => new Date(row.lastSeenAt).toLocaleString(),
    },
    {
      header: 'Device',
      key: 'deviceName',
      width: 180,
      render: (row) =>
        row.deviceName ? (
          <span title={row.managementAddress ?? undefined}>
            {row.deviceName}
            {row.siteName && <span className="ml-1 text-xs text-slate-400">({row.siteName})</span>}
          </span>
        ) : (
          <span className="text-slate-400">—</span>
        ),
    },
    {
      header: 'Plugin',
      key: 'pluginName',
      width: 180,
      render: (row) => row.pluginName ?? <span className="text-slate-400">—</span>,
    },
  ];

  return (
    <Layout>
      <div className="mb-4">
        <h1 className="text-xl font-bold text-slate-900">Hosts</h1>
        <p className="mt-1 text-sm text-slate-500">
          Discovered hosts from all devices — ARP/NDP neighbor tables, DHCP leases and WLAN clients. Entries not seen for 24h are removed automatically.
        </p>
      </div>

      {hostsQuery.isLoading && <p className="text-sm text-slate-500">Loading hosts...</p>}
      {hostsQuery.isError && (
        <p className="text-sm text-red-600">Failed to load hosts: {(hostsQuery.error as Error).message}</p>
      )}
      {hostsQuery.data && (
        <DataTable
          columns={columns}
          rows={hostsQuery.data}
          rowKey={(row) => `${row.deviceId}|${row.pluginId}|${row.mac}`}
          storageKey="hosts"
          searchPlaceholder="Search hosts…"
          emptyMessage="No hosts discovered yet — assign a plugin (e.g. OPNsense) to a device and wait for the next poll."
        />
      )}
    </Layout>
  );
}
