import { useQuery } from '@tanstack/react-query';
import { Layout } from '../components/Layout';
import { DataTable, DataTableColumn } from '../components/DataTable';
import { DeviceChip } from '../components/DeviceChip';
import { IpGroupChips } from '../components/IpGroups';
import { api, HostRow } from '../api/client';

/** Color-coded pill for one discovery source; a merged host shows all of its sources. */
function SourceBadges({ sources }: { sources: HostRow['sources'] }) {
  const cls = (s: string) =>
    s === 'dhcp'
      ? 'bg-success text-success-fg'
      : s === 'ndp'
        ? 'bg-purple-100 text-purple-700'
        : s === 'wlan'
          ? 'bg-warning text-warning-fg'
          : s === 'self'
            ? 'bg-muted text-secondary'
            : s === 'vm'
              ? 'bg-indigo-100 text-indigo-700'
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
      render: (row) => <IpGroupChips ips={row.ips} />,
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
    },
    {
      header: 'Manufacturer',
      key: 'manufacturer',
      render: (row) => row.manufacturer ?? <span className="text-faint">—</span>,
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
    },
    {
      header: 'Lease expiry',
      key: 'expiry',
      width: 180,
      sortAccessor: (row) => (row.expiry ? new Date(row.expiry).getTime() : null),
      render: (row) => (row.expiry ? new Date(row.expiry).toLocaleString() : <span className="text-faint">—</span>),
    },
    {
      header: 'Last seen',
      key: 'lastSeenAt',
      width: 180,
      sortAccessor: (row) => new Date(row.lastSeenAt).getTime(),
      render: (row) => new Date(row.lastSeenAt).toLocaleString(),
    },
  ];

  return (
    <Layout title="Hosts">

      {hostsQuery.isLoading && <p className="text-sm text-muted-foreground">Loading hosts...</p>}
      {hostsQuery.isError && (
        <p className="text-sm text-danger-fg">Failed to load hosts: {(hostsQuery.error as Error).message}</p>
      )}
      {hostsQuery.data && (
        <DataTable
          columns={columns}
          rows={hostsQuery.data}
          rowKey={(row) => row.mac}
          storageKey="hosts"
          autoRefresh={{ intervalMs: 30_000, queries: [hostsQuery] }}
          searchPlaceholder="Search hosts…"
          emptyMessage="No hosts discovered yet — assign a plugin (e.g. OPNsense) to a device and wait for the next poll."
        />
      )}
    </Layout>
  );
}
