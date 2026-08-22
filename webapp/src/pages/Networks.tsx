import { useQuery } from '@tanstack/react-query';
import { Layout } from '../components/Layout';
import { DataTable, DataTableColumn } from '../components/DataTable';
import { api, NetworkRow } from '../api/client';

/** Small colored pill for the address family. */
function VersionBadge({ version }: { version?: string | null }) {
  if (!version) return <span className="text-slate-400">—</span>;
  const cls =
    version === 'v6'
      ? 'bg-purple-100 text-purple-700'
      : 'bg-blue-100 text-blue-700';
  return (
    <span className={`inline-flex rounded px-1.5 py-0.5 text-xs font-medium ${cls}`}>
      {version}
    </span>
  );
}

/** CIDR cell: `ip/prefix` when both are known, bare IP otherwise. */
function CidrCell({ row }: { row: NetworkRow }) {
  if (!row.ip) return <span className="text-slate-400">—</span>;
  const cidr = row.prefix !== null && row.prefix !== undefined ? `${row.ip}/${row.prefix}` : row.ip;
  return <span className="font-mono text-xs">{cidr}</span>;
}

export default function Networks() {
  // The API polls plugins every 30s and upserts these rows — refresh at the
  // same cadence so the view tracks live inventory.
  const networksQuery = useQuery({
    queryKey: ['networks'],
    queryFn: () => api.networks(),
    refetchInterval: 30_000,
  });

  const columns: DataTableColumn<NetworkRow>[] = [
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
    { header: 'Interface', key: 'name' },
    {
      header: 'VLAN ID',
      key: 'vlanId',
      width: 90,
      render: (row) =>
        row.vlanId !== null && row.vlanId !== undefined ? (
          <span className="inline-flex rounded bg-slate-100 px-1.5 py-0.5 text-xs font-medium text-slate-700">
            {row.vlanId}
          </span>
        ) : (
          <span className="text-slate-400">—</span>
        ),
    },
    { header: 'CIDR', key: 'ip', width: 180, render: (row) => <CidrCell row={row} /> },
    { header: 'Version', key: 'version', width: 90, render: (row) => <VersionBadge version={row.version} /> },
    {
      header: 'MAC',
      key: 'mac',
      width: 150,
      render: (row) =>
        row.mac ? <span className="font-mono text-xs">{row.mac}</span> : <span className="text-slate-400">—</span>,
    },
    {
      header: 'Status',
      key: 'status',
      width: 100,
      render: (row) => row.status ?? <span className="text-slate-400">—</span>,
    },
    {
      header: 'Collected',
      key: 'collectedAt',
      width: 180,
      sortAccessor: (row) => new Date(row.collectedAt).getTime(),
      render: (row) => new Date(row.collectedAt).toLocaleString(),
    },
  ];

  return (
    <Layout>
      <div className="mb-4">
        <h1 className="text-xl font-bold text-slate-900">Networks</h1>
        <p className="mt-1 text-sm text-slate-500">
          Configured networks (interface IPs with CIDR and VLAN id) collected from all devices.
        </p>
      </div>

      {networksQuery.isLoading && <p className="text-sm text-slate-500">Loading networks...</p>}
      {networksQuery.isError && (
        <p className="text-sm text-red-600">Failed to load networks: {(networksQuery.error as Error).message}</p>
      )}
      {networksQuery.data && (
        <DataTable
          columns={columns}
          rows={networksQuery.data}
          rowKey={(row) => `${row.deviceId}|${row.pluginId}|${row.name}|${row.ip ?? ''}`}
          storageKey="networks"
          searchPlaceholder="Search networks…"
          emptyMessage="No networks collected yet — assign a plugin (e.g. OPNsense) to a device and wait for the next poll."
        />
      )}
    </Layout>
  );
}
