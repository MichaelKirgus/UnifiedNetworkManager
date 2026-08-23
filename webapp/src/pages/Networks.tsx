import { useQuery } from '@tanstack/react-query';
import { Layout } from '../components/Layout';
import { DataTable, DataTableColumn } from '../components/DataTable';
import { DeviceChip } from '../components/DeviceChip';
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

/** CIDR chip, IPv6 tinted. */
function CidrChip({ cidr }: { cidr: string }) {
  return (
    <span
      className={`rounded px-1.5 py-0.5 font-mono text-xs ${
        cidr.includes(':') ? 'bg-purple-50 text-purple-700' : 'bg-slate-100 text-slate-700'
      }`}
    >
      {cidr}
    </span>
  );
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
      header: 'Network',
      key: 'name',
      width: 200,
      render: (row) => (
        <span className="font-medium text-slate-800" title={row.subnet ?? undefined}>
          {row.name}
        </span>
      ),
    },
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
    {
      header: 'Version',
      key: 'versions',
      width: 90,
      exportValue: (row) => row.versions.join(','),
      render: (row) => (
        <span className="inline-flex gap-1">
          {row.versions.length > 0 ? row.versions.map((v) => <VersionBadge key={v} version={v} />) : <VersionBadge version={null} />}
        </span>
      ),
    },
    {
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
              extraTooltip={[d.mac ? `MAC ${d.mac}` : '', d.status ? `status: ${d.status}` : '']}
              interfaces={d.interfaces}
            />
          ))}
        </div>
      ),
    },
    {
      header: 'Addresses',
      key: 'cidrs',
      width: 240,
      exportValue: (row) => row.devices.flatMap((d) => d.cidrs).join(', '),
      render: (row) => {
        const cidrs = Array.from(new Set(row.devices.flatMap((d) => d.cidrs)));
        if (cidrs.length === 0) return <span className="text-slate-400">—</span>;
        return (
          <div className="flex flex-wrap gap-1">
            {cidrs.map((c) => (
              <CidrChip key={c} cidr={c} />
            ))}
          </div>
        );
      },
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
          Logical networks across all devices — interfaces sharing a subnet or VLAN are merged into one row (e.g. the same SSID on many APs).
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
          rowKey={(row) => row.key}
          storageKey="networks"
          searchPlaceholder="Search networks…"
          emptyMessage="No networks collected yet — assign a plugin (e.g. OPNsense) to a device and wait for the next poll."
        />
      )}
    </Layout>
  );
}
