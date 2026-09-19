import { useQuery } from '@tanstack/react-query';
import { Layout } from '../components/Layout';
import { DataTable, DataTableColumn } from '../components/DataTable';
import { DeviceChip } from '../components/DeviceChip';
import { StatusBadge } from '../components/StatusBadge';
import { formatBytes, formatDuration } from '../components/formatMetric';
import { api, TunnelRow } from '../api/client';
import { useTimeFormat } from '../utils/time';

/** Small colored pill for the tunnel technology. */
const TYPE_STYLES: Record<TunnelRow['type'], string> = {
  wireguard: 'bg-indigo-100 text-indigo-700',
  openvpn: 'bg-teal-100 text-teal-700',
  ipsec: 'bg-purple-100 text-purple-700',
  pppoe: 'bg-warning text-warning-fg',
  gre: 'bg-muted text-secondary',
};

function TypeBadge({ type }: { type: TunnelRow['type'] }) {
  return (
    <span className={`inline-flex rounded px-1.5 py-0.5 text-xs font-medium uppercase ${TYPE_STYLES[type] ?? 'bg-muted text-secondary'}`}>
      {type}
    </span>
  );
}

/** "—" for empty/unknown values (the API stores '' for unknown addresses). */
function orDash(v?: string | null): string {
  return v && v.trim() !== '' ? v : '—';
}

export default function Tunnels() {
  const { formatDateTime } = useTimeFormat();
  // The API polls plugins every 30s and upserts these rows — refresh at the
  // same cadence so the view tracks live inventory (rates update per poll).
  const tunnelsQuery = useQuery({
    queryKey: ['tunnels'],
    queryFn: () => api.tunnels(),
    refetchInterval: 30_000,
  });

  const columns: DataTableColumn<TunnelRow>[] = [
    {
      header: 'Tunnel',
      key: 'name',
      width: 220,
      render: (row) => <span className="font-medium text-foreground">{row.name}</span>,
    },
    {
      header: 'Type',
      key: 'type',
      width: 110,
      render: (row) => <TypeBadge type={row.type} />,
    },
    {
      header: 'Device',
      key: 'deviceName',
      width: 260,
      exportValue: (row) => `${row.deviceName ?? '?'} (${row.managementAddress ?? '?'})`,
      render: (row) => (
        <DeviceChip
          deviceName={row.deviceName}
          managementAddress={row.managementAddress}
          pluginName={row.pluginName}
          siteName={row.siteName}
          interfaces={row.interfaceName ? [row.interfaceName] : []}
        />
      ),
    },
    {
      header: 'Peer / Remote',
      key: 'peerAddress',
      width: 180,
      render: (row) => <span className="font-mono text-xs">{orDash(row.peerAddress)}</span>,
    },
    {
      header: 'Local / Subnet',
      key: 'localAddress',
      width: 200,
      exportValue: (row) => [row.localAddress, row.subnet].filter(Boolean).join(' ') || '',
      render: (row) => (
        <div className="flex flex-col gap-0.5">
          {row.localAddress && row.localAddress.trim() !== '' && (
            <span className="font-mono text-xs">{row.localAddress}</span>
          )}
          {row.subnet && (
            <span className="inline-flex w-fit rounded bg-muted px-1.5 py-0.5 font-mono text-[11px] text-secondary">
              {row.subnet}
            </span>
          )}
          {!row.localAddress && !row.subnet && <span className="text-faint">—</span>}
        </div>
      ),
    },
    {
      header: 'Status',
      key: 'status',
      width: 110,
      render: (row) => <StatusBadge status={row.status} />,
    },
    {
      // Seconds since the last WireGuard handshake (live from service/show).
      // Green when fresh (< keepalive window), amber when stale, "—" otherwise.
      header: 'Last Activity',
      key: 'lastHandshakeSeconds',
      width: 130,
      sortAccessor: (row) => row.lastHandshakeSeconds ?? Number.MAX_SAFE_INTEGER,
      render: (row) => {
        if (row.lastHandshakeSeconds === null || row.lastHandshakeSeconds === undefined) {
          return <span className="text-faint">—</span>;
        }
        const stale = row.lastHandshakeSeconds > 120; // ~2 keepalives missed
        return (
          <span className={`font-mono text-xs ${stale ? 'text-warning-fg' : 'text-success-fg'}`}>
            {formatDuration(row.lastHandshakeSeconds)} ago
          </span>
        );
      },
    },
    {
      header: 'Uptime',
      key: 'uptimeSeconds',
      width: 110,
      sortAccessor: (row) => row.uptimeSeconds ?? -1,
      render: (row) =>
        row.uptimeSeconds !== null && row.uptimeSeconds !== undefined ? (
          formatDuration(row.uptimeSeconds)
        ) : (
          <span className="text-faint">—</span>
        ),
    },
    {
      header: 'Rx / Tx',
      key: 'rxRate',
      width: 170,
      sortAccessor: (row) => (row.rxRate ?? 0) + (row.txRate ?? 0),
      render: (row) =>
        row.rxRate !== null && row.rxRate !== undefined || row.txRate !== null && row.txRate !== undefined ? (
          <span className="font-mono text-xs">
            {row.rxRate !== null && row.rxRate !== undefined ? `${formatBytes(row.rxRate)}/s` : '—'}{' '}
            <span className="text-faint">/</span>{' '}
            {row.txRate !== null && row.txRate !== undefined ? `${formatBytes(row.txRate)}/s` : '—'}
          </span>
        ) : (
          <span className="text-faint">—</span>
        ),
    },
    {
      header: 'Collected',
      key: 'collectedAt',
      width: 180,
      sortAccessor: (row) => new Date(row.collectedAt).getTime(),
      render: (row) => formatDateTime(row.collectedAt),
    },
  ];

  return (
    <Layout title="Tunnels">

      {tunnelsQuery.isLoading && <p className="text-sm text-muted-foreground">Loading tunnels...</p>}
      {tunnelsQuery.isError && (
        <p className="text-sm text-danger-fg">Failed to load tunnels: {(tunnelsQuery.error as Error).message}</p>
      )}
      {tunnelsQuery.data && (
        <DataTable
          columns={columns}
          rows={tunnelsQuery.data}
          rowKey={(row) => `${row.deviceId}|${row.pluginId}|${row.name}|${row.type}`}
          storageKey="tunnels"
          autoRefresh={{ intervalMs: 30_000, queries: [tunnelsQuery] }}
          searchPlaceholder="Search tunnels…"
          emptyMessage="No tunnels collected yet — assign a router plugin (e.g. OPNsense or LANCOM LCOS) to a device and wait for the next poll."
        />
      )}
    </Layout>
  );
}
