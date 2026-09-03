import { useQuery } from '@tanstack/react-query';
import { Layout } from '../components/Layout';
import { DataTable, DataTableColumn } from '../components/DataTable';
import { DeviceChip } from '../components/DeviceChip';
import { StatusBadge } from '../components/StatusBadge';
import { IpGroupChips } from '../components/IpGroups';
import { api, RouteRow } from '../api/client';

/** Small colored pill for the route protocol. */
const PROTOCOL_STYLES: Record<RouteRow['protocol'], string> = {
  static: 'bg-slate-200 text-slate-700',
  connected: 'bg-cyan-100 text-cyan-800',
  ospf: 'bg-indigo-100 text-indigo-700',
  bgp: 'bg-purple-100 text-purple-700',
  rip: 'bg-amber-100 text-amber-800',
  other: 'bg-slate-100 text-slate-600',
};

function ProtocolBadge({ protocol }: { protocol: RouteRow['protocol'] }) {
  return (
    <span className={`inline-flex rounded px-1.5 py-0.5 text-xs font-medium uppercase ${PROTOCOL_STYLES[protocol] ?? 'bg-slate-100 text-slate-600'}`}>
      {protocol}
    </span>
  );
}

/** "—" for empty/unknown values (the API stores '' for unknown gateways). */
function orDash(v?: string | null): string {
  return v && v.trim() !== '' ? v : '—';
}

export default function Routes() {
  // The API polls plugins every 30s and upserts these rows — refresh at the
  // same cadence so the view tracks live inventory.
  const routesQuery = useQuery({
    queryKey: ['routes'],
    queryFn: () => api.routes(),
    refetchInterval: 30_000,
  });

  const columns: DataTableColumn<RouteRow>[] = [
    {
      header: 'Destination',
      key: 'destination',
      width: 200,
      render: (row) => <IpGroupChips ips={[row.destination]} />,
    },
    {
      header: 'Gateway',
      key: 'gateway',
      width: 190,
      exportValue: (row) => orDash(row.gateway),
      render: (row) => {
        const extra = row.extra ?? {};
        const latency = typeof extra['gatewayLatencyMs'] === 'number' ? (extra['gatewayLatencyMs'] as number) : null;
        const gwStatus = typeof extra['gatewayStatus'] === 'string' ? (extra['gatewayStatus'] as string) : undefined;
        return (
          <div className="flex flex-col gap-0.5">
            <span className="font-mono text-xs">{orDash(row.gateway)}</span>
            {gwStatus && gwStatus !== 'unknown' && (
              <span className={`text-[11px] ${gwStatus === 'online' ? 'text-emerald-600' : 'text-red-600'}`}>
                gateway {gwStatus}
                {latency !== null ? ` · ${Math.round(latency)} ms` : ''}
              </span>
            )}
          </div>
        );
      },
    },
    {
      header: 'Protocol',
      key: 'protocol',
      width: 110,
      render: (row) => <ProtocolBadge protocol={row.protocol} />,
    },
    {
      header: 'Distance / Metric',
      key: 'distance',
      width: 130,
      exportValue: (row) => [row.distance ?? '', row.metric ?? ''].filter((x) => x !== '').join(' / '),
      render: (row) => {
        const parts = [
          row.distance !== null && row.distance !== undefined ? `dist ${row.distance}` : '',
          row.metric !== null && row.metric !== undefined ? `metric ${row.metric}` : '',
        ].filter(Boolean);
        return parts.length > 0 ? (
          <span className="font-mono text-xs">{parts.join(' · ')}</span>
        ) : (
          <span className="text-slate-400">—</span>
        );
      },
    },
    {
      header: 'Device',
      key: 'deviceName',
      width: 260,
      exportValue: (row) => `${row.deviceName ?? '?'} (${row.managementAddress ?? '?'})`,
      render: (row) => {
        // LCOS rows carry the route's peer/interface name in extra.peer.
        const peerRaw = row.extra?.['peer'];
        const peer = typeof peerRaw === 'string' && peerRaw.trim() !== '' ? peerRaw : null;
        return (
          <DeviceChip
            deviceName={row.deviceName}
            managementAddress={row.managementAddress}
            pluginName={row.pluginName}
            siteName={row.siteName}
            interfaces={peer ? [peer] : []}
          />
        );
      },
    },
    {
      header: 'Status',
      key: 'status',
      width: 110,
      render: (row) => <StatusBadge status={row.status} />,
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
    <Layout title="Routes">

      {routesQuery.isLoading && <p className="text-sm text-slate-500">Loading routes...</p>}
      {routesQuery.isError && (
        <p className="text-sm text-red-600">Failed to load routes: {(routesQuery.error as Error).message}</p>
      )}
      {routesQuery.data && (
        <DataTable
          columns={columns}
          rows={routesQuery.data}
          rowKey={(row) => `${row.deviceId}|${row.pluginId}|${row.destination}|${row.protocol}`}
          storageKey="routes"
          autoRefresh={{ intervalMs: 30_000, queries: [routesQuery] }}
          searchPlaceholder="Search routes…"
          emptyMessage="No routes collected yet — assign a routing plugin (e.g. OPNsense, LANCOM LCOS or LANCOM SX) to a device and wait for the next poll."
        />
      )}
    </Layout>
  );
}
