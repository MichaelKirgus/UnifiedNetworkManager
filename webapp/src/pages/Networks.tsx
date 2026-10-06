import { useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { Globe } from 'lucide-react';
import { Layout } from '../components/Layout';
import { DataTable, DataTableColumn } from '../components/DataTable';
import { DeviceChip } from '../components/DeviceChip';
import { IpGroupChips } from '../components/IpGroups';
import { formatBytes } from '../components/formatMetric';
import { api, NetworkRow } from '../api/client';
import { can } from '../auth/permissions';
import { useTimeFormat } from '../utils/time';

/** Fixed window for the traffic column — matches what the header advertises. */
const TRAFFIC_WINDOW_MS = 24 * 60 * 60 * 1000;

/** One network's traffic totals over the window (null = no flows observed). */
interface NetworkTraffic {
  sent: number;
  received: number;
}

/** Small colored pill for the address family. */
function VersionBadge({ version }: { version?: string | null }) {
  if (!version) return <span className="text-faint">—</span>;
  const cls =
    version === 'v6'
      ? 'bg-accent-purple text-accent-purple-fg'
      : 'bg-info text-info-fg';
  return (
    <span className={`inline-flex rounded px-1.5 py-0.5 text-xs font-medium ${cls}`}>
      {version}
    </span>
  );
}

export default function Networks() {
  const navigate = useNavigate();
  const { formatDateTime } = useTimeFormat();
  // The API polls plugins every 30s and upserts these rows — refresh at the
  // same cadence so the view tracks live inventory.
  const networksQuery = useQuery({
    queryKey: ['networks'],
    queryFn: () => api.networks(),
    refetchInterval: 30_000,
  });

  // Traffic over the last 24h per logical network — keyed by the SAME canonical
  // identity this page's rows carry (`key`), so joining is a direct lookup.
  // Rollups land every 5 minutes; refresh on that cadence.
  const trafficQuery = useQuery({
    queryKey: ['flows', 'inventory'],
    queryFn: () => {
      const to = new Date();
      return api.flowsInventory({ from: new Date(Date.now() - TRAFFIC_WINDOW_MS).toISOString(), to: to.toISOString() });
    },
    enabled: can('flows:read'),
    refetchInterval: 300_000,
  });

  const trafficByKey = useMemo(() => {
    const map = new Map<string, NetworkTraffic>();
    for (const r of trafficQuery.data?.perNetwork ?? []) {
      map.set(r.key, { sent: Number(r.srcEstBytes), received: Number(r.dstEstBytes) });
    }
    return map;
  }, [trafficQuery.data]);

  const columns: DataTableColumn<NetworkRow>[] = [
    {
      header: 'Network',
      key: 'name',
      width: 260,
      // Search/export must see ALL subnets of the group — a dual-stack row's
      // name is only its canonical (often v6) subnet.
      exportValue: (row) => [row.name, ...(row.subnets ?? [])].join(', '),
      render: (row) => {
        // Dual-stack groups carry both CIDRs — show every real subnet of the
        // group, merged into one chip per scope type; fall back to the label
        // for VLAN/name rows.
        if ((row.subnets ?? []).length > 0) return <IpGroupChips ips={row.subnets ?? []} />;
        return <span className="font-medium text-foreground">{row.name}</span>;
      },
    },
    {
      header: 'VLAN ID',
      key: 'vlanId',
      width: 90,
      render: (row) =>
        row.vlanId !== null && row.vlanId !== undefined ? (
          <span className="inline-flex rounded bg-muted px-1.5 py-0.5 text-xs font-medium text-secondary">
            {row.vlanId}
          </span>
        ) : (
          <span className="text-faint">—</span>
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
        // One chip per scope type — a dual-stack network with several members
        // collapses to at most three chips instead of one per address.
        return <IpGroupChips ips={cidrs} />;
      },
    },
    {
      header: 'Collected',
      key: 'collectedAt',
      width: 180,
      sortAccessor: (row) => new Date(row.collectedAt).getTime(),
      render: (row) => formatDateTime(row.collectedAt),
    },
    {
      // Flow-collector traffic over the last 24h — estimated bytes sourced from
      // and destined for this network. "—" when no flows were observed.
      header: 'Traffic (24h)',
      key: 'traffic',
      width: 170,
      sortAccessor: (row) => {
        const t = trafficByKey.get(row.key);
        return t ? t.sent + t.received : null;
      },
      exportValue: (row) => {
        const t = trafficByKey.get(row.key);
        return t ? `${t.sent} sent / ${t.received} received` : '';
      },
      render: (row) => {
        const t = trafficByKey.get(row.key);
        if (!t) return <span className="text-faint">—</span>;
        return (
          <div className="flex flex-col leading-tight" title={`Last 24h — sent ${formatBytes(t.sent)}, received ${formatBytes(t.received)}`}>
            <span className="font-mono text-xs"><span className="text-faint">↑</span> {formatBytes(t.sent)}</span>
            <span className="font-mono text-xs"><span className="text-faint">↓</span> {formatBytes(t.received)}</span>
          </div>
        );
      },
    },
  ];

  return (
    <Layout
      title="Networks"
      actions={
        <>
          <button
            type="button"
            onClick={() => navigate('/networks/rollout', { state: { from: '/networks' } })}
            className="inline-flex items-center gap-2 rounded-md bg-primary px-3 py-1.5 text-sm font-medium text-white hover:bg-primary-hover"
          >
            <Globe className="h-4 w-4" /> Roll out network
          </button>
        </>
      }
    >

      {networksQuery.isLoading && <p className="text-sm text-muted-foreground">Loading networks...</p>}
      {networksQuery.isError && (
        <p className="text-sm text-danger-fg">Failed to load networks: {(networksQuery.error as Error).message}</p>
      )}
      {networksQuery.data && (
        <DataTable
          columns={columns}
          rows={networksQuery.data}
          rowKey={(row) => row.key}
          storageKey="networks"
          autoRefresh={{ intervalMs: 30_000, queries: [networksQuery] }}
          searchPlaceholder="Search networks…"
          emptyMessage="No networks collected yet — assign a plugin (e.g. OPNsense) to a device and wait for the next poll."
        />
      )}
    </Layout>
  );
}
