import { useQuery } from '@tanstack/react-query';
import clsx from 'clsx';
import { Layout } from '../components/Layout';
import { DataTable, DataTableColumn } from '../components/DataTable';
import { DeviceChip } from '../components/DeviceChip';
import { formatDuration } from '../components/formatMetric';
import { api, ContainerNetwork, ContainerRow, ContainerServiceDetail } from '../api/client';

/** Uptime cell — UNM-observed "running since" (the TrueNAS API exposes no real
 * container start-time). RUNNING + startedAt → duration; non-RUNNING or no stamp
 * → "—". The tooltip discloses the value is tracked by UNM from state transitions,
 * so it resets after restarts and underestimates true uptime for apps UNM only
 * started watching mid-run. */
function UptimeCell({ row }: { row: ContainerRow }) {
  if (row.state !== 'RUNNING' || !row.startedAt) return <span className="text-slate-400">—</span>;
  const since = new Date(row.startedAt).getTime();
  if (Number.isNaN(since)) return <span className="text-slate-400">—</span>;
  const secs = Math.max(0, (Date.now() - since) / 1000);
  return (
    <span
      className="font-mono text-xs text-slate-700"
      title={`Running since ${new Date(row.startedAt).toLocaleString()} — tracked by UNM from state transitions (resets after restarts; a lower bound if UNM started observing while it was already running)`}
    >
      {formatDuration(secs)}
    </span>
  );
}

/** App workload state → badge style (TrueNAS SCALE states are uppercase). */
const STATE_STYLES: Record<string, string> = {
  RUNNING: 'bg-emerald-100 text-emerald-800 border-emerald-300',
  STOPPED: 'bg-slate-200 text-slate-600 border-slate-300',
  ERROR: 'bg-red-100 text-red-800 border-red-300',
  FAILED: 'bg-red-100 text-red-800 border-red-300',
};

function StateBadge({ state }: { state: string }) {
  const style = STATE_STYLES[state] ?? 'bg-amber-100 text-amber-800 border-amber-300';
  return (
    <span className={clsx('inline-flex items-center rounded-full border px-2.5 py-0.5 text-xs font-medium', style)}>
      {state.toLowerCase()}
    </span>
  );
}

/** Reads the `extra` JSON object defensively — corrupt rows must not break the table. */
function extraOf(row: ContainerRow): Record<string, unknown> {
  const e = row.extra;
  return e && typeof e === 'object' ? (e as Record<string, unknown>) : {};
}

/** Networks[] from extra (defensive). */
function networksOf(row: ContainerRow): ContainerNetwork[] {
  const n = extraOf(row)['networks'];
  if (!Array.isArray(n)) return [];
  return n.filter((x): x is ContainerNetwork => !!x && typeof x === 'object' && typeof (x as ContainerNetwork).name === 'string');
}

/** Static container IPs from extra. */
function ipsOf(row: ContainerRow): string[] {
  const i = extraOf(row)['ips'];
  return Array.isArray(i) ? i.filter((x): x is string => typeof x === 'string') : [];
}

/** Published host ports from extra. */
function portsOf(row: ContainerRow): number[] {
  const p = extraOf(row)['ports'];
  return Array.isArray(p) ? p.filter((x): x is number => typeof x === 'number') : [];
}

/** Per-service detail for the expandable row (multi-container apps). */
function servicesOf(row: ContainerRow): ContainerServiceDetail[] {
  const c = extraOf(row)['containers'];
  if (!Array.isArray(c)) return [];
  return c.filter((x): x is ContainerServiceDetail => !!x && typeof x === 'object');
}

/** Volume mount sources from extra. */
function volumesOf(row: ContainerRow): string[] {
  const v = extraOf(row)['volumeMounts'];
  return Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string') : [];
}

/** One docker-network chip — name on top, driver + subnets in the tooltip. */
function NetworkChip({ net }: { net: ContainerNetwork }) {
  const tip = [net.name, net.driver ? `driver: ${net.driver}` : '', ...(net.subnets ?? [])].filter(Boolean).join(' · ');
  return (
    <span title={tip} className="inline-flex items-center rounded border border-sky-200 bg-sky-50 px-1.5 py-0.5 font-mono text-[11px] leading-4 text-sky-800">
      {net.name}
    </span>
  );
}

/** One static IP chip (v4 blue / v6 violet — same convention as the Firewall page). */
function IpChip({ ip }: { ip: string }) {
  const isV6 = ip.includes(':');
  return (
    <span className={clsx('inline-flex items-center rounded border px-1.5 py-0.5 font-mono text-[11px] leading-4', isV6 ? 'border-violet-200 bg-violet-50 text-violet-800' : 'border-blue-200 bg-blue-50 text-blue-800')}>
      {ip}
    </span>
  );
}

/** Network + IP cell: static IPs first, then network chips; "—" when neither. */
function NetworkCell({ row }: { row: ContainerRow }) {
  const ips = ipsOf(row);
  const nets = networksOf(row);
  if (ips.length === 0 && nets.length === 0) return <span className="text-slate-400">—</span>;
  return (
    <div className="flex flex-col gap-1">
      {ips.length > 0 && (
        <span className="flex flex-wrap gap-x-1 gap-y-0.5">{ips.map((ip) => <IpChip key={ip} ip={ip} />)}</span>
      )}
      {nets.length > 0 && (
        <span className="flex flex-wrap gap-x-1 gap-y-0.5">
          {nets.slice(0, 4).map((n) => <NetworkChip key={n.name} net={n} />)}
          {nets.length > 4 && <span className="text-[11px] text-slate-400" title={nets.map((n) => n.name).join(', ')}>+{nets.length - 4}</span>}
        </span>
      )}
    </div>
  );
}

/** Published host ports — first three + "+N" overflow. */
function PortsCell({ row }: { row: ContainerRow }) {
  const ports = portsOf(row);
  if (ports.length === 0) return <span className="text-slate-400">—</span>;
  const shown = ports.slice(0, 3);
  return (
    <span title={ports.join(', ')} className="font-mono text-xs text-slate-700">
      {shown.map((p) => p).join(', ')}
      {ports.length > 3 && <span className="text-slate-400"> +{ports.length - 3}</span>}
    </span>
  );
}

/** Version cell with an amber "update available" dot. */
function VersionCell({ row }: { row: ContainerRow }) {
  const v = row.version && row.version.trim() !== '' ? row.version : null;
  if (!v) return <span className="text-slate-400">—</span>;
  return (
    <span className="inline-flex items-center gap-1.5 font-mono text-xs text-slate-700" title={row.upgradeAvailable ? 'Update available' : undefined}>
      {v}
      {row.upgradeAvailable && <span className="h-2 w-2 rounded-full bg-amber-400" title="Update available" />}
    </span>
  );
}

/** Expandable detail: per-service containers + volume mounts (multi-container apps). */
function RowDetail({ row }: { row: ContainerRow }) {
  const services = servicesOf(row);
  const volumes = volumesOf(row);
  if (services.length === 0 && volumes.length === 0) return null;
  return (
    <div className="flex flex-col gap-2 px-3 py-2">
      {services.length > 1 && (
        <div>
          <p className="mb-1 text-[11px] font-semibold uppercase tracking-wide text-slate-400">Containers</p>
          <div className="flex flex-col gap-1">
            {services.map((s, i) => (
              <div key={i} className="flex items-center gap-2 text-xs">
                <span className="font-medium text-slate-700">{s.service ?? '—'}</span>
                {s.state && s.state !== 'running' && (
                  <span className={clsx('rounded px-1 py-0.5 text-[10px] font-medium uppercase', s.state === 'running' ? 'bg-emerald-100 text-emerald-700' : 'bg-slate-200 text-slate-600')}>{s.state}</span>
                )}
                {s.image && <span className="truncate font-mono text-[11px] text-slate-500" title={s.image}>{s.image}</span>}
              </div>
            ))}
          </div>
        </div>
      )}
      {volumes.length > 0 && (
        <div>
          <p className="mb-1 text-[11px] font-semibold uppercase tracking-wide text-slate-400">Volume mounts</p>
          <div className="flex flex-wrap gap-x-2 gap-y-0.5">
            {volumes.map((v) => (
              <span key={v} className="font-mono text-[11px] text-slate-600">{v}</span>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

export default function Containers() {
  // The API polls plugins every ~30s and upserts these rows — refresh at the
  // same cadence so the view tracks live inventory.
  const containersQuery = useQuery({
    queryKey: ['containers'],
    queryFn: () => api.containers(),
    refetchInterval: 30_000,
  });

  const columns: DataTableColumn<ContainerRow>[] = [
    {
      header: 'App',
      key: 'name',
      width: 210,
      render: (row) => (
        <div className="flex flex-col gap-0.5">
          <span className="font-medium text-slate-800">{row.name}</span>
          {typeof extraOf(row)['customApp'] === 'boolean' && (extraOf(row)['customApp'] as boolean) && (
            <span className="text-[10px] uppercase tracking-wide text-slate-400">custom</span>
          )}
        </div>
      ),
    },
    {
      header: 'Device',
      key: 'deviceName',
      width: 230,
      exportValue: (row) => `${row.deviceName ?? '?'} (${row.managementAddress ?? '?'})`,
      render: (row) => (
        <DeviceChip
          deviceName={row.deviceName}
          managementAddress={row.managementAddress}
          pluginName={row.pluginName}
          siteName={row.siteName}
          interfaces={[]}
        />
      ),
    },
    {
      header: 'State',
      key: 'state',
      width: 110,
      render: (row) => <StateBadge state={row.state} />,
    },
    {
      header: 'Uptime',
      key: 'startedAt',
      width: 120,
      exportValue: (row) => row.startedAt ?? '',
      sortAccessor: (row) => (row.startedAt ? new Date(row.startedAt).getTime() : null),
      render: (row) => <UptimeCell row={row} />,
    },
    {
      header: 'Image',
      key: 'image',
      width: 240,
      exportValue: (row) => row.image ?? '',
      render: (row) => {
        const services = servicesOf(row);
        // Multi-container apps have no single image — show the count instead.
        if (!row.image && services.length > 1) return <span className="text-xs text-slate-500">{services.length} containers</span>;
        return row.image ? (
          <span className="block truncate font-mono text-xs text-slate-700" title={row.image}>{row.image}</span>
        ) : (
          <span className="text-slate-400">—</span>
        );
      },
    },
    {
      header: 'Network / IPs',
      key: 'networks',
      width: 230,
      exportValue: (row) => [...ipsOf(row), ...networksOf(row).map((n) => n.name)].join(', '),
      render: (row) => <NetworkCell row={row} />,
    },
    {
      header: 'Ports',
      key: 'ports',
      width: 120,
      exportValue: (row) => portsOf(row).join(','),
      render: (row) => <PortsCell row={row} />,
    },
    {
      header: 'Version',
      key: 'version',
      width: 130,
      render: (row) => <VersionCell row={row} />,
    },
    {
      header: 'Collected',
      key: 'collectedAt',
      width: 170,
      sortAccessor: (row) => new Date(row.collectedAt).getTime(),
      render: (row) => new Date(row.collectedAt).toLocaleString(),
    },
  ];

  return (
    <Layout title="Containers">
      {containersQuery.isLoading && <p className="text-sm text-slate-500">Loading containers...</p>}
      {containersQuery.isError && (
        <p className="text-sm text-red-600">Failed to load containers: {(containersQuery.error as Error).message}</p>
      )}
      {containersQuery.data && (
        <DataTable
          columns={columns}
          rows={containersQuery.data.containers}
          rowKey={(row) => `${row.deviceId}|${row.pluginId}|${row.name}`}
          storageKey="containers"
          autoRefresh={{ intervalMs: 30_000, queries: [containersQuery] }}
          searchPlaceholder="Search containers…"
          renderRowDetail={(row) => <RowDetail row={row} />}
          emptyMessage="No containers collected yet — assign a TrueNAS plugin to a device and wait for the next poll."
        />
      )}
    </Layout>
  );
}
