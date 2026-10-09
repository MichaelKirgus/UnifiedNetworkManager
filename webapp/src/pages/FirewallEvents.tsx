import { useMemo, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Layout } from '../components/Layout';
import { DataTable, DataTableColumn } from '../components/DataTable';
import { DeviceChip } from '../components/DeviceChip';
import { api, FirewallEventRow } from '../api/client';
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

/** Time-range presets for the filter bar. */
const TIME_RANGES = [
  { value: '1h', label: 'Last hour' },
  { value: '24h', label: 'Last 24 hours' },
  { value: '7d', label: 'Last 7 days' },
] as const;

type TimeRange = (typeof TIME_RANGES)[number]['value'];

const RANGE_MS: Record<TimeRange, number> = {
  '1h': 60 * 60 * 1000,
  '24h': 24 * 60 * 60 * 1000,
  '7d': 7 * 24 * 60 * 60 * 1000,
};

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
  const [search, setSearch] = useState('');
  const [range, setRange] = useState<TimeRange>('1h');

  // Options for the device filter select.
  const devicesQuery = useQuery({ queryKey: ['devices'], queryFn: api.devices });

  // The `from` bound is computed at fetch time so "last hour" keeps sliding as
  // the page refetches. Newest-first, capped by the API (default 500 rows).
  const eventsQuery = useQuery({
    queryKey: ['firewallEvents', action, deviceId, search, range],
    queryFn: () => {
      const from = new Date(Date.now() - RANGE_MS[range]).toISOString();
      return api.firewallEvents({
        from,
        deviceId: deviceId || undefined,
        action: (action || undefined) as 'pass' | 'block' | 'rdr' | 'nat' | 'binat' | 'other' | undefined,
        search: search.trim() || undefined,
      });
    },
    refetchInterval: 30_000,
  });

  const devices = useMemo(() => (devicesQuery.data ?? []).slice().sort((a, b) => a.name.localeCompare(b.name)), [devicesQuery.data]);
  const summary = eventsQuery.data?.summary;

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
      render: (row) => <ActionBadge action={row.action} />,
    },
    {
      header: 'Device',
      key: 'deviceName',
      width: 220,
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
      render: (row) => <span className="font-mono text-xs">{orDash(row.interfaceName)}</span>,
    },
    {
      // Source → destination in one cell — the core question this page answers.
      header: 'Source → Destination',
      key: 'srcIp',
      width: 300,
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
      render: (row) => <span className="text-xs uppercase">{orDash(row.proto)}</span>,
    },
    {
      // The matched rule's description — the "why" of allow/block.
      header: 'Rule',
      key: 'ruleName',
      width: 240,
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
        <div className="sm:col-span-2">
          <label className="mb-1 block text-xs font-medium text-secondary">Time range</label>
          <select className="w-full rounded-md border border-border px-2.5 py-1.5 text-sm" value={range} onChange={(e) => setRange(e.target.value as TimeRange)}>
            {TIME_RANGES.map((r) => (
              <option key={r.value} value={r.value}>
                {r.label}
              </option>
            ))}
          </select>
        </div>
        <div className="sm:col-span-2">
          <label className="mb-1 block text-xs font-medium text-secondary">Search</label>
          <input
            type="text"
            className="w-full rounded-md border border-border px-2.5 py-1.5 text-sm"
            placeholder="Source/destination IP or rule name…"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </div>
      </div>

      {eventsQuery.isLoading && <p className="text-sm text-muted-foreground">Loading firewall events...</p>}
      {eventsQuery.isError && (
        <p className="text-sm text-danger-fg">Failed to load firewall events: {(eventsQuery.error as Error).message}</p>
      )}
      {eventsQuery.data && (
        <DataTable
          columns={columns}
          rows={eventsQuery.data.rows}
          rowKey={(row) => row.id}
          storageKey="firewall-events"
          autoRefresh={{ intervalMs: 30_000, queries: [eventsQuery] }}
          searchPlaceholder="Search firewall events…"
          emptyMessage="No firewall events in this range yet — assign an OPNsense plugin to a device and wait for the next poll (logging must be enabled on the appliance)."
        />
      )}
    </Layout>
  );
}
