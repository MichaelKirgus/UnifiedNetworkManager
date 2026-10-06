import { useQuery } from '@tanstack/react-query';
import { Layout } from '../components/Layout';
import { DataTable, DataTableColumn } from '../components/DataTable';
import { DeviceChip } from '../components/DeviceChip';
import { RuleAddressCell } from '../components/FirewallAddressCell';
import { formatBytes } from '../components/formatMetric';
import { api, FirewallRuleRow, FirewallSessionRow } from '../api/client';

/** "1h 23m" / "45s" style compact duration for session ages. */
function fmtDurationSec(sec: number): string {
  if (!Number.isFinite(sec) || sec < 0) return '—';
  const h = Math.floor(sec / 3600);
  const m = Math.floor((sec % 3600) / 60);
  const s = Math.floor(sec % 60);
  if (h > 0) return `${h}h ${m}m`;
  if (m > 0) return `${m}m ${s}s`;
  return `${s}s`;
}

/**
 * Live connection-state overview — one card per device reporting session data.
 * Reads the latest telemetry snapshot server-side (GET /firewall-sessions), so
 * this section tracks the same poll cadence as the rest of the page.
 */
function SessionsSection() {
  const sessionsQuery = useQuery({
    queryKey: ['firewall-sessions'],
    queryFn: () => api.firewallSessions(),
    refetchInterval: 30_000,
  });

  if (sessionsQuery.isLoading) return null; // don't flash an empty card while the rules table loads too
  const devices = sessionsQuery.data?.devices ?? [];
  if (devices.length === 0) return null; // no firewall-capable device reporting yet — section stays hidden

  return (
    <div className="mb-4 rounded-md border border-border bg-card p-3 shadow-sm">
      <h2 className="mb-2 text-sm font-semibold text-foreground">Sessions</h2>
      <div className="grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-3">
        {devices.map((d) => (
          <SessionCard key={d.deviceId} row={d} />
        ))}
      </div>
    </div>
  );
}

function SessionCard({ row }: { row: FirewallSessionRow }) {
  const pct = typeof row.stateLimit === 'number' && row.stateLimit > 0 ? (row.totalSessions / row.stateLimit) * 100 : null;
  return (
    <div className="rounded-md border border-border bg-muted/30 p-3">
      <div className="mb-2 flex items-center justify-between gap-2">
        <span className="truncate text-sm font-medium">{row.deviceName ?? row.deviceId}</span>
        {pct !== null && (
          <span
            className={`shrink-0 rounded px-1.5 py-0.5 text-xs font-mono ${
              pct >= 90 ? 'bg-danger/20 text-danger-fg' : pct >= 70 ? 'bg-warning/20 text-warning-fg' : 'bg-muted text-secondary'
            }`}
          >
            {pct.toFixed(1)}% of limit
          </span>
        )}
      </div>
      <dl className="grid grid-cols-2 gap-x-3 gap-y-1 text-xs">
        <dt className="text-muted-foreground">Active sessions</dt>
        <dd className="text-right font-mono">{row.totalSessions.toLocaleString()}{typeof row.stateLimit === 'number' ? ` / ${row.stateLimit.toLocaleString()}` : ''}</dd>
        <dt className="text-muted-foreground">Oldest session</dt>
        <dd className="text-right font-mono">{row.oldestAgeSec !== null && row.oldestAgeSec !== undefined ? fmtDurationSec(row.oldestAgeSec) : '—'}</dd>
        <dt className="text-muted-foreground">Adaptive timeouts</dt>
        <dd className={`text-right font-medium ${row.adaptiveEnabled === true ? 'text-success-fg' : row.adaptiveEnabled === false ? 'text-warning-fg' : 'text-faint'}`}>
          {row.adaptiveEnabled === null ? '—' : row.adaptiveEnabled ? `on (≥ ${(row.adaptiveStartStates ?? 0).toLocaleString()} states)` : 'off'}
        </dd>
        <dt className="text-muted-foreground">State table</dt>
        <dd className="text-right font-mono text-faint" title="state-table lookups per second (latest inventory cycle)">
          {row.stateTableSearchesRate !== null && row.stateTableSearchesRate !== undefined
            ? `${(row.stateTableSearchesRate ?? 0).toFixed(1)}/s`
            : '—'}
        </dd>
      </dl>
    </div>
  );
}

/** Small colored pill for the rule kind (filter vs. NAT kinds). */
const TYPE_STYLES: Record<FirewallRuleRow['ruleType'], string> = {
  filter: 'bg-muted text-secondary',
  dnat: 'bg-accent-indigo text-accent-indigo-fg',
  snat: 'bg-accent-teal text-accent-teal-fg',
  'one-to-one': 'bg-accent-purple text-accent-purple-fg',
  npt: 'bg-warning text-warning-fg',
};

function TypeBadge({ type }: { type: FirewallRuleRow['ruleType'] }) {
  return (
    <span className={`inline-flex rounded px-1.5 py-0.5 text-xs font-medium uppercase ${TYPE_STYLES[type] ?? 'bg-muted text-secondary'}`}>
      {type}
    </span>
  );
}

/** Verdict pill — allow green, deny red, NAT/other slate. */
const ACTION_STYLES: Record<FirewallRuleRow['action'], string> = {
  allow: 'bg-success text-success-fg',
  deny: 'bg-danger text-danger-fg',
  other: 'bg-muted text-secondary',
};

function ActionBadge({ action }: { action: FirewallRuleRow['action'] }) {
  return (
    <span className={`inline-flex rounded px-1.5 py-0.5 text-xs font-medium uppercase ${ACTION_STYLES[action] ?? 'bg-muted text-secondary'}`}>
      {action}
    </span>
  );
}

/** "—" for empty/unknown values (the API stores '' for any/unknown). */
function orDash(v?: string | null): string {
  return v && v.trim() !== '' ? v : '—';
}

/** IP-family pill — v4 blue, v6 violet, both slate. */
const IP_STYLES: Record<string, string> = {
  v4: 'bg-info text-info-fg',
  v6: 'bg-accent-violet text-accent-violet-fg',
  both: 'bg-muted text-secondary',
};

function IpBadge({ version }: { version?: string }) {
  const v = (version ?? '').trim().toLowerCase();
  return (
    <span className={`inline-flex rounded px-1.5 py-0.5 text-xs font-medium ${IP_STYLES[v] ?? 'bg-muted text-secondary'}`}>
      {v || '—'}
    </span>
  );
}

/** Compact live-counter cell: packets + bytes (+ states when reported). */
function StatsCell({ row }: { row: FirewallRuleRow }) {
  const hasPackets = typeof row.packets === 'number';
  const hasBytes = typeof row.bytes === 'number';
  const hasStates = typeof row.states === 'number' && (row.states ?? 0) > 0;
  if (!hasPackets && !hasBytes && !hasStates) return <span className="text-faint">—</span>;
  return (
    <div className="flex flex-col text-xs leading-tight">
      {hasPackets && <span className="font-mono text-secondary" title="packets matched">{row.packets!.toLocaleString()} pkt</span>}
      {hasBytes && <span className="font-mono text-muted-foreground" title="bytes matched">{formatBytes(row.bytes!)}</span>}
      {hasStates && <span className="text-faint" title="active connection states">{row.states!.toLocaleString()} states</span>}
    </div>
  );
}

/** Combines an address with its port(s) for compact display ("10.0.0.5:443"). */
function addrPort(addr?: string, port?: string | null): string {
  const a = (addr ?? '').trim();
  const p = (port ?? '').trim();
  if (!a && !p) return '—';
  if (!a) return p;
  if (!p) return a;
  return `${a}:${p}`;
}

export default function Firewall() {
  // The API polls plugins every 30s and upserts these rows — refresh at the
  // same cadence so the view tracks live inventory.
  const firewallQuery = useQuery({
    queryKey: ['firewall-rules'],
    queryFn: () => api.firewallRules(),
    refetchInterval: 30_000,
  });

  const columns: DataTableColumn<FirewallRuleRow>[] = [
    {
      header: 'Device',
      key: 'deviceName',
      width: 240,
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
      header: 'Type',
      key: 'ruleType',
      width: 110,
      render: (row) => <TypeBadge type={row.ruleType} />,
    },
    {
      // Order within the rule set on the device — shown as 1-based for humans.
      header: '#',
      key: 'position',
      width: 60,
      sortAccessor: (row) => row.position,
      render: (row) => <span className="font-mono text-xs text-muted-foreground">{row.position + 1}</span>,
    },
    {
      // IP family the rule applies to — v4 / v6 / both.
      header: 'IP',
      key: 'ipVersion',
      width: 70,
      render: (row) => <IpBadge version={row.ipVersion} />,
    },
    {
      header: 'Protocol',
      key: 'protocol',
      width: 90,
      render: (row) => <span className="text-xs uppercase">{orDash(row.protocol)}</span>,
    },
    {
      // Resolved against the cross-device inventory — subnet chips + host count.
      header: 'Source',
      key: 'sourceIp',
      width: 230,
      exportValue: (row) => addrPort(row.sourceIp, row.sourcePort),
      render: (row) => <RuleAddressCell row={row} side="source" />,
    },
    {
      // Resolved against the cross-device inventory — subnet chips + host count.
      header: 'Destination',
      key: 'destIp',
      width: 230,
      exportValue: (row) => addrPort(row.destIp, row.destPort),
      render: (row) => <RuleAddressCell row={row} side="dest" />,
    },
    {
      header: 'Action',
      key: 'action',
      width: 100,
      render: (row) => <ActionBadge action={row.action} />,
    },
    {
      // Where the rule applies — OPNsense interface, RouterOS chain + iface lists.
      header: 'Scope',
      key: 'scope',
      width: 160,
      render: (row) => <span className="text-xs text-secondary">{orDash(row.scope)}</span>,
    },
    {
      // Live hit counters — both vendors report them now (OPNsense pf rule_stats
      // is keyed by the rule's own uuid; RouterOS carries packets/bytes inline).
      // NAT rules have no per-rule stats endpoint, so they show '—'.
      header: 'Stats',
      key: 'packets',
      width: 130,
      sortAccessor: (row) => row.packets ?? -1,
      render: (row) => <StatsCell row={row} />,
    },
    {
      // Disabled rules are dimmed instead of hidden — they still matter.
      header: 'Enabled',
      key: 'enabled',
      width: 90,
      render: (row) =>
        row.enabled ? (
          <span className="text-xs font-medium text-success-fg">yes</span>
        ) : (
          <span className="text-xs font-medium text-faint">no</span>
        ),
    },
    {
      header: 'Description',
      key: 'description',
      width: 260,
      render: (row) =>
        row.description && row.description.trim() !== '' ? (
          <span className="text-xs text-secondary">{row.description}</span>
        ) : (
          <span className="text-faint">—</span>
        ),
    },
  ];

  return (
    <Layout title="Firewall">

      {/* Live connection-state overview — hidden until a device reports session data. */}
      <SessionsSection />

      {firewallQuery.isLoading && <p className="text-sm text-muted-foreground">Loading firewall rules...</p>}
      {firewallQuery.isError && (
        <p className="text-sm text-danger-fg">Failed to load firewall rules: {(firewallQuery.error as Error).message}</p>
      )}
      {firewallQuery.data && (
        <DataTable
          columns={columns}
          rows={firewallQuery.data}
          rowKey={(row) => `${row.deviceId}|${row.pluginId}|${row.ruleType}|${row.vendorRuleId}`}
          storageKey="firewall-rules"
          autoRefresh={{ intervalMs: 30_000, queries: [firewallQuery] }}
          searchPlaceholder="Search firewall rules…"
          emptyMessage="No firewall rules collected yet — assign an OPNsense or RouterOS plugin to a device and wait for the next poll."
        />
      )}
    </Layout>
  );
}
