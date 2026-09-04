import { useQuery } from '@tanstack/react-query';
import { Layout } from '../components/Layout';
import { DataTable, DataTableColumn } from '../components/DataTable';
import { DeviceChip } from '../components/DeviceChip';
import { RuleAddressCell } from '../components/FirewallAddressCell';
import { formatBytes } from '../components/formatMetric';
import { api, FirewallRuleRow } from '../api/client';

/** Small colored pill for the rule kind (filter vs. NAT kinds). */
const TYPE_STYLES: Record<FirewallRuleRow['ruleType'], string> = {
  filter: 'bg-slate-200 text-slate-700',
  dnat: 'bg-indigo-100 text-indigo-700',
  snat: 'bg-teal-100 text-teal-700',
  'one-to-one': 'bg-purple-100 text-purple-700',
  npt: 'bg-amber-100 text-amber-800',
};

function TypeBadge({ type }: { type: FirewallRuleRow['ruleType'] }) {
  return (
    <span className={`inline-flex rounded px-1.5 py-0.5 text-xs font-medium uppercase ${TYPE_STYLES[type] ?? 'bg-slate-100 text-slate-600'}`}>
      {type}
    </span>
  );
}

/** Verdict pill — allow green, deny red, NAT/other slate. */
const ACTION_STYLES: Record<FirewallRuleRow['action'], string> = {
  allow: 'bg-emerald-100 text-emerald-700',
  deny: 'bg-red-100 text-red-700',
  other: 'bg-slate-100 text-slate-600',
};

function ActionBadge({ action }: { action: FirewallRuleRow['action'] }) {
  return (
    <span className={`inline-flex rounded px-1.5 py-0.5 text-xs font-medium uppercase ${ACTION_STYLES[action] ?? 'bg-slate-100 text-slate-600'}`}>
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
  v4: 'bg-blue-100 text-blue-700',
  v6: 'bg-violet-100 text-violet-700',
  both: 'bg-slate-200 text-slate-700',
};

function IpBadge({ version }: { version?: string }) {
  const v = (version ?? '').trim().toLowerCase();
  return (
    <span className={`inline-flex rounded px-1.5 py-0.5 text-xs font-medium ${IP_STYLES[v] ?? 'bg-slate-100 text-slate-600'}`}>
      {v || '—'}
    </span>
  );
}

/** Compact live-counter cell: packets + bytes (+ states when reported). */
function StatsCell({ row }: { row: FirewallRuleRow }) {
  const hasPackets = typeof row.packets === 'number';
  const hasBytes = typeof row.bytes === 'number';
  const hasStates = typeof row.states === 'number' && (row.states ?? 0) > 0;
  if (!hasPackets && !hasBytes && !hasStates) return <span className="text-slate-400">—</span>;
  return (
    <div className="flex flex-col text-xs leading-tight">
      {hasPackets && <span className="font-mono text-slate-700" title="packets matched">{row.packets!.toLocaleString()} pkt</span>}
      {hasBytes && <span className="font-mono text-slate-500" title="bytes matched">{formatBytes(row.bytes!)}</span>}
      {hasStates && <span className="text-slate-400" title="active connection states">{row.states!.toLocaleString()} states</span>}
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
      render: (row) => <span className="font-mono text-xs text-slate-500">{row.position + 1}</span>,
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
      render: (row) => <span className="text-xs text-slate-600">{orDash(row.scope)}</span>,
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
          <span className="text-xs font-medium text-emerald-700">yes</span>
        ) : (
          <span className="text-xs font-medium text-slate-400">no</span>
        ),
    },
    {
      header: 'Description',
      key: 'description',
      width: 260,
      render: (row) =>
        row.description && row.description.trim() !== '' ? (
          <span className="text-xs text-slate-700">{row.description}</span>
        ) : (
          <span className="text-slate-400">—</span>
        ),
    },
  ];

  return (
    <Layout title="Firewall">

      {firewallQuery.isLoading && <p className="text-sm text-slate-500">Loading firewall rules...</p>}
      {firewallQuery.isError && (
        <p className="text-sm text-red-600">Failed to load firewall rules: {(firewallQuery.error as Error).message}</p>
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
