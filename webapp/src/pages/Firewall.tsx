import { useEffect, useMemo, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Activity, ListFilter } from 'lucide-react';
import { Layout } from '../components/Layout';
import { DataTable, DataTableColumn } from '../components/DataTable';
import { DeviceChip } from '../components/DeviceChip';
import { PageTabs } from '../components/PageTabs';
import { RuleAddressCell } from '../components/FirewallAddressCell';
import { formatBytes } from '../components/formatMetric';
import { ALL_PAGES, useServerTable } from '../components/useServerTable';
import { api, FirewallRuleRow, FirewallSessionLiveRow, FirewallSessionsPagedResponse } from '../api/client';

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
    <span className={`inline-flex rounded px-1.5 py-0.5 text-xs font-medium uppercase ${ACTION_STYLES[action] ?? ACTION_STYLES.other}`}>
      {action}
    </span>
  );
}

/** "—\" for empty/unknown values (the API stores '' for any/unknown). */
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

/** "42s ago" / "5m ago" relative age from an epoch-ms timestamp. */
function fmtAgo(ms: number): string {
  const s = Math.max(0, Math.floor((Date.now() - ms) / 1000));
  if (s < 60) return `${s}s ago`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 48) return `${h}h ago`;
  return `${Math.floor(h / 24)}d ago`;
}

/** "3d 2h" / "1h 5m" compact duration for the remaining session timeout. */
function fmtTimeoutSec(sec?: number | null): string {
  if (typeof sec !== 'number' || !Number.isFinite(sec) || sec <= 0) return '—';
  const d = Math.floor(sec / 86400);
  const h = Math.floor((sec % 86400) / 3600);
  const m = Math.floor((sec % 3600) / 60);
  if (d > 0) return `${d}d ${h}h`;
  if (h > 0) return `${h}h ${m}m`;
  if (m > 0) return `${m}m`;
  return `${Math.floor(sec)}s`;
}

/** "10.0.0.5:443" with a numeric port (session rows carry ports as numbers). */
function addrPortNum(addr?: string, port?: number | null): string {
  const a = (addr ?? '').trim();
  if (!a) return '—';
  return typeof port === 'number' && port > 0 ? `${a}:${port}` : a;
}

type FwTab = 'rules' | 'sessions';

/**
 * Firewall — rules + live sessions. Two tabs, same design language as the
 * other paginated pages: Rules is the classic client-side table (the API
 * polls plugins every 30 s and upserts rows), Sessions is a SERVER-PAGINATED
 * DataTable fed by GET /firewall-sessions — live state-table rows replicated
 * continuously from every firewall device (OPNsense pf states, RouterOS
 * /ip/firewall/connection) via POST /plugin/firewall-sessions. The API keeps
 * only each device's latest snapshot (replace-on-push), so the table always
 * shows current sessions across all firewalls; "Collected" shows how fresh
 * each device's snapshot is. Gated by `firewall:read`.
 */
export default function Firewall() {
  const [tab, setTab] = useState<FwTab>('rules');

  // --- Rules tab (client-side table over the polled inventory) -------------
  // '' = all firewalls; otherwise the selected device's id.
  const [deviceFilter, setDeviceFilter] = useState('');

  // The API polls plugins every 30s and upserts these rows — refresh at the
  // same cadence so the view tracks live inventory.
  const firewallQuery = useQuery({
    queryKey: ['firewallRules'],
    queryFn: () => api.firewallRules(),
    refetchInterval: 30_000,
  });

  // Options for the device filter — only devices that actually carry collected
  // rules (derived from the same payload, so no extra request). Filtering is
  // client-side: the page already fetches every row each cycle.
  const ruleDevices = useMemo(() => {
    const names = new Map<string, string>();
    for (const r of firewallQuery.data ?? []) if (r.deviceName) names.set(r.deviceId, r.deviceName);
    return [...names.entries()].sort((a, b) => a[1].localeCompare(b[1]));
  }, [firewallQuery.data]);

  const visibleRows = useMemo(
    () => (deviceFilter ? (firewallQuery.data ?? []).filter((r) => r.deviceId === deviceFilter) : firewallQuery.data),
    [firewallQuery.data, deviceFilter]
  );

  // --- Sessions tab (server-paginated live rows) ---------------------------
  const [sessionDevice, setSessionDevice] = useState('');
  const [sessionSearchDraft, setSessionSearchDraft] = useState('');

  // Options for the sessions device filter (all devices — only firewalls have rows).
  const allDevicesQuery = useQuery({ queryKey: ['devices'], queryFn: api.devices });
  const sessionDevices = useMemo(
    () => (allDevicesQuery.data ?? []).slice().sort((a, b) => a.name.localeCompare(b.name)),
    [allDevicesQuery.data]
  );

  const extra = useMemo(() => ({ sessionDevice }), [sessionDevice]);
  const sessionsTable = useServerTable<{ sessionDevice: string }, FirewallSessionLiveRow, FirewallSessionsPagedResponse>({
    fetcher: async (p) => {
      const res = await api.firewallSessionsPaged({
        deviceId: p.sessionDevice || undefined,
        search: p.q,
        page: p.pageSize === ALL_PAGES ? undefined : p.page,
        pageSize: p.pageSize === ALL_PAGES ? undefined : p.pageSize,
        all: p.pageSize === ALL_PAGES || undefined,
        sort: p.sort?.key as 'collectedAtMs' | 'srcIp' | 'dstIp' | 'state' | undefined,
        dir: p.sort?.dir,
      });
      return { ...res, total: res.total ?? 0 };
    },
    extra,
    storageKey: 'firewall-sessions',
  });

  // Debounce the filter-bar search into the committed server query (300 ms).
  useEffect(() => {
    const t = setTimeout(() => sessionsTable.setQ(sessionSearchDraft.trim()), 300);
    return () => clearTimeout(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [sessionSearchDraft]);

  const ruleColumns: DataTableColumn<FirewallRuleRow>[] = [
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
    {      // Hit counter — packets matched by this rule since the counters were last
      // reset (OPNsense pf rule_stats keyed by rule uuid; RouterOS inline).
      // Zero = never used → a cleanup candidate for firewall optimization, so it
      // gets an explicit warning highlight. '—' when the vendor exposes no
      // per-rule counter (NAT rules). Sortable: unreported rows sort last.
      header: 'Hits',
      key: 'hits',
      width: 90,
      sortAccessor: (row) => row.packets ?? -1,
      exportValue: (row) => row.packets ?? '',
      render: (row) => {
        if (typeof row.packets !== 'number') return <span className="text-faint">—</span>;
        return row.packets === 0 ? (
          <span
            title="Never matched since counters were last reset — candidate for removal"
            className="rounded bg-warning/20 px-1.5 py-0.5 font-mono text-xs font-semibold text-warning-fg"
          >
            0
          </span>
        ) : (
          <span className="font-mono text-secondary">{row.packets.toLocaleString()}</span>
        );
      },
    },
    {      // Live hit counters — both vendors report them now (OPNsense pf rule_stats
      // is keyed by the rule's own uuid; RouterOS carries packets/bytes inline).
      // NAT rules have no per-rule stats endpoint, so they show '—'.
      header: 'Stats',
      key: 'packets',
      width: 130,
      sortAccessor: (row) => row.packets ?? -1,
      render: (row) => <StatsCell row={row} />,
    },
    {
      // Disabled rules are dimmed row-wide instead of hidden — they still
      // matter; the pill in this cell names why a row is dimmed.
      header: 'Description',
      key: 'description',
      width: 260,
      render: (row) => (
        <span className="flex items-center gap-1.5">
          {!row.enabled && (
            <span
              title="Rule is disabled on the device — it never matches traffic"
              className="shrink-0 rounded-full bg-muted px-1.5 py-px text-[9px] font-semibold uppercase tracking-wide text-secondary"
            >
              disabled
            </span>
          )}
          {row.description && row.description.trim() !== '' ? (
            <span className="text-xs text-secondary">{row.description}</span>
          ) : row.enabled ? (
            <span className="text-faint">—</span>
          ) : null}
        </span>
      ),
    },
  ];

  const sessionColumns: DataTableColumn<FirewallSessionLiveRow>[] = [
    {
      header: 'Device',
      key: 'deviceName',
      width: 200,
      sortable: false, // the device filter select owns this axis
      exportValue: (row) => row.deviceName ?? '',
      render: (row) => (
        <DeviceChip deviceName={row.deviceName} managementAddress={null} pluginName={row.pluginName} siteName={row.siteName} interfaces={[]} />
      ),
    },
    {
      header: 'Source',
      key: 'srcIp',
      width: 190,
      exportValue: (row) => addrPortNum(row.srcIp, row.srcPort),
      render: (row) => <span className="font-mono text-xs">{addrPortNum(row.srcIp, row.srcPort)}</span>,
    },
    {
      header: 'Destination',
      key: 'dstIp',
      width: 190,
      exportValue: (row) => addrPortNum(row.dstIp, row.dstPort),
      render: (row) => <span className="font-mono text-xs">{addrPortNum(row.dstIp, row.dstPort)}</span>,
    },
    {
      header: 'Proto',
      key: 'proto',
      width: 70,
      sortable: false,
      render: (row) => <span className="text-xs uppercase">{orDash(row.proto)}</span>,
    },
    {
      // Connection state — pf (ESTABLISHED, SYN_SENT…) or RouterOS (established, time-wait…).
      header: 'State',
      key: 'state',
      width: 140,
      render: (row) => <span className="font-mono text-xs text-secondary">{orDash(row.state)}</span>,
    },
    {
      // Remaining connection timeout — OPNsense pf reports it; RouterOS does not.
      header: 'Timeout',
      key: 'timeoutSec',
      width: 90,
      sortable: false,
      render: (row) => <span className="font-mono text-xs text-muted-foreground">{fmtTimeoutSec(row.timeoutSec)}</span>,
    },
    {
      // OPNsense interface name; RouterOS connection direction (in/out).
      header: 'Iface',
      key: 'iface',
      width: 90,
      sortable: false,
      render: (row) => <span className="font-mono text-xs">{orDash(row.iface)}</span>,
    },
    {
      // Freshness — the API stamps collectedAtMs at ingest, one value per whole
      // push. Stale = that device's walk hasn't run recently (slow cadence or
      // the appliance is unreachable).
      header: 'Collected',
      key: 'collectedAtMs',
      width: 110,
      render: (row) => {
        const staleSec = Date.now() - row.collectedAtMs;
        return (
          <span className={`font-mono text-xs ${staleSec > 3_600_000 ? 'text-warning-fg' : 'text-muted-foreground'}`}>
            {fmtAgo(row.collectedAtMs)}
          </span>
        );
      },
    },
  ];

  return (
    <Layout title="Firewall">
      <PageTabs
        tabs={[
          { id: 'rules', label: 'Rules', icon: <ListFilter className="h-3.5 w-3.5" />, count: firewallQuery.data?.length ?? null, loading: firewallQuery.isLoading },
          { id: 'sessions', label: 'Sessions', icon: <Activity className="h-3.5 w-3.5" />, count: sessionsTable.data?.total ?? null, loading: sessionsTable.isFetching },
        ]}
        value={tab}
        onChange={setTab}
      />

      {tab === 'rules' && (
        <>
          {/* Device filter — narrow the rule table to one firewall (device). */}
          {firewallQuery.data && ruleDevices.length > 0 && (
            <div className="mb-3 flex items-center gap-2">
              <label htmlFor="fw-device-filter" className="text-xs font-medium text-secondary">Firewall</label>
              <select
                id="fw-device-filter"
                value={deviceFilter}
                onChange={(e) => setDeviceFilter(e.target.value)}
                className="w-64 rounded-md border border-border bg-background px-2 py-1.5 text-sm"
              >
                <option value="">All firewalls ({ruleDevices.length})</option>
                {ruleDevices.map(([id, name]) => (
                  <option key={id} value={id}>
                    {name}
                  </option>
                ))}
              </select>
            </div>
          )}

          {firewallQuery.isLoading && <p className="text-sm text-muted-foreground">Loading firewall rules...</p>}
          {firewallQuery.isError && (
            <p className="text-sm text-danger-fg">Failed to load firewall rules: {(firewallQuery.error as Error).message}</p>
          )}
          {firewallQuery.data && (
            <DataTable
              columns={ruleColumns}
              rows={visibleRows ?? []}
              rowKey={(row) => `${row.deviceId}|${row.pluginId}|${row.ruleType}|${row.vendorRuleId}`}
              // Disabled rules are dimmed instead of hidden — they still matter.
              rowClassName={(row) => (row.enabled ? undefined : 'opacity-50')}
              storageKey="firewall-rules"
              autoRefresh={{ intervalMs: 30_000, queries: [firewallQuery] }}
              searchPlaceholder="Search firewall rules…"
              emptyMessage="No firewall rules collected yet — assign an OPNsense or RouterOS plugin to a device and wait for the next poll."
            />
          )}
        </>
      )}

      {tab === 'sessions' && (
        <>
          {/* Filter bar — device + search (debounced into the server query). */}
          <div className="mb-4 grid grid-cols-1 gap-3 rounded-md border border-border bg-card p-3 shadow-sm sm:grid-cols-2">
            <div>
              <label className="mb-1 block text-xs font-medium text-secondary">Device</label>
              <select className="w-full rounded-md border border-border px-2.5 py-1.5 text-sm" value={sessionDevice} onChange={(e) => setSessionDevice(e.target.value)}>
                <option value="">All devices</option>
                {sessionDevices.map((d) => (
                  <option key={d.id} value={d.id}>
                    {d.name}
                  </option>
                ))}
              </select>
            </div>
            <div>
              <label className="mb-1 block text-xs font-medium text-secondary">Search</label>
              <input
                type="text"
                className="w-full rounded-md border border-border px-2.5 py-1.5 text-sm"
                placeholder="Source/destination IP, state or protocol…"
                value={sessionSearchDraft}
                onChange={(e) => setSessionSearchDraft(e.target.value)}
              />
            </div>
          </div>

          {sessionsTable.isError && (
            <p className="text-sm text-danger-fg">Failed to load firewall sessions: {sessionsTable.error?.message}</p>
          )}
          <DataTable
            columns={sessionColumns}
            rows={sessionsTable.data?.rows ?? []}
            rowKey={(row) => row.id}
            storageKey="firewall-sessions"
            isFetching={sessionsTable.isFetching}
            showSearch={false} // the filter bar above owns search (debounced into table.q)
            onSearch={sessionsTable.setQ}
            externalSearch={sessionsTable.q || null}
            serverPagination={{
              total: sessionsTable.data?.total ?? 0,
              page: sessionsTable.page,
              pageSize: sessionsTable.pageSize,
              onPageChange: sessionsTable.setPage,
              onPageSizeChange: sessionsTable.setPageSize,
              // Default sort is newest snapshot first (collectedAtMs desc).
              sort: sessionsTable.sort,
              onSortChange: sessionsTable.setSort,
            }}
            autoRefresh={{ intervalMs: 30_000, queries: [sessionsTable] }}
            emptyMessage="No live sessions replicated yet — assign an OPNsense or RouterOS plugin to a firewall device and wait for its first state-table walk (OPNsense: up to 15 min, RouterOS: ~5 min)."
          />
        </>
      )}
    </Layout>
  );
}
