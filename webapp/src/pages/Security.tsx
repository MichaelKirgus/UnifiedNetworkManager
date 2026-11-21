import { useQuery, useQueryClient } from '@tanstack/react-query';
import { Bug, Loader2, RefreshCw, Radar, ShieldCheck, ShieldAlert, ShieldX, Info, Trash2 } from 'lucide-react';
import { Link } from 'react-router-dom';
import { useMemo, useState } from 'react';
import clsx from 'clsx';
import { Layout } from '../components/Layout';
import { DataTable, DataTableColumn } from '../components/DataTable';
import { ALL_PAGES, useServerTable } from '../components/useServerTable';
import { DeviceChip } from '../components/DeviceChip';
import { PageTabs } from '../components/PageTabs';
import { api, SecurityCheckRow, CvePackageRow, CveVulnerabilityRow, ThreatIntelSource } from '../api/client';

/** Check-kind pill — the vocabulary is shared across all plugins (SDK contract). */
const KIND_STYLES: Record<string, string> = {
  'auth-failures': 'bg-accent-indigo text-accent-indigo-fg',
  'file-integrity': 'bg-accent-violet text-accent-violet-fg',
  'rate-limiting': 'bg-accent-teal text-accent-teal-fg',
  account: 'bg-accent-sky text-accent-sky-fg',
  'service-exposure': 'bg-warning text-warning-fg',
  // Custom kinds emitted by specific plugins (the SDK allows arbitrary strings).
  'wifi-encryption': 'bg-accent-purple text-accent-purple-fg',
  'vpn-crypto': 'bg-accent-cyan text-accent-cyan-fg',
  'email-auth': 'bg-accent-sky text-accent-sky-fg',
  other: 'bg-muted text-secondary',
};

const KIND_LABELS: Record<string, string> = {
  'auth-failures': 'failed logins',
  'file-integrity': 'file integrity',
  'rate-limiting': 'rate limiting',
  account: 'accounts',
  'service-exposure': 'exposure',
  // Custom kinds emitted by specific plugins (the SDK allows arbitrary strings).
  'wifi-encryption': 'wifi encryption',
  'vpn-crypto': 'vpn crypto',
  'email-auth': 'email auth',
  other: 'other',
};

function KindBadge({ kind }: { kind: string }) {
  return (
    <span className={`inline-flex rounded px-1.5 py-0.5 text-xs font-medium ${KIND_STYLES[kind] ?? 'bg-muted text-secondary'}`}>
      {KIND_LABELS[kind] ?? kind}
    </span>
  );
}

/** Verdict pill — 'ok' rows are dropped at ingest; info/warning/critical persist. */
function StatusBadge({ status }: { status: string }) {
  if (status === 'critical') {
    return (
      <span className="inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-xs font-medium bg-danger text-danger-fg">
        <ShieldX className="h-3 w-3" /> critical
      </span>
    );
  }
  if (status === 'warning') {
    return (
      <span className="inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-xs font-medium bg-warning text-warning-fg">
        <ShieldAlert className="h-3 w-3" /> warning
      </span>
    );
  }
  return (
    <span className="inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-xs font-medium bg-info text-info-fg">
      <Info className="h-3 w-3" /> info
    </span>
  );
}

/** "—" for empty/unknown values. */
function orDash(v?: string | null): string {
  return v && v.trim() !== '' ? v : '—';
}

/** Relative age of the last observation ("2m ago") — findings refresh on each inventory poll. */
function timeAgo(iso: string): string {
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return '—';
  const s = Math.max(0, Math.round((Date.now() - t) / 1000));
  if (s < 60) return `${s}s ago`;
  const m = Math.round(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.round(m / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.round(h / 24)}d ago`;
}

/** Severity-rank pill for CVE rows — same color language as the status badges. */
const RANK_STYLES: Record<string, string> = {
  critical: 'bg-danger text-danger-fg',
  high: 'bg-warning text-warning-fg',
  medium: 'bg-info text-info-fg',
  low: 'bg-muted text-secondary',
  unknown: 'bg-muted text-faint',
};

function RankBadge({ rank, score }: { rank: string; score?: number | null }) {
  return (
    <span className={`inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-xs font-medium ${RANK_STYLES[rank] ?? 'bg-muted text-secondary'}`} title={typeof score === 'number' ? `CVSS score ${score.toFixed(1)}` : undefined}>
      {rank}
      {typeof score === 'number' && <span className="font-mono opacity-80">{score.toFixed(1)}</span>}
    </span>
  );
}

export default function Security() {
  // The API polls plugins every 30s and upserts findings on inventory-due polls —
  // refresh at the same cadence so the view tracks live checks.
  const securityQuery = useQuery({
    queryKey: ['securityChecks'],
    queryFn: () => api.securityChecks(),
    refetchInterval: 30_000,
  });

  const rows = securityQuery.data?.rows ?? [];
  const criticalCount = rows.filter((r) => r.status === 'critical').length;
  const warningCount = rows.filter((r) => r.status === 'warning').length;
  const infoCount = rows.length - criticalCount - warningCount;

  // --- CVE vulnerability tracking (installed packages × known advisories) ------
  const queryClient = useQueryClient();
  const cveSummaryQuery = useQuery({
    queryKey: ['cveSummary'],
    queryFn: () => api.cveSummary(),
    refetchInterval: 30_000,
  });

  // --- CVE list state (Phase 2 — server-side pagination + smart default view) --
  // The raw CVE table has tens of thousands of rows on a real fleet, so the API
  // paginates and this page defaults to the GROUPED packages view (one row per
  // vulnerable package instance). Every filter is SERVER-SIDE — the DOM never
  // holds more than one page of rows. Page/pageSize/search/sort live in the
  // useServerTable hooks below; this page only owns the SHARED filters.
  type CveSeverity = 'critical' | 'high' | 'medium' | 'low' | 'unknown';
  const [cveView, setCveView] = useState<'packages' | 'vulns'>('packages');
  const [cveSeverity, setCveSeverity] = useState<CveSeverity | ''>('');
  const [cveComponent, setCveComponent] = useState<'all' | 'host' | 'container'>('all');

  // Shared filters — a STABLE object (the hooks use its JSON as change key).
  const cveExtra = useMemo(
    () => ({
      severityRank: (cveSeverity || undefined) as CveSeverity | undefined,
      component: (cveComponent === 'all' ? undefined : cveComponent) as 'host' | 'container' | undefined,
    }),
    [cveSeverity, cveComponent]
  );

  // Column key → API sort field per view (DataTable passes column keys).
  const PKG_SORT_MAP: Record<string, string> = { component: 'componentName', packageName: 'packageName', ecosystem: 'ecosystem', cveCount: 'cveCount', worstRank: 'worstRank' };
  const VULN_SORT_MAP: Record<string, string> = { component: 'componentName', packageName: 'packageName', cveId: 'cveId', severityRank: 'severityRank', ecosystem: 'ecosystem' };

  const pkgTable = useServerTable({
    // pageSize === ALL_PAGES → unpaginated `all=true`; column filters map COLUMN KEY → API param.
    fetcher: (p) => {
      const { filters, ...rest } = p;
      return api.cvePackages({ ...rest, ecosystem: filters?.ecosystem || undefined, all: p.pageSize === ALL_PAGES ? true : undefined, sort: p.sort ? PKG_SORT_MAP[p.sort.key] : undefined, dir: p.sort?.dir });
    },
    extra: cveExtra,
    storageKey: 'security-cves-packages',
  });
  const vulnTable = useServerTable({
    // pageSize === ALL_PAGES → unpaginated `all=true`; column filters map COLUMN KEY → API param.
    fetcher: (p) => {
      const { filters, ...rest } = p;
      return api.cveVulnerabilities({ ...rest, ecosystem: filters?.ecosystem || undefined, all: p.pageSize === ALL_PAGES ? true : undefined, sort: p.sort ? VULN_SORT_MAP[p.sort.key] : undefined, dir: p.sort?.dir });
    },
    extra: cveExtra,
    storageKey: 'security-cves',
  });

  function toggleCveSeverity(rank: CveSeverity) {
    setCveSeverity((prev) => (prev === rank ? '' : rank)); // hooks reset to page 1 on filter change
  }

  // Drill-down: a grouped package row → the raw CVE list pre-filtered to that package.
  function drillIntoPackage(row: CvePackageRow) {
    setCveView('vulns');
    vulnTable.setQ(row.packageName); // externalSearch syncs the box on view switch
  }

  // "Refresh advisories" runs one full fetch cycle server-side (~3.5 min) — fire
  // and forget; the summary's lastSuccessAt/lastError surface the outcome.
  const [refreshingCves, setRefreshingCves] = useState(false);
  async function refreshAdvisories() {
    if (refreshingCves) return;
    setRefreshingCves(true);
    try {
      await api.refreshCveAdvisories();
      void queryClient.invalidateQueries({ queryKey: ['cveSummary'] });
      // Both CVE tables share the 'serverTable' key prefix.
      void queryClient.invalidateQueries({ queryKey: ['serverTable'] });
    } catch (err) {
      // The cycle itself never throws — a 502 here means the fetch FAILED and
      // its error is already in lastError. Still surface it as a notice.
      void queryClient.invalidateQueries({ queryKey: ['cveSummary'] });
      console.warn('CVE advisory refresh reported an error:', (err as Error).message);
    } finally {
      setRefreshingCves(false);
    }
  }

  const summary = cveSummaryQuery.data;

  // Findings | Vulnerabilities (CVEs) | Threat Intel — each section is a
  // self-contained tab so the page reads top-down instead of one long scroll.
  const [tab, setTab] = useState<'findings' | 'vulnerabilities' | 'threat-intel'>('findings');

  const columns: DataTableColumn<SecurityCheckRow>[] = [
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
      header: 'Check',
      key: 'name',
      width: 200,
      exportValue: (row) => row.name,
      render: (row) => <span className="font-mono text-xs">{orDash(row.name)}</span>,
    },
    {
      header: 'Kind',
      key: 'kind',
      width: 130,
      exportValue: (row) => row.kind,
      render: (row) => <KindBadge kind={row.kind} />,
    },
    {
      header: 'Status',
      key: 'status',
      width: 110,
      sortAccessor: (row) => ({ critical: 0, warning: 1, info: 2 }[row.status] ?? 3),
      render: (row) => <StatusBadge status={row.status} />,
    },
    {
      header: 'Finding',
      key: 'detail',
      width: 420,
      exportValue: (row) => row.detail ?? '',
      render: (row) =>
        row.detail && row.detail.trim() !== '' ? (
          <span className="text-xs text-secondary break-words">{row.detail}</span>
        ) : (
          <span className="text-faint">—</span>
        ),
    },
    {
      header: 'Count',
      key: 'count',
      width: 90,
      sortAccessor: (row) => row.count ?? -1,
      render: (row) =>
        typeof row.count === 'number' ? (
          <span className="font-mono text-xs">{row.count.toLocaleString()}</span>
        ) : (
          <span className="text-faint">—</span>
        ),
    },
    {
      header: 'Observed',
      key: 'collectedAt',
      width: 110,
      sortAccessor: (row) => Date.parse(row.collectedAt),
      render: (row) => <span className="text-xs text-faint">{timeAgo(row.collectedAt)}</span>,
    },
  ];

  const cveColumns: DataTableColumn<CveVulnerabilityRow>[] = [
    {
      // Not sortable server-side (would need a join to devices) — the API's
      // allowlist decides what headers can sort in server-pagination mode.
      header: 'Device',
      key: 'deviceName',
      width: 240,
      sortable: false,
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
      header: 'Component',
      key: 'component',
      width: 190,
      sortAccessor: (row) => `${row.component ?? 'host'}|${row.componentName ?? ''}`,
      exportValue: (row) => (row.component === 'container' ? `container:${row.componentName ?? '?'}` : 'host'),
      render: (row) =>
        row.component === 'container' ? (
          <span className="inline-flex items-center gap-1 rounded-md bg-info/15 px-2 py-0.5 text-xs font-medium text-info-fg" title={`Software inside container ${row.componentName ?? ''}`}>
            container · {row.componentName}
          </span>
        ) : (
          <span className="text-xs text-secondary">host</span>
        ),
    },
    {
      header: 'Package',
      key: 'packageName',
      width: 240,
      exportValue: (row) => row.packageName,
      render: (row) => (
        <span className="font-mono text-xs">
          {row.packageName}
          {row.installedVersion ? (
            <span className="text-faint"> @ {row.installedVersion}</span>
          ) : null}
        </span>
      ),
    },
    {
      header: 'CVE',
      key: 'cveId',
      width: 160,
      exportValue: (row) => row.cveId,
      render: (row) =>
        row.url ? (
          <a href={row.url} target="_blank" rel="noreferrer" title={`Open ${row.cveId} details`} className="font-mono text-xs text-info hover:underline">
            {row.cveId}
          </a>
        ) : (
          <span className="font-mono text-xs">{row.cveId}</span>
        ),
    },
    {
      header: 'Severity',
      key: 'severityRank',
      width: 130,
      sortAccessor: (row) => ({ critical: 0, high: 1, medium: 2, low: 3, unknown: 4 }[row.severityRank] ?? 5),
      render: (row) => <RankBadge rank={row.severityRank} score={row.severityScore} />,
    },
    {
      // serverFilter: the API already has an `ecosystem` param — the fetcher maps this key to it.
      header: 'Ecosystem',
      key: 'ecosystem',
      width: 120,
      serverFilter: true,
      exportValue: (row) => row.ecosystem,
      render: (row) => <span className="text-xs text-secondary">{orDash(row.ecosystem)}</span>,
    },
    {
      header: 'Summary',
      key: 'summary',
      width: 420,
      sortable: false, // free text — not a server sort field
      exportValue: (row) => row.summary ?? '',
      render: (row) =>
        row.summary && row.summary.trim() !== '' ? (
          <span className="text-xs text-secondary break-words">{row.summary}</span>
        ) : (
          <span className="text-faint">—</span>
        ),
    },
  ];

  // Grouped "smart default" view — one row per vulnerable package instance.
  const cvePackageColumns: DataTableColumn<CvePackageRow>[] = [
    {
      // Not sortable server-side (would need a join to devices).
      header: 'Device',
      key: 'deviceName',
      width: 240,
      sortable: false,
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
      header: 'Component',
      key: 'component',
      width: 190,
      exportValue: (row) => (row.component === 'container' ? `container:${row.componentName ?? '?'}` : 'host'),
      render: (row) =>
        row.component === 'container' ? (
          <span className="inline-flex items-center gap-1 rounded-md bg-info/15 px-2 py-0.5 text-xs font-medium text-info-fg" title={`Software inside container ${row.componentName ?? ''}`}>
            container · {row.componentName}
          </span>
        ) : (
          <span className="text-xs text-secondary">host</span>
        ),
    },
    {
      header: 'Package',
      key: 'packageName',
      width: 260,
      exportValue: (row) => row.packageName,
      render: (row) => (
        <span className="font-mono text-xs">
          {row.packageName}
          {row.installedVersion ? (
            <span className="text-faint"> @ {row.installedVersion}</span>
          ) : null}
        </span>
      ),
    },
    {
      // serverFilter: the API already has an `ecosystem` param — the fetcher maps this key to it.
      header: 'Ecosystem',
      key: 'ecosystem',
      width: 120,
      serverFilter: true,
      exportValue: (row) => row.ecosystem,
      render: (row) => <span className="text-xs text-secondary">{orDash(row.ecosystem)}</span>,
    },
    {
      header: 'CVEs',
      key: 'cveCount',
      width: 90,
      sortAccessor: (row) => row.cveCount,
      exportValue: (row) => row.cveCount,
      render: (row) => <span className="font-mono text-xs">{row.cveCount.toLocaleString()}</span>,
    },
    {
      header: 'Worst severity',
      key: 'worstRank',
      width: 140,
      sortAccessor: (row) => ({ critical: 0, high: 1, medium: 2, low: 3, unknown: 4 }[row.worstRank] ?? 5),
      exportValue: (row) => row.worstRank,
      render: (row) => <RankBadge rank={row.worstRank} score={row.worstScore} />,
    },
    {
      header: 'Top CVEs',
      key: 'topCves',
      width: 320,
      sortable: false, // aggregated list — not a server sort field
      exportValue: (row) => row.topCves.join(', '),
      render: (row) => (
        <span className="flex flex-wrap items-center gap-x-2 gap-y-0.5">
          {row.topCves.slice(0, 3).map((id) => (
            <a key={id} href={`https://www.cve.org/CVERecord?id=${id}`} target="_blank" rel="noreferrer" className="font-mono text-xs text-info hover:underline">
              {id}
            </a>
          ))}
          {row.topCves.length > 3 && (
            <span className="text-xs text-faint">+{row.cveCount - 3} more</span>
          )}
        </span>
      ),
    },
  ];

  return (
    <Layout title="Security">
      <PageTabs
        tabs={[
          { id: 'findings', label: 'Findings', icon: <ShieldAlert className="h-3.5 w-3.5" />, count: securityQuery.data ? rows.length : null },
          { id: 'vulnerabilities', label: 'Vulnerabilities (CVEs)', icon: <Bug className="h-3.5 w-3.5" />, count: summary?.totalMatches ?? null },
          { id: 'threat-intel', label: 'Threat Intel', icon: <Radar className="h-3.5 w-3.5" /> },
        ]}
        value={tab}
        onChange={setTab}
      />

      {tab === 'findings' && (<>
      {/* Summary strip — the badge in the sidebar is this same count. */}
      <div className="mb-4 flex items-center gap-3 text-sm">
        {rows.length === 0 ? (
          <span className="inline-flex items-center gap-1.5 text-success-fg">
            <ShieldCheck className="h-4 w-4" /> No open security findings across your devices.
          </span>
        ) : (
          <>
            {criticalCount > 0 && (
              <span className="inline-flex items-center gap-1 rounded-md bg-danger px-2 py-1 text-xs font-medium text-danger-fg">
                <ShieldX className="h-3.5 w-3.5" /> {criticalCount} critical
              </span>
            )}
            {warningCount > 0 && (
              <span className="inline-flex items-center gap-1 rounded-md bg-warning px-2 py-1 text-xs font-medium text-warning-fg">
                <ShieldAlert className="h-3.5 w-3.5" /> {warningCount} warning{warningCount === 1 ? '' : 's'}
              </span>
            )}
            {infoCount > 0 && (
              <span className="inline-flex items-center gap-1 rounded-md bg-info px-2 py-1 text-xs font-medium text-info-fg">
                <Info className="h-3.5 w-3.5" /> {infoCount} info
              </span>
            )}
          </>
        )}
      </div>

      {securityQuery.isLoading && <p className="text-sm text-muted-foreground">Loading security findings...</p>}
      {securityQuery.isError && (
        <p className="text-sm text-danger-fg">Failed to load security findings: {(securityQuery.error as Error).message}</p>
      )}
      {securityQuery.data && (
        <DataTable
          columns={columns}
          rows={rows}
          rowKey={(row) => `${row.deviceId}|${row.pluginId}|${row.kind}|${row.name}`}
          storageKey="security-checks"
          autoRefresh={{ intervalMs: 30_000, queries: [securityQuery] }}
          searchPlaceholder="Search security findings…"
          emptyMessage="No open security findings — devices report unsuccessful logins, changed important files and active rate limiting here. Assign an SSH-capable plugin (Generic SSH, OpenWRT, OPNsense) or a RouterOS plugin to start collecting."
        />
      )}
      </>)}

      {tab === 'vulnerabilities' && (
      <div>
        {/* Installed packages matched against known advisories — refresh right-aligned where the section header used to be */}
        {summary && summary.totalMatches > 0 && (
          <div className="mb-3 flex justify-end">
            <button
              type="button"
              onClick={() => void refreshAdvisories()}
              disabled={refreshingCves}
              title="Fetch the latest advisories from OSV and re-match all installed packages (~3.5 min)"
              className="inline-flex items-center gap-2 rounded-md border border-border px-3 py-1.5 text-sm font-medium text-secondary hover:bg-muted disabled:opacity-60"
            >
              {refreshingCves ? <Loader2 className="h-4 w-4 animate-spin" /> : <RefreshCw className="h-4 w-4" />} Refresh advisories
            </button>
          </div>
        )}

        {/* Summary chips — severity distribution + worker fetch state */}
        {cveSummaryQuery.isLoading && <p className="text-sm text-muted-foreground">Loading vulnerability data…</p>}
        {cveSummaryQuery.isError && (
          <p className="text-sm text-danger-fg">Failed to load vulnerability summary: {(cveSummaryQuery.error as Error).message}</p>
        )}
        {summary && (
          <div className="mb-4 flex flex-wrap items-center gap-3 text-sm">
            {summary.totalMatches === 0 ? (
              <span className="inline-flex items-center gap-1.5 text-success-fg">
                <ShieldCheck className="h-4 w-4" /> No known vulnerabilities on tracked packages.
              </span>
            ) : (
              <>
                {/* Severity chips are CLICKABLE server-side filters (toggle on/off). */}
                {(Object.entries(summary.bySeverity) as Array<[string, number]>).filter(([, n]) => n > 0).map(([rank, n]) => {
                  const active = cveSeverity === rank;
                  return (
                    <button
                      key={rank}
                      type="button"
                      onClick={() => toggleCveSeverity(rank as CveSeverity)}
                      title={active ? `Clear the ${rank} filter` : `Filter to severity ${rank}${cveView === 'packages' ? ' (packages carrying at least one such CVE)' : ''}`}
                      className={clsx(
                        'inline-flex items-center gap-1 rounded-md px-2 py-1 text-xs font-medium',
                        RANK_STYLES[rank] ?? 'bg-muted text-secondary',
                        active ? 'ring-2 ring-focus-ring' : 'opacity-80 hover:opacity-100'
                      )}
                    >
                      {n.toLocaleString()} {rank}
                    </button>
                  );
                })}
                <span className="text-faint">·</span>
                <span className="text-sm text-secondary">
                  on <strong className="text-foreground">{summary.affectedDevices}</strong> device{summary.affectedDevices === 1 ? '' : 's'}
                </span>
                {typeof summary.affectedContainers === 'number' && summary.affectedContainers > 0 && (
                  <>
                    <span className="text-faint">·</span>
                    <span className="text-sm text-secondary">
                      in <strong className="text-foreground">{summary.affectedContainers}</strong> container{summary.affectedContainers === 1 ? '' : 's'}
                    </span>
                  </>
                )}
              </>
            )}
            {summary.lastError && (
              <span className="inline-flex items-center gap-1 rounded-md bg-danger/20 px-2 py-1 text-xs font-medium text-danger-fg" title={String(summary.lastError)}>
                last fetch failed: {String(summary.lastError).slice(0, 80)}{String(summary.lastError).length > 80 ? '…' : ''}
              </span>
            )}
            {!summary.lastError && summary.lastSuccessAt && (
              <span className="text-xs text-faint" title={new Date(summary.lastSuccessAt).toLocaleString()}>
                advisories fetched {timeAgo(summary.lastSuccessAt)}
              </span>
            )}
          </div>
        )}

        {/* Controls row — view toggle + component filter (both server-side). */}
        <div className="mb-2 flex flex-wrap items-center gap-3">
          <div className="flex rounded-md border border-border p-0.5 text-xs font-medium" role="tablist" aria-label="CVE view">
            {(['packages', 'vulns'] as const).map((v) => (
              <button
                key={v}
                type="button"
                onClick={() => setCveView(v)} // each table keeps its own page/sort/search
                className={clsx('rounded px-2.5 py-1', cveView === v ? 'bg-muted text-foreground' : 'text-secondary hover:text-foreground')}
              >
                {v === 'packages'
                  ? `Packages${pkgTable.data ? ` (${pkgTable.data.total.toLocaleString()})` : ''}`
                  : `All CVEs${vulnTable.data ? ` (${vulnTable.data.total.toLocaleString()})` : ''}`}
              </button>
            ))}
          </div>
          <label htmlFor="cve-component-filter" className="text-xs text-faint">Component</label>
          <select
            id="cve-component-filter"
            value={cveComponent}
            onChange={(e) => setCveComponent(e.target.value as 'all' | 'host' | 'container')}
            className="rounded-md border border-border bg-background px-2 py-1 text-xs text-foreground"
          >
            <option value="all">All</option>
            <option value="host">Host (appliance OS)</option>
            <option value="container">Containers</option>
          </select>
        </div>

        {cveView === 'packages' ? (
          pkgTable.data ? (
            <DataTable
              columns={cvePackageColumns}
              rows={pkgTable.data.rows}
              rowKey={(row) => `${row.deviceId}|${row.pluginId}|${row.component ?? 'host'}|${row.componentName ?? ''}|${row.ecosystem}|${row.packageName}`}
              storageKey="security-cves-packages"
              serverPagination={{
                total: pkgTable.data.total,
                page: pkgTable.page,
                pageSize: pkgTable.pageSize,
                onPageChange: pkgTable.setPage,
                onPageSizeChange: pkgTable.setPageSize,
                // pageSizeOptions omitted → global `tablePageSizeOptions` setting + built-in "All".
                filters: pkgTable.filters,
                onFiltersChange: pkgTable.setFilters,
                sort: pkgTable.sort,
                onSortChange: pkgTable.setSort,
              }}
              isFetching={pkgTable.isFetching}
              onSearch={pkgTable.setQ}
              externalSearch={pkgTable.q}
              onRowClick={drillIntoPackage}
              autoRefresh={{ intervalMs: 30_000, queries: [pkgTable] }}
              searchPlaceholder="Search package or CVE id…"
              emptyMessage={
                cveSeverity || cveComponent !== 'all' || pkgTable.q
                  ? 'No vulnerable packages match the current filters.'
                  : "No known vulnerabilities — packages are matched against OSV advisories once the fleet's installed-package inventory is collected and at least one advisory fetch has succeeded."
              }
            />
          ) : pkgTable.isError ? (
            <p className="text-sm text-danger-fg">Failed to load vulnerable packages: {pkgTable.error?.message}</p>
          ) : (
            <p className="text-sm text-muted-foreground">Loading vulnerability data…</p>
          )
        ) : vulnTable.data ? (
          <DataTable
            columns={cveColumns}
            rows={vulnTable.data.rows}
            rowKey={(row) => `${row.deviceId}|${row.pluginId}|${row.component ?? 'host'}|${row.componentName ?? ''}|${row.packageName}|${row.cveId}`}
            storageKey="security-cves"
            serverPagination={{
              total: vulnTable.data.total,
              page: vulnTable.page,
              pageSize: vulnTable.pageSize,
              onPageChange: vulnTable.setPage,
              onPageSizeChange: vulnTable.setPageSize,
              // pageSizeOptions omitted → global `tablePageSizeOptions` setting + built-in "All".
              filters: vulnTable.filters,
              onFiltersChange: vulnTable.setFilters,
              sort: vulnTable.sort,
              onSortChange: vulnTable.setSort,
            }}
            isFetching={vulnTable.isFetching}
            onSearch={vulnTable.setQ}
            externalSearch={vulnTable.q}
            autoRefresh={{ intervalMs: 30_000, queries: [vulnTable] }}
            searchPlaceholder="Search package or CVE id…"
            emptyMessage={
              cveSeverity || cveComponent !== 'all' || vulnTable.q
                ? 'No CVE matches for the current filters.'
                : "No known vulnerabilities — packages are matched against OSV advisories once the fleet's installed-package inventory is collected and at least one advisory fetch has succeeded."
            }
          />
        ) : vulnTable.isError ? (
          <p className="text-sm text-danger-fg">Failed to load CVE matches: {vulnTable.error?.message}</p>
        ) : (
          <p className="text-sm text-muted-foreground">Loading vulnerability data…</p>
        )}
      </div>
      )}

      {/* Threat intelligence — IOC feed sources + recent hits */}
      {tab === 'threat-intel' && <ThreatIntelSection />}
    </Layout>
  );
}

/** Threat-intel section: managed IOC feeds, per-source fetch state and recent hits. */
function ThreatIntelSection() {
  const queryClient = useQueryClient();
  const tiQuery = useQuery({
    queryKey: ['threatIntel'],
    queryFn: () => api.threatIntel(),
    refetchInterval: 30_000,
  });

  // Add-source form state.
  const [name, setName] = useState('');
  const [url, setUrl] = useState('');
  const [format, setFormat] = useState<'ip-list' | 'stix' | 'domain-list'>('ip-list');
  const [adding, setAdding] = useState(false);
  const [addError, setAddError] = useState<string | null>(null);

  // "Fetch now" runs one full cycle server-side — fire and forget; the
  // per-source lastSuccessAt/lastError surface the outcome.
  const [fetching, setFetching] = useState(false);
  async function fetchNow() {
    if (fetching) return;
    setFetching(true);
    try {
      await api.fetchThreatIntelNow();
      void queryClient.invalidateQueries({ queryKey: ['threatIntel'] });
    } catch (err) {
      console.warn('Threat-intel fetch reported an error:', (err as Error).message);
    } finally {
      setFetching(false);
    }
  }

  async function addSource() {
    if (adding || !name.trim() || !url.trim()) return;
    setAdding(true);
    setAddError(null);
    try {
      await api.addThreatIntelSource({ name: name.trim(), url: url.trim(), format });
      setName('');
      setUrl('');
      void queryClient.invalidateQueries({ queryKey: ['threatIntel'] });
    } catch (err) {
      setAddError((err as Error).message);
    } finally {
      setAdding(false);
    }
  }

  async function toggleSource(s: ThreatIntelSource) {
    try {
      await api.updateThreatIntelSource(s.id, { enabled: !s.enabled });
      void queryClient.invalidateQueries({ queryKey: ['threatIntel'] });
    } catch (err) {
      console.warn('Failed to toggle threat-intel source:', (err as Error).message);
    }
  }

  async function deleteSource(s: ThreatIntelSource) {
    if (!window.confirm(`Delete the "${s.name}" feed and all ${s.iocCount} of its indicators?`)) return;
    try {
      await api.deleteThreatIntelSource(s.id);
      void queryClient.invalidateQueries({ queryKey: ['threatIntel'] });
    } catch (err) {
      console.warn('Failed to delete threat-intel source:', (err as Error).message);
    }
  }

  const data = tiQuery.data;
  const sources = data?.sources ?? [];
  const hits = data?.recentHits ?? [];

  const sourceColumns: DataTableColumn<ThreatIntelSource>[] = [
    {
      header: 'Name',
      key: 'name',
      width: 200,
      exportValue: (row) => row.name,
      render: (row) => <span className="text-sm font-medium">{row.name}</span>,
    },
    {
      header: 'URL',
      key: 'url',
      width: 320,
      exportValue: (row) => row.url,
      render: (row) => (
        <a href={row.url} target="_blank" rel="noreferrer" className="font-mono text-xs text-info hover:underline break-all">
          {row.url}
        </a>
      ),
    },
    {
      header: 'Format',
      key: 'format',
      width: 100,
      exportValue: (row) => row.format,
      render: (row) => <span className="text-xs text-secondary">{row.format}</span>,
    },
    {
      header: 'IOCs',
      key: 'iocCount',
      width: 90,
      sortAccessor: (row) => row.iocCount,
      render: (row) => <span className="font-mono text-xs">{row.iocCount.toLocaleString()}</span>,
    },
    {
      header: 'Last fetch',
      key: 'lastSuccessAt',
      width: 130,
      sortAccessor: (row) => Date.parse(row.lastSuccessAt ?? '') || 0,
      render: (row) => (
        <span className="text-xs text-faint" title={row.lastError ? String(row.lastError) : undefined}>
          {row.lastSuccessAt ? timeAgo(row.lastSuccessAt) : 'never'}
        </span>
      ),
    },
    {
      header: 'Status',
      key: 'status',
      width: 260,
      render: (row) =>
        row.enabled ? (
          row.lastError ? (
            <span className="inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-xs font-medium bg-danger/20 text-danger-fg" title={String(row.lastError)}>
              {String(row.lastError).slice(0, 60)}{String(row.lastError).length > 60 ? '…' : ''}
            </span>
          ) : (
            <span className="inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-xs font-medium bg-success/20 text-success-fg">
              ok
            </span>
          )
        ) : (
          <span className="inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-xs font-medium bg-muted text-secondary">disabled</span>
        ),
    },
    {
      header: '',
      key: 'actions',
      width: 120,
      render: (row) => (
        <div className="flex items-center justify-end gap-1">
          <button
            type="button"
            onClick={() => void toggleSource(row)}
            title={row.enabled ? 'Disable this feed' : 'Enable this feed'}
            className="rounded px-2 py-1 text-xs font-medium text-secondary hover:bg-muted"
          >
            {row.enabled ? 'Disable' : 'Enable'}
          </button>
          <button
            type="button"
            onClick={() => void deleteSource(row)}
            title={`Delete "${row.name}"`}
            className="rounded p-1 text-secondary hover:bg-danger/20 hover:text-danger-fg"
          >
            <Trash2 className="h-3.5 w-3.5" />
          </button>
        </div>
      ),
    },
  ];

  return (
    <div>
      {/* "Fetch now" right-aligned where the section header used to be (the tab label provides context) */}
      {sources.some((s) => s.enabled) && (
        <div className="mb-3 flex justify-end">
          <button
            type="button"
            onClick={() => void fetchNow()}
            disabled={fetching}
            title="Fetch all enabled feeds now (bypasses the interval)"
            className="inline-flex items-center gap-2 rounded-md border border-border px-3 py-1.5 text-sm font-medium text-secondary hover:bg-muted disabled:opacity-60"
          >
            {fetching ? <Loader2 className="h-4 w-4 animate-spin" /> : <RefreshCw className="h-4 w-4" />} Fetch now
          </button>
        </div>
      )}

      {/* Summary chips — active indicator count + worker state */}
      {tiQuery.isLoading && <p className="text-sm text-muted-foreground">Loading threat intelligence…</p>}
      {tiQuery.isError && (
        <p className="text-sm text-danger-fg">Failed to load threat intelligence: {(tiQuery.error as Error).message}</p>
      )}
      {data && (
        <div className="mb-4 flex flex-wrap items-center gap-3 text-sm">
          {!data.enabled ? (
            <Link
              to="/settings"
              title="Master switch + fetch interval live in the central settings page (category Security)"
              className="inline-flex items-center gap-1.5 rounded-md bg-muted px-2 py-1 text-xs font-medium text-secondary hover:bg-border hover:text-foreground"
            >
              Threat-intel matching is disabled — open Settings to enable it
            </Link>
          ) : data.worker.iocTotal > 0 ? (
            <span className="inline-flex items-center gap-1.5 text-success-fg">
              <Radar className="h-4 w-4" /> {data.worker.iocTotal.toLocaleString()} active indicators
            </span>
          ) : (
            <span className="text-sm text-secondary">No indicators yet — add a feed below to start matching.</span>
          )}
          {data.worker.lastError && (
            <span className="inline-flex items-center gap-1 rounded-md bg-danger/20 px-2 py-1 text-xs font-medium text-danger-fg" title={String(data.worker.lastError)}>
              worker error: {String(data.worker.lastError).slice(0, 80)}{String(data.worker.lastError).length > 80 ? '…' : ''}
            </span>
          )}
        </div>
      )}

      {/* Feed sources */}
      {data && (
        <DataTable
          columns={sourceColumns}
          rows={sources}
          rowKey={(row) => row.id}
          storageKey="threat-intel-sources"
          autoRefresh={{ intervalMs: 30_000, queries: [tiQuery] }}
          searchPlaceholder="Search feeds…"
          emptyMessage={'No IOC feed sources yet — add one below (IP/CIDR list, STIX bundle or Pi-hole-style domain blocklist). Each fetch is an authoritative snapshot; matches raise "threat intel hit" findings.'}
        />
      )}

      {/* Add-source form */}
      <div className="mt-3 flex flex-wrap items-end gap-2 rounded-md border border-border bg-muted/30 p-3">
        <label className="flex flex-col gap-1 text-xs font-medium text-secondary">
          Name
          <input value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. Emerging Threats" className="w-44 rounded-md border border-border bg-background px-2 py-1.5 text-sm text-foreground" />
        </label>
        <label className="flex flex-col gap-1 text-xs font-medium text-secondary">
          Feed URL
          <input value={url} onChange={(e) => setUrl(e.target.value)} placeholder="https://…/blocklist.txt" className="w-72 rounded-md border border-border bg-background px-2 py-1.5 font-mono text-sm text-foreground" />
        </label>
        <label className="flex flex-col gap-1 text-xs font-medium text-secondary">
          Format
          <select value={format} onChange={(e) => setFormat(e.target.value as 'ip-list' | 'stix' | 'domain-list')} className="rounded-md border border-border bg-background px-2 py-1.5 text-sm text-foreground">
            <option value="ip-list">IP list (one per line)</option>
            <option value="stix">STIX 2.x bundle</option>
            <option value="domain-list">Domain blocklist (Pi-hole style)</option>
          </select>
        </label>
        <button
          type="button"
          onClick={() => void addSource()}
          disabled={adding || !name.trim() || !url.trim()}
          className="inline-flex items-center gap-2 rounded-md bg-primary px-3 py-1.5 text-sm font-medium text-primary-fg hover:opacity-90 disabled:opacity-60"
        >
          {adding && <Loader2 className="h-4 w-4 animate-spin" />}
          Add feed
        </button>
        {addError && <span className="text-xs text-danger-fg">{addError}</span>}
      </div>

      {/* Recent hits */}
      {hits.length > 0 && (
        <div className="mt-4">
          <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-faint">Recent threat-intel hits</h3>
          <ul className="space-y-1.5">
            {hits.slice(0, 10).map((h) => (
              <li key={h.id} className="flex items-baseline gap-2 rounded-md border border-border bg-muted/20 px-3 py-2 text-xs" title={h.detail}>
                <span className={`shrink-0 rounded px-1.5 py-0.5 font-medium uppercase ${h.severity === 'critical' ? 'bg-danger text-danger-fg' : h.severity === 'warning' ? 'bg-warning text-warning-fg' : 'bg-info text-info-fg'}`}>
                  {h.severity}
                </span>
                <span className="font-mono shrink-0">
                  {h.kind === 'dns-ioc-hit' && h.domain ? (
                    <>
                      {h.srcIp} queried <span className="text-danger-fg">{h.domain}</span>
                    </>
                  ) : (
                    <>{h.srcIp} → {h.dstIp ?? '?'}</>
                  )}
                </span>
                <span className="text-secondary break-words">{h.detail}</span>
                <span className="ml-auto shrink-0 text-faint" title={new Date(h.lastSeenAt).toLocaleString()}>
                  {timeAgo(h.lastSeenAt)}
                </span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}
