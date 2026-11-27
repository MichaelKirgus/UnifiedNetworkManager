import { useQuery, useQueryClient } from '@tanstack/react-query';
import { Bug, Download, Eye, FileSearch, Globe, Loader2, Pencil, Plus, RefreshCw, Radar, Rss, ShieldCheck, ShieldAlert, ShieldX, Info, Trash2 } from 'lucide-react';
import { Link } from 'react-router-dom';
import { useMemo, useState } from 'react';
import clsx from 'clsx';
import { Layout } from '../components/Layout';
import { DialogShell } from '../components/DialogShell';
import { DataTable, DataTableColumn } from '../components/DataTable';
import { ALL_PAGES, useServerTable } from '../components/useServerTable';
import { DeviceChip } from '../components/DeviceChip';
import { PageTabs } from '../components/PageTabs';
import { api, ApiError, SecurityCheckRow, CvePackageRow, CveVulnerabilityRow, ThreatIntelSource, ThreatIntelSourceInput, LogRule, LogRuleFeed, FeedSyncResult, LogRuleImportResult, DnsQueryEvent } from '../api/client';

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
  'spam-filtering': 'bg-accent-violet text-accent-violet-fg',
  'auth-activity': 'bg-accent-indigo text-accent-indigo-fg',
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
  'spam-filtering': 'spam filtering',
  'auth-activity': 'login activity',
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

  // Findings | Vulnerabilities (CVEs) | Threat Intel | DNS — each section is a
  // self-contained tab so the page reads top-down instead of one long scroll.
  const [tab, setTab] = useState<'findings' | 'vulnerabilities' | 'threat-intel' | 'log-rules' | 'dns'>('findings');

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
          { id: 'log-rules', label: 'Log rules', icon: <FileSearch className="h-3.5 w-3.5" /> },
          { id: 'dns', label: 'DNS', icon: <Globe className="h-3.5 w-3.5" /> },
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

      {/* Log rules — Sigma detection over ingested log lines */}
      {tab === 'log-rules' && <LogRulesSection />}

      {/* DNS query events from appliance resolvers (unbound qstats) */}
      {tab === 'dns' && <DnsSection />}
    </Layout>
  );
}

/** Triggers a browser download of an already-fetched blob under `name` (same pattern as the Files page). */
function saveBlob(blob: Blob, name: string): void {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = name;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 10_000);
}

/** Create/edit dialog for one threat-intel source — URL feed or pasted content, optional auth header. */
function ThreatIntelSourceDialog({ source, onClose }: { source: ThreatIntelSource | null; onClose: () => void }) {
  const queryClient = useQueryClient();
  const [name, setName] = useState(source?.name ?? '');
  const [url, setUrl] = useState(source?.url ?? '');
  const [content, setContent] = useState(source?.content ?? '');
  const [authHeader, setAuthHeader] = useState(source?.authHeader ?? '');
  const [format, setFormat] = useState<'ip-list' | 'stix' | 'domain-list'>(source?.format ?? 'ip-list');
  const [severity, setSeverity] = useState<'info' | 'warning' | 'critical'>(source?.severity ?? 'warning');
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const isManual = url.trim() === '';
  const canSave = name.trim() !== '' && (!isManual || content.trim() !== '');

  async function save() {
    if (saving || !canSave) return;
    setSaving(true);
    setError(null);
    try {
      const body: ThreatIntelSourceInput = {
        name: name.trim(),
        url: url.trim(),
        content: isManual ? content : undefined,
        authHeader: authHeader.trim() || undefined,
        format,
        severity,
      };
      if (source) await api.updateThreatIntelSource(source.id, body);
      else await api.addThreatIntelSource(body);
      void queryClient.invalidateQueries({ queryKey: ['threatIntel'] });
      onClose();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setSaving(false);
    }
  }

  const fieldCls = 'w-full rounded-md border border-border bg-background px-3 py-2 text-sm focus:border-focus-ring focus:outline-none';
  return (
    <DialogShell
      title={source ? `Edit feed "${source.name}"` : 'Add IOC feed'}
      subtitle={source ? 'Changing the URL, content or format forces an immediate re-fetch.' : 'Point at a public feed URL or paste a blocklist / STIX bundle directly.'}
      onClose={onClose}
      maxWidth="max-w-lg"
    >
      <div className="space-y-3">
        {error && <p className="rounded-md border border-danger-border bg-danger px-3 py-2 text-xs text-danger-fg">{error}</p>}
        <div>
          <label className="mb-1 block text-sm font-medium text-secondary">Name</label>
          <input value={name} onChange={(e) => setName(e.target.value)} maxLength={100} placeholder="e.g. Emerging Threats" className={fieldCls} />
        </div>
        <div>
          <label className="mb-1 block text-sm font-medium text-secondary">Feed URL</label>
          <input value={url} onChange={(e) => setUrl(e.target.value)} placeholder={isManual ? 'leave empty to paste content below' : 'https://…/blocklist.txt'} className={`${fieldCls} font-mono`} />
        </div>
        {isManual && (
          <div>
            <label className="mb-1 block text-sm font-medium text-secondary">Pasted feed content</label>
            <textarea value={content} onChange={(e) => setContent(e.target.value)} rows={8} maxLength={2_048_576} placeholder={format === 'stix' ? '{ "type": "bundle", "objects": [ … ] }' : 'one entry per line (IP/CIDR or domain)'} className={`${fieldCls} font-mono text-xs`} />
            <p className="mt-1 text-xs text-faint">Manual sources are parsed on every fetch cycle without any network download — handy for private or one-off blocklists.</p>
          </div>
        )}
        {!isManual && (
          <div>
            <label className="mb-1 block text-sm font-medium text-secondary">Auth header (optional)</label>
            <input value={authHeader} onChange={(e) => setAuthHeader(e.target.value)} maxLength={512} placeholder="Authorization: Bearer ***" className={`${fieldCls} font-mono`} />
            <p className="mt-1 text-xs text-faint">Sent with the feed download via the web-fetch plugin; stored server-side and never logged.</p>
          </div>
        )}
        <div className="grid grid-cols-2 gap-3">
          <div>
            <label className="mb-1 block text-sm font-medium text-secondary">Format</label>
            <select value={format} onChange={(e) => setFormat(e.target.value as 'ip-list' | 'stix' | 'domain-list')} className={fieldCls}>
              <option value="ip-list">IP list (one per line)</option>
              <option value="stix">STIX 2.x bundle</option>
              <option value="domain-list">Domain blocklist (Pi-hole / Adblock)</option>
            </select>
          </div>
          <div>
            <label className="mb-1 block text-sm font-medium text-secondary">Notification severity</label>
            <select value={severity} onChange={(e) => setSeverity(e.target.value as 'info' | 'warning' | 'critical')} className={fieldCls}>
              <option value="info">Info</option>
              <option value="warning">Warning</option>
              <option value="critical">Critical</option>
            </select>
          </div>
        </div>
        <p className="text-xs text-faint">Findings raised by this feed use the selected severity — a hit matching several feeds escalates to the highest one. Existing open findings are never downgraded.</p>
        <div className="flex items-center justify-end gap-2 border-t border-border pt-3">
          <button type="button" onClick={onClose} className="rounded-md px-3 py-1.5 text-sm text-secondary hover:bg-muted">Cancel</button>
          <button
            type="button"
            onClick={() => void save()}
            disabled={saving || !canSave}
            className="inline-flex items-center gap-1.5 rounded-md bg-primary px-3 py-1.5 text-sm font-medium text-white hover:bg-primary-hover disabled:opacity-50"
          >
            {saving && <Loader2 size={14} className="animate-spin" />}
            {source ? 'Save changes' : 'Add feed'}
          </button>
        </div>
      </div>
    </DialogShell>
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

  // Source dialogs — one unified create/edit dialog (URL feed or pasted content).
  const [editing, setEditing] = useState<ThreatIntelSource | null>(null);
  const [creating, setCreating] = useState(false);

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

  /** Downloads the raw feed snapshot of the last successful fetch from the central file repo. */
  async function downloadSnapshot(s: ThreatIntelSource) {
    if (!s.repoFileId) return;
    try {
      const blob = await api.downloadRepoFile(s.repoFileId);
      saveBlob(blob, `${s.name.replace(/[^\w.\-]+/g, '-').slice(0, 80) || 'feed'}.${s.format === 'stix' ? 'json' : 'txt'}`);
    } catch (err) {
      console.warn('Failed to download threat-intel snapshot:', (err as Error).message);
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
      render: (row) =>
        row.url === '' ? (
          <span
            className="rounded bg-muted px-1.5 py-0.5 text-xs font-medium text-secondary"
            title={`Manual source — ${(row.content ?? '').length.toLocaleString()} characters of pasted content, no network download`}
          >
            manual
          </span>
        ) : (
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
      header: 'Severity',
      key: 'severity',
      width: 100,
      exportValue: (row) => row.severity,
      render: (row) => (
        <span
          className={`rounded px-1.5 py-0.5 text-xs font-medium uppercase ${row.severity === 'critical' ? 'bg-danger text-danger-fg' : row.severity === 'warning' ? 'bg-warning text-warning-fg' : 'bg-info text-info-fg'}`}
          title="Notification severity for findings raised by this feed"
        >
          {row.severity}
        </span>
      ),
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
      render: (row) => {
        const err = row.lastError ? String(row.lastError) : '';
        if (!row.enabled) {
          return row.failCount > 0 ? (
            <span
              className="inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-xs font-medium bg-danger/20 text-danger-fg"
              title={`Auto-paused after ${row.failCount} consecutive failures${err ? ` — last error: ${err}` : ''}. Enable the feed to resume fetching.`}
            >
              auto-paused ({row.failCount}× failed)
            </span>
          ) : (
            <span className="inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-xs font-medium bg-muted text-secondary" title={err || undefined}>
              disabled
            </span>
          );
        }
        if (row.health === 'down') {
          return (
            <span className="inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-xs font-medium bg-danger/20 text-danger-fg" title={err || undefined}>
              {row.failCount}× failed{err ? ` — ${err.slice(0, 60)}${err.length > 60 ? '…' : ''}` : ''}
            </span>
          );
        }
        if (row.health === 'degraded') {
          return (
            <span className="inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-xs font-medium bg-warning/20 text-warning-fg" title={err || undefined}>
              1 consecutive failure
            </span>
          );
        }
        return (
          <span className="inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-xs font-medium bg-success/20 text-success-fg">
            ok
          </span>
        );
      },
    },
    {
      header: '',
      key: 'actions',
      width: 150,
      render: (row) => (
        <div className="flex items-center justify-end gap-1">
          {row.repoFileId && (
            <button
              type="button"
              onClick={() => void downloadSnapshot(row)}
              title="Download the raw feed snapshot of the last successful fetch (from the file repo)"
              className="rounded p-1 text-secondary hover:bg-muted"
            >
              <Download className="h-3.5 w-3.5" />
            </button>
          )}
          <button
            type="button"
            onClick={() => setEditing(row)}
            title={`Edit "${row.name}" (URL, format, severity)`}
            className="rounded p-1 text-secondary hover:bg-muted"
          >
            <Pencil className="h-3.5 w-3.5" />
          </button>
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
          emptyMessage={'No IOC feed sources yet — add one below (IP/CIDR list, STIX bundle or a domain blocklist in Pi-hole / Adblock style). Each fetch is an authoritative snapshot; matches raise "threat intel hit" findings.'}
        />
      )}

      {/* Add-feed entry — opens the create dialog (URL feed or pasted content) */}
      <div className="mt-3">
        <button
          type="button"
          onClick={() => setCreating(true)}
          title="Add an IOC feed source — public URL or pasted blocklist / STIX bundle"
          className="inline-flex items-center gap-2 rounded-md border border-border px-3 py-1.5 text-sm font-medium text-secondary hover:bg-muted"
        >
          <Plus className="h-4 w-4" /> Add feed
        </button>
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

      {/* Create/edit dialog (URL feed or pasted content) */}
      {(creating || editing) && (
        <ThreatIntelSourceDialog
          source={editing}
          onClose={() => {
            setCreating(false);
            setEditing(null);
          }}
        />
      )}
    </div>
  );
}

/** Log rules section — Sigma detection over ingested log lines (built-in pack + user rules). */
function LogRulesSection() {
  const queryClient = useQueryClient();
  const lrQuery = useQuery({
    queryKey: ['logRules'],
    queryFn: () => api.logRules(),
    refetchInterval: 30_000,
  });

  const [creating, setCreating] = useState(false);
  const [importing, setImporting] = useState(false);
  const [viewingId, setViewingId] = useState<string | null>(null);
  const [view, setView] = useState<'rules' | 'feeds'>('rules');
  const [editingFeed, setEditingFeed] = useState<{ mode: 'create' } | { mode: 'edit'; feed: LogRuleFeed } | null>(null);

  async function toggleRule(r: LogRule) {
    try {
      await api.updateLogRule(r.id, { enabled: !r.enabled });
      void queryClient.invalidateQueries({ queryKey: ['logRules'] });
    } catch (err) {
      console.warn('Failed to toggle log rule:', (err as Error).message);
    }
  }

  async function deleteRule(r: LogRule) {
    if (!window.confirm(`Delete the "${r.name}" rule? Open findings it raised stay until they auto-resolve.`)) return;
    try {
      await api.deleteLogRule(r.id);
      void queryClient.invalidateQueries({ queryKey: ['logRules'] });
    } catch (err) {
      console.warn('Failed to delete log rule:', (err as Error).message);
    }
  }

  const data = lrQuery.data;
  const rules = data?.rules ?? [];
  const viewing = viewingId ? rules.find((r) => r.id === viewingId) : undefined;

  const columns: DataTableColumn<LogRule>[] = [
    {
      header: 'Name',
      key: 'name',
      width: 260,
      exportValue: (row) => row.name,
      render: (row) => (
        <span className="flex items-center gap-1.5">
          <span className="text-sm font-medium">{row.name}</span>
          {row.source === 'builtin' && (
            <span className="rounded bg-muted px-1 py-0.5 text-[10px] font-medium uppercase tracking-wide text-faint" title="Seeded by UNM — the YAML is managed; disable the rule or override its severity instead">
              builtin
            </span>
          )}
          {row.source === 'feed' && (
            <span className="rounded bg-accent-sky px-1 py-0.5 text-[10px] font-medium uppercase tracking-wide text-accent-sky-fg" title="Synced from a URL feed — the YAML follows the feed on each sync; manage it in the Feeds view">
              feed
            </span>
          )}
        </span>
      ),
    },
    {
      header: 'Severity',
      key: 'severityOverride',
      width: 100,
      exportValue: (row) => row.severityOverride ?? 'default',
      render: (row) =>
        row.severityOverride ? (
          <span className={`rounded px-1.5 py-0.5 text-xs font-medium uppercase ${row.severityOverride === 'critical' ? 'bg-danger text-danger-fg' : row.severityOverride === 'warning' ? 'bg-warning text-warning-fg' : 'bg-info text-info-fg'}`}>
            {row.severityOverride}
          </span>
        ) : (
          <span className="text-xs text-faint" title="Uses the level declared in the rule's Sigma YAML">default</span>
        ),
    },
    {
      header: 'Last hit',
      key: 'lastHitAt',
      width: 150,
      sortAccessor: (row) => Date.parse(row.lastHitAt ?? '') || 0,
      render: (row) =>
        row.lastHitAt ? (
          <span className="text-xs text-secondary" title={new Date(row.lastHitAt).toLocaleString()}>
            {timeAgo(row.lastHitAt)}{row.occurrences > 1 ? ` · ×${row.occurrences}` : ''}
          </span>
        ) : (
          <span className="text-xs text-faint">never</span>
        ),
    },
    {
      header: 'Status',
      key: 'status',
      width: 240,
      render: (row) =>
        row.lastError ? (
          <span className="inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-xs font-medium bg-danger/20 text-danger-fg" title={String(row.lastError)}>
            {String(row.lastError).slice(0, 60)}{String(row.lastError).length > 60 ? '…' : ''}
          </span>
        ) : row.enabled ? (
          <span className="inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-xs font-medium bg-success/20 text-success-fg">active</span>
        ) : (
          <span className="inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-xs font-medium bg-muted text-secondary">disabled</span>
        ),
    },
    {
      header: '',
      key: 'actions',
      width: 170,
      render: (row) => (
        <div className="flex items-center justify-end gap-1">
          <button type="button" onClick={() => setViewingId(row.id)} title={`View the Sigma YAML of "${row.name}"`} className="rounded p-1 text-secondary hover:bg-muted">
            <Eye className="h-3.5 w-3.5" />
          </button>
          {row.source === 'user' && (
            <button type="button" onClick={() => setViewingId(row.id)} title={`Edit the Sigma YAML of "${row.name}"`} className="rounded p-1 text-secondary hover:bg-muted">
              <Pencil className="h-3.5 w-3.5" />
            </button>
          )}
          <button type="button" onClick={() => void toggleRule(row)} title={row.enabled ? 'Disable this rule' : 'Enable this rule'} className="rounded px-2 py-1 text-xs font-medium text-secondary hover:bg-muted">
            {row.enabled ? 'Disable' : 'Enable'}
          </button>
          {row.source === 'user' && (
            <button type="button" onClick={() => void deleteRule(row)} title={`Delete "${row.name}"`} className="rounded p-1 text-secondary hover:bg-danger/20 hover:text-danger-fg">
              <Trash2 className="h-3.5 w-3.5" />
            </button>
          )}
        </div>
      ),
    },
  ];

  return (
    <div>
      {/* Rules/Feeds sub-view — left; context actions right */}
      <div className="mb-3 flex items-center justify-between gap-2">
        <div className="flex rounded-md border border-border p-0.5 text-sm font-medium">
          <button type="button" onClick={() => setView('rules')} className={clsx('rounded px-3 py-1', view === 'rules' ? 'bg-muted text-foreground' : 'text-secondary hover:text-foreground')}>Rules</button>
          <button type="button" onClick={() => setView('feeds')} className={clsx('rounded px-3 py-1', view === 'feeds' ? 'bg-muted text-foreground' : 'text-secondary hover:text-foreground')}>Feeds</button>
        </div>
        {view === 'rules' ? (
          <div className="flex gap-2">
            <button type="button" onClick={() => setImporting(true)} title="Paste one or more Sigma documents separated by ---" className="inline-flex items-center gap-2 rounded-md border border-border px-3 py-1.5 text-sm font-medium text-secondary hover:bg-muted">
              Import YAML
            </button>
            <button type="button" onClick={() => setCreating(true)} className="inline-flex items-center gap-2 rounded-md bg-primary px-3 py-1.5 text-sm font-medium text-primary-fg hover:opacity-90">
              New rule
            </button>
          </div>
        ) : (
          <button type="button" onClick={() => setEditingFeed({ mode: 'create' })} className="inline-flex items-center gap-2 rounded-md bg-primary px-3 py-1.5 text-sm font-medium text-primary-fg hover:opacity-90">
            <Rss className="h-4 w-4" /> New feed
          </button>
        )}
      </div>

      {view === 'feeds' ? (
        <LogRuleFeedsSection onEditFeed={(feed) => setEditingFeed({ mode: 'edit', feed })} />
      ) : (
        <>
      {lrQuery.isLoading && <p className="text-sm text-muted-foreground">Loading log rules…</p>}
      {lrQuery.isError && (
        <p className="text-sm text-danger-fg">Failed to load log rules: {(lrQuery.error as Error).message}</p>
      )}
      {data && (
        <div className="mb-4 flex flex-wrap items-center gap-3 text-sm">
          {!data.enabled ? (
            <Link
              to="/settings"
              title="Master switch + scan limit live in the central settings page (category Security)"
              className="inline-flex items-center gap-1.5 rounded-md bg-muted px-2 py-1 text-xs font-medium text-secondary hover:bg-border hover:text-foreground"
            >
              Log-rule scanning is disabled — open Settings to enable it
            </Link>
          ) : (
            <span className="inline-flex items-center gap-1.5 text-success-fg">
              <FileSearch className="h-4 w-4" /> {data.worker.rulesEnabled ?? 0} active rules · {data.worker.hitsLast24h.toLocaleString()} hits in the last 24 h
            </span>
          )}
          {data.worker.lastError && (
            <span className="inline-flex items-center gap-1 rounded-md bg-danger/20 px-2 py-1 text-xs font-medium text-danger-fg" title={String(data.worker.lastError)}>
              worker error: {String(data.worker.lastError).slice(0, 80)}{String(data.worker.lastError).length > 80 ? '…' : ''}
            </span>
          )}
        </div>
      )}

      {data && (
        <DataTable
          columns={columns}
          rows={rules}
          rowKey={(row) => row.id}
          storageKey="log-rules"
          autoRefresh={{ intervalMs: 30_000, queries: [lrQuery] }}
          searchPlaceholder="Search rules…"
          emptyMessage={'No log rules yet — create one below or import Sigma YAML. Built-in rules are seeded automatically at boot.'}
        />
      )}
        </>
      )}

      {creating && <LogRuleCreateDialog onClose={() => setCreating(false)} />}
      {importing && <LogRuleImportDialog onClose={() => setImporting(false)} />}
      {viewing && <LogRuleYamlDialog rule={viewing} onClose={() => setViewingId(null)} />}
      {editingFeed && (
        <FeedDialog feed={editingFeed.mode === 'edit' ? editingFeed.feed : null} onClose={() => setEditingFeed(null)} />
      )}
    </div>
  );
}

/** Log rule feeds — named YAML-URL / GitHub-repo sources the leader worker syncs on an interval. */
function LogRuleFeedsSection({ onEditFeed }: { onEditFeed: (feed: LogRuleFeed) => void }) {
  const queryClient = useQueryClient();
  const feedsQuery = useQuery({
    queryKey: ['logRuleFeeds'],
    queryFn: () => api.logRuleFeeds(),
    refetchInterval: 30_000,
  });

  const [syncingId, setSyncingId] = useState<string | null>(null);
  const [lastSync, setLastSync] = useState<{ name: string; result: FeedSyncResult } | null>(null);
  const [syncError, setSyncError] = useState<string | null>(null);

  async function toggleFeed(f: LogRuleFeed) {
    try {
      await api.updateLogRuleFeed(f.id, { enabled: !f.enabled });
      void queryClient.invalidateQueries({ queryKey: ['logRuleFeeds'] });
    } catch (err) {
      console.warn('Failed to toggle log rule feed:', (err as Error).message);
    }
  }

  async function deleteFeed(f: LogRuleFeed) {
    if (!window.confirm(`Delete the "${f.name}" feed? Its ${f.ruleCount} rule(s) become ordinary user rules.`)) return;
    try {
      await api.deleteLogRuleFeed(f.id);
      void queryClient.invalidateQueries({ queryKey: ['logRuleFeeds'] });
      void queryClient.invalidateQueries({ queryKey: ['logRules'] });
    } catch (err) {
      console.warn('Failed to delete log rule feed:', (err as Error).message);
    }
  }

  async function syncNow(f: LogRuleFeed) {
    setSyncingId(f.id);
    setLastSync(null);
    setSyncError(null);
    try {
      const result = await api.syncLogRuleFeed(f.id);
      setLastSync({ name: f.name, result });
      void queryClient.invalidateQueries({ queryKey: ['logRuleFeeds'] });
      void queryClient.invalidateQueries({ queryKey: ['logRules'] });
    } catch (err) {
      setSyncError((err as Error).message);
    } finally {
      setSyncingId(null);
    }
  }

  const feeds = feedsQuery.data?.feeds ?? [];

  const columns: DataTableColumn<LogRuleFeed>[] = [
    {
      header: 'Name',
      key: 'name',
      width: 200,
      render: (row) => <span className="text-sm font-medium">{row.name}</span>,
    },
    {
      header: 'Kind',
      key: 'kind',
      width: 160,
      render: (row) => (
        <span className="flex items-center gap-1.5">
          <span className={clsx('rounded px-1.5 py-0.5 text-[10px] font-medium uppercase tracking-wide', row.kind === 'github-repo' ? 'bg-accent-sky text-accent-sky-fg' : 'bg-muted text-secondary')}>
            {row.kind}
          </span>
          {row.pathPrefix && <span className="truncate font-mono text-[11px] text-faint" title={row.pathPrefix}>{row.pathPrefix}/</span>}
        </span>
      ),
    },
    {
      header: 'Source',
      key: 'url',
      width: 260,
      render: (row) => <span className="block truncate font-mono text-[11px] text-secondary" title={row.url}>{row.url}</span>,
    },
    {
      header: 'Interval',
      key: 'intervalMinutes',
      width: 90,
      sortAccessor: (row) => row.intervalMinutes,
      render: (row) => <span className="text-xs text-secondary">{row.intervalMinutes > 0 ? `${row.intervalMinutes} min` : 'manual'}</span>,
    },
    {
      header: 'Rules',
      key: 'ruleCount',
      width: 70,
      sortAccessor: (row) => row.ruleCount,
      render: (row) => <span className="text-xs text-secondary">{row.ruleCount}</span>,
    },
    {
      header: 'Last sync',
      key: 'lastSyncAt',
      width: 160,
      sortAccessor: (row) => Date.parse(row.lastSyncAt ?? '') || 0,
      render: (row) =>
        row.lastError ? (
          <span className="inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-xs font-medium bg-danger/20 text-danger-fg" title={String(row.lastError)}>
            {String(row.lastError).slice(0, 60)}{String(row.lastError).length > 60 ? '…' : ''}
          </span>
        ) : row.lastSyncAt ? (
          <span className="text-xs text-secondary" title={new Date(row.lastSyncAt).toLocaleString()}>{timeAgo(row.lastSyncAt)}</span>
        ) : (
          <span className="text-xs text-faint">never</span>
        ),
    },
    {
      header: 'Status',
      key: 'enabled',
      width: 90,
      render: (row) =>
        row.enabled ? (
          <span className="inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-xs font-medium bg-success/20 text-success-fg">active</span>
        ) : (
          <span className="inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-xs font-medium bg-muted text-secondary">disabled</span>
        ),
    },
    {
      header: '',
      key: 'actions',
      width: 180,
      render: (row) => (
        <div className="flex items-center justify-end gap-1">
          <button type="button" onClick={() => void syncNow(row)} disabled={syncingId === row.id} title={`Sync "${row.name}" now`} className="rounded p-1 text-secondary hover:bg-muted disabled:opacity-40">
            {syncingId === row.id ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <RefreshCw className="h-3.5 w-3.5" />}
          </button>
          <button type="button" onClick={() => onEditFeed(row)} title={`Edit "${row.name}"`} className="rounded p-1 text-secondary hover:bg-muted">
            <Pencil className="h-3.5 w-3.5" />
          </button>
          <button type="button" onClick={() => void toggleFeed(row)} title={row.enabled ? 'Disable this feed' : 'Enable this feed'} className="rounded px-2 py-1 text-xs font-medium text-secondary hover:bg-muted">
            {row.enabled ? 'Disable' : 'Enable'}
          </button>
          <button type="button" onClick={() => void deleteFeed(row)} title={`Delete "${row.name}"`} className="rounded p-1 text-secondary hover:bg-danger/20 hover:text-danger-fg">
            <Trash2 className="h-3.5 w-3.5" />
          </button>
        </div>
      ),
    },
  ];

  return (
    <div>
      {feedsQuery.isLoading && <p className="text-sm text-muted-foreground">Loading feeds…</p>}
      {feedsQuery.isError && (
        <p className="text-sm text-danger-fg">Failed to load log rule feeds: {(feedsQuery.error as Error).message}</p>
      )}
      {!feedsQuery.isLoading && (
        <DataTable
          columns={columns}
          rows={feeds}
          rowKey={(row) => row.id}
          storageKey="log-rule-feeds"
          autoRefresh={{ intervalMs: 30_000, queries: [feedsQuery] }}
          searchPlaceholder="Search feeds…"
          emptyMessage={'No log rule feeds yet — add one to sync Sigma rules from a YAML URL or GitHub repository.'}
        />
      )}

      {syncError && (
        <div className="mt-3 rounded-md border border-danger-border bg-danger px-3 py-2 text-xs text-danger-fg">Sync failed: {syncError}</div>
      )}
      {lastSync && (
        <div className="mt-3 rounded-md border border-border bg-muted/30 px-3 py-2 text-xs text-secondary">
          <span className="font-medium">{lastSync.name}</span>: {lastSync.result.created} created · {lastSync.result.updated} updated · {lastSync.result.unchanged} unchanged · {lastSync.result.disabled} disabled
          {lastSync.result.skipped.length > 0 && <> · {lastSync.result.skipped.length} skipped</>}
          {lastSync.result.conflicts.length > 0 && <> · {lastSync.result.conflicts.length} conflicts</>}
          {lastSync.result.skipped.length > 0 && (
            <ul className="mt-1 list-disc pl-4 text-faint">
              {lastSync.result.skipped.slice(0, 5).map((s) => (
                <li key={s.name ?? s.error}>{s.name ? `${s.name}: ` : ''}{s.error}</li>
              ))}
            </ul>
          )}
          {lastSync.result.conflicts.length > 0 && (
            <ul className="mt-1 list-disc pl-4 text-faint">
              {lastSync.result.conflicts.slice(0, 5).map((c) => (
                <li key={c.name}>{c.name} — already owned by a {c.owner} rule</li>
              ))}
            </ul>
          )}
        </div>
      )}
    </div>
  );
}

/** Create/edit dialog for one log rule feed (YAML URL or GitHub repository). */
function FeedDialog({ feed, onClose }: { feed: LogRuleFeed | null; onClose: () => void }) {
  const queryClient = useQueryClient();
  const [name, setName] = useState(feed?.name ?? '');
  const [kind, setKind] = useState<'yaml-url' | 'github-repo'>(feed?.kind ?? 'yaml-url');
  const [url, setUrl] = useState(feed?.url ?? '');
  const [pathPrefix, setPathPrefix] = useState(feed?.pathPrefix ?? '');
  const [intervalMinutes, setIntervalMinutes] = useState(feed ? String(feed.intervalMinutes) : '60');
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function save() {
    if (saving || !name.trim() || !url.trim()) return;
    setSaving(true);
    setError(null);
    try {
      const body = {
        name: name.trim(),
        kind,
        url: url.trim(),
        pathPrefix: kind === 'github-repo' ? (pathPrefix.trim() || null) : null,
        intervalMinutes: Math.max(0, Math.min(1440, Number(intervalMinutes) || 0)),
      };
      if (feed) await api.updateLogRuleFeed(feed.id, body);
      else await api.createLogRuleFeed(body);
      void queryClient.invalidateQueries({ queryKey: ['logRuleFeeds'] });
      onClose();
    } catch (err) {
      setError((err as ApiError).message);
    } finally {
      setSaving(false);
    }
  }

  const fieldCls = 'w-full rounded-md border border-border bg-background px-3 py-2 text-sm focus:border-focus-ring focus:outline-none';
  return (
    <DialogShell title={feed ? `Edit feed — ${feed.name}` : 'New log rule feed'} subtitle="Sync Sigma rules from a YAML URL or GitHub repository. The raw snapshot of each sync is stored in the file repo (tagged log-rules)." onClose={onClose} maxWidth="max-w-xl">
      <div className="space-y-3">
        {error && (
          <div className="rounded-md border border-danger-border bg-danger px-3 py-2 text-xs text-danger-fg">{error}</div>
        )}
        <label className="block text-sm font-medium text-secondary">
          Name
          <input value={name} onChange={(e) => setName(e.target.value)} maxLength={200} placeholder="sigma-base" className={`${fieldCls} mt-1`} />
        </label>
        <div className="grid grid-cols-2 gap-3">
          <label className="block text-sm font-medium text-secondary">
            Kind
            <select value={kind} onChange={(e) => setKind(e.target.value as 'yaml-url' | 'github-repo')} className={`${fieldCls} mt-1`}>
              <option value="yaml-url">YAML URL</option>
              <option value="github-repo">GitHub repository</option>
            </select>
          </label>
          <label className="block text-sm font-medium text-secondary">
            Interval (minutes) <span className="font-normal text-faint">(0 = manual only)</span>
            <input type="number" min={0} max={1440} value={intervalMinutes} onChange={(e) => setIntervalMinutes(e.target.value)} className={`${fieldCls} mt-1`} />
          </label>
        </div>
        <label className="block text-sm font-medium text-secondary">
          {kind === 'yaml-url' ? 'URL (https, serves a YAML file)' : 'Repository (owner/repo or GitHub URL)'}
          <input value={url} onChange={(e) => setUrl(e.target.value)} placeholder={kind === 'yaml-url' ? 'https://example.com/rules.yml' : 'sigmahq/sigma-rulestest'} className={`${fieldCls} mt-1`} />
        </label>
        {kind === 'github-repo' && (
          <label className="block text-sm font-medium text-secondary">
            Path prefix <span className="font-normal text-faint">(optional — subfolder of the repo)</span>
            <input value={pathPrefix} onChange={(e) => setPathPrefix(e.target.value)} placeholder="rules/linux" className={`${fieldCls} mt-1`} />
          </label>
        )}
        <div className="flex justify-end gap-2">
          <button type="button" onClick={onClose} className="rounded-md border border-border px-3 py-1.5 text-sm font-medium text-secondary hover:bg-muted">Cancel</button>
          <button type="button" onClick={() => void save()} disabled={saving || !name.trim() || !url.trim()}
            className="inline-flex items-center gap-2 rounded-md bg-primary px-3 py-1.5 text-sm font-medium text-primary-fg hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-50">
            {saving && <Loader2 className="h-4 w-4 animate-spin" />}
            {feed ? 'Save feed' : 'Add feed'}
          </button>
        </div>
      </div>
    </DialogShell>
  );
}

/** Create dialog for one user rule from a single Sigma document. */
function LogRuleCreateDialog({ onClose }: { onClose: () => void }) {
  const queryClient = useQueryClient();
  const [name, setName] = useState('');
  const [yaml, setYaml] = useState('');
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [details, setDetails] = useState<string[]>([]);

  async function save() {
    if (saving || !yaml.trim()) return;
    setSaving(true);
    setError(null);
    setDetails([]);
    try {
      await api.createLogRule({ yaml: yaml.trim(), ...(name.trim() ? { name: name.trim() } : {}) });
      void queryClient.invalidateQueries({ queryKey: ['logRules'] });
      onClose();
    } catch (err) {
      const e = err as ApiError;
      setError(e.message);
      setDetails(e.details ?? []);
    } finally {
      setSaving(false);
    }
  }

  const fieldCls = 'w-full rounded-md border border-border bg-background px-3 py-2 text-sm focus:border-focus-ring focus:outline-none';
  return (
    <DialogShell title="New log rule" subtitle="One Sigma document — the single-line subset UNM supports." onClose={onClose} maxWidth="max-w-2xl">
      <div className="space-y-3">
        {error && (
          <div className="rounded-md border border-danger-border bg-danger px-3 py-2 text-xs text-danger-fg">
            <p>{error}</p>
            {details.length > 0 && (
              <ul className="mt-1 list-disc pl-4">
                {details.map((d) => (
                  <li key={d}>{d}</li>
                ))}
              </ul>
            )}
          </div>
        )}
        <label className="block text-sm font-medium text-secondary">
          Name <span className="font-normal text-faint">(optional — defaults to the YAML title)</span>
          <input value={name} onChange={(e) => setName(e.target.value)} maxLength={100} placeholder="my-log-rule" className={`${fieldCls} mt-1`} />
        </label>
        <div>
          <label className="mb-1 block text-sm font-medium text-secondary">Sigma YAML</label>
          <textarea value={yaml} onChange={(e) => setYaml(e.target.value)} rows={14} spellCheck={false} placeholder={'title: My rule\ndetection:\n  s:\n    message:\n      contains: "Failed password"\ncondition: s\nunm.threshold:\n  count: 5\n  withinMinutes: 5\n  groupBy: srcIp'} className={`${fieldCls} font-mono text-xs`} />
        </div>
        <p className="text-xs text-faint">
          Supported fields: message, appname, facility, hostname, srcIp, dstIp. Matchers: plain value (case-insensitive equality), list (OR), contains, startswith, endswith, re.
          Add <span className="font-mono">unm.threshold</span> for rolling-window counting (brute-force style).
        </p>
        <div className="flex items-center justify-end gap-2 border-t border-border pt-3">
          <button type="button" onClick={onClose} className="rounded-md px-3 py-1.5 text-sm text-secondary hover:bg-muted">Cancel</button>
          <button type="button" onClick={() => void save()} disabled={saving || !yaml.trim()} className="inline-flex items-center gap-1.5 rounded-md bg-primary px-3 py-1.5 text-sm font-medium text-white hover:bg-primary-hover disabled:opacity-50">
            {saving && <Loader2 size={14} className="animate-spin" />}
            Create rule
          </button>
        </div>
      </div>
    </DialogShell>
  );
}

/** Import dialog — multi-document Sigma YAML; per-rule results, never all-or-nothing. */
function LogRuleImportDialog({ onClose }: { onClose: () => void }) {
  const queryClient = useQueryClient();
  const [yaml, setYaml] = useState('');
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [results, setResults] = useState<LogRuleImportResult[] | null>(null);

  async function run() {
    if (saving || !yaml.trim()) return;
    setSaving(true);
    setError(null);
    try {
      const res = await api.importLogRules(yaml.trim());
      setResults(res.results);
      void queryClient.invalidateQueries({ queryKey: ['logRules'] });
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setSaving(false);
    }
  }

  const fieldCls = 'w-full rounded-md border border-border bg-background px-3 py-2 text-sm focus:border-focus-ring focus:outline-none';
  return (
    <DialogShell title="Import log rules" subtitle="Paste one or more Sigma documents separated by ---. Each document is validated independently." onClose={onClose} maxWidth="max-w-2xl">
      <div className="space-y-3">
        {error && <p className="rounded-md border border-danger-border bg-danger px-3 py-2 text-xs text-danger-fg">{error}</p>}
        <textarea value={yaml} onChange={(e) => setYaml(e.target.value)} rows={14} spellCheck={false} placeholder={'title: First rule\n…\n---\ntitle: Second rule\n…'} className={`${fieldCls} font-mono text-xs`} />
        {results && (
          <div>
            <h4 className="mb-1.5 text-xs font-semibold uppercase tracking-wide text-faint">Results</h4>
            <ul className="max-h-48 space-y-1 overflow-y-auto">
              {results.map((r, i) => (
                <li key={`${r.name ?? 'doc'}-${i}`} className="flex items-baseline gap-2 rounded-md border border-border bg-muted/20 px-3 py-1.5 text-xs" title={r.error}>
                  <span className={`shrink-0 rounded px-1.5 py-0.5 font-medium uppercase ${r.status === 'created' ? 'bg-success/20 text-success-fg' : r.status === 'duplicate' ? 'bg-warning text-warning-fg' : 'bg-danger text-danger-fg'}`}>
                    {r.status}
                  </span>
                  <span className="font-medium">{r.name ?? '(unparseable document)'}</span>
                  {r.error && <span className="text-secondary break-words">{r.error}</span>}
                </li>
              ))}
            </ul>
          </div>
        )}
        <div className="flex items-center justify-end gap-2 border-t border-border pt-3">
          <button type="button" onClick={onClose} className="rounded-md px-3 py-1.5 text-sm text-secondary hover:bg-muted">{results ? 'Close' : 'Cancel'}</button>
          {!results && (
            <button type="button" onClick={() => void run()} disabled={saving || !yaml.trim()} className="inline-flex items-center gap-1.5 rounded-md bg-primary px-3 py-1.5 text-sm font-medium text-white hover:bg-primary-hover disabled:opacity-50">
              {saving && <Loader2 size={14} className="animate-spin" />}
              Import
            </button>
          )}
        </div>
      </div>
    </DialogShell>
  );
}

/** View (and for user rules, edit) the Sigma YAML of one rule; severity override applies to all. */
function LogRuleYamlDialog({ rule, onClose }: { rule: LogRule; onClose: () => void }) {
  const queryClient = useQueryClient();
  const [yaml, setYaml] = useState(rule.sigmaYaml);
  const [severityOverride, setSeverityOverride] = useState<string>(rule.severityOverride ?? '');
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const yamlChanged = rule.source === 'user' && yaml.trim() !== rule.sigmaYaml;
  const sevChanged = (severityOverride || null) !== rule.severityOverride;

  async function save() {
    if (saving || (!yamlChanged && !sevChanged)) return;
    setSaving(true);
    setError(null);
    try {
      await api.updateLogRule(rule.id, {
        ...(yamlChanged ? { yaml: yaml.trim() } : {}),
        ...(sevChanged ? { severityOverride: (severityOverride || null) as 'info' | 'warning' | 'critical' | null } : {}),
      });
      void queryClient.invalidateQueries({ queryKey: ['logRules'] });
      onClose();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setSaving(false);
    }
  }

  const fieldCls = 'w-full rounded-md border border-border bg-background px-3 py-2 text-sm focus:border-focus-ring focus:outline-none';
  return (
    <DialogShell title={rule.source === 'user' ? `Edit rule "${rule.name}"` : `Rule "${rule.name}"`} subtitle={rule.source === 'builtin' ? 'Built-in rules are managed by UNM — the YAML is read-only; disable the rule or override its severity.' : 'The stored name stays stable when you replace the YAML.'} onClose={onClose} maxWidth="max-w-2xl">
      <div className="space-y-3">
        {error && <p className="rounded-md border border-danger-border bg-danger px-3 py-2 text-xs text-danger-fg">{error}</p>}
        {rule.source === 'user' ? (
          <textarea value={yaml} onChange={(e) => setYaml(e.target.value)} rows={14} spellCheck={false} className={`${fieldCls} font-mono text-xs`} />
        ) : (
          <pre className="max-h-96 overflow-y-auto rounded-md border border-border bg-muted/30 p-3 font-mono text-xs">{rule.sigmaYaml}</pre>
        )}
        <div>
          <label className="mb-1 block text-sm font-medium text-secondary">Severity override</label>
          <select value={severityOverride} onChange={(e) => setSeverityOverride(e.target.value)} className={`${fieldCls} w-48`}>
            <option value="">Rule default (from YAML level)</option>
            <option value="info">Info</option>
            <option value="warning">Warning</option>
            <option value="critical">Critical</option>
          </select>
        </div>
        <div className="flex items-center justify-end gap-2 border-t border-border pt-3">
          <button type="button" onClick={onClose} className="rounded-md px-3 py-1.5 text-sm text-secondary hover:bg-muted">{yamlChanged || sevChanged ? 'Cancel' : 'Close'}</button>
          {(yamlChanged || sevChanged) && (
            <button type="button" onClick={() => void save()} disabled={saving} className="inline-flex items-center gap-1.5 rounded-md bg-primary px-3 py-1.5 text-sm font-medium text-white hover:bg-primary-hover disabled:opacity-50">
              {saving && <Loader2 size={14} className="animate-spin" />}
              Save changes
            </button>
          )}
        </div>
      </div>
    </DialogShell>
  );
}

/** Resolver action pill — pass (normal), block (DNSBL hit), drop (policy). */
function DnsActionBadge({ action }: { action: string }) {
  if (action === 'block') {
    return <span className="inline-flex rounded px-1.5 py-0.5 text-xs font-medium bg-danger/20 text-danger-fg">block</span>;
  }
  if (action === 'drop') {
    return <span className="inline-flex rounded px-1.5 py-0.5 text-xs font-medium bg-warning/20 text-warning-fg">drop</span>;
  }
  return <span className="inline-flex rounded px-1.5 py-0.5 text-xs font-medium bg-muted text-secondary">pass</span>;
}

/** DNS section — per-query resolver log from appliances (OPNsense unbound qstats)
 *  plus window aggregates: action counts and the top blocked domains. */
function DnsSection() {
  const [sinceHours, setSinceHours] = useState<24 | 168>(24);
  const [action, setAction] = useState<'all' | 'pass' | 'block' | 'drop'>('all');

  const dnsQuery = useQuery({
    queryKey: ['dnsQueries', sinceHours, action],
    queryFn: () => api.dnsQueries({ sinceHours, action: action === 'all' ? undefined : action }),
    refetchInterval: 30_000,
  });

  const data = dnsQuery.data;
  const rows = data?.rows ?? [];
  const summary = data?.summary;

  const columns: DataTableColumn<DnsQueryEvent>[] = [
    {
      header: 'Time',
      key: 'tsMs',
      width: 130,
      sortAccessor: (row) => row.tsMs,
      exportValue: (row) => new Date(row.tsMs).toISOString(),
      render: (row) => (
        <span className="text-xs text-secondary" title={new Date(row.tsMs).toLocaleString()}>
          {timeAgo(new Date(row.tsMs).toISOString())}
        </span>
      ),
    },
    {
      header: 'Client',
      key: 'client',
      width: 180,
      exportValue: (row) => row.client,
      render: (row) => <span className="font-mono text-xs">{row.client}</span>,
    },
    {
      header: 'Domain',
      key: 'domain',
      width: 260,
      exportValue: (row) => row.domain,
      render: (row) => <span className="font-mono text-xs break-all">{row.domain}</span>,
    },
    {
      header: 'Type',
      key: 'qtype',
      width: 70,
      exportValue: (row) => row.qtype ?? '',
      render: (row) => <span className="text-xs text-secondary">{orDash(row.qtype)}</span>,
    },
    {
      header: 'Action',
      key: 'action',
      width: 90,
      exportValue: (row) => row.action,
      render: (row) => <DnsActionBadge action={row.action} />,
    },
    {
      header: 'Rcode',
      key: 'rcode',
      width: 100,
      exportValue: (row) => row.rcode ?? '',
      render: (row) => <span className="text-xs text-secondary">{orDash(row.rcode)}</span>,
    },
    {
      header: 'Blocklist',
      key: 'blocklist',
      width: 140,
      exportValue: (row) => row.blocklist ?? '',
      render: (row) => <span className="text-xs text-secondary">{orDash(row.blocklist)}</span>,
    },
    {
      header: 'Device',
      key: 'deviceName',
      width: 180,
      exportValue: (row) => row.deviceName ?? '?',
      render: (row) => <span className="text-xs">{orDash(row.deviceName)}</span>,
    },
  ];

  return (
    <div>
      {/* Controls — window + action filter (both server-side). */}
      <div className="mb-3 flex flex-wrap items-center gap-3">
        <label htmlFor="dns-window" className="text-xs text-faint">Window</label>
        <select
          id="dns-window"
          value={String(sinceHours)}
          onChange={(e) => setSinceHours(Number(e.target.value) as 24 | 168)}
          className="rounded-md border border-border bg-background px-2 py-1 text-xs text-foreground"
        >
          <option value="24">Last 24 hours</option>
          <option value="168">Last 7 days</option>
        </select>
        <label htmlFor="dns-action" className="text-xs text-faint">Action</label>
        <select
          id="dns-action"
          value={action}
          onChange={(e) => setAction(e.target.value as 'all' | 'pass' | 'block' | 'drop')}
          className="rounded-md border border-border bg-background px-2 py-1 text-xs text-foreground"
        >
          <option value="all">All</option>
          <option value="pass">Pass</option>
          <option value="block">Block</option>
          <option value="drop">Drop</option>
        </select>
      </div>

      {/* Summary chips — action counts + what the appliance's DNSBL is catching */}
      {dnsQuery.isLoading && <p className="text-sm text-muted-foreground">Loading DNS query events…</p>}
      {dnsQuery.isError && (
        <p className="text-sm text-danger-fg">Failed to load DNS query events: {(dnsQuery.error as Error).message}</p>
      )}
      {summary && (
        <div className="mb-4 flex flex-wrap items-center gap-3 text-sm">
          <span className="inline-flex items-center gap-1 rounded-md bg-muted px-2 py-1 text-xs font-medium text-secondary">
            <Globe className="h-3.5 w-3.5" /> {summary.total.toLocaleString()} queries
          </span>
          {summary.blocked > 0 && (
            <span className="inline-flex items-center gap-1 rounded-md bg-danger/20 px-2 py-1 text-xs font-medium text-danger-fg">
              {summary.blocked.toLocaleString()} blocked
            </span>
          )}
          {summary.dropped > 0 && (
            <span className="inline-flex items-center gap-1 rounded-md bg-warning/20 px-2 py-1 text-xs font-medium text-warning-fg">
              {summary.dropped.toLocaleString()} dropped
            </span>
          )}
          {summary.topBlocked.length > 0 && (
            <span className="flex flex-wrap items-center gap-x-2 gap-y-1 text-xs text-secondary" title="Top blocked domains in the window — what the appliance's own DNSBL is catching">
              <span className="text-faint">top blocked:</span>
              {summary.topBlocked.map((t) => (
                <span key={`${t.domain}|${t.blocklist ?? ''}`} className="inline-flex items-center gap-1 rounded bg-muted px-1.5 py-0.5 font-mono" title={t.blocklist ? `blocked by ${t.blocklist}` : undefined}>
                  {t.domain} <span className="text-faint">×{t.count}</span>
                </span>
              ))}
            </span>
          )}
        </div>
      )}

      {data && (
        <DataTable
          columns={columns}
          rows={rows}
          rowKey={(row) => row.id}
          storageKey="dns-queries"
          autoRefresh={{ intervalMs: 30_000, queries: [dnsQuery] }}
          searchPlaceholder="Search domain or client…"
          emptyMessage={'No DNS query events in this window. Devices that expose a resolver query log push per-query rows to UNM on each telemetry poll — make sure DNS logging is enabled on the appliance and wait for the next poll.'}
        />
      )}
    </div>
  );
}
