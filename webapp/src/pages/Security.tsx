import { useQuery, useQueryClient } from '@tanstack/react-query';
import { Bug, Loader2, RefreshCw, ShieldCheck, ShieldAlert, ShieldX, Info } from 'lucide-react';
import { useState } from 'react';
import { Layout } from '../components/Layout';
import { DataTable, DataTableColumn } from '../components/DataTable';
import { DeviceChip } from '../components/DeviceChip';
import { api, SecurityCheckRow, CveVulnerabilityRow } from '../api/client';

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
  const cveVulnsQuery = useQuery({
    queryKey: ['cveVulnerabilities'],
    queryFn: () => api.cveVulnerabilities(),
    refetchInterval: 30_000,
  });

  // "Refresh advisories" runs one full fetch cycle server-side (~3.5 min) — fire
  // and forget; the summary's lastSuccessAt/lastError surface the outcome.
  const [refreshingCves, setRefreshingCves] = useState(false);
  async function refreshAdvisories() {
    if (refreshingCves) return;
    setRefreshingCves(true);
    try {
      await api.refreshCveAdvisories();
      void queryClient.invalidateQueries({ queryKey: ['cveSummary'] });
      void queryClient.invalidateQueries({ queryKey: ['cveVulnerabilities'] });
    } catch (err) {
      // The cycle itself never throws — a 502 here means the fetch FAILED and
      // its error is already in lastError. Still surface it as a notice.
      void queryClient.invalidateQueries({ queryKey: ['cveSummary'] });
      console.warn('CVE advisory refresh reported an error:', (err as Error).message);
    } finally {
      setRefreshingCves(false);
    }
  }

  const cveRows = cveVulnsQuery.data?.rows ?? [];
  const summary = cveSummaryQuery.data;

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
      header: 'Ecosystem',
      key: 'ecosystem',
      width: 120,
      exportValue: (row) => row.ecosystem,
      render: (row) => <span className="text-xs text-secondary">{orDash(row.ecosystem)}</span>,
    },
    {
      header: 'Summary',
      key: 'summary',
      width: 420,
      exportValue: (row) => row.summary ?? '',
      render: (row) =>
        row.summary && row.summary.trim() !== '' ? (
          <span className="text-xs text-secondary break-words">{row.summary}</span>
        ) : (
          <span className="text-faint">—</span>
        ),
    },
  ];

  return (
    <Layout title="Security">
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

      {/* CVE vulnerability tracking — installed packages matched against known advisories */}
      <div className="mt-8">
        <div className="mb-3 flex items-center justify-between gap-3">
          <h2 className="flex items-center gap-2 text-sm font-semibold text-foreground">
            <Bug className="h-4 w-4" /> Vulnerabilities (CVEs)
          </h2>
          {summary && summary.totalMatches > 0 && (
            <button
              type="button"
              onClick={() => void refreshAdvisories()}
              disabled={refreshingCves}
              title="Fetch the latest advisories from OSV and re-match all installed packages (~3.5 min)"
              className="inline-flex items-center gap-2 rounded-md border border-border px-3 py-1.5 text-sm font-medium text-secondary hover:bg-muted disabled:opacity-60"
            >
              {refreshingCves ? <Loader2 className="h-4 w-4 animate-spin" /> : <RefreshCw className="h-4 w-4" />} Refresh advisories
            </button>
          )}
        </div>

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
                {(Object.entries(summary.bySeverity) as Array<[string, number]>).filter(([, n]) => n > 0).map(([rank, n]) => (
                  <span key={rank} className={`inline-flex items-center gap-1 rounded-md px-2 py-1 text-xs font-medium ${RANK_STYLES[rank] ?? 'bg-muted text-secondary'}`}>
                    {n.toLocaleString()} {rank}
                  </span>
                ))}
                <span className="text-faint">·</span>
                <span className="text-sm text-secondary">
                  on <strong className="text-foreground">{summary.affectedDevices}</strong> device{summary.affectedDevices === 1 ? '' : 's'}
                </span>
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

        {cveVulnsQuery.data && (
          <DataTable
            columns={cveColumns}
            rows={cveRows}
            rowKey={(row) => `${row.deviceId}|${row.pluginId}|${row.packageName}|${row.cveId}`}
            storageKey="security-cves"
            autoRefresh={{ intervalMs: 30_000, queries: [cveVulnsQuery] }}
            searchPlaceholder="Search package or CVE id…"
            emptyMessage="No known vulnerabilities — packages are matched against OSV advisories once the fleet's installed-package inventory is collected (Generic SSH plugin on Linux hosts) and at least one advisory fetch has succeeded."
          />
        )}
      </div>
    </Layout>
  );
}
