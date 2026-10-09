import { useQuery } from '@tanstack/react-query';
import { ShieldCheck, ShieldAlert, ShieldX, Info } from 'lucide-react';
import { Layout } from '../components/Layout';
import { DataTable, DataTableColumn } from '../components/DataTable';
import { DeviceChip } from '../components/DeviceChip';
import { api, SecurityCheckRow } from '../api/client';

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
    </Layout>
  );
}
