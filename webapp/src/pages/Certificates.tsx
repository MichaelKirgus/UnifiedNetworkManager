import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Check, History, ShieldAlert } from 'lucide-react';
import { Layout } from '../components/Layout';
import { DataTable, DataTableColumn } from '../components/DataTable';
import { DeviceChip } from '../components/DeviceChip';
import { api, CertificateHistoryRow, CertificateRow } from '../api/client';
import { can } from '../auth/permissions';
import { useTimeFormat } from '../utils/time';

/** Short fingerprint for inline display ("SHA256:abc…xyz"). */
function shortFp(fp?: string | null): string {
  if (!fp) return '—';
  const body = fp.replace(/^SHA256:/i, '');
  return body.length > 16 ? `${body.slice(0, 8)}…${body.slice(-6)}` : body;
}

/**
 * Expandable detail for a MISMATCHED endpoint: shows the trusted vs observed key,
 * the fingerprint history (which key was used when), and an "Accept" action that
 * re-pins the currently-observed key (clears the condition after a legit re-key).
 */
function MismatchDetail({ row }: { row: CertificateRow }) {
  const queryClient = useQueryClient();
  const { formatDateTime } = useTimeFormat();

  const historyQuery = useQuery({
    queryKey: ['certificateHistory', row.deviceId, row.name],
    queryFn: () => api.certificateHistory(row.deviceId, row.name, 20),
  });

  const acceptMutation = useMutation({
    mutationFn: (fp?: string) => api.acceptCertificate(row.deviceId, row.name, fp),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ['certificates'] });
      void queryClient.invalidateQueries({ queryKey: ['navCounts'] });
    },
  });

  const canWrite = can('certificates:write');
  const history = historyQuery.data ?? [];

  return (
    <div className="space-y-3 py-1">
      <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs">
        <span className="inline-flex items-center gap-1.5 font-medium text-danger-fg">
          <ShieldAlert className="h-4 w-4" /> Certificate / host key changed — strict pinning is refusing connections
        </span>
      </div>

      <div className="grid grid-cols-1 gap-x-6 gap-y-1 sm:grid-cols-2">
        <div>
          <div className="text-[10px] uppercase tracking-wide text-faint">Trusted (pinned)</div>
          <span className="font-mono text-xs break-all">{row.trustedFingerprint ?? '—'}</span>
        </div>
        <div>
          <div className="text-[10px] uppercase tracking-wide text-faint">Observed now</div>
          <span className="font-mono text-xs break-all text-danger-fg">{row.fingerprint ?? '—'}</span>
        </div>
      </div>

      {canWrite && (
        <div className="flex flex-wrap items-center gap-2">
          <button
            type="button"
            onClick={() => acceptMutation.mutate(undefined)}
            disabled={acceptMutation.isPending}
            title="Set the trusted fingerprint to the key currently presented by the endpoint"
            className="inline-flex items-center gap-1.5 rounded-md bg-primary px-3 py-1.5 text-xs font-medium text-white hover:bg-primary-hover disabled:opacity-50"
          >
            <Check className="h-3.5 w-3.5" />
            {acceptMutation.isPending ? 'Accepting…' : 'Accept new key (re-pin)'}
          </button>
          {acceptMutation.isSuccess && (
            <span className="text-xs text-success-fg">Accepted — the endpoint is pinned to its current key.</span>
          )}
          {acceptMutation.isError && (
            <span className="text-xs text-danger-fg">{(acceptMutation.error as Error).message}</span>
          )}
        </div>
      )}

      <div>
        <div className="mb-1 flex items-center gap-1.5 text-[10px] uppercase tracking-wide text-faint">
          <History className="h-3.5 w-3.5" /> Fingerprint history (newest first)
        </div>
        {historyQuery.isLoading && <span className="text-xs text-secondary">Loading…</span>}
        {!historyQuery.isLoading && history.length === 0 && (
          <span className="text-xs text-faint">No history recorded yet.</span>
        )}
        {history.length > 0 && (
          <div className="overflow-x-auto rounded border border-border">
            <table className="w-full text-left text-xs">
              <thead className="bg-background/60 text-[10px] uppercase tracking-wide text-faint">
                <tr>
                  <th className="px-2 py-1.5 font-medium">Fingerprint</th>
                  <th className="px-2 py-1.5 font-medium">Key</th>
                  <th className="px-2 py-1.5 font-medium">First seen</th>
                  <th className="px-2 py-1.5 font-medium">Last seen</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {history.map((h: CertificateHistoryRow) => (
                  <tr key={h.fingerprint} className={h.fingerprint === row.trustedFingerprint ? 'bg-success/10' : h.fingerprint === row.fingerprint ? 'bg-danger/10' : undefined}>
                    <td className="px-2 py-1.5 font-mono text-[11px] break-all">
                      {shortFp(h.fingerprint)}
                      {h.fingerprint === row.trustedFingerprint && (
                        <span className="ml-1.5 rounded bg-success/20 px-1 py-0.5 text-[9px] font-semibold uppercase text-success-fg">trusted</span>
                      )}
                      {h.fingerprint !== row.trustedFingerprint && h.fingerprint === row.fingerprint && (
                        <span className="ml-1.5 rounded bg-danger/20 px-1 py-0.5 text-[9px] font-semibold uppercase text-danger-fg">observed</span>
                      )}
                    </td>
                    <td className="whitespace-nowrap px-2 py-1.5 font-mono text-[11px]">{h.keyAlgorithm || '—'}{h.keySizeBits ? ` ${h.keySizeBits}` : ''}</td>
                    <td className="whitespace-nowrap px-2 py-1.5 text-secondary">{formatDateTime(h.firstSeenAt)}</td>
                    <td className="whitespace-nowrap px-2 py-1.5 text-secondary">{formatDateTime(h.lastSeenAt)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}

/** Small colored pill for the endpoint kind. */
const TYPE_STYLES: Record<CertificateRow['type'], string> = {
  https: 'bg-accent-teal text-accent-teal-fg',
  ssh: 'bg-accent-indigo text-accent-indigo-fg',
};

function TypeBadge({ type }: { type: CertificateRow['type'] }) {
  return (
    <span className={`inline-flex rounded px-1.5 py-0.5 text-xs font-medium uppercase ${TYPE_STYLES[type] ?? 'bg-muted text-secondary'}`}>
      {type}
    </span>
  );
}

/** "—" for empty/unknown values. */
function orDash(v?: string | null): string {
  return v && v.trim() !== '' ? v : '—';
}

/**
 * Expiry cell for the LEAF cert. Red when expired, amber within `warnDays`,
 * green otherwise. Also flags an EXPIRED ISSUER (chainDaysToExpiry < 0) even
 * when the leaf itself is still valid — that's a real break in the chain.
 */
function ExpiryCell({ row, warnDays = 30 }: { row: CertificateRow; warnDays?: number }) {
  const { formatDate } = useTimeFormat();
  if (row.type === 'ssh') return <span className="text-faint">n/a</span>;

  const leaf = row.daysToExpiry;
  const chain = row.chainDaysToExpiry;

  // Expired issuer is the most severe — surface it first.
  if (chain !== null && chain !== undefined && chain < 0) {
    return (
      <div className="flex flex-col gap-0.5">
        <span className="text-xs font-medium text-danger-fg">issuer expired {-chain}d ago</span>
        {leaf !== null && leaf !== undefined && (
          <span className="font-mono text-[11px] text-secondary">leaf: {formatDate(row.notAfter)}</span>
        )}
      </div>
    );
  }

  if (leaf === null || leaf === undefined) return <span className="text-faint">—</span>;
  const cls = leaf < 0 ? 'text-danger-fg' : leaf <= warnDays ? 'text-warning-fg' : 'text-success-fg';
  const label = leaf < 0 ? `expired ${-leaf}d ago` : `${leaf}d left`;
  return (
    <div className="flex flex-col gap-0.5">
      <span className={`font-mono text-xs font-medium ${cls}`}>{label}</span>
      <span className="text-[11px] text-secondary">{formatDate(row.notAfter)}</span>
    </div>
  );
}

/** Chain-validation verdict badge (valid / invalid / unknown). */
function ValidBadge({ row }: { row: CertificateRow }) {
  if (row.type === 'ssh') return <span className="text-faint">—</span>;
  if (row.valid === true) {
    return <span className="inline-flex rounded bg-success/15 px-1.5 py-0.5 text-xs font-medium text-success-fg">valid</span>;
  }
  if (row.valid === false) {
    return (
      <span title={row.invalidReason ?? undefined} className="inline-flex cursor-help rounded bg-danger/15 px-1.5 py-0.5 text-xs font-medium text-danger-fg">
        invalid
      </span>
    );
  }
  return <span className="text-faint">unknown</span>;
}

/** Key algorithm + size, e.g. "RSA 2048" / "ECDSA P-256" / "ED25519". */
function keyLabel(row: CertificateRow): string {
  const alg = (row.keyAlgorithm ?? '').trim();
  if (!alg) return '—';
  if (row.curveName) return `${alg} ${row.curveName}`;
  if (row.keySizeBits) return `${alg} ${row.keySizeBits}`;
  return alg;
}

/** At-a-glance security overview: total endpoints, expiring soon, expired, invalid chains. */
function SummaryStrip({ rows }: { rows: CertificateRow[] }) {
  const https = rows.filter((r) => r.type === 'https');
  const ssh = rows.length - https.length;
  const devices = new Set(rows.map((r) => r.deviceId)).size;
  // Expired = leaf OR any chain element (issuer) already past its validity window.
  const isExpired = (r: CertificateRow): boolean =>
    (r.daysToExpiry != null && r.daysToExpiry < 0) || (r.chainDaysToExpiry != null && r.chainDaysToExpiry < 0);
  const expired = https.filter(isExpired).length;
  // Expiring soon = leaf within 30 days, not already expired.
  const expiringSoon = https.filter(
    (r) => !isExpired(r) && r.daysToExpiry != null && r.daysToExpiry >= 0 && r.daysToExpiry <= 30
  ).length;
  const invalid = https.filter((r) => r.valid === false).length;
  // Key changed since UNM pinned it — strict pinning refuses these endpoints.
  const mismatched = rows.filter((r) => r.fingerprintMismatch).length;

  const cell = (label: string, value: number | string, tone?: 'danger' | 'warning') => (
    <div className="flex items-baseline gap-2 rounded-lg border bg-card px-3 py-2">
      <span className={`text-xl font-semibold ${tone === 'danger' ? 'text-danger-fg' : tone === 'warning' ? 'text-warning-fg' : 'text-foreground'}`}>
        {value}
      </span>
      <span className="text-xs text-secondary">{label}</span>
    </div>
  );

  return (
    <div className="mb-3 flex flex-wrap gap-2">
      {cell('endpoints', rows.length)}
      {cell('devices', devices)}
      {cell('TLS certs', https.length)}
      {cell('SSH host keys', ssh)}
      {expired > 0 ? cell('expired', expired, 'danger') : null}
      {expiringSoon > 0 ? cell('expiring ≤30d', expiringSoon, 'warning') : null}
      {invalid > 0 ? cell('invalid chain', invalid, 'danger') : null}
      {mismatched > 0 ? cell('key changed', mismatched, 'danger') : null}
    </div>
  );
}

export default function Certificates() {
  const { formatDateTime } = useTimeFormat();
  // The API polls plugins on the inventory window and upserts these rows — refresh
  // at a relaxed cadence (certificates change rarely).
  const certsQuery = useQuery({
    queryKey: ['certificates'],
    queryFn: () => api.certificates(),
    refetchInterval: 60_000,
  });

  const columns: DataTableColumn<CertificateRow>[] = [
    {
      header: 'Endpoint',
      key: 'name',
      width: 150,
      render: (row) => (
        <div className="flex items-center gap-2">
          <TypeBadge type={row.type} />
          <span className="font-mono text-xs">{row.name}</span>
        </div>
      ),
    },
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
      header: 'Subject / CN',
      key: 'commonName',
      width: 200,
      render: (row) => <span className="font-medium text-foreground">{orDash(row.commonName)}</span>,
    },
    {
      header: 'Issuer',
      key: 'issuer',
      width: 220,
      exportValue: (row) => row.issuer ?? '',
      render: (row) => (
        <div className="flex flex-col gap-0.5">
          <span className="truncate text-xs" title={orDash(row.issuer)}>
            {orDash(row.issuer)}
          </span>
          {row.selfSigned && row.type === 'https' && (
            <span className="inline-flex w-fit rounded bg-muted px-1 py-0.5 text-[10px] uppercase tracking-wide text-secondary">self-signed</span>
          )}
        </div>
      ),
    },
    {
      header: 'Expiry',
      key: 'daysToExpiry',
      width: 160,
      sortAccessor: (row) => row.daysToExpiry ?? Number.MAX_SAFE_INTEGER,
      render: (row) => <ExpiryCell row={row} />,
    },
    {
      header: 'Key',
      key: 'keyAlgorithm',
      width: 130,
      exportValue: (row) => keyLabel(row),
      render: (row) => <span className="font-mono text-xs">{keyLabel(row)}</span>,
    },
    {
      header: 'Chain',
      key: 'valid',
      width: 100,
      exportValue: (row) => (row.valid === true ? 'valid' : row.valid === false ? `invalid: ${row.invalidReason ?? ''}` : 'unknown'),
      render: (row) => <ValidBadge row={row} />,
    },
    {
      header: 'Fingerprint',
      key: 'fingerprint',
      width: 200,
      exportValue: (row) => row.fingerprint ?? '',
      render: (row) =>
        row.fingerprint ? (
          <div className="flex flex-col gap-0.5">
            {row.fingerprintMismatch && (
              <span
                title={`Trusted ${row.trustedFingerprint} — observed ${row.fingerprint}. Strict pinning refuses connections until the new key is accepted.`}
                className="inline-flex w-fit cursor-help items-center gap-1 rounded bg-danger/15 px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-danger-fg"
              >
                <ShieldAlert className="h-3 w-3" /> key changed
              </span>
            )}
            <span className="font-mono text-[11px] break-all" title={row.fingerprint}>
              {row.fingerprint.length > 28 ? `${row.fingerprint.slice(0, 25)}…` : row.fingerprint}
            </span>
          </div>
        ) : (
          <span className="text-faint">—</span>
        ),
    },
    {
      header: 'Collected',
      key: 'collectedAt',
      width: 170,
      sortAccessor: (row) => new Date(row.collectedAt).getTime(),
      render: (row) => <span className="text-xs text-secondary">{formatDateTime(row.collectedAt)}</span>,
    },
  ];

  return (
    <Layout title="Certificates">
      {certsQuery.isLoading && <p className="text-sm text-muted-foreground">Loading certificates…</p>}
      {certsQuery.isError && (
        <p className="text-sm text-danger-fg">Failed to load certificates: {(certsQuery.error as Error).message}</p>
      )}
      {certsQuery.data && (
        <>
          <SummaryStrip rows={certsQuery.data} />
          <p className="mb-3 max-w-4xl text-xs text-muted-foreground">
            TLS certificates served by device management endpoints and SSH host keys, collected per inventory poll. The chain is validated for
            expiry of every element — an expired issuer is flagged even when the leaf itself is still valid. Expiry/invalidity also raises a
            notification (auto-resolved once renewed).
          </p>
          <DataTable
            columns={columns}
            rows={certsQuery.data}
            rowKey={(row) => `${row.deviceId}|${row.pluginId}|${row.name}`}
            storageKey="certificates"
            autoRefresh={{ intervalMs: 60_000, queries: [certsQuery] }}
            searchPlaceholder="Search certificates…"
            emptyMessage="No certificates collected yet — assign a router plugin (OPNsense, RouterOS, LANCOM, TrueNAS or FRITZ!Box) to a device and wait for the next inventory poll."
            renderRowDetail={(row) =>
              row.fingerprintMismatch ? <MismatchDetail row={row} /> : null
            }
          />
        </>
      )}
    </Layout>
  );
}
