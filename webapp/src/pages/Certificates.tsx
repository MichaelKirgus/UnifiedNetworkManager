import { useQuery } from '@tanstack/react-query';
import { Layout } from '../components/Layout';
import { DataTable, DataTableColumn } from '../components/DataTable';
import { DeviceChip } from '../components/DeviceChip';
import { api, CertificateRow } from '../api/client';

/** Small colored pill for the endpoint kind. */
const TYPE_STYLES: Record<CertificateRow['type'], string> = {
  https: 'bg-teal-100 text-teal-700',
  ssh: 'bg-indigo-100 text-indigo-700',
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

/** Formats an ISO date as a short local date ("2026-12-31"). */
function fmtDate(iso?: string | null): string {
  if (!iso) return '—';
  const t = Date.parse(iso);
  if (!Number.isFinite(t)) return iso;
  return new Date(t).toLocaleDateString();
}

/**
 * Expiry cell for the LEAF cert. Red when expired, amber within `warnDays`,
 * green otherwise. Also flags an EXPIRED ISSUER (chainDaysToExpiry < 0) even
 * when the leaf itself is still valid — that's a real break in the chain.
 */
function ExpiryCell({ row, warnDays = 30 }: { row: CertificateRow; warnDays?: number }) {
  if (row.type === 'ssh') return <span className="text-faint">n/a</span>;

  const leaf = row.daysToExpiry;
  const chain = row.chainDaysToExpiry;

  // Expired issuer is the most severe — surface it first.
  if (chain !== null && chain !== undefined && chain < 0) {
    return (
      <div className="flex flex-col gap-0.5">
        <span className="text-xs font-medium text-danger-fg">issuer expired {-chain}d ago</span>
        {leaf !== null && leaf !== undefined && (
          <span className="font-mono text-[11px] text-secondary">leaf: {fmtDate(row.notAfter)}</span>
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
      <span className="text-[11px] text-secondary">{fmtDate(row.notAfter)}</span>
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
    </div>
  );
}

export default function Certificates() {
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
          <span className="font-mono text-[11px] break-all" title={row.fingerprint}>
            {row.fingerprint.length > 28 ? `${row.fingerprint.slice(0, 25)}…` : row.fingerprint}
          </span>
        ) : (
          <span className="text-faint">—</span>
        ),
    },
    {
      header: 'Collected',
      key: 'collectedAt',
      width: 170,
      sortAccessor: (row) => new Date(row.collectedAt).getTime(),
      render: (row) => <span className="text-xs text-secondary">{new Date(row.collectedAt).toLocaleString()}</span>,
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
          />
        </>
      )}
    </Layout>
  );
}
