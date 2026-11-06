import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Activity, Check, Copy, Download, KeyRound, Network, Plus, RefreshCw, Wifi } from 'lucide-react';
import { Layout } from '../components/Layout';
import { DialogShell } from '../components/DialogShell';
import { DataTable, DataTableColumn } from '../components/DataTable';
import { api, CaStatus, CaKeyType, RadiusAuthLogRow, RadiusNasClient, RadiusStatus, RadiusUserProfile, Secret, WifiClientCert } from '../api/client';
import { can } from '../auth/permissions';
import { useTimeFormat } from '../utils/time';

/** Triggers a browser download of an already-fetched blob under `name`. */
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

/** Base64 → Blob (for the P12 download). */
function base64ToBlob(b64: string, type = 'application/x-pkcs12'): Blob {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return new Blob([bytes], { type });
}

/**
 * Client platforms that import the EAP-TLS cert. Windows/Android/iOS/macOS all
 * consume PKCS#12 (.p12) — PEM is offered as a generic fallback (Linux, custom
 * supplicants). `steps` = short per-platform import instructions shown in the
 * install dialog after the download starts.
 */
const INSTALL_PLATFORMS: Array<{ id: string; label: string; format: 'pem' | 'p12'; steps: string[] }> = [
  {
    id: 'windows',
    label: 'Windows (.p12)',
    format: 'p12',
    steps: [
      'Double-click the .p12 file and follow the Personal Certificates import wizard.',
      'Enter the password shown below when prompted (twice).',
      'Keep "Export this private key" selected; finish the wizard. The cert appears in certmgr.msc → Personal.',
    ],
  },
  {
    id: 'android',
    label: 'Android (.p12)',
    format: 'p12',
    steps: [
      'Copy the .p12 file to the phone (e.g. via USB or a shared link).',
      'Settings → Security → Encryption & credentials → Install certificates → VPN and apps.',
      'Pick the .p12 file and enter the password shown below.',
    ],
  },
  {
    id: 'ios',
    label: 'iOS (.p12)',
    format: 'p12',
    steps: [
      'Open the .p12 file on the iPhone/iPad (e.g. from Files or Mail).',
      'Settings → General → VPN & Device Management → import the profile, then enter the password shown below.',
      'Trust the UNM CA root under Settings → General → About → Certificate Trust Settings if prompted.',
    ],
  },
  {
    id: 'macos',
    label: 'macOS (.p12)',
    format: 'p12',
    steps: [
      'Double-click the .p12 file and import it into the "login" keychain.',
      'Enter the password shown below when prompted.',
      'In Keychain Access, double-click the imported certificate → Trust → set "When using this certificate" to Always Trust.',
    ],
  },
  {
    id: 'pem',
    label: 'PEM bundle (Linux / other)',
    format: 'pem',
    steps: [
      'The file contains the full chain plus the private key in one PEM document.',
      'Install per your supplicant, e.g. copy to /etc/ssl and reference it from wpa_supplicant/wpa_supplicant-iwd (EAP-TLS).',
    ],
  },
];

/** The optional RADIUS plugin advertises this capability — its presence is what
 * makes the EAP-TLS sections relevant on this instance. */
const RADIUS_CAPABILITY = 'radius';

/** localStorage key for "show the WiFi section even without a radius plugin". */
const WIFI_FORCE_SHOW_KEY = 'unm.wifiCerts.forceShow';

function readWifiForceShow(): boolean {
  try {
    return window.localStorage.getItem(WIFI_FORCE_SHOW_KEY) === '1';
  } catch {
    return false;
  }
}

/** Copy text to the clipboard with a transient "copied" state. */
function useCopyState(): [boolean, (text: string) => void] {
  const [copied, setCopied] = useState(false);
  const copy = (text: string) => {
    void navigator.clipboard?.writeText(text).then(
      () => {
        setCopied(true);
        setTimeout(() => setCopied(false), 2_000);
      },
      () => undefined,
    );
  };
  return [copied, copy];
}

/** Password display for a downloaded P12 — mono field + copy button. */
function P12PasswordPanel({ password }: { password: string }) {
  const [copied, copy] = useCopyState();
  return (
    <div className="rounded-md border bg-background p-3">
      <div className="mb-1 text-[10px] uppercase tracking-wide text-faint">Import password — enter this when the import dialog asks</div>
      <div className="flex items-center gap-2">
        <code className="flex-1 select-all break-all rounded bg-muted/50 px-2 py-1.5 font-mono text-xs">{password}</code>
        <button
          type="button"
          onClick={() => copy(password)}
          title="Copy password"
          className="inline-flex shrink-0 items-center gap-1 rounded border px-2 py-1.5 text-[10px] font-medium hover:bg-muted/40"
        >
          {copied ? <Check className="h-3 w-3 text-success-fg" /> : <Copy className="h-3 w-3" />}
          {copied ? 'Copied' : 'Copy'}
        </button>
      </div>
      <p className="mt-1.5 text-[10px] text-faint">The password is generated per download and only shown here — store it together with the .p12 file if you may need to re-import.</p>
    </div>
  );
}

/**
 * Install dialog for one WiFi client cert: pick the target platform, download
 * the matching bundle (P12 for Windows/Android/iOS/macOS, PEM otherwise), and
 * get per-platform import steps + the P12 password.
 */
function WifiInstallDialog({ row, onClose }: { row: WifiClientCert; onClose: () => void }) {
  const [platformId, setPlatformId] = useState('windows');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [p12Password, setP12Password] = useState<string | null>(null);

  const platform = INSTALL_PLATFORMS.find((p) => p.id === platformId) ?? INSTALL_PLATFORMS[0];

  async function download() {
    setBusy(true);
    setError(null);
    try {
      if (platform.format === 'p12') {
        const bundle = await api.caWifiDownloadP12(row.serial);
        saveBlob(base64ToBlob(bundle.p12Base64), `${row.cn}-eaptls.p12`);
        setP12Password(bundle.password);
      } else {
        saveBlob(await api.caWifiDownload(row.serial), `${row.cn}-eaptls.pem`);
        setP12Password(null);
      }
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <DialogShell
      title={`Install certificate — ${row.name}`}
      subtitle={`${row.cn} · valid until ${new Date(row.notAfter).toLocaleDateString()}`}
      icon={<Wifi className="h-4 w-4" />}
      onClose={onClose}
      maxWidth="max-w-md"
    >
      <div className="space-y-3">
        <label className="flex flex-col gap-1 text-[10px] uppercase tracking-wide text-faint">
          Target platform
          <select value={platformId} onChange={(e) => setPlatformId(e.target.value)} className="w-full rounded-md border bg-background px-2 py-1.5 text-xs normal-case tracking-normal">
            {INSTALL_PLATFORMS.map((p) => (
              <option key={p.id} value={p.id}>{p.label}</option>
            ))}
          </select>
        </label>

        <button
          type="button"
          onClick={() => void download()}
          disabled={busy}
          className="inline-flex w-full items-center justify-center gap-1.5 rounded-md bg-primary px-3 py-2 text-xs font-medium text-white hover:bg-primary-hover disabled:opacity-50"
        >
          <Download className={`h-3.5 w-3.5 ${busy ? 'animate-pulse' : ''}`} />
          {busy ? 'Preparing…' : `Download ${platform.format === 'p12' ? '.p12 file' : 'PEM bundle'}`}
        </button>

        {error && <div className="text-xs text-danger-fg">{error}</div>}

        {p12Password !== null && (
          <>
            <P12PasswordPanel password={p12Password} />
            <ol className="list-decimal space-y-1 pl-4 text-[11px] text-secondary">
              {platform.steps.map((s) => (
                <li key={s}>{s}</li>
              ))}
            </ol>
          </>
        )}

        {p12Password === null && !error && (
          <p className="text-[11px] text-faint">Pick the platform matching the device you are configuring, then download. The file contains the full certificate chain plus the private key.</p>
        )}
      </div>
    </DialogShell>
  );
}

/** Days until an ISO date (negative when already past). */
function daysUntil(iso?: string | null): number | null {
  if (!iso) return null;
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return null;
  return Math.floor((t - Date.now()) / 86_400_000);
}

/** One CA chain element: name, expiry date + colored days-left badge. */
function ChainChip({ label, iso }: { label: string; iso?: string | null }) {
  const { formatDate } = useTimeFormat();
  const d = daysUntil(iso);
  if (d === null) return <span className="text-xs text-faint">{label}: unknown</span>;
  const cls = d < 0 ? 'bg-danger/15 text-danger-fg' : d <= 365 ? 'bg-warning/15 text-warning-fg' : 'bg-success/15 text-success-fg';
  return (
    <span className="inline-flex items-center gap-2 rounded-md border bg-card px-2.5 py-1.5">
      <span className="text-xs font-medium">{label}</span>
      <span className="font-mono text-[11px] text-secondary">{formatDate(iso!)}</span>
      <span className={`rounded px-1.5 py-0.5 font-mono text-[10px] font-semibold ${cls}`}>
        {d < 0 ? `expired ${-d}d ago` : `${d}d left`}
      </span>
    </span>
  );
}

/**
 * WiFi (EAP-TLS) client certificates — UNM's own CA issues long-lived certs for
 * 802.1X supplicants. Shows the CA chain health, an enrollment form (all fields
 * overridable), and the enrolled-certs table with install/revoke actions.
 *
 * VISIBILITY: EAP-TLS only matters when a RADIUS server plugin is loaded on this
 * instance (capability 'radius'). Without one, the section collapses into a slim
 * hint card — but can be re-shown ("Show anyway", persisted) for setups where an
 * external RADIUS/EAP server consumes UNM-issued certificates. The gate lives in
 * THIS component; all data hooks live in WifiCertsPanel below (rules of hooks).
 */
function WifiCertsSection() {
  // Plugin-aware visibility — is any loaded plugin advertising the 'radius' capability?
  const pluginsQuery = useQuery({ queryKey: ['plugins'], queryFn: api.plugins, staleTime: 5 * 60_000 });
  const radiusLoaded = (pluginsQuery.data ?? []).some((p) => (p.capabilities ?? []).includes(RADIUS_CAPABILITY));
  const [forceShow, setForceShow] = useState(readWifiForceShow);

  function persistForceShow(v: boolean): void {
    setForceShow(v);
    try { window.localStorage.setItem(WIFI_FORCE_SHOW_KEY, v ? '1' : '0'); } catch { /* ignore */ }
  }

  if (!radiusLoaded && !forceShow) {
    return (
      <section className="mb-6 rounded-lg border bg-card p-3">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="flex items-center gap-2 text-xs text-secondary">
            <Wifi className="h-4 w-4 shrink-0" />
            <span>
              WiFi client certificates (EAP-TLS) are available when a RADIUS server plugin is loaded — none is currently.
              {pluginsQuery.isLoading ? ' Checking plugins…' : ''}
            </span>
          </div>
          <button
            type="button"
            onClick={() => persistForceShow(true)}
            className="rounded-md border px-2.5 py-1 text-[10px] font-medium hover:bg-muted/40"
          >
            Show anyway (external RADIUS)
          </button>
        </div>
      </section>
    );
  }

  return <WifiCertsPanel radiusLoaded={radiusLoaded} onHide={() => persistForceShow(false)} />;
}

/** The full WiFi EAP-TLS section body — CA chain health, enrollment form, table. */
function WifiCertsPanel({ radiusLoaded, onHide }: { radiusLoaded: boolean; onHide: () => void }) {
  const queryClient = useQueryClient();
  const canManage = can('ca:manage');

  // Install dialog target (a full table row, or a minimal one right after enrollment).
  const [installRow, setInstallRow] = useState<WifiClientCert | null>(null);

  const statusQuery = useQuery({
    queryKey: ['caStatus'],
    queryFn: () => api.caStatus(),
    refetchInterval: 60_000,
  });
  const wifiQuery = useQuery({
    queryKey: ['caWifiCerts'],
    queryFn: () => api.caWifiCerts(),
    refetchInterval: 60_000,
  });

  // Enrollment form state.
  const [name, setName] = useState('');
  const [cn, setCn] = useState('');
  const [organization, setOrganization] = useState('');
  const [organizationalUnit, setOrganizationalUnit] = useState('');
  const [sans, setSans] = useState('');
  const [keyType, setKeyType] = useState<CaKeyType>('ec-p256');
  const [days, setDays] = useState('');

  const enrollMutation = useMutation({
    mutationFn: () =>
      api.caEnroll({
        name: name.trim(),
        cn: cn.trim() || undefined,
        organization: organization.trim() || undefined,
        organizationalUnit: organizationalUnit.trim() || undefined,
        sans: sans.split(',').map((s) => s.trim()).filter(Boolean),
        keyType,
        days: days.trim() === '' ? undefined : Number(days),
      }),
    onSuccess: (result) => {
      void queryClient.invalidateQueries({ queryKey: ['caWifiCerts'] });
      setName(''); setCn(''); setOrganization(''); setOrganizationalUnit(''); setSans(''); setDays('');
      // Offer the install dialog immediately — the fresh cert is ready to ship.
      setInstallRow({
        name: result.cn,
        cn: result.cn,
        organization: '',
        organizationalUnit: '',
        sans: [],
        keyType,
        serial: result.serial,
        issuer: 'UNM CA Intermediate CA',
        notBefore: result.notBefore,
        notAfter: result.notAfter,
        status: 'issued',
        createdAt: new Date().toISOString(),
      });
    },
  });

  const renewMutation = useMutation({
    mutationFn: () => api.caRenewIntermediate(),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ['caStatus'] });
    },
  });

  const revokeWifi = async (row: WifiClientCert) => {
    if (!window.confirm(`Revoke "${row.name}" (${row.cn})? The certificate stops being usable for new EAP-TLS authentications and can no longer be downloaded.`)) return;
    try {
      await api.caRevokeWifi(row.serial);
      void queryClient.invalidateQueries({ queryKey: ['caWifiCerts'] });
    } catch (err) {
      alert((err as Error).message);
    }
  };

  const downloadRoot = async () => {
    try {
      saveBlob(await api.caRootBundle(), 'unm-ca-root.pem');
    } catch (err) {
      alert((err as Error).message);
    }
  };

  const status: CaStatus | undefined = statusQuery.data?.status;
  const certs = wifiQuery.data?.certificates ?? [];
  const inputCls = 'w-full rounded-md border bg-background px-2 py-1.5 text-xs';

  const certColumns: DataTableColumn<WifiClientCert>[] = [
    {
      header: 'Name / CN',
      key: 'name',
      width: 200,
      exportValue: (row) => row.name,
      render: (row) => (
        <div>
          <div className="font-medium">{row.name}</div>
          {row.cn !== row.name && <div className="font-mono text-[10px] text-secondary">CN: {row.cn}</div>}
          {(row.organization || row.organizationalUnit) && (
            <div className="text-[10px] text-faint">{[row.organization, row.organizationalUnit].filter(Boolean).join(' / ')}</div>
          )}
        </div>
      ),
    },
    { header: 'Key', key: 'keyType', width: 120, render: (row) => <span className="font-mono text-[11px]">{row.keyType}</span> },
    {
      header: 'Serial',
      key: 'serial',
      width: 160,
      exportValue: (row) => row.serial,
      render: (row) => <span className="font-mono text-[10px]" title={row.serial}>{row.serial.length > 16 ? `${row.serial.slice(0, 13)}…` : row.serial}</span>,
    },
    {
      header: 'Validity',
      key: 'notAfter',
      width: 140,
      sortAccessor: (row) => daysUntil(row.notAfter) ?? Number.MAX_SAFE_INTEGER,
      exportValue: (row) => row.notAfter,
      render: (row) => {
        const d = daysUntil(row.notAfter);
        const validCls = row.status === 'revoked' ? 'text-faint' : d !== null && d < 0 ? 'bg-danger/15 text-danger-fg' : d !== null && d <= 30 ? 'bg-warning/15 text-warning-fg' : 'bg-success/15 text-success-fg';
        return (
          <span className={`rounded px-1.5 py-0.5 font-mono text-[10px] font-semibold ${validCls}`}>
            {row.status === 'revoked' ? 'revoked' : d !== null && d < 0 ? `expired ${-d}d ago` : `${d}d left`}
          </span>
        );
      },
    },
    {
      header: 'Status',
      key: 'status',
      width: 100,
      render: (row) =>
        row.status === 'revoked' ? (
          <span className="rounded bg-danger/15 px-1.5 py-0.5 text-[10px] font-semibold uppercase text-danger-fg">revoked</span>
        ) : (
          <span className="rounded bg-success/15 px-1.5 py-0.5 text-[10px] font-semibold uppercase text-success-fg">issued</span>
        ),
    },
    ...(canManage
      ? [
          {
            header: 'Actions',
            key: 'actions',
            width: 180,
            sortable: false,
            filterable: false,
            excludeFromExport: true,
            render: (row: WifiClientCert) =>
              row.status !== 'revoked' ? (
                <div className="flex items-center justify-end gap-2">
                  <button type="button" onClick={() => setInstallRow(row)} title="Download for Windows / Android / iOS / macOS (.p12) or PEM bundle" className="inline-flex items-center gap-1 rounded border px-2 py-1 text-[10px] font-medium hover:bg-muted/40">
                    <Download className="h-3 w-3" /> Download
                  </button>
                  <button type="button" onClick={() => void revokeWifi(row)} title="Revoke this certificate" className="inline-flex items-center gap-1 rounded border px-2 py-1 text-[10px] font-medium text-danger-fg hover:bg-danger/10">
                    Revoke
                  </button>
                </div>
              ) : null,
          },
        ]
      : []),
  ];

  return (
    <section className="mb-6 space-y-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h2 className="inline-flex items-center gap-2 text-sm font-semibold">
          <Wifi className="h-4 w-4" /> WiFi client certificates (EAP-TLS)
          {!radiusLoaded && (
            <span className="rounded bg-warning/15 px-1.5 py-0.5 text-[9px] font-semibold uppercase tracking-wide text-warning-fg">no RADIUS plugin</span>
          )}
        </h2>
        <div className="flex flex-wrap items-center gap-2">
          {!radiusLoaded && (
            <button type="button" onClick={onHide} title="Hide this section again — it reappears automatically when a RADIUS plugin is loaded" className="rounded-md border px-2.5 py-1 text-[10px] font-medium hover:bg-muted/40">
              Hide
            </button>
          )}
        {canManage && (
          <div className="flex flex-wrap items-center gap-2">
            <button type="button" onClick={downloadRoot} className="inline-flex items-center gap-1.5 rounded-md border px-3 py-1.5 text-xs font-medium hover:bg-muted/40">
              <Download className="h-3.5 w-3.5" /> Root bundle (PEM)
            </button>
            <button
              type="button"
              onClick={() => renewMutation.mutate()}
              disabled={renewMutation.isPending}
              title="Renew the intermediate CA now — same key, new validity window clamped to the root expiry minus 7 days (the chain can never break)"
              className="inline-flex items-center gap-1.5 rounded-md border px-3 py-1.5 text-xs font-medium hover:bg-muted/40 disabled:opacity-50"
            >
              <RefreshCw className={`h-3.5 w-3.5 ${renewMutation.isPending ? 'animate-spin' : ''}`} />
              {renewMutation.isPending ? 'Renewing… (up to 90s)' : 'Renew intermediate'}
            </button>
          </div>
        )}
        </div>
      </div>

      {/* CA chain health — the guard that keeps issued certs valid. */}
      <div className="flex flex-wrap items-center gap-2">
        {status ? (
          <>
            <ChainChip label="Root" iso={status.rootNotAfter} />
            <ChainChip label="Intermediate" iso={status.intermediateNotAfter ?? null} />
            <span className="font-mono text-[10px] text-faint">step-ca {status.version}</span>
          </>
        ) : (
          <span className="text-xs text-warning-fg">{statusQuery.isError ? 'CA unreachable — chain status unknown' : 'Loading CA status…'}</span>
        )}
      </div>

      {/* Enrollment form. */}
      {canManage && (
        <div className="rounded-lg border bg-card p-3">
          <div className="mb-2 text-xs font-medium">Enroll a new client certificate</div>
          <div className="grid grid-cols-1 gap-2 sm:grid-cols-2 lg:grid-cols-4">
            <label className="flex flex-col gap-1 text-[10px] uppercase tracking-wide text-faint">
              Name *
              <input value={name} onChange={(e) => setName(e.target.value)} placeholder="office-ap-01" className={inputCls} />
            </label>
            <label className="flex flex-col gap-1 text-[10px] uppercase tracking-wide text-faint">
              CN (defaults to name)
              <input value={cn} onChange={(e) => setCn(e.target.value)} placeholder={name || 'office-ap-01'} className={inputCls} />
            </label>
            <label className="flex flex-col gap-1 text-[10px] uppercase tracking-wide text-faint">
              Organization (O)
              <input value={organization} onChange={(e) => setOrganization(e.target.value)} placeholder="Acme Corp" className={inputCls} />
            </label>
            <label className="flex flex-col gap-1 text-[10px] uppercase tracking-wide text-faint">
              Organizational unit (OU)
              <input value={organizationalUnit} onChange={(e) => setOrganizationalUnit(e.target.value)} placeholder="IT" className={inputCls} />
            </label>
            <label className="flex flex-col gap-1 text-[10px] uppercase tracking-wide text-faint">
              Extra SANs (comma-separated)
              <input value={sans} onChange={(e) => setSans(e.target.value)} placeholder="ap01.lan, ap01.example.com" className={inputCls} />
            </label>
            <label className="flex flex-col gap-1 text-[10px] uppercase tracking-wide text-faint">
              Key type
              <select value={keyType} onChange={(e) => setKeyType(e.target.value as CaKeyType)} className={inputCls}>
                <option value="ec-p256">ECDSA P-256 (default)</option>
                <option value="ec-p384">ECDSA P-384</option>
                <option value="rsa-2048">RSA 2048</option>
                <option value="rsa-3072">RSA 3072</option>
                <option value="rsa-4096">RSA 4096</option>
              </select>
            </label>
            <label className="flex flex-col gap-1 text-[10px] uppercase tracking-wide text-faint">
              Validity (days)
              <input value={days} onChange={(e) => setDays(e.target.value)} placeholder="default 3 years" inputMode="numeric" className={inputCls} />
            </label>
            <div className="flex items-end justify-end">
              <button
                type="button"
                onClick={() => enrollMutation.mutate()}
                disabled={!name.trim() || enrollMutation.isPending}
                className="inline-flex items-center gap-1.5 rounded-md bg-primary px-3 py-1.5 text-xs font-medium text-white hover:bg-primary-hover disabled:opacity-50"
              >
                <KeyRound className="h-3.5 w-3.5" />
                {enrollMutation.isPending ? 'Enrolling…' : 'Enroll'}
              </button>
            </div>
          </div>
          <p className="mt-2 text-[11px] text-faint">
            The validity is clamped to the CA chain expiry minus a 7-day safety margin — issued certificates can never outlive their issuer.
            Post-quantum key types (e.g. ML-DSA) are not offered yet: current supplicant/EAP-TLS stacks do not accept them; ECDSA P-256 is the default.
          </p>
          {enrollMutation.isSuccess && (
            <div className="mt-2 space-y-1 text-xs">
              <span className="inline-flex items-center gap-1.5 font-medium text-success-fg">
                <Check className="h-3.5 w-3.5" /> Enrolled {enrollMutation.data.cn} — valid until {new Date(enrollMutation.data.notAfter).toLocaleDateString()} (serial {enrollMutation.data.serial.slice(0, 16)}…)
              </span>
              <div className="text-secondary">The install dialog is open — pick the target platform and download. You can also re-open it from the table below.</div>
              {enrollMutation.data.clamped && <div className="text-warning-fg">{enrollMutation.data.clampReason}</div>}
            </div>
          )}
          {enrollMutation.isError && <div className="mt-2 text-xs text-danger-fg">{(enrollMutation.error as Error).message}</div>}
        </div>
      )}

      {/* Enrolled certs table. */}
      <DataTable
        columns={certColumns}
        rows={certs}
        rowKey={(row) => row.serial}
        storageKey="radius-wifi-certs"
        searchPlaceholder="Search WiFi client certificates…"
        emptyMessage="No WiFi client certificates enrolled yet."
        autoRefresh={{ intervalMs: 60_000, queries: [wifiQuery] }}
        selectable={canManage}
        bulkActions={
          canManage
            ? [
                {
                  label: 'Revoke selected',
                  confirm: (count) => `Revoke ${count} certificate${count === 1 ? '' : 's'}? They stop working for new EAP-TLS authentications immediately and can no longer be downloaded.`,
                  enabled: (rows) => rows.some((r) => r.status !== 'revoked'),
                  onClick: async (selected) => {
                    const serials = selected.filter((r) => r.status !== 'revoked').map((r) => r.serial);
                    try {
                      await api.caRevokeWifiBulk(serials);
                      void queryClient.invalidateQueries({ queryKey: ['caWifiCerts'] });
                    } catch (err) {
                      alert((err as Error).message);
                    }
                  },
                },
              ]
            : undefined
        }
      />

      {renewMutation.isSuccess && (
        <p className="text-xs text-success-fg">Intermediate renewed — now valid until {renewMutation.data.intermediateNotAfter ? new Date(renewMutation.data.intermediateNotAfter).toLocaleDateString() : 'a later date'}.</p>
      )}
      {renewMutation.isError && (
        <p className="text-xs text-danger-fg">{(renewMutation.error as Error).message}</p>
      )}

      {/* Install dialog — platform picker + P12 password. */}
      {installRow && <WifiInstallDialog row={installRow} onClose={() => setInstallRow(null)} />}
    </section>
  );
}

/**
 * RADIUS self-monitoring + auth log. The radiusMonitor worker probes the
 * sidecar every minute with UNM's internal probe client (any well-formed reply
 * = alive — the EAP-only site answers the PAP test with Access-Reject) and
 * audits radpostauth for failed logins, which it turns into notifications.
 * This section shows the latest probe outcome + recent auth attempts (the
 * unsuccessful-login audit trail). Read-only; requires radius:read.
 */
function RadiusStatusSection() {
  const canRead = can('radius:read');
  const { formatDateTime } = useTimeFormat();

  // Same capability gate as the other RADIUS sections.
  const pluginsQuery = useQuery({ queryKey: ['plugins'], queryFn: api.plugins, staleTime: 5 * 60_000 });
  const radiusLoaded = (pluginsQuery.data ?? []).some((p) => (p.capabilities ?? []).includes(RADIUS_CAPABILITY));

  const statusQuery = useQuery({
    queryKey: ['radiusStatus'],
    queryFn: () => api.radiusStatus(),
    enabled: canRead,
    refetchInterval: 30_000,
  });

  const [filter, setFilter] = useState<'all' | 'reject' | 'accept'>('all');
  const logQuery = useQuery({
    queryKey: ['radiusAuthLog', filter],
    queryFn: () => api.radiusAuthLog(filter === 'all' ? { limit: 50 } : { result: filter, limit: 50 }),
    enabled: canRead && radiusLoaded,
    refetchInterval: 30_000,
  });

  if (!canRead) return null;
  if (!radiusLoaded) return null;

  const status: RadiusStatus | undefined = statusQuery.data;
  const probe = status?.probe ?? null;
  const logRows: RadiusAuthLogRow[] = logQuery.data ?? [];

  const logColumns: DataTableColumn<RadiusAuthLogRow>[] = [
    {
      header: 'Time',
      key: 'authdate',
      width: 170,
      sortAccessor: (row) => new Date(row.authdate).getTime(),
      render: (row) => <span className="text-secondary">{formatDateTime(row.authdate)}</span>,
    },
    { header: 'User (cert CN)', key: 'username', width: 200, render: (row) => <span className="font-medium">{row.username}</span> },
    {
      header: 'Result',
      key: 'result',
      width: 110,
      render: (row) =>
        row.result === 'reject' ? (
          <span className="rounded bg-danger/15 px-1.5 py-0.5 text-[9px] font-semibold uppercase tracking-wide text-danger-fg">rejected</span>
        ) : row.result === 'accept' ? (
          <span className="rounded bg-success/15 px-1.5 py-0.5 text-[9px] font-semibold uppercase tracking-wide text-success-fg">accepted</span>
        ) : (
          <span className="text-faint">{row.result ?? '—'}</span>
        ),
    },
    {
      header: 'NAS / client',
      key: 'calledStationId',
      width: 240,
      exportValue: (row) => [row.calledStationId, row.callingStationId].filter(Boolean).join(' / '),
      render: (row) => <span className="font-mono text-[10px] text-secondary">{[row.calledStationId, row.callingStationId].filter(Boolean).join(' / ') || '—'}</span>,
    },
  ];

  // Probe chip — ok is the expected steady state (Access-Reject IS healthy).
  const probeChip = !probe ? (
    <span className="rounded bg-muted px-1.5 py-0.5 text-[9px] font-semibold uppercase tracking-wide text-secondary">no data yet</span>
  ) : probe.outcome === 'ok' ? (
    <span className="inline-flex items-center gap-1 rounded bg-success/15 px-1.5 py-0.5 text-[9px] font-semibold uppercase tracking-wide text-success-fg" title={probe.detail ?? undefined}>
      <Activity className="h-3 w-3" /> {probe.packetType} · {probe.latencyMs != null ? `${probe.latencyMs}ms` : ''}
    </span>
  ) : (
    <span className="inline-flex items-center gap-1 rounded bg-danger/15 px-1.5 py-0.5 text-[9px] font-semibold uppercase tracking-wide text-danger-fg" title={probe.detail ?? undefined}>
      {probe.outcome === 'bad-auth' ? 'secret out of sync' : 'unreachable'}
    </span>
  );

  return (
    <section className="mb-6 space-y-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h2 className="inline-flex items-center gap-2 text-sm font-semibold">
          <Activity className="h-4 w-4" /> RADIUS server status
        </h2>
        {probe && probe.lastProbeAt && (
          <span className="text-[10px] text-faint" title={probe.detail ?? undefined}>
            last probe {formatDateTime(probe.lastProbeAt)}
          </span>
        )}
      </div>

      <div className="flex flex-wrap items-center gap-2 rounded-lg border p-3">
        {probeChip}
        {!status?.enabled && (
          <span className="rounded bg-warning/15 px-1.5 py-0.5 text-[9px] font-semibold uppercase tracking-wide text-warning-fg">RADIUS disabled</span>
        )}
        <span className="text-[11px] text-secondary" title={probe?.detail ?? undefined}>
          {status?.enabled === false
            ? 'The RADIUS server is switched off — no probe runs while it stays off.'
            : !probe
              ? 'Waiting for the first self-monitoring probe (runs every 60s).'
              : probe.outcome === 'ok'
                ? `Sidecar alive — answered with ${probe.packetType}. The EAP-only site rejects the plain test request, which is exactly what proves it is up and loaded its config.`
                : probe.detail ?? 'Probe failing.'}
        </span>
        <span className="ml-auto flex items-center gap-2 text-[10px] text-faint">
          last 24h: <span className="font-medium text-secondary">{status?.last24h.accepts ?? 0} accepted</span> ·{' '}
          <span className={status && status.last24h.rejects > 0 ? 'font-medium text-warning-fg' : 'text-secondary'}>{status?.last24h.rejects ?? 0} rejected</span>
        </span>
      </div>

      <div className="flex flex-wrap items-center justify-between gap-2">
        <p className="max-w-3xl text-[11px] text-faint">
          Authentication log — one row per completed EAP-TLS attempt (accept and reject). Failed logins raise a notification; rows are kept for the
          configured retention period.
        </p>
        <div className="flex items-center gap-1">
          {(['all', 'reject', 'accept'] as const).map((f) => (
            <button
              key={f}
              type="button"
              onClick={() => setFilter(f)}
              className={`rounded-md px-2 py-1 text-[10px] font-medium ${filter === f ? 'bg-primary text-white' : 'border hover:bg-muted/40'}`}
            >
              {f}
            </button>
          ))}
        </div>
      </div>

      <DataTable
        columns={logColumns}
        rows={logRows}
        rowKey={(row) => String(row.id)}
        storageKey="radius-auth-log"
        searchPlaceholder="Search auth attempts…"
        emptyMessage={`No auth attempts logged yet${filter !== 'all' ? ` for this filter` : ''}.`}
        autoRefresh={{ intervalMs: 30_000, queries: [logQuery] }}
      />
    </section>
  );
}

/**
 * RADIUS NAS clients — the allowlist of access points / gateways permitted to
 * send RADIUS requests to the unm-radius sidecar. Each row is an IP plus a
 * reference to a secret from the installed credentials providers (same pattern
 * as device plugin assignments) — no plaintext secrets in this table, and the
 * rendered raddb file resolves + decrypts them at render time.
 *
 * VISIBILITY: hidden entirely until either a RADIUS server plugin is loaded
 * (capability 'radius') or rows already exist — on instances without any of
 * that there is nothing to manage here (the WiFi hint card above explains the
 * missing plugin).
 */
function RadiusNasClientsSection() {
  const queryClient = useQueryClient();
  const canRead = can('radius:read');
  const canWrite = can('radius:write');

  // Same capability gate as the WiFi section — a 'radius' plugin makes this relevant.
  const pluginsQuery = useQuery({ queryKey: ['plugins'], queryFn: api.plugins, staleTime: 5 * 60_000 });
  const radiusLoaded = (pluginsQuery.data ?? []).some((p) => (p.capabilities ?? []).includes(RADIUS_CAPABILITY));

  const clientsQuery = useQuery({
    queryKey: ['radiusNasClients'],
    queryFn: () => api.radiusNasClients(),
    enabled: canRead,
    refetchInterval: 60_000,
  });
  // All secrets (metadata only) — the picker offers every installed credential,
  // same as the device form; single-value types map directly to the shared secret.
  const secretsQuery = useQuery({
    queryKey: ['secrets'],
    queryFn: () => api.secrets(),
    enabled: canWrite && can('secrets:read'),
  });

  const [dialog, setDialog] = useState<{ mode: 'create' } | { mode: 'edit'; row: RadiusNasClient } | null>(null);

  if (!canRead) return null;
  if (!radiusLoaded && (clientsQuery.data ?? []).length === 0) return null;

  const clients = clientsQuery.data ?? [];
  const secrets: Secret[] = secretsQuery.data ?? [];

  const clientColumns: DataTableColumn<RadiusNasClient>[] = [
    { header: 'Name', key: 'name', width: 180, exportValue: (row) => row.name ?? '', render: (row) => <span className="font-medium">{row.name || <span className="text-faint">—</span>}</span> },
    { header: 'IP address', key: 'ip', width: 160, render: (row) => <span className="font-mono text-[11px]">{row.ip}</span> },
    {
      header: 'Shared secret',
      key: 'secretLabel',
      width: 220,
      exportValue: (row) => row.secretLabel ?? '',
      render: (row) =>
        row.secretId ? (
          <span className="inline-flex items-center gap-1.5" title={row.secretType ?? undefined}>
            <KeyRound className="h-3 w-3 text-faint" />
            <span>{row.secretLabel || row.secretId}</span>
            {row.secretType && <span className="rounded bg-muted px-1 py-0.5 font-mono text-[9px] uppercase tracking-wide text-secondary">{row.secretType}</span>}
          </span>
        ) : (
          <span className="rounded bg-warning/15 px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-warning-fg">no secret</span>
        ),
    },
    ...(canWrite
      ? [
          {
            header: 'Actions',
            key: 'actions',
            width: 160,
            sortable: false,
            filterable: false,
            excludeFromExport: true,
            render: (row: RadiusNasClient) => (
              <div className="flex items-center justify-end gap-2">
                <button type="button" onClick={() => setDialog({ mode: 'edit', row })} title="Edit this NAS client" className="rounded border px-2 py-1 text-[10px] font-medium hover:bg-muted/40">
                  Edit
                </button>
                <RadiusDeleteButton id={row.id} label={`${row.name || row.ip}`} />
              </div>
            ),
          },
        ]
      : []),
  ];

  return (
    <section className="mb-6 space-y-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h2 className="inline-flex items-center gap-2 text-sm font-semibold">
          <KeyRound className="h-4 w-4" /> RADIUS NAS clients
          {!radiusLoaded && (
            <span className="rounded bg-warning/15 px-1.5 py-0.5 text-[9px] font-semibold uppercase tracking-wide text-warning-fg">no RADIUS plugin</span>
          )}
        </h2>
        {canWrite && (
          <button type="button" onClick={() => setDialog({ mode: 'create' })} className="inline-flex items-center gap-1.5 rounded-md bg-primary px-3 py-1.5 text-xs font-medium text-white hover:bg-primary-hover">
            <Plus className="h-3.5 w-3.5" /> Add NAS client
          </button>
        )}
      </div>

      <p className="max-w-4xl text-[11px] text-faint">
        Access points and gateways allowed to send RADIUS requests (EAP-TLS) to the UNM RADIUS server. The shared secret is picked from your installed
        credentials — single-value secrets (API key, PSK) are used directly; for multi-field types the password/secret half applies. Changes apply live
        without a restart. A localhost entry with a stable dev secret is always present for testing.
      </p>

      <DataTable
        columns={clientColumns}
        rows={clients}
        rowKey={(row) => row.id}
        storageKey="radius-nas-clients"
        searchPlaceholder="Search NAS clients…"
        emptyMessage="No NAS clients configured yet."
        autoRefresh={{ intervalMs: 60_000, queries: [clientsQuery] }}
        selectable={canWrite}
        bulkActions={
          canWrite
            ? [
                {
                  label: 'Remove selected',
                  confirm: (count) => `Remove ${count} NAS client${count === 1 ? '' : 's'}? They will no longer be able to authenticate.`,
                  onClick: async (selected) => {
                    try {
                      await api.radiusNasClientBulkDelete(selected.map((r) => r.id));
                      void queryClient.invalidateQueries({ queryKey: ['radiusNasClients'] });
                    } catch (err) {
                      alert((err as Error).message);
                    }
                  },
                },
              ]
            : undefined
        }
      />

      {dialog && (
        <RadiusNasClientDialog
          initial={dialog.mode === 'edit' ? dialog.row : null}
          secrets={secrets}
          onClose={() => setDialog(null)}
        />
      )}
    </section>
  );
}

/** Delete with confirm — invalidates the list on success. */
function RadiusDeleteButton({ id, label }: { id: string; label: string }) {
  const queryClient = useQueryClient();
  const mutation = useMutation({
    mutationFn: () => api.radiusNasClientDelete(id),
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: ['radiusNasClients'] }),
  });
  return (
    <button
      type="button"
      onClick={() => {
        if (!window.confirm(`Remove NAS client "${label}"? It will no longer be able to authenticate.`)) return;
        mutation.mutate();
      }}
      disabled={mutation.isPending}
      title="Remove this NAS client"
      className="inline-flex items-center gap-1 rounded border px-2 py-1 text-[10px] font-medium text-danger-fg hover:bg-danger/10 disabled:opacity-50"
    >
      {mutation.isPending ? 'Removing…' : 'Remove'}
    </button>
  );
}

/** Add / edit dialog — IP + name + secret picker (same pattern as device forms). */
function RadiusNasClientDialog({ initial, secrets, onClose }: { initial: RadiusNasClient | null; secrets: Secret[]; onClose: () => void }) {
  const queryClient = useQueryClient();
  const [name, setName] = useState(initial?.name ?? '');
  const [ip, setIp] = useState(initial?.ip ?? '');
  const [secretId, setSecretId] = useState(initial?.secretId ?? '');

  const mutation = useMutation({
    mutationFn: () =>
      initial
        ? api.radiusNasClientUpdate(initial.id, { name: name.trim() || null, ip: ip.trim(), secretId: secretId || null })
        : api.radiusNasClientCreate({ name: name.trim() || null, ip: ip.trim(), secretId: secretId || null }),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ['radiusNasClients'] });
      onClose();
    },
  });

  const inputCls = 'w-full rounded-md border bg-background px-2 py-1.5 text-xs';

  return (
    <DialogShell
      title={initial ? `Edit NAS client ${initial.name || initial.ip}` : 'Add NAS client'}
      subtitle="Access points / gateways allowed to send RADIUS requests"
      icon={<KeyRound className="h-4 w-4 text-primary" />}
      onClose={onClose}
      maxWidth="max-w-md"
      footer={
        <div className="flex items-center justify-end gap-2">
          <button type="button" onClick={onClose} className="rounded-md border px-3 py-1.5 text-xs font-medium hover:bg-muted/40">Cancel</button>
          <button
            type="submit"
            disabled={!ip.trim() || mutation.isPending}
            className="inline-flex items-center gap-1.5 rounded-md bg-primary px-3 py-1.5 text-xs font-medium text-white hover:bg-primary-hover disabled:opacity-50"
          >
            <Check className="h-3.5 w-3.5" />
            {mutation.isPending ? 'Saving…' : initial ? 'Save changes' : 'Add client'}
          </button>
        </div>
      }
    >
      <form
        onSubmit={(e) => {
          e.preventDefault();
          mutation.mutate();
        }}
        className="space-y-3"
      >
        <label className="flex flex-col gap-1 text-[10px] uppercase tracking-wide text-faint">
          IP address *
          <input value={ip} onChange={(e) => setIp(e.target.value)} placeholder="192.168.1.50" className={`${inputCls} font-mono`} />
        </label>
        <label className="flex flex-col gap-1 text-[10px] uppercase tracking-wide text-faint">
          Name (optional)
          <input value={name} onChange={(e) => setName(e.target.value)} placeholder="office-ap-01" className={inputCls} />
        </label>
        <label className="flex flex-col gap-1 text-[10px] uppercase tracking-wide text-faint">
          Shared secret *
          <select value={secretId} onChange={(e) => setSecretId(e.target.value)} className={inputCls}>
            <option value="">No credentials</option>
            {secrets.map((s) => (
              <option key={s.id} value={s.id}>{s.label || s.id} [{s.type}]</option>
            ))}
          </select>
        </label>
        {secrets.length === 0 && can('secrets:read') && (
          <p className="text-[11px] text-warning-fg">No credentials are visible to you — create one on the Secrets page first.</p>
        )}
        <p className="text-[11px] text-faint">
          Single-value secrets (API key, PSK) are used directly as the RADIUS shared secret; for multi-field types the password/secret half applies. The
          value is resolved from the credentials provider at render time — it never leaves UNM in plaintext here.
        </p>
        {mutation.isError && <div className="text-xs text-danger-fg">{(mutation.error as Error).message}</div>}
      </form>
    </DialogShell>
  );
}

/** Per-user RADIUS reply profiles (VLAN / static IP / session limits) — keyed by client cert serial. */
function RadiusUserProfilesSection() {
  const queryClient = useQueryClient();
  const canRead = can('radius:read');
  const canWrite = can('radius:write');

  // Same capability gate as the NAS clients section.
  const pluginsQuery = useQuery({ queryKey: ['plugins'], queryFn: api.plugins, staleTime: 5 * 60_000 });
  const radiusLoaded = (pluginsQuery.data ?? []).some((p) => (p.capabilities ?? []).includes(RADIUS_CAPABILITY));

  const profilesQuery = useQuery({
    queryKey: ['radiusUserProfiles'],
    queryFn: () => api.radiusUserProfiles(),
    enabled: canRead,
    refetchInterval: 60_000,
  });
  // Issued WiFi certs — the serial picker offers every enrolled client cert.
  const wifiCertsQuery = useQuery({
    queryKey: ['caWifiCerts'],
    queryFn: () => api.caWifiCerts(),
    enabled: canWrite,
    staleTime: 5 * 60_000,
  });

  const [dialog, setDialog] = useState<{ mode: 'create' } | { mode: 'edit'; row: RadiusUserProfile } | null>(null);

  if (!canRead) return null;
  if (!radiusLoaded && (profilesQuery.data ?? []).length === 0) return null;

  const profiles = profilesQuery.data ?? [];
  const wifiCerts: WifiClientCert[] = (wifiCertsQuery.data?.certificates ?? []).filter((c) => c.status === 'issued');

  const profileColumns: DataTableColumn<RadiusUserProfile>[] = [
    {
      header: 'Certificate',
      key: 'certName',
      width: 200,
      exportValue: (row) => row.certName ?? row.name ?? row.serial,
      render: (row) => (
        <div>
          <div className="font-medium">{row.certName || row.name || 'unknown cert'}</div>
          <div className="font-mono text-[10px] text-faint" title={`serial ${row.serial}`}>{row.serial.slice(0, 24)}…</div>
        </div>
      ),
    },
    {
      header: 'VLAN',
      key: 'vlanId',
      width: 90,
      render: (row) =>
        row.vlanId ? (
          <span className="rounded bg-primary/10 px-1.5 py-0.5 font-mono text-[10px] font-semibold text-primary">{row.vlanId}</span>
        ) : (
          <span className="text-faint">—</span>
        ),
    },
    {
      header: 'Static IP',
      key: 'framedIp',
      width: 180,
      exportValue: (row) => [row.framedIp, row.framedIpv6].filter(Boolean).join(' / '),
      render: (row) => <span className="font-mono text-[11px]">{[row.framedIp, row.framedIpv6].filter(Boolean).join(' / ') || <span className="text-faint">—</span>}</span>,
    },
    {
      header: 'Session limits',
      key: 'sessionTimeoutSec',
      width: 170,
      exportValue: (row) => [row.sessionTimeoutSec ? `re-auth ${Math.round(row.sessionTimeoutSec / 60)}m` : null, row.idleTimeoutSec ? `idle ${Math.round(row.idleTimeoutSec / 60)}m` : null].filter(Boolean).join(' · '),
      render: (row) => (
        <span className="text-[11px]">
          {row.sessionTimeoutSec ? `re-auth ${Math.round(row.sessionTimeoutSec / 60)}m` : null}
          {row.sessionTimeoutSec && row.idleTimeoutSec ? ' · ' : ''}
          {row.idleTimeoutSec ? `idle ${Math.round(row.idleTimeoutSec / 60)}m` : null}
          {!row.sessionTimeoutSec && !row.idleTimeoutSec ? <span className="text-faint">—</span> : null}
        </span>
      ),
    },
    ...(canWrite
      ? [
          {
            header: 'Actions',
            key: 'actions',
            width: 160,
            sortable: false,
            filterable: false,
            excludeFromExport: true,
            render: (row: RadiusUserProfile) => (
              <div className="flex items-center justify-end gap-2">
                <button type="button" onClick={() => setDialog({ mode: 'edit', row })} title="Edit this profile" className="rounded border px-2 py-1 text-[10px] font-medium hover:bg-muted/40">
                  Edit
                </button>
                <RadiusProfileDeleteButton id={row.id} label={row.certName || row.name || row.serial.slice(0, 16)} />
              </div>
            ),
          },
        ]
      : []),
  ];

  return (
    <section className="mb-6 space-y-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h2 className="inline-flex items-center gap-2 text-sm font-semibold">
          <Network className="h-4 w-4" /> RADIUS user profiles
          {!radiusLoaded && (
            <span className="rounded bg-warning/15 px-1.5 py-0.5 text-[9px] font-semibold uppercase tracking-wide text-warning-fg">no RADIUS plugin</span>
          )}
        </h2>
        {canWrite && (
          <button type="button" onClick={() => setDialog({ mode: 'create' })} className="inline-flex items-center gap-1.5 rounded-md bg-primary px-3 py-1.5 text-xs font-medium text-white hover:bg-primary-hover">
            <Plus className="h-3.5 w-3.5" /> Add profile
          </button>
        )}
      </div>

      <p className="max-w-4xl text-[11px] text-faint">
        Per-client RADIUS reply attributes for WiFi EAP-TLS — keyed by the client certificate's serial. A VLAN ID is sent as
        Tunnel-Type=IEEE-802 + Tunnel-Medium-Type=IEEE-802 + Tunnel-Private-Group-ID; static IPs and session limits are applied to that
        session only, on top of whatever the NAS would assign otherwise. No profile = plain access.
      </p>

      <DataTable
        columns={profileColumns}
        rows={profiles}
        rowKey={(row) => row.id}
        storageKey="radius-user-profiles"
        searchPlaceholder="Search user profiles…"
        emptyMessage="No user profiles configured — all clients get plain access."
        autoRefresh={{ intervalMs: 60_000, queries: [profilesQuery] }}
        selectable={canWrite}
        bulkActions={
          canWrite
            ? [
                {
                  label: 'Remove selected',
                  confirm: (count) => `Remove ${count} profile${count === 1 ? '' : 's'}? The affected clients will get plain access again.`,
                  onClick: async (selected) => {
                    try {
                      await api.radiusUserProfileBulkDelete(selected.map((r) => r.id));
                      void queryClient.invalidateQueries({ queryKey: ['radiusUserProfiles'] });
                    } catch (err) {
                      alert((err as Error).message);
                    }
                  },
                },
              ]
            : undefined
        }
      />

      {dialog && (
        <RadiusUserProfileDialog
          initial={dialog.mode === 'edit' ? dialog.row : null}
          wifiCerts={wifiCerts}
          onClose={() => setDialog(null)}
        />
      )}
    </section>
  );
}

/** Delete with confirm — invalidates the list on success. */
function RadiusProfileDeleteButton({ id, label }: { id: string; label: string }) {
  const queryClient = useQueryClient();
  const mutation = useMutation({
    mutationFn: () => api.radiusUserProfileDelete(id),
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: ['radiusUserProfiles'] }),
  });
  return (
    <button
      type="button"
      onClick={() => {
        if (!window.confirm(`Remove the RADIUS profile for "${label}"? The client will get plain access again.`)) return;
        mutation.mutate();
      }}
      disabled={mutation.isPending}
      title="Remove this profile"
      className="inline-flex items-center gap-1 rounded border px-2 py-1 text-[10px] font-medium text-danger-fg hover:bg-danger/10 disabled:opacity-50"
    >
      {mutation.isPending ? 'Removing…' : 'Remove'}
    </button>
  );
}

/** Add / edit dialog — cert serial picker + VLAN / static IP / session limits. */
function RadiusUserProfileDialog({ initial, wifiCerts, onClose }: { initial: RadiusUserProfile | null; wifiCerts: WifiClientCert[]; onClose: () => void }) {
  const queryClient = useQueryClient();
  const [serial, setSerial] = useState(initial?.serial ?? '');
  const [vlanId, setVlanId] = useState(initial?.vlanId ? String(initial.vlanId) : '');
  const [framedIp, setFramedIp] = useState(initial?.framedIp ?? '');
  const [framedIpv6, setFramedIpv6] = useState(initial?.framedIpv6 ?? '');
  const [sessionTimeoutSec, setSessionTimeoutSec] = useState(initial?.sessionTimeoutSec ? String(initial.sessionTimeoutSec) : '');
  const [idleTimeoutSec, setIdleTimeoutSec] = useState(initial?.idleTimeoutSec ? String(initial.idleTimeoutSec) : '');
  const [replyMessage, setReplyMessage] = useState(initial?.replyMessage ?? '');

  // The picker lists enrolled certs; a freeform serial is also accepted (e.g.
  // for certs issued by another CA that still authenticates here).
  const knownSerials = new Set(wifiCerts.map((c) => c.serial.toLowerCase()));
  const selectedCert = wifiCerts.find((c) => c.serial.toLowerCase() === serial.trim().toLowerCase());

  const mutation = useMutation({
    mutationFn: () => {
      const body = {
        vlanId: vlanId ? Number(vlanId) : null,
        framedIp: framedIp.trim() || null,
        framedIpv6: framedIpv6.trim() || null,
        sessionTimeoutSec: sessionTimeoutSec ? Number(sessionTimeoutSec) : null,
        idleTimeoutSec: idleTimeoutSec ? Number(idleTimeoutSec) : null,
        replyMessage: replyMessage.trim() || null,
      };
      return initial
        ? api.radiusUserProfileUpdate(initial.id, body)
        : api.radiusUserProfileCreate({ serial: serial.trim().toLowerCase(), name: selectedCert?.name ?? null, ...body });
    },
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ['radiusUserProfiles'] });
      onClose();
    },
  });

  const inputCls = 'w-full rounded-md border bg-background px-2 py-1.5 text-xs';

  return (
    <DialogShell
      title={initial ? `Edit profile — ${initial.certName || initial.name || initial.serial.slice(0, 16)}` : 'Add RADIUS user profile'}
      subtitle="Per-client reply attributes for WiFi EAP-TLS sessions"
      icon={<Network className="h-4 w-4 text-primary" />}
      onClose={onClose}
      maxWidth="max-w-md"
      footer={
        <div className="flex items-center justify-end gap-2">
          <button type="button" onClick={onClose} className="rounded-md border px-3 py-1.5 text-xs font-medium hover:bg-muted/40">Cancel</button>
          <button
            type="submit"
            disabled={!serial.trim() || mutation.isPending}
            className="inline-flex items-center gap-1.5 rounded-md bg-primary px-3 py-1.5 text-xs font-medium text-white hover:bg-primary-hover disabled:opacity-50"
          >
            <Check className="h-3.5 w-3.5" />
            {mutation.isPending ? 'Saving…' : initial ? 'Save changes' : 'Add profile'}
          </button>
        </div>
      }
    >
      <form
        onSubmit={(e) => {
          e.preventDefault();
          mutation.mutate();
        }}
        className="space-y-3"
      >
        {!initial && (
          <label className="flex flex-col gap-1 text-[10px] uppercase tracking-wide text-faint">
            Client certificate *
            {wifiCerts.length > 0 ? (
              <select value={serial} onChange={(e) => setSerial(e.target.value)} className={inputCls}>
                <option value="">Select a certificate…</option>
                {wifiCerts.map((c) => (
                  <option key={c.serial} value={c.serial}>{c.name} — {c.cn}</option>
                ))}
              </select>
            ) : (
              <input value={serial} onChange={(e) => setSerial(e.target.value)} placeholder="cert serial (lowercase hex, no 0x prefix)" className={`${inputCls} font-mono`} />
            )}
          </label>
        )}
        {initial && (
          <div className="rounded-md border bg-background/60 px-2 py-1.5 text-[11px]">
            <span className="font-medium">{initial.certName || initial.name}</span>{' '}
            <span className="font-mono text-faint" title={initial.serial}>{initial.serial.slice(0, 32)}…</span>
          </div>
        )}
        {wifiCerts.length > 0 && !knownSerials.has(serial.trim().toLowerCase()) && serial.trim() !== '' && (
          <p className="text-[11px] text-warning-fg">This serial is not an enrolled UNM WiFi cert — make sure it matches the client's certificate.</p>
        )}

        <div className="grid grid-cols-2 gap-3">
          <label className="flex flex-col gap-1 text-[10px] uppercase tracking-wide text-faint">
            VLAN ID (1–4094)
            <input value={vlanId} onChange={(e) => setVlanId(e.target.value)} placeholder="e.g. 20" inputMode="numeric" className={`${inputCls} font-mono`} />
          </label>
          <label className="flex flex-col gap-1 text-[10px] uppercase tracking-wide text-faint">
            Static IPv4
            <input value={framedIp} onChange={(e) => setFramedIp(e.target.value)} placeholder="192.168.50.10" className={`${inputCls} font-mono`} />
          </label>
        </div>
        <div className="grid grid-cols-2 gap-3">
          <label className="flex flex-col gap-1 text-[10px] uppercase tracking-wide text-faint">
            Static IPv6
            <input value={framedIpv6} onChange={(e) => setFramedIpv6(e.target.value)} placeholder="fd00::50:10" className={`${inputCls} font-mono`} />
          </label>
          <div className="grid grid-cols-2 gap-3">
            <label className="flex flex-col gap-1 text-[10px] uppercase tracking-wide text-faint">
              Re-auth (sec)
              <input value={sessionTimeoutSec} onChange={(e) => setSessionTimeoutSec(e.target.value)} placeholder="86400" inputMode="numeric" className={`${inputCls} font-mono`} />
            </label>
            <label className="flex flex-col gap-1 text-[10px] uppercase tracking-wide text-faint">
              Idle (sec)
              <input value={idleTimeoutSec} onChange={(e) => setIdleTimeoutSec(e.target.value)} placeholder="3600" inputMode="numeric" className={`${inputCls} font-mono`} />
            </label>
          </div>
        </div>
        <label className="flex flex-col gap-1 text-[10px] uppercase tracking-wide text-faint">
          Reply message (optional)
          <input value={replyMessage} onChange={(e) => setReplyMessage(e.target.value)} placeholder='"IoT device — VLAN 20"' maxLength={256} className={inputCls} />
        </label>
        <p className="text-[11px] text-faint">
          All fields optional — empty means the NAS default applies. The VLAN is sent as Tunnel-Type=IEEE-802 +
          Tunnel-Medium-Type=IEEE-802 + Tunnel-Private-Group-ID; re-auth adds Termination-Action=RESTART.
        </p>
        {mutation.isError && <div className="text-xs text-danger-fg">{(mutation.error as Error).message}</div>}
      </form>
    </DialogShell>
  );
}

/**
 * RADIUS — the UNM authentication service (unm-radius sidecar, FreeRADIUS).
 * Serves 802.1X for WiFi EAP-TLS AND wired clients: server self-monitoring +
 * auth-fail audit trail, the NAS client allowlist, per-user reply profiles and
 * the CA-issued client certificates. Gated on radius:read (route guard); the
 * individual sections additionally respect radius:write / ca:manage.
 */
export default function Radius() {
  return (
    <Layout title="RADIUS">
      <p className="mb-4 max-w-4xl text-xs text-muted-foreground">
        The UNM RADIUS server authenticates 802.1X supplicants — WiFi EAP-TLS and wired clients alike — against client certificates issued by the UNM CA.
        This page covers the server's self-monitoring probe, the unsuccessful-login audit trail (failed logins raise notifications), the NAS allowlist,
        per-user reply profiles and the enrolled client certificates. Device TLS endpoints and SSH host keys live on the{' '}
        <a href="/certificates" className="font-medium text-primary underline-offset-2 hover:underline">Certificates</a> page.
      </p>
      <RadiusStatusSection />
      <RadiusNasClientsSection />
      <RadiusUserProfilesSection />
      <WifiCertsSection />
    </Layout>
  );
}
