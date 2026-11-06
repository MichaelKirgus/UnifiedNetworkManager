import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Check, Copy, Download, History, KeyRound, Network, Plus, RefreshCw, ShieldAlert, Wifi } from 'lucide-react';
import { Layout } from '../components/Layout';
import { DataTable, DataTableColumn } from '../components/DataTable';
import { DeviceChip } from '../components/DeviceChip';
import { DialogShell } from '../components/DialogShell';
import { api, CaStatus, CaKeyType, CertificateRow, CertificateHistoryRow, RadiusNasClient, RadiusUserProfile, Secret, WifiClientCert } from '../api/client';
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
 * makes the WiFi EAP-TLS section relevant on this instance. */
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
      <div className="overflow-x-auto rounded-lg border">
        <table className="w-full text-left text-xs">
          <thead className="bg-background/60 text-[10px] uppercase tracking-wide text-faint">
            <tr>
              <th className="px-2 py-1.5 font-medium">Name / CN</th>
              <th className="px-2 py-1.5 font-medium">Key</th>
              <th className="px-2 py-1.5 font-medium">Serial</th>
              <th className="px-2 py-1.5 font-medium">Validity</th>
              <th className="px-2 py-1.5 font-medium">Status</th>
              {canManage && <th className="px-2 py-1.5 font-medium text-right">Actions</th>}
            </tr>
          </thead>
          <tbody className="divide-y divide-border">
            {certs.length === 0 && (
              <tr><td colSpan={canManage ? 6 : 5} className="px-2 py-3 text-faint">No WiFi client certificates enrolled yet.</td></tr>
            )}
            {certs.map((row) => {
              const d = daysUntil(row.notAfter);
              const validCls = row.status === 'revoked' ? 'text-faint' : d !== null && d < 0 ? 'bg-danger/15 text-danger-fg' : d !== null && d <= 30 ? 'bg-warning/15 text-warning-fg' : 'bg-success/15 text-success-fg';
              return (
                <tr key={row.serial}>
                  <td className="px-2 py-1.5">
                    <div className="font-medium">{row.name}</div>
                    {row.cn !== row.name && <div className="font-mono text-[10px] text-secondary">CN: {row.cn}</div>}
                    {(row.organization || row.organizationalUnit) && (
                      <div className="text-[10px] text-faint">{[row.organization, row.organizationalUnit].filter(Boolean).join(' / ')}</div>
                    )}
                  </td>
                  <td className="whitespace-nowrap px-2 py-1.5 font-mono text-[11px]">{row.keyType}</td>
                  <td className="px-2 py-1.5 font-mono text-[10px]" title={row.serial}>{row.serial.length > 16 ? `${row.serial.slice(0, 13)}…` : row.serial}</td>
                  <td className="whitespace-nowrap px-2 py-1.5">
                    <span className={`rounded px-1.5 py-0.5 font-mono text-[10px] font-semibold ${validCls}`}>
                      {row.status === 'revoked' ? 'revoked' : d !== null && d < 0 ? `expired ${-d}d ago` : `${d}d left`}
                    </span>
                  </td>
                  <td className="px-2 py-1.5">
                    {row.status === 'revoked' ? (
                      <span className="rounded bg-danger/15 px-1.5 py-0.5 text-[10px] font-semibold uppercase text-danger-fg">revoked</span>
                    ) : (
                      <span className="rounded bg-success/15 px-1.5 py-0.5 text-[10px] font-semibold uppercase text-success-fg">issued</span>
                    )}
                  </td>
                  {canManage && (
                    <td className="whitespace-nowrap px-2 py-1.5 text-right">
                      {row.status !== 'revoked' && (
                        <>
                          <button type="button" onClick={() => setInstallRow(row)} title="Download for Windows / Android / iOS / macOS (.p12) or PEM bundle" className="mr-2 inline-flex items-center gap-1 rounded border px-2 py-1 text-[10px] font-medium hover:bg-muted/40">
                            <Download className="h-3 w-3" /> Download
                          </button>
                          <button type="button" onClick={() => void revokeWifi(row)} title="Revoke this certificate" className="inline-flex items-center gap-1 rounded border px-2 py-1 text-[10px] font-medium text-danger-fg hover:bg-danger/10">
                            Revoke
                          </button>
                        </>
                      )}
                    </td>
                  )}
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

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
  mtls: 'bg-accent-violet text-accent-violet-fg',
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
  if (row.revoked) {
    return (
      <span title={row.invalidReason ?? undefined} className="inline-flex cursor-help rounded bg-danger/15 px-1.5 py-0.5 text-xs font-medium uppercase tracking-wide text-danger-fg">
        revoked
      </span>
    );
  }
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
  const ssh = rows.filter((r) => r.type === 'ssh').length;
  const mtls = rows.filter((r) => r.type === 'mtls').length;
  // UNM's own mTLS leaves have no device — don't count the empty deviceId as one.
  const devices = new Set(rows.filter((r) => r.deviceId).map((r) => r.deviceId)).size;
  // Every TLS cert (device endpoints + UNM's own mTLS leaves) counts for expiry/validity.
  const tls = rows.filter((r) => r.type !== 'ssh');
  // Expired = leaf OR any chain element (issuer) already past its validity window.
  const isExpired = (r: CertificateRow): boolean =>
    (r.daysToExpiry != null && r.daysToExpiry < 0) || (r.chainDaysToExpiry != null && r.chainDaysToExpiry < 0);
  const expired = tls.filter(isExpired).length;
  // Expiring soon = leaf within 30 days, not already expired.
  const expiringSoon = tls.filter(
    (r) => !isExpired(r) && r.daysToExpiry != null && r.daysToExpiry >= 0 && r.daysToExpiry <= 30
  ).length;
  const invalid = tls.filter((r) => r.valid === false).length;
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
      {mtls > 0 ? cell('UNM mTLS leaves', mtls) : null}
      {expired > 0 ? cell('expired', expired, 'danger') : null}
      {expiringSoon > 0 ? cell('expiring ≤30d', expiringSoon, 'warning') : null}
      {invalid > 0 ? cell('invalid chain', invalid, 'danger') : null}
      {mismatched > 0 ? cell('key changed', mismatched, 'danger') : null}
    </div>
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

      <div className="overflow-x-auto rounded-lg border">
        <table className="w-full text-left text-xs">
          <thead className="bg-background/60 text-[10px] uppercase tracking-wide text-faint">
            <tr>
              <th className="px-2 py-1.5 font-medium">Name</th>
              <th className="px-2 py-1.5 font-medium">IP address</th>
              <th className="px-2 py-1.5 font-medium">Shared secret</th>
              {canWrite && <th className="px-2 py-1.5 font-medium text-right">Actions</th>}
            </tr>
          </thead>
          <tbody className="divide-y divide-border">
            {clients.length === 0 && (
              <tr><td colSpan={canWrite ? 4 : 3} className="px-2 py-3 text-faint">No NAS clients configured yet.</td></tr>
            )}
            {clients.map((row) => (
              <tr key={row.id}>
                <td className="px-2 py-1.5 font-medium">{row.name || <span className="text-faint">—</span>}</td>
                <td className="whitespace-nowrap px-2 py-1.5 font-mono text-[11px]">{row.ip}</td>
                <td className="px-2 py-1.5">
                  {row.secretId ? (
                    <span className="inline-flex items-center gap-1.5" title={row.secretType ?? undefined}>
                      <KeyRound className="h-3 w-3 text-faint" />
                      <span>{row.secretLabel || row.secretId}</span>
                      {row.secretType && <span className="rounded bg-muted px-1 py-0.5 font-mono text-[9px] uppercase tracking-wide text-secondary">{row.secretType}</span>}
                    </span>
                  ) : (
                    <span className="rounded bg-warning/15 px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-warning-fg">no secret</span>
                  )}
                </td>
                {canWrite && (
                  <td className="whitespace-nowrap px-2 py-1.5 text-right">
                    <button type="button" onClick={() => setDialog({ mode: 'edit', row })} title="Edit this NAS client" className="mr-2 rounded border px-2 py-1 text-[10px] font-medium hover:bg-muted/40">
                      Edit
                    </button>
                    <RadiusDeleteButton id={row.id} label={`${row.name || row.ip}`} />
                  </td>
                )}
              </tr>
            ))}
          </tbody>
        </table>
      </div>

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

      <div className="overflow-x-auto rounded-lg border">
        <table className="w-full text-left text-xs">
          <thead className="bg-background/60 text-[10px] uppercase tracking-wide text-faint">
            <tr>
              <th className="px-2 py-1.5 font-medium">Certificate</th>
              <th className="px-2 py-1.5 font-medium">VLAN</th>
              <th className="px-2 py-1.5 font-medium">Static IP</th>
              <th className="px-2 py-1.5 font-medium">Session limits</th>
              {canWrite && <th className="px-2 py-1.5 font-medium text-right">Actions</th>}
            </tr>
          </thead>
          <tbody className="divide-y divide-border">
            {profiles.length === 0 && (
              <tr><td colSpan={canWrite ? 5 : 4} className="px-2 py-3 text-faint">No user profiles configured — all clients get plain access.</td></tr>
            )}
            {profiles.map((row) => (
              <tr key={row.id}>
                <td className="px-2 py-1.5">
                  <div className="font-medium">{row.certName || row.name || 'unknown cert'}</div>
                  <div className="font-mono text-[10px] text-faint" title={`serial ${row.serial}`}>{row.serial.slice(0, 24)}…</div>
                </td>
                <td className="whitespace-nowrap px-2 py-1.5">
                  {row.vlanId ? (
                    <span className="rounded bg-primary/10 px-1.5 py-0.5 font-mono text-[10px] font-semibold text-primary">{row.vlanId}</span>
                  ) : (
                    <span className="text-faint">—</span>
                  )}
                </td>
                <td className="whitespace-nowrap px-2 py-1.5 font-mono text-[11px]">
                  {[row.framedIp, row.framedIpv6].filter(Boolean).join(' / ') || <span className="text-faint">—</span>}
                </td>
                <td className="whitespace-nowrap px-2 py-1.5 text-[11px]">
                  {row.sessionTimeoutSec ? `re-auth ${Math.round(row.sessionTimeoutSec / 60)}m` : null}
                  {row.sessionTimeoutSec && row.idleTimeoutSec ? ' · ' : ''}
                  {row.idleTimeoutSec ? `idle ${Math.round(row.idleTimeoutSec / 60)}m` : null}
                  {!row.sessionTimeoutSec && !row.idleTimeoutSec ? <span className="text-faint">—</span> : null}
                </td>
                {canWrite && (
                  <td className="whitespace-nowrap px-2 py-1.5 text-right">
                    <button type="button" onClick={() => setDialog({ mode: 'edit', row })} title="Edit this profile" className="mr-2 rounded border px-2 py-1 text-[10px] font-medium hover:bg-muted/40">
                      Edit
                    </button>
                    <RadiusProfileDeleteButton id={row.id} label={row.certName || row.name || row.serial.slice(0, 16)} />
                  </td>
                )}
              </tr>
            ))}
          </tbody>
        </table>
      </div>

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
      <WifiCertsSection />
      <RadiusNasClientsSection />
      <RadiusUserProfilesSection />
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
            notification (auto-resolved once renewed). Violet <span className="font-medium uppercase">mtls</span> rows are UNM's own CA-issued
            leaves (plugins, api, mcp) from the certificate registry — they have no device and refresh on each metrics poll.
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
