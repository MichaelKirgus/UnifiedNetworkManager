import { useMemo, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import clsx from 'clsx';
import { ArchiveRestore, DatabaseBackup, Download, Loader2, Plus, RefreshCw, Trash2 } from 'lucide-react';
import { DialogShell } from '../components/DialogShell';
import { Layout } from '../components/Layout';
import { formatBytes } from '../components/formatMetric';
import { api, BackupEntry, ReplicationTarget, ReplicationTargetInput } from '../api/client';
import { useTimeFormat } from '../utils/time';

/**
 * Backups — backup / restore / replication of UNM's own database.
 *
 * Card-stack page (MyAccount pattern), gated on `instance:backup`:
 *   1. BACKUPS — create section-based archives into the local volume or a
 *      file-repo instance; list stored backups with Download/Delete.
 *   2. RESTORE — upload an archive or pick a stored one → full-page wizard.
 *   3. REPLICATION — one-way sync targets (push/pull) with manual + scheduled
 *      sync, per-target exclusion of stack-dependent settings.
 */

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

/** Parses the stored `sections` field (JSON string from the API). */
function backupSections(b: BackupEntry): string[] {
  if (Array.isArray(b.sections)) return b.sections;
  try {
    const parsed = JSON.parse(b.sections);
    return Array.isArray(parsed) ? parsed.filter((s): s is string => typeof s === 'string') : [];
  } catch {
    return [];
  }
}

/** Last-sync status chip for a replication target row. */
function SyncStatusChip({ t }: { t: ReplicationTarget }) {
  if (!t.lastSyncAt) return <span className="text-faint">never synced</span>;
  if (t.lastSyncStatus === 'ok') {
    return <span className="rounded bg-success px-1.5 py-0.5 text-[10px] font-semibold text-success-fg" title={String(t.lastReport?.at ?? '')}>ok</span>;
  }
  return (
    <span className="rounded bg-danger px-1.5 py-0.5 text-[10px] font-semibold text-danger-fg" title={t.lastError ?? undefined}>
      error
    </span>
  );
}

/** Add/edit dialog for a replication target. */
function TargetDialog({ existing, onClose }: { existing: ReplicationTarget | null; onClose: () => void }) {
  const queryClient = useQueryClient();
  const [name, setName] = useState(existing?.name ?? '');
  const [baseUrl, setBaseUrl] = useState(existing?.baseUrl ?? '');
  const [token, setToken] = useState('');
  const [direction, setDirection] = useState<'push' | 'pull'>(existing?.direction ?? 'push');
  const [enabled, setEnabled] = useState(existing?.enabled ?? true);
  const [intervalText, setIntervalText] = useState(existing?.intervalMinutes != null ? String(existing.intervalMinutes) : '');
  const [excludeText, setExcludeText] = useState((existing?.excludeKeys ?? []).join('\n'));
  const [error, setError] = useState<string | null>(null);

  const save = useMutation({
    mutationFn: () => {
      const body: ReplicationTargetInput = {
        name,
        baseUrl,
        token,
        direction,
        enabled,
        intervalMinutes: intervalText.trim() === '' ? null : Number(intervalText),
        excludeKeys: excludeText.split(/[\n,]+/).map((s) => s.trim()).filter(Boolean),
      };
      return existing ? api.updateReplicationTarget(existing.id, body) : api.createReplicationTarget(body);
    },
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ['replicationTargets'] });
      onClose();
    },
    onError: (err: unknown) => setError(err instanceof Error ? err.message : String(err)),
  });

  return (
    <DialogShell
      title={existing ? 'Edit replication target' : 'Add replication target'}
      subtitle="One-way sync peer — the token must carry `instance:backup` on the PEER instance."
      icon={<RefreshCw className="h-4 w-4 text-primary" />}
      onClose={onClose}
      maxWidth="max-w-lg"
      footer={
        <div className="flex items-center justify-end gap-2">
          <button type="button" onClick={onClose} className="rounded-md px-3 py-1.5 text-sm text-secondary hover:bg-muted">Cancel</button>
          <button
            type="button"
            disabled={save.isPending || !name.trim() || !baseUrl.trim() || !token.trim()}
            onClick={() => save.mutate()}
            className="inline-flex items-center gap-2 rounded-md bg-primary px-4 py-1.5 text-sm font-medium text-white hover:bg-primary-hover disabled:opacity-50"
          >
            {save.isPending && <Loader2 className="h-4 w-4 animate-spin" />}
            Save target
          </button>
        </div>
      }
    >
      <div className="space-y-3 text-sm">
        {error && <p className="rounded-md border border-danger-border bg-danger px-3 py-2 text-xs text-danger-fg">{error}</p>}
        <label className="block">
          <span className="mb-1 block text-xs font-medium uppercase tracking-wide text-faint">Name</span>
          <input className="w-full rounded-md border border-border bg-background px-2 py-1.5" value={name} onChange={(e) => setName(e.target.value)} placeholder="prod-unm" />
        </label>
        <label className="block">
          <span className="mb-1 block text-xs font-medium uppercase tracking-wide text-faint">Peer base URL</span>
          <input className="w-full rounded-md border border-border bg-background px-2 py-1.5 font-mono" value={baseUrl} onChange={(e) => setBaseUrl(e.target.value)} placeholder="https://unm.example.com" />
        </label>
        <label className="block">
          <span className="mb-1 block text-xs font-medium uppercase tracking-wide text-faint">Peer API token</span>
          <input type="password" className="w-full rounded-md border border-border bg-background px-2 py-1.5 font-mono" value={token} onChange={(e) => setToken(e.target.value)} placeholder="unm_…" />
        </label>
        <div className="grid grid-cols-2 gap-3">
          <label className="block">
            <span className="mb-1 block text-xs font-medium uppercase tracking-wide text-faint">Direction</span>
            <select className="w-full rounded-md border border-border bg-background px-2 py-1.5" value={direction} onChange={(e) => setDirection(e.target.value as 'push' | 'pull')}>
              <option value="push">Push — send this instance's config to the peer</option>
              <option value="pull">Pull — fetch and merge the peer's config here</option>
            </select>
          </label>
          <label className="block" title="Leave empty for manual-only sync. 1–1440 minutes.">
            <span className="mb-1 block text-xs font-medium uppercase tracking-wide text-faint">Interval (minutes)</span>
            <input type="number" min={1} max={1440} className="w-full rounded-md border border-border bg-background px-2 py-1.5" value={intervalText} onChange={(e) => setIntervalText(e.target.value)} placeholder="manual only" />
          </label>
        </div>
        <label className="flex items-center gap-2">
          <input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} />
          <span className="text-secondary">Enabled (scheduler runs due targets)</span>
        </label>
        <label className="block" title="Setting keys stripped before sending/applying — one per line. Defaults cover identity-bound settings (instance name, update feed, provider bindings…).">
          <span className="mb-1 block text-xs font-medium uppercase tracking-wide text-faint">Excluded setting keys</span>
          <textarea rows={4} className="w-full rounded-md border border-border bg-background px-2 py-1.5 font-mono text-xs" value={excludeText} onChange={(e) => setExcludeText(e.target.value)} placeholder={'instanceName\nupdateFeedUrl'} />
        </label>
      </div>
    </DialogShell>
  );
}

export default function Backups() {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const { formatDateTime } = useTimeFormat();
  const fileInputRef = useRef<HTMLInputElement>(null);

  // --- Create-backup form state -------------------------------------------------
  const [preset, setPreset] = useState<string>('config');
  const [sections, setSections] = useState<Set<string>>(new Set());
  const [destination, setDestination] = useState<'local' | 'repo'>('local');
  const [providerId, setProviderId] = useState<string>('');
  const [backupName, setBackupName] = useState('');

  // --- Replication state ----------------------------------------------------------
  const [targetDialog, setTargetDialog] = useState<{ open: boolean; existing: ReplicationTarget | null }>({ open: false, existing: null });
  const [syncingId, setSyncingId] = useState<string | null>(null);

  // --- Queries ---------------------------------------------------------------------
  const metaQuery = useQuery({ queryKey: ['backupMeta'], queryFn: api.backupMeta });
  const backupsQuery = useQuery({ queryKey: ['backups'], queryFn: api.listBackups });
  const providersQuery = useQuery({ queryKey: ['repoFileProviders'], queryFn: api.repoFileProviders });
  const targetsQuery = useQuery({ queryKey: ['replicationTargets'], queryFn: api.listReplicationTargets });

  // --- Mutations ---------------------------------------------------------------------
  const invalidateBackups = () => void queryClient.invalidateQueries({ queryKey: ['backups'] });

  const createBackup = useMutation({
    mutationFn: (body: { name?: string; sections: string[]; destination: 'local' | 'repo'; providerId?: string }) => api.createBackup(body),
    onSuccess: () => {
      setBackupName('');
      invalidateBackups();
    },
  });

  const deleteBackup = useMutation({
    mutationFn: (id: string) => api.deleteBackup(id),
    onSuccess: invalidateBackups,
  });

  const downloadBackup = async (b: BackupEntry) => {
    try {
      const blob = await api.downloadBackup(b.id);
      saveBlob(blob, `${b.name}.unmbak.gz`);
    } catch (err) {
      window.alert(`Download failed: ${err instanceof Error ? err.message : String(err)}`);
    }
  };

  const syncNow = useMutation({
    mutationFn: (targetId: string) => api.replicationSyncNow(targetId),
    onSettled: () => {
      setSyncingId(null);
      void queryClient.invalidateQueries({ queryKey: ['replicationTargets'] });
    },
  });

  const deleteTarget = useMutation({
    mutationFn: (id: string) => api.deleteReplicationTarget(id),
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: ['replicationTargets'] }),
  });

  // Effective section selection — preset drives the set until the user toggles manually.
  const meta = metaQuery.data;
  const effectiveSections = useMemo(() => {
    if (sections.size > 0) return [...sections];
    return meta?.presets[preset] ?? [];
  }, [meta, preset, sections]);

  function toggleSection(key: string) {
    setPreset('custom'); // manual selection overrides the preset
    const next = new Set(sections);
    if (next.has(key)) next.delete(key); else next.add(key);
    setSections(next);
  }

  function pickPreset(p: string) {
    setPreset(p);
    setSections(new Set()); // reset manual toggles — the preset's bundle applies
  }

  const providers = providersQuery.data?.providers ?? [];
  const onlineProviders = providers.filter((p) => p.online);
  const targets = targetsQuery.data?.targets ?? [];

  return (
    <Layout title="Backups">
      <div className="space-y-4">
        {/* ================= BACKUPS card ================= */}
        <div className="rounded-md border border-border bg-card p-4 shadow-sm">
          <h2 className="mb-1 flex items-center gap-2 text-base font-semibold text-foreground">
            <DatabaseBackup className="h-4 w-4 text-primary" /> Backups
          </h2>
          <p className="mb-3 text-xs text-faint">
            Section-based archives of this instance's own database. Restore is a safe merge — rows absent from the archive are never deleted.
            API tokens, passkeys and live inventory telemetry never move (tokens re-mint, passkeys re-register).
          </p>

          {meta && (
            <div className="mb-4 space-y-3">
              {/* Preset row */}
              <div className="flex flex-wrap items-center gap-2 text-sm">
                <span className="text-xs font-medium uppercase tracking-wide text-faint">Preset</span>
                {Object.entries(meta.presets).map(([key, keys]) => (
                  <button
                    key={key}
                    type="button"
                    onClick={() => pickPreset(key)}
                    className={clsx(
                      'rounded-md border px-2.5 py-1 text-xs font-medium',
                      preset === key && sections.size === 0 ? 'border-primary bg-primary/10 text-primary' : 'border-border hover:bg-muted'
                    )}
                  >
                    {key[0].toUpperCase() + key.slice(1)} <span className="text-faint">({keys.length})</span>
                  </button>
                ))}
              </div>

              {/* Section checkboxes */}
              <div className="flex flex-wrap gap-2 text-sm">
                {meta.sections.map((s) => (
                  <label key={s.key} className="flex items-center gap-1.5 rounded-md border border-border px-2 py-1" title={`Tables: ${s.tables.join(', ')}`}>
                    <input type="checkbox" checked={effectiveSections.includes(s.key)} onChange={() => toggleSection(s.key)} />
                    <span>{s.key}</span>
                    <span className="text-xs text-faint">({s.tables.length})</span>
                  </label>
                ))}
              </div>

              {/* Destination + name + create */}
              <div className="flex flex-wrap items-end gap-3 border-t border-border pt-3">
                <label className="block text-sm" title="Local volume (unm-backups) or a registered file-repo instance — the backup's bytes are bound to exactly one destination.">
                  <span className="mb-1 block text-xs font-medium uppercase tracking-wide text-faint">Destination</span>
                  <select className="rounded-md border border-border bg-background px-2 py-1.5" value={destination} onChange={(e) => setDestination(e.target.value as 'local' | 'repo')}>
                    <option value="local">Local volume (unm-backups)</option>
                    <option value="repo" disabled={providers.length === 0}>File repo {providers.length === 0 ? '(none registered)' : ''}</option>
                  </select>
                </label>
                <label className="block text-sm">
                  <span className="mb-1 block text-xs font-medium uppercase tracking-wide text-faint">Name (optional)</span>
                  <input className="w-56 rounded-md border border-border bg-background px-2 py-1.5" value={backupName} onChange={(e) => setBackupName(e.target.value)} placeholder={`backup-${preset}-…`} />
                </label>
                <button
                  type="button"
                  disabled={createBackup.isPending || effectiveSections.length === 0 || (destination === 'repo' && (!providerId || !onlineProviders.some((p) => p.id === providerId)))}
                  onClick={() => {
                    const body = destination === 'repo'
                      ? { name: backupName.trim() || undefined, sections: effectiveSections, destination: 'repo' as const, providerId }
                      : { name: backupName.trim() || undefined, sections: effectiveSections, destination: 'local' as const };
                    createBackup.mutate(body);
                  }}
                  className="inline-flex items-center gap-2 rounded-md bg-primary px-4 py-1.5 text-sm font-medium text-white hover:bg-primary-hover disabled:opacity-50"
                >
                  {createBackup.isPending && <Loader2 className="h-4 w-4 animate-spin" />}
                  Create backup
                </button>
              </div>

              {/* Repo destination needs an explicit instance pick (strict binding — no fallback to a sibling). */}
              {destination === 'repo' && providers.length > 0 && (
                <div className="flex flex-wrap items-center gap-2 text-sm">
                  <span className="text-xs font-medium uppercase tracking-wide text-faint">File-repo instance</span>
                  {providers.map((p) => (
                    <label key={p.id} className={clsx('flex items-center gap-1.5 rounded-md border px-2 py-1', !p.online && 'opacity-50')} title={p.endpoint || undefined}>
                      <input type="radio" name="backup-provider" disabled={!p.online} checked={providerId === p.id} onChange={() => setProviderId(p.id)} />
                      {p.name}{p.endpoint ? <span className="font-mono text-xs text-faint">{p.endpoint}</span> : null}
                    </label>
                  ))}
                </div>
              )}

              {(createBackup.isError || deleteBackup.isError) && (
                <p className="rounded-md border border-danger-border bg-danger px-3 py-2 text-xs text-danger-fg">
                  {((createBackup.error ?? deleteBackup.error) as Error).message}
                </p>
              )}
            </div>
          )}

          {/* Stored backups table */}
          <div className="overflow-x-auto rounded-md border border-border">
            <table className="w-full text-left text-xs">
              <thead className="bg-muted">
                <tr>
                  <th className="px-2 py-1.5 font-medium">Name</th>
                  <th className="px-2 py-1.5 font-medium">Scope</th>
                  <th className="px-2 py-1.5 font-medium">Destination</th>
                  <th className="px-2 py-1.5 font-medium">Size</th>
                  <th className="px-2 py-1.5 font-medium">Created</th>
                  <th className="px-2 py-1.5 text-right font-medium">Actions</th>
                </tr>
              </thead>
              <tbody>
                {backupsQuery.isLoading && (
                  <tr><td colSpan={6} className="px-2 py-4 text-center text-faint"><Loader2 className="mx-auto h-4 w-4 animate-spin" /></td></tr>
                )}
                {!backupsQuery.isLoading && (backupsQuery.data?.backups ?? []).length === 0 && (
                  <tr><td colSpan={6} className="px-2 py-4 text-center text-faint">No stored backups yet.</td></tr>
                )}
                {(backupsQuery.data?.backups ?? []).map((b) => {
                  const secs = backupSections(b);
                  return (
                    <tr key={b.id} className="border-t border-border">
                      <td className="max-w-[240px] truncate px-2 py-1.5 font-medium" title={`${b.name}\nsha256 ${b.sha256.slice(0, 16)}…`}>{b.name}</td>
                      <td className="px-2 py-1.5">
                        <span className="flex flex-wrap gap-1">
                          {secs.map((s) => (
                            <span key={s} className="rounded bg-muted px-1.5 py-0.5 text-[10px] font-medium text-secondary">{s}</span>
                          ))}
                        </span>
                      </td>
                      <td className="px-2 py-1.5">
                        {b.source === 'local' ? (
                          b.fileMissing
                            ? <span className="text-danger-fg" title="Metadata exists but the bytes are gone — delete this row to clean up.">bytes missing</span>
                            : <span className="rounded bg-info px-1.5 py-0.5 text-[10px] font-semibold text-info-fg">local volume</span>
                        ) : (
                          <span className="text-secondary" title={b.providerId ?? undefined}>{b.providerName ?? 'unknown provider'}</span>
                        )}
                      </td>
                      <td className="whitespace-nowrap px-2 py-1.5">{formatBytes(Number(b.sizeBytes))}</td>
                      <td className="whitespace-nowrap px-2 py-1.5 text-faint">{formatDateTime(b.createdAt)}</td>
                      <td className="px-2 py-1.5">
                        <span className="flex items-center justify-end gap-1">
                          <button type="button" title="Download archive" onClick={() => void downloadBackup(b)} className="rounded p-1 text-secondary hover:bg-muted"><Download className="h-3.5 w-3.5" /></button>
                          <button
                            type="button"
                            title="Restore from this backup"
                            onClick={() => navigate(`/backups/restore?backupId=${encodeURIComponent(b.id)}`)}
                            className="rounded p-1 text-secondary hover:bg-muted"
                          >
                            <ArchiveRestore className="h-3.5 w-3.5" />
                          </button>
                          <button type="button" title="Delete backup (metadata + bytes)" onClick={() => { if (window.confirm(`Delete backup "${b.name}"?`)) deleteBackup.mutate(b.id); }} className="rounded p-1 text-danger-fg hover:bg-muted"><Trash2 className="h-3.5 w-3.5" /></button>
                        </span>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>

          {/* Restore entry point */}
          <div className="mt-4 flex flex-wrap items-center gap-3 border-t border-border pt-3 text-sm">
            <span className="text-xs font-medium uppercase tracking-wide text-faint">Restore</span>
            <button type="button" onClick={() => fileInputRef.current?.click()} className="inline-flex items-center gap-2 rounded-md border border-border px-3 py-1.5 text-sm hover:bg-muted">
              Upload archive…
            </button>
            <input ref={fileInputRef} type="file" accept=".unmbak.gz,application/gzip,application/octet-stream" className="hidden" onChange={(e) => { const f = e.target.files?.[0]; if (f) navigate(`/backups/restore?upload=${encodeURIComponent(f.name)}`); e.target.value = ''; }} />
            <button type="button" onClick={() => navigate('/backups/restore')} className="inline-flex items-center gap-2 rounded-md border border-border px-3 py-1.5 text-sm hover:bg-muted">
              Restore from stored backup…
            </button>
            <span className="text-xs text-faint">Opens the restore wizard — preview first, then a safe merge (upsert by id; absent rows untouched).</span>
          </div>
        </div>

        {/* ================= REPLICATION card ================= */}
        <div className="rounded-md border border-border bg-card p-4 shadow-sm">
          <h2 className="mb-1 flex items-center gap-2 text-base font-semibold text-foreground">
            <RefreshCw className="h-4 w-4 text-primary" /> Replication
          </h2>
          <p className="mb-3 text-xs text-faint">
            One-way sync of portable config (identity, settings, devices, documented, plans) to/from a peer instance. Live inventory never replicates — it is regenerated locally by polling.
            Secrets move only between instances sharing the same MASTER_KEY + CRYPTO_SALT.
          </p>

          <div className="mb-3 flex justify-end">
            <button type="button" onClick={() => setTargetDialog({ open: true, existing: null })} className="inline-flex items-center gap-2 rounded-md bg-primary px-3 py-1.5 text-sm font-medium text-white hover:bg-primary-hover">
              <Plus className="h-4 w-4" /> Add target
            </button>
          </div>

          {targetsQuery.isError && (
            <p className="rounded-md border border-danger-border bg-danger px-3 py-2 text-xs text-danger-fg">{(targetsQuery.error as Error).message}</p>
          )}

          <div className="overflow-x-auto rounded-md border border-border">
            <table className="w-full text-left text-xs">
              <thead className="bg-muted">
                <tr>
                  <th className="px-2 py-1.5 font-medium">Name</th>
                  <th className="px-2 py-1.5 font-medium">Peer</th>
                  <th className="px-2 py-1.5 font-medium">Direction</th>
                  <th className="px-2 py-1.5 font-medium">Interval</th>
                  <th className="px-2 py-1.5 font-medium">Last sync</th>
                  <th className="px-2 py-1.5 text-right font-medium">Actions</th>
                </tr>
              </thead>
              <tbody>
                {targetsQuery.isLoading && (
                  <tr><td colSpan={6} className="px-2 py-4 text-center text-faint"><Loader2 className="mx-auto h-4 w-4 animate-spin" /></td></tr>
                )}
                {!targetsQuery.isLoading && targets.length === 0 && (
                  <tr><td colSpan={6} className="px-2 py-4 text-center text-faint">No replication targets yet.</td></tr>
                )}
                {targets.map((t) => (
                  <tr key={t.id} className={clsx('border-t border-border', !t.enabled && 'opacity-60')}>
                    <td className="px-2 py-1.5 font-medium">{t.name}</td>
                    <td className="max-w-[220px] truncate px-2 py-1.5 font-mono" title={t.baseUrl}>{t.baseUrl}</td>
                    <td className="px-2 py-1.5">
                      <span className={clsx('rounded px-1.5 py-0.5 text-[10px] font-semibold', t.direction === 'push' ? 'bg-info text-info-fg' : 'bg-muted text-secondary')}>{t.direction}</span>
                    </td>
                    <td className="whitespace-nowrap px-2 py-1.5">{t.intervalMinutes != null ? `${t.intervalMinutes} min` : <span className="text-faint">manual</span>}</td>
                    <td className="whitespace-nowrap px-2 py-1.5">
                      <span className="flex items-center gap-1.5">
                        <SyncStatusChip t={t} />
                        {t.lastSyncAt && <span className="text-faint">{formatDateTime(t.lastSyncAt)}</span>}
                      </span>
                    </td>
                    <td className="px-2 py-1.5">
                      <span className="flex items-center justify-end gap-1">
                        <button
                          type="button"
                          title={syncingId === t.id ? 'Syncing…' : 'Sync now'}
                          disabled={syncingId !== null}
                          onClick={() => { setSyncingId(t.id); syncNow.mutate(t.id); }}
                          className="rounded p-1 text-secondary hover:bg-muted disabled:opacity-50"
                        >
                          <RefreshCw className={clsx('h-3.5 w-3.5', syncingId === t.id && 'animate-spin')} />
                        </button>
                        <button type="button" title="Edit target" onClick={() => setTargetDialog({ open: true, existing: t })} className="rounded p-1 text-secondary hover:bg-muted">
                          <span className="text-[10px] font-semibold uppercase">edit</span>
                        </button>
                        <button type="button" title="Delete target" onClick={() => { if (window.confirm(`Delete replication target "${t.name}"?`)) deleteTarget.mutate(t.id); }} className="rounded p-1 text-danger-fg hover:bg-muted"><Trash2 className="h-3.5 w-3.5" /></button>
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {syncNow.isError && (
            <p className="mt-2 rounded-md border border-danger-border bg-danger px-3 py-2 text-xs text-danger-fg">
              Sync failed: {(syncNow.error as Error).message} — see the target's last-sync status for details.
            </p>
          )}
        </div>
      </div>

      {targetDialog.open && <TargetDialog existing={targetDialog.existing} onClose={() => setTargetDialog({ open: false, existing: null })} />}
    </Layout>
  );
}
