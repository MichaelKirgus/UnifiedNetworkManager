import { useEffect, useRef, useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import clsx from 'clsx';
import { ArchiveRestore, Check, FileUp, Loader2 } from 'lucide-react';
import { api, BackupEntry, BackupManifest, SectionMergeReport } from '../api/client';
import { WizardLayout } from '../components/Wizard';

/**
 * BackupRestorePage — full-page restore wizard (3 steps on the shared shell):
 *   1. SOURCE — upload a .unmbak.gz archive (staged server-side for preview) or
 *      pick a stored backup; section toggles default to everything present.
 *   2. PREVIEW — manifest summary (per-section row counts when known) + the
 *      safe-merge explanation; Apply runs the merge.
 *   3. DONE — per-section report (created / updated / skipped + warnings).
 *
 * Restore is a SAFE MERGE: upsert by primary key, rows absent from the archive
 * are never deleted. A staged upload is discarded server-side on cancel/exit.
 */

/** Parses the stored `sections` field (JSON string from the API). */
function sectionsOf(entry: BackupEntry): string[] {
  if (Array.isArray(entry.sections)) return entry.sections;
  try {
    const parsed = JSON.parse(entry.sections);
    return Array.isArray(parsed) ? parsed.filter((s): s is string => typeof s === 'string') : [];
  } catch {
    return [];
  }
}

/** Human label for a section key. */
const SECTION_LABELS: Record<string, string> = {
  identity: 'Identity (users, roles, policies)',
  settings: 'Settings',
  devices: 'Devices & plugins',
  documented: 'Documented networks/hosts',
  plans: 'Plans',
  liveInventory: 'Live inventory (regenerable)',
};

export default function BackupRestorePage() {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [searchParams] = useSearchParams();
  const from = searchParams.get('from') ?? '/backups';
  const storedBackupId = searchParams.get('backupId');
  const uploadHint = searchParams.get('upload');

  const fileInputRef = useRef<HTMLInputElement>(null);

  // --- Source state -------------------------------------------------------------
  const [sourceType, setSourceType] = useState<'none' | 'upload' | 'stored'>('none');
  const [pendingId, setPendingId] = useState<string | null>(null);
  const [manifest, setManifest] = useState<BackupManifest | null>(null);
  const [storedEntry, setStoredEntry] = useState<BackupEntry | null>(null);
  const [selectedSections, setSelectedSections] = useState<Set<string>>(new Set());

  // --- Wizard state ---------------------------------------------------------------
  const [step, setStep] = useState<1 | 2 | 3>(1);
  const [report, setReport] = useState<SectionMergeReport[] | null>(null);

  const backupsQuery = useQuery({ queryKey: ['backups'], queryFn: api.listBackups });

  // Resolve a stored backup passed via ?backupId= — its section keys seed the toggles.
  useEffect(() => {
    if (!storedBackupId || !backupsQuery.data) return;
    const entry = backupsQuery.data.backups.find((b) => b.id === storedBackupId);
    if (entry) {
      setStoredEntry(entry);
      setSourceType('stored');
      setSelectedSections(new Set(sectionsOf(entry)));
    }
  }, [storedBackupId, backupsQuery.data]);

  // When a manifest arrives (upload staged), default to all its sections.
  useEffect(() => {
    if (manifest) setSelectedSections(new Set(Object.keys(manifest.sections)));
  }, [manifest]);

  const stageUpload = useMutation({
    mutationFn: (file: File) => api.uploadBackupForRestore(file),
    onSuccess: (res) => {
      setPendingId(res.pendingId);
      setManifest(res.manifest);
      setSourceType('upload');
    },
  });

  const applyMutation = useMutation({
    mutationFn: () =>
      sourceType === 'upload' && pendingId
        ? api.applyBackupRestore({ pendingId, sections: [...selectedSections] })
        : storedEntry
          ? api.applyBackupRestore({ backupId: storedEntry.id, sections: [...selectedSections] })
          : Promise.reject(new Error('No source selected')),
    onSuccess: (res) => {
      setReport(res.report);
      setStep(3);
      void queryClient.invalidateQueries({ queryKey: ['backups'] });
    },
  });

  // Best-effort discard of a staged upload when the user leaves without applying.
  useEffect(() => {
    return () => {
      if (pendingId && !report) {
        void api.discardPendingRestore(pendingId).catch(() => undefined);
      }
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [pendingId, report]);

  const manifestSections = manifest ? Object.entries(manifest.sections) : [];
  const totalRows = manifestSections.reduce((sum, [, s]) => sum + (s.rowCount ?? 0), 0);
  const versionWarning = manifest && manifest.schemaVersion > 1;
  const buildTagNote = manifest?.buildTag ? `Exported by ${manifest.instanceName || 'another instance'} (build ${manifest.buildTag})` : null;

  function toggleSection(key: string) {
    setSelectedSections((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key); else next.add(key);
      return next;
    });
  }

  // Section rows for the preview — manifest counts when available, keys only otherwise.
  const previewRows: Array<{ key: string; rowCount?: number }> = sourceType === 'upload' && manifest
    ? Object.entries(manifest.sections).map(([key, s]) => ({ key, rowCount: s.rowCount }))
    : storedEntry
      ? sectionsOf(storedEntry).map((key) => ({ key }))
      : [];

  const createdTotal = report?.reduce((sum, r) => sum + (r.tables ?? []).reduce((s, t) => s + (t.created ?? 0), 0), 0) ?? 0;
  const updatedTotal = report?.reduce((sum, r) => sum + (r.tables ?? []).reduce((s, t) => s + (t.updated ?? 0), 0), 0) ?? 0;

  return (
    <WizardLayout
      title="Restore backup"
      icon={<ArchiveRestore className="h-4 w-4 text-primary" />}
      steps={[{ label: 'Source' }, { label: 'Preview' }, { label: 'Done' }]}
      current={step - 1}
      onExit={() => navigate(from)}
    >
      {/* ================= STEP 1 — source ================= */}
      {step === 1 && (
        <div className="space-y-4">
          <p className="text-sm text-secondary">
            Restore merges the archive into this instance with SAFE semantics: every row is upserted by its primary key, and rows absent from the
            archive are never deleted. API tokens and passkeys are not part of any backup (re-mint / re-register).
          </p>

          {/* Upload source */}
          <div className="rounded-md border border-border bg-background p-3">
            <h3 className="mb-2 flex items-center gap-2 text-sm font-semibold"><FileUp className="h-4 w-4 text-primary" /> Upload an archive</h3>
            {sourceType === 'upload' && manifest ? (
              <div className="flex items-center justify-between gap-2 rounded-md border border-success/40 bg-success/10 px-3 py-2 text-sm">
                <span className="font-medium">{uploadHint ?? 'Archive staged'} — ready to preview</span>
                <button type="button" onClick={() => fileInputRef.current?.click()} className="text-xs text-secondary underline hover:text-foreground">Replace</button>
              </div>
            ) : (
              <>
                <p className="mb-2 text-xs text-faint">A .unmbak.gz archive exported from any UNM instance{uploadHint ? ` — you picked "${uploadHint}" on the Backups page` : ''}.</p>
                <button type="button" onClick={() => fileInputRef.current?.click()} className="inline-flex items-center gap-2 rounded-md border border-border px-3 py-1.5 text-sm hover:bg-muted">
                  Choose archive…
                </button>
              </>
            )}
            <input
              ref={fileInputRef}
              type="file"
              accept=".unmbak.gz,application/gzip,application/octet-stream"
              className="hidden"
              onChange={(e) => { const f = e.target.files?.[0]; if (f) stageUpload.mutate(f); e.target.value = ''; }}
            />
          </div>

          {/* Stored source */}
          <div className="rounded-md border border-border bg-background p-3">
            <h3 className="mb-2 flex items-center gap-2 text-sm font-semibold"><ArchiveRestore className="h-4 w-4 text-primary" /> Or a stored backup</h3>
            {sourceType === 'stored' && storedEntry ? (
              <div className="flex items-center justify-between gap-2 rounded-md border border-success/40 bg-success/10 px-3 py-2 text-sm">
                <span className="font-medium">{storedEntry.name}</span>
                <button type="button" onClick={() => { setStoredEntry(null); setSourceType('none'); setSelectedSections(new Set()); }} className="text-xs text-secondary underline hover:text-foreground">Clear</button>
              </div>
            ) : (
              <>
                <p className="mb-2 text-xs text-faint">Pick one of this instance's stored backups.</p>
                {backupsQuery.isLoading ? (
                  <p className="flex items-center gap-2 text-sm text-faint"><Loader2 className="h-3.5 w-3.5 animate-spin" /> Loading…</p>
                ) : (backupsQuery.data?.backups ?? []).length === 0 ? (
                  <p className="text-xs text-faint">No stored backups on this instance.</p>
                ) : (
                  <div className="max-h-56 space-y-1 overflow-y-auto">
                    {(backupsQuery.data?.backups ?? []).map((b) => (
                      <label key={b.id} className="flex cursor-pointer items-center gap-2 rounded-md border border-border px-3 py-2 text-sm hover:bg-muted">
                        <input type="radio" name="stored-backup" checked={storedEntry?.id === b.id} onChange={() => { setStoredEntry(b); setSourceType('stored'); }} />
                        <span className="font-medium">{b.name}</span>
                        <span className="text-xs text-faint">{new Date(b.createdAt).toLocaleDateString()}</span>
                      </label>
                    ))}
                  </div>
                )}
              </>
            )}
          </div>

          {(stageUpload.isError || applyMutation.isError) && (
            <p className="rounded-md border border-danger-border bg-danger px-3 py-2 text-sm text-danger-fg">{((stageUpload.error ?? applyMutation.error) as Error).message}</p>
          )}

          {stageUpload.isPending && (
            <p className="flex items-center gap-2 text-sm text-faint"><Loader2 className="h-3.5 w-3.5 animate-spin" /> Staging archive…</p>
          )}

          <div className="flex justify-end gap-2 border-t border-border pt-3">
            <button type="button" onClick={() => navigate(from)} className="rounded-md px-3 py-1.5 text-sm text-secondary hover:bg-muted">Cancel</button>
            <button
              type="button"
              disabled={sourceType === 'none' || stageUpload.isPending}
              onClick={() => setStep(2)}
              className="inline-flex items-center gap-2 rounded-md bg-primary px-4 py-1.5 text-sm font-medium text-white hover:bg-primary-hover disabled:opacity-50"
            >
              Preview <Check className="h-4 w-4" />
            </button>
          </div>
        </div>
      )}

      {/* ================= STEP 2 — preview + apply ================= */}
      {step === 2 && (
        <div className="space-y-4">
          <p className="text-sm text-secondary">
            Select which sections to merge. The merge is per-section transactional — a failed section rolls back on its own and never touches the others.
          </p>

          {versionWarning && (
            <p className="rounded-md border border-danger-border bg-danger px-3 py-2 text-sm text-danger-fg">
              This archive uses schema version {manifest?.schemaVersion} — this instance only understands version 1. The API will refuse to apply it.
            </p>
          )}
          {buildTagNote && !versionWarning && (
            <p className="rounded-md border border-border bg-background px-3 py-2 text-xs text-faint">{buildTagNote}</p>
          )}

          {/* Section toggles */}
          <div className="space-y-1">
            {previewRows.map(({ key, rowCount }) => (
              <label key={key} className="flex items-center justify-between gap-3 rounded-md border border-border px-3 py-2 text-sm" title={`Section "${key}"`}>
                <span className="flex items-center gap-2">
                  <input type="checkbox" checked={selectedSections.has(key)} onChange={() => toggleSection(key)} />
                  {SECTION_LABELS[key] ?? key}
                </span>
                <span className="text-xs text-faint">{rowCount != null ? `${rowCount.toLocaleString()} rows` : 'row counts available after download'}</span>
              </label>
            ))}
          </div>

          {manifest && (
            <p className="text-xs text-faint">Archive total: {totalRows.toLocaleString()} rows across {manifestSections.length} section(s), exported {new Date(manifest.exportedAt).toLocaleString()}.</p>
          )}

          {/* Apply */}
          {applyMutation.isPending ? (
            <div className="rounded-md border border-border bg-background p-4 text-center">
              <Loader2 className="mx-auto h-5 w-5 animate-spin text-primary" />
              <p className="mt-2 text-sm font-medium text-secondary">Merging {selectedSections.size} section(s)…</p>
            </div>
          ) : (
            <div className="flex justify-end gap-2 border-t border-border pt-3">
              <button type="button" onClick={() => setStep(1)} className="rounded-md px-3 py-1.5 text-sm text-secondary hover:bg-muted">Back to source</button>
              <button
                type="button"
                disabled={selectedSections.size === 0 || !!versionWarning}
                onClick={() => applyMutation.mutate()}
                className="inline-flex items-center gap-2 rounded-md bg-primary px-4 py-1.5 text-sm font-medium text-white hover:bg-primary-hover disabled:opacity-50"
              >
                <ArchiveRestore className="h-4 w-4" /> Apply restore ({selectedSections.size} section(s))
              </button>
            </div>
          )}
        </div>
      )}

      {/* ================= STEP 3 — report ================= */}
      {step === 3 && report && (
        <div className="space-y-4">
          <div className="flex flex-wrap gap-2 text-sm">
            <span className="rounded bg-success px-2 py-1 font-medium text-success-fg">{createdTotal.toLocaleString()} created</span>
            <span className="rounded bg-info px-2 py-1 font-medium text-info-fg">{updatedTotal.toLocaleString()} updated (merged)</span>
          </div>

          <div className="overflow-x-auto rounded-md border border-border">
            <table className="w-full text-left text-xs">
              <thead className="bg-muted">
                <tr>
                  <th className="px-2 py-1.5 font-medium">Section</th>
                  <th className="px-2 py-1.5 font-medium">Table</th>
                  <th className="px-2 py-1.5 text-right font-medium">Created</th>
                  <th className="px-2 py-1.5 text-right font-medium">Updated</th>
                  <th className="px-2 py-1.5 text-right font-medium">Skipped</th>
                </tr>
              </thead>
              <tbody>
                {report.flatMap((r) => (r.tables ?? []).map((t, i) => (
                  <tr key={`${r.section}-${t.table}-${i}`} className="border-t border-border">
                    <td className={clsx('px-2 py-1.5', i > 0 && 'text-faint')}>{i === 0 ? r.section : ''}</td>
                    <td className="px-2 py-1.5 font-mono">{t.table}</td>
                    <td className="px-2 py-1.5 text-right">{(t.created ?? 0).toLocaleString()}</td>
                    <td className="px-2 py-1.5 text-right">{(t.updated ?? 0).toLocaleString()}</td>
                    <td className="px-2 py-1.5 text-right">{(t.skipped ?? 0) > 0 ? (t.skipped ?? 0).toLocaleString() : '—'}</td>
                  </tr>
                )))}
              </tbody>
            </table>
          </div>

          {report.some((r) => (r.warnings ?? []).length > 0) && (
            <div className="rounded-md border border-border bg-background p-3">
              <h4 className="mb-1 text-xs font-medium uppercase tracking-wide text-faint">Warnings</h4>
              <ul className="list-inside list-disc space-y-0.5 text-xs text-secondary">
                {report.flatMap((r) => (r.warnings ?? []).map((w, i) => <li key={`${r.section}-${i}`}>{w}</li>))}
              </ul>
            </div>
          )}

          <div className="flex justify-end border-t border-border pt-3">
            <button type="button" onClick={() => navigate(from)} className="inline-flex items-center gap-2 rounded-md bg-primary px-4 py-1.5 text-sm font-medium text-white hover:bg-primary-hover">
              Done
            </button>
          </div>
        </div>
      )}
    </WizardLayout>
  );
}
