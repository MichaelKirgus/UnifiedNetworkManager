import { useEffect, useRef, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import clsx from 'clsx';
import { Database, Download, FileUp, FolderOpen, History, Loader2, Pencil, Plus, Tag, Timer, Trash2, X } from 'lucide-react';
import { DialogShell } from '../components/DialogShell';
import { Layout } from '../components/Layout';
import { DataTable, DataTableColumn } from '../components/DataTable';
import { formatBytes } from '../components/formatMetric';
import { api, ApiError, RepoFileEntry, RepoFileUse, RetentionPolicy, RetentionPolicyInput } from '../api/client';
import { can } from '../auth/permissions';
import { useTimeFormat } from '../utils/time';

/**
 * Files — the central file repository. A DEVICE-INDEPENDENT store of ISOs,
 * firmware images, config backups and scripts: files live on a volume only the
 * UNM API mounts (metadata + usage audit trail in Postgres), so nothing is
 * duplicated per device or per plugin. Plugins reach the repo through the API's
 * internal /plugin/files/* routes (SDK createFileRepoClient) and push files onto
 * devices via their own native transport — e.g. a VM install ISO fetched here
 * can be attached to a TrueNAS VM from the VMs page.
 */

const CATEGORIES = ['iso', 'firmware', 'config-backup', 'script', 'other'] as const;

/** localStorage key for the user's preferred upload target (survives reloads). */
const UPLOAD_PROVIDER_KEY = 'unm.files.uploadProvider';

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

/** One-line human summary of a policy's enforcement dimensions. */
function retentionSummary(p: RetentionPolicy): string {
  const parts: string[] = [];
  if (p.maxAgeDays) parts.push(`delete after ${p.maxAgeDays}d`);
  if (p.keepLatestPerDevice) parts.push(`keep newest ${p.keepLatestPerDevice}/device`);
  return parts.join(' + ');
}

/** One-line human summary of a policy's matchers. */
function matcherSummary(p: RetentionPolicy): string {
  const m: string[] = [];
  if (p.category) m.push(p.category);
  if (p.namePattern) m.push(`name ~ ${p.namePattern}`);
  return m.length > 0 ? m.join(', ') : 'any file';
}

const fieldCls = 'w-full rounded-md border border-border bg-background px-2.5 py-1.5 text-xs focus:border-focus-ring focus:outline-none';
const labelCls = 'mb-1 block text-[11px] font-medium uppercase tracking-wide text-faint';

/** Retention lifecycle templates — create/edit/delete policies, bulk-assign them to
 * matching files, and run the sweep on demand. Files with no policy are kept forever. */
function RetentionPoliciesDialog({ onClose }: { onClose: () => void }) {
  const queryClient = useQueryClient();
  const canWrite = can('files:write');

  const policiesQuery = useQuery({ queryKey: ['retentionPolicies'], queryFn: () => api.listRetentionPolicies() });
  const policies = policiesQuery.data?.policies ?? [];

  // Create/edit form state — editingId 'new' opens the empty form, a policy id pre-fills it.
  const [editingId, setEditingId] = useState<string | null>(null);
  const [form, setForm] = useState({ name: '', description: '', category: '', namePattern: '', maxAgeDays: '', keepLatestPerDevice: '' });
  const [error, setError] = useState<string | null>(null);
  const [sweepResult, setSweepResult] = useState<{ totalDeleted: number; perPolicy: Array<{ name: string; deleted: number }> } | null>(null);

  function openCreate() {
    setForm({ name: '', description: '', category: '', namePattern: '', maxAgeDays: '', keepLatestPerDevice: '' });
    setEditingId('new');
    setError(null);
  }
  function openEdit(p: RetentionPolicy) {
    setForm({
      name: p.name,
      description: p.description ?? '',
      category: p.category ?? '',
      namePattern: p.namePattern ?? '',
      maxAgeDays: p.maxAgeDays ? String(p.maxAgeDays) : '',
      keepLatestPerDevice: p.keepLatestPerDevice ? String(p.keepLatestPerDevice) : '',
    });
    setEditingId(p.id);
    setError(null);
  }

  const invalidate = () => {
    queryClient.invalidateQueries({ queryKey: ['retentionPolicies'] });
    queryClient.invalidateQueries({ queryKey: ['repoFiles'] });
  };

  const saveMutation = useMutation({
    mutationFn: async (): Promise<RetentionPolicy> => {
      const body: RetentionPolicyInput = {
        name: form.name.trim(),
        description: form.description.trim() || null,
        category: form.category.trim().toLowerCase() || null,
        namePattern: form.namePattern.trim() || null,
        maxAgeDays: form.maxAgeDays.trim() === '' ? null : Number(form.maxAgeDays),
        keepLatestPerDevice: form.keepLatestPerDevice.trim() === '' ? null : Number(form.keepLatestPerDevice),
      };
      if (editingId === 'new') return (await api.createRetentionPolicy(body)).policy;
      const { policy } = await api.updateRetentionPolicy(editingId as string, body);
      return policy;
    },
    onSuccess: () => {
      setEditingId(null);
      setError(null);
      invalidate();
    },
    onError: (err) => setError(err instanceof Error ? err.message : String(err)),
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => api.deleteRetentionPolicy(id),
    onSuccess: () => invalidate(),
    onError: (err) => setError(err instanceof Error ? err.message : String(err)),
  });

  const applyMutation = useMutation({
    mutationFn: (id: string) => api.applyRetentionPolicyToMatching(id),
    onSuccess: ({ assigned }) => {
      setSweepResult(null);
      setError(null);
      invalidate();
      // eslint-disable-next-line no-console
      console.log(`[files] retention policy applied to ${assigned} file(s)`);
    },
    onError: (err) => setError(err instanceof Error ? err.message : String(err)),
  });

  const toggleMutation = useMutation({
    mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) => api.updateRetentionPolicy(id, { enabled }),
    onSuccess: () => invalidate(),
    onError: (err) => setError(err instanceof Error ? err.message : String(err)),
  });

  const sweepMutation = useMutation({
    mutationFn: () => api.runRetentionSweep(),
    onSuccess: (res) => {
      setSweepResult(res);
      invalidate();
    },
    onError: (err) => setError(err instanceof Error ? err.message : String(err)),
  });

  return (
    <DialogShell title="Retention policies" subtitle="Lifecycle templates for repo files — a file with no policy is kept forever." onClose={onClose} maxWidth="max-w-2xl" bodyMaxHeight="70vh">
      <div className="space-y-3">
        {error && (
          <div className="flex items-center gap-2 rounded-md border border-danger-border bg-danger px-3 py-2 text-xs text-danger-fg">
            <span className="flex-1">{error}</span>
            <button type="button" aria-label="Dismiss error" onClick={() => setError(null)}><X size={12} /></button>
          </div>
        )}

        {/* Policy list */}
        {policiesQuery.isLoading ? (
          <p className="flex items-center gap-2 text-sm text-muted-foreground"><Loader2 size={14} className="animate-spin" /> Loading…</p>
        ) : policies.length === 0 && editingId !== 'new' ? (
          <p className="text-sm text-faint">No retention policies yet. Create one below — e.g. "config backups: delete after 30 days + keep newest 7 per device".</p>
        ) : (
          <div className="space-y-1.5">
            {policies.map((p) => (
              <div key={p.id} className={clsx('rounded-md border px-3 py-2', p.enabled ? 'border-border bg-background/60' : 'border-border bg-muted/40 opacity-70')}>
                <div className="flex items-center gap-2">
                  {canWrite && (
                    <input type="checkbox" checked={p.enabled} onChange={(e) => toggleMutation.mutate({ id: p.id, enabled: e.target.checked })} title={p.enabled ? 'Enabled — the worker enforces this policy' : 'Disabled — files are kept until re-enabled'} />
                  )}
                  <span className="text-sm font-medium text-secondary">{p.name}</span>
                  <span className="rounded border border-border bg-background px-1.5 py-0.5 text-[10px] text-faint">{p.fileCount ?? 0} file(s)</span>
                  <div className="ml-auto flex items-center gap-0.5">
                    {canWrite && (
                      <>
                        <button type="button" title="Apply to matching unassigned files (backfill)" disabled={applyMutation.isPending}
                          onClick={() => { if (window.confirm(`Assign "${p.name}" to all currently UNASSIGNED ${matcherSummary(p)}? They will then be cleaned up by this policy.`)) applyMutation.mutate(p.id); }}
                          className="rounded-md p-1.5 text-secondary hover:bg-muted disabled:opacity-40"><Timer size={13} /></button>
                        <button type="button" title="Edit" onClick={() => openEdit(p)} className="rounded-md p-1.5 text-secondary hover:bg-muted"><Pencil size={13} /></button>
                        <button type="button" title={'Delete (files become "no policy → kept forever")'} disabled={deleteMutation.isPending}
                          onClick={() => { if (window.confirm(`Delete policy "${p.name}"? Its ${p.fileCount ?? 0} file(s) are unassigned and KEPT FOREVER — nothing is deleted.`)) deleteMutation.mutate(p.id); }}
                          className="rounded-md p-1.5 text-danger-fg hover:bg-muted disabled:opacity-40"><Trash2 size={13} /></button>
                      </>
                    )}
                  </div>
                </div>
                <p className="mt-1 text-xs text-muted-foreground">{retentionSummary(p)} · matches {matcherSummary(p)}</p>
                {p.description && <p className="mt-0.5 text-[11px] text-faint">{p.description}</p>}
              </div>
            ))}
          </div>
        )}

        {/* Create / edit form */}
        {editingId !== null ? (
          <form className="space-y-2 rounded-md border border-border bg-background/60 p-3" onSubmit={(e) => { e.preventDefault(); saveMutation.mutate(); }}>
            <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
              <div>
                <label className={labelCls}>Name</label>
                <input className={fieldCls} value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} placeholder="Config backups (30 days)" required />
              </div>
              <div>
                <label className={labelCls}>Category matcher (empty = any)</label>
                <input className={fieldCls} value={form.category} onChange={(e) => setForm({ ...form, category: e.target.value })} placeholder="config-backup" list="retention-categories" />
                <datalist id="retention-categories">
                  {CATEGORIES.map((c) => <option key={c} value={c} />)}
                </datalist>
              </div>
              <div>
                <label className={labelCls}>Name pattern (regex, empty = any)</label>
                <input className={fieldCls} value={form.namePattern} onChange={(e) => setForm({ ...form, namePattern: e.target.value })} placeholder=".*__config-backup-.*" />
              </div>
              <div>
                <label className={labelCls}>Description (optional)</label>
                <input className={fieldCls} value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} placeholder="Daily intent backups — keep a month" />
              </div>
              <div>
                <label className={labelCls}>Max age (days, empty = no limit)</label>
                <input className={fieldCls} type="number" min={1} value={form.maxAgeDays} onChange={(e) => setForm({ ...form, maxAgeDays: e.target.value })} placeholder="30" />
              </div>
              <div>
                <label className={labelCls}>Keep newest per device (empty = no limit)</label>
                <input className={fieldCls} type="number" min={1} value={form.keepLatestPerDevice} onChange={(e) => setForm({ ...form, keepLatestPerDevice: e.target.value })} placeholder="7" />
              </div>
            </div>
            <p className="text-[11px] text-faint">At least one of max age / keep-newest is required. The matchers decide which files the policy applies to (default assignment + backfill) — the sweep only ever touches ASSIGNED files.</p>
            <div className="flex items-center gap-2">
              <button type="submit" disabled={saveMutation.isPending}
                className="inline-flex items-center gap-1.5 rounded-md bg-primary px-3 py-1.5 text-xs font-medium text-primary-fg hover:opacity-90 disabled:opacity-50">
                {saveMutation.isPending && <Loader2 size={12} className="animate-spin" />}
                {editingId === 'new' ? 'Create policy' : 'Save changes'}
              </button>
              <button type="button" onClick={() => setEditingId(null)} className="rounded-md px-3 py-1.5 text-xs text-secondary hover:bg-muted">Cancel</button>
            </div>
          </form>
        ) : (
          canWrite && (
            <button type="button" onClick={openCreate} className="inline-flex items-center gap-1.5 rounded-md border border-border px-3 py-1.5 text-xs font-medium text-secondary hover:bg-muted">
              <Plus size={12} /> New policy
            </button>
          )
        )}

        {/* Manual sweep */}
        {canWrite && (
          <div className="flex items-center gap-3 border-t border-border pt-3">
            <button type="button" onClick={() => sweepMutation.mutate()} disabled={sweepMutation.isPending}
              className="inline-flex items-center gap-1.5 rounded-md border border-border px-3 py-1.5 text-xs font-medium text-secondary hover:bg-muted disabled:opacity-50">
              {sweepMutation.isPending ? <Loader2 size={12} className="animate-spin" /> : <Timer size={12} />}
              Run sweep now
            </button>
            {sweepResult && (
              <span className="text-xs text-secondary">
                Removed <b>{sweepResult.totalDeleted}</b> file(s)
                {sweepResult.perPolicy.filter((p) => p.deleted > 0).map((p) => ` · ${p.name}: ${p.deleted}`).join('')}
              </span>
            )}
          </div>
        )}
      </div>
    </DialogShell>
  );
}

/** Per-file retention assignment — pick a policy or "no policy (kept forever)". */
function FileRetentionDialog({ entry, onClose }: { entry: RepoFileEntry; onClose: () => void }) {
  const queryClient = useQueryClient();
  const [policyId, setPolicyId] = useState<string>(entry.retentionPolicyId ?? '');
  const [error, setError] = useState<string | null>(null);

  const policiesQuery = useQuery({ queryKey: ['retentionPolicies'], queryFn: () => api.listRetentionPolicies() });
  const policies = policiesQuery.data?.policies ?? [];

  const saveMutation = useMutation({
    mutationFn: () => api.setFileRetentionPolicy(entry.id, policyId === '' ? null : policyId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['repoFiles'] });
      onClose();
    },
    onError: (err) => setError(err instanceof Error ? err.message : String(err)),
  });

  return (
    <DialogShell title="Retention policy" subtitle={<span className="block truncate font-mono" title={entry.name}>{entry.name}</span>} onClose={onClose} maxWidth="max-w-md">
      <div className="space-y-3">
        {error && <p className="text-xs text-danger-fg">{error}</p>}
        <label className={labelCls}>Policy for this file</label>
        <select className={fieldCls} value={policyId} onChange={(e) => setPolicyId(e.target.value)} disabled={policiesQuery.isLoading}>
          <option value="">No policy — kept forever</option>
          {policies.map((p) => (
            <option key={p.id} value={p.id}>{p.name} ({retentionSummary(p)}){p.enabled ? '' : ' [disabled]'}</option>
          ))}
        </select>
        <div className="flex items-center gap-2">
          <button type="button" onClick={() => saveMutation.mutate()} disabled={saveMutation.isPending}
            className="inline-flex items-center gap-1.5 rounded-md bg-primary px-3 py-1.5 text-xs font-medium text-primary-fg hover:opacity-90 disabled:opacity-50">
            {saveMutation.isPending && <Loader2 size={12} className="animate-spin" />}
            Save
          </button>
          <button type="button" onClick={onClose} className="rounded-md px-3 py-1.5 text-xs text-secondary hover:bg-muted">Cancel</button>
        </div>
      </div>
    </DialogShell>
  );
}

/** Usage-history dialog for one repo file (the "which device, when" audit trail). */
function UsesDialog({ entry, onClose }: { entry: RepoFileEntry; onClose: () => void }) {
  const { formatDateTime } = useTimeFormat();
  const [uses, setUses] = useState<RepoFileUse[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  (async () => {
    try {
      const res = await api.repoFileUses(entry.id);
      setUses(res.uses);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  })();

  return (
    <DialogShell
      title="Usage history"
      subtitle={<span className="block truncate font-mono" title={entry.name}>{entry.name}</span>}
      onClose={onClose}
      maxWidth="max-w-lg"
      bodyMaxHeight="50vh"
    >
        <div className="space-y-2">
          {error && <p className="text-xs text-danger-fg">{error}</p>}
          {!error && uses === null && (
            <p className="flex items-center gap-2 text-sm text-muted-foreground"><Loader2 size={14} className="animate-spin" /> Loading…</p>
          )}
          {uses !== null && uses.length === 0 && (
            <p className="text-sm text-faint">No recorded usage yet — downloads and plugin fetches appear here.</p>
          )}
          {uses?.map((u) => (
            <div key={u.id} className="rounded-md border border-border bg-background/60 px-3 py-2 text-xs">
              <div className="flex items-center justify-between gap-2">
                <span className="font-medium text-secondary">{u.deviceId ?? '—'}</span>
                <span className="text-faint">{formatDateTime(u.createdAt)}</span>
              </div>
              {u.note && <p className="mt-0.5 text-muted-foreground">{u.note}</p>}
              {u.usedBy && <p className="mt-0.5 text-[11px] text-faint">by {u.usedByName ?? u.usedBy}</p>}
            </div>
          ))}
        </div>
    </DialogShell>
  );
}

export default function Files() {
  const { formatDateTime } = useTimeFormat();
  const queryClient = useQueryClient();
  const canWrite = can('files:write');

  const [category, setCategory] = useState<string>(''); // '' = all
  const [tag, setTag] = useState<string>(''); // '' = all (flat feature-tag filter)
  const [uploadCategory, setUploadCategory] = useState<string>('iso');
  const [uploadTags, setUploadTags] = useState(''); // comma-separated, optional
  const [uploadProvider, setUploadProvider] = useState<string>(''); // '' = API default
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [usesEntry, setUsesEntry] = useState<RepoFileEntry | null>(null);
  const [retentionEntry, setRetentionEntry] = useState<RepoFileEntry | null>(null);
  const [tagsEntry, setTagsEntry] = useState<RepoFileEntry | null>(null);
  const [editEntry, setEditEntry] = useState<RepoFileEntry | null>(null); // rename / recategorize (metadata only)
  const [bulkTags, setBulkTags] = useState<{ rows: RepoFileEntry[]; mode: 'add' | 'remove' } | null>(null);
  const [bulkCategoryRows, setBulkCategoryRows] = useState<RepoFileEntry[] | null>(null);
  const [policiesOpen, setPoliciesOpen] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const filesQuery = useQuery({
    queryKey: ['repoFiles', category, tag],
    queryFn: () => api.repoFiles(category || undefined, tag || undefined),
  });
  const files = filesQuery.data?.files ?? [];

  // Distinct tags across the whole repo — feeds the tag filter chips. Invalidated
  // alongside file mutations so new feature tags appear without a reload.
  const tagsQuery = useQuery({
    queryKey: ['repoFileTags'],
    queryFn: () => api.listRepoTags(),
  });
  const allTags = tagsQuery.data?.tags ?? [];

  // Registered file-repo backends + the effective default (system setting /
  // env). Refreshed periodically so online state stays current.
  const providersQuery = useQuery({
    queryKey: ['repoFileProviders'],
    queryFn: () => api.repoFileProviders(),
    refetchInterval: 30_000,
  });
  const providers = providersQuery.data?.providers ?? [];
  const defaultProviderId = providersQuery.data?.defaultProviderId ?? null;
  const multiRepo = providers.length > 1;

  // Preselect the API's effective default so users normally never touch this.
  // A choice made in the picker is persisted (localStorage) and preserved on
  // later visits — only a missing/unknown saved value falls back to the default.
  useEffect(() => {
    if (providers.length === 0) return;
    let saved: string | null = null;
    try { saved = localStorage.getItem(UPLOAD_PROVIDER_KEY); } catch { /* ignore */ }
    if (saved && providers.some((p) => p.id === saved)) return; // keep the user's choice
    setUploadProvider(defaultProviderId ?? providers.find((p) => p.online)?.id ?? '');
  }, [providers, defaultProviderId]);

  function chooseProvider(id: string) {
    setUploadProvider(id);
    try { localStorage.setItem(UPLOAD_PROVIDER_KEY, id); } catch { /* ignore */ }
  }

  const providerName = (f: RepoFileEntry): string => {
    if (!f.providerId) return 'local';
    return providers.find((p) => p.id === f.providerId)?.name ?? 'unknown repo';
  };

  const invalidate = () => {
    queryClient.invalidateQueries({ queryKey: ['repoFiles'] });
    queryClient.invalidateQueries({ queryKey: ['repoFileTags'] });
  };

  const uploadMutation = useMutation({
    mutationFn: (file: File) => {
      const tags = uploadTags.split(',').map((t) => t.trim()).filter(Boolean);
      return api.uploadRepoFile(file, uploadCategory || undefined, uploadProvider || undefined, tags.length > 0 ? tags : undefined);
    },
    onSuccess: ({ file, deduplicated }) => {
      setBusy(false);
      setError(null);
      if (deduplicated) setNotice(`"${file.name}" already exists in the repo (identical content) — nothing was re-uploaded.`);
      else setNotice(`Uploaded "${file.name}" (${formatBytes(file.sizeBytes)}).`);
      invalidate();
    },
    onError: (err) => {
      setBusy(false);
      setError(err instanceof Error ? err.message : String(err));
    },
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => api.deleteRepoFile(id),
    onSuccess: () => {
      setNotice('File deleted.');
      invalidate();
    },
    onError: (err) => setError(err instanceof Error ? err.message : String(err)),
  });

  // One shared mutation for every bulk operation from the selection bar — the
  // dialogs only collect input; success closes them and surfaces a count notice.
  const bulkMutation = useMutation({
    mutationFn: (args: { ids: string[]; op: 'add-tags' | 'remove-tags' | 'set-category' | 'delete'; tags?: string[]; category?: string }) => api.bulkRepoFiles(args),
    onSuccess: ({ affected }, vars) => {
      const verb = vars.op === 'delete' ? 'deleted' : vars.op === 'set-category' ? 'recategorized' : 'updated';
      setNotice(`${affected} file${affected === 1 ? '' : 's'} ${verb}.`);
      setBulkTags(null);
      setBulkCategoryRows(null);
      invalidate();
    },
    onError: (err) => setError(err instanceof Error ? err.message : String(err)),
  });

  function pickFiles(list: FileList | null) {
    if (!list || list.length === 0) return;
    // Upload the first picked file (multi-select is rare for multi-GB ISOs).
    setBusy(true);
    uploadMutation.mutate(list[0]);
  }

  async function download(entry: RepoFileEntry) {
    setError(null);
    try {
      const blob = await api.downloadRepoFile(entry.id);
      saveBlob(blob, entry.name);
    } catch (err) {
      if (err instanceof ApiError && err.status === 404) setNotice('The file is missing from the repo volume — only its metadata remains.');
      else setError(err instanceof Error ? err.message : String(err));
    }
  }

  function remove(entry: RepoFileEntry) {
    if (!window.confirm(`Delete "${entry.name}" (${formatBytes(entry.sizeBytes)}) from the repository? This removes the stored file. Usage history is kept.`)) return;
    deleteMutation.mutate(entry.id);
  }

  const totalBytes = files.reduce((sum, f) => sum + (f.sizeBytes ?? 0), 0);

  // DataTable columns — the Repository column only exists when multiple file-repo
  // backends are registered; SHA-256 is available but hidden by default.
  const columns: DataTableColumn<RepoFileEntry>[] = [
    {
      header: 'Name',
      key: 'name',
      width: 320,
      render: (row) => <span className="block truncate font-mono text-xs text-secondary" title={row.name}>{row.name}</span>,
    },
    {
      header: 'Category',
      key: 'category',
      width: 110,
      render: (row) => (
        <span className="rounded border border-border bg-background px-1.5 py-0.5 text-[11px] text-secondary">{row.category}</span>
      ),
    },
    {
      header: 'Tags',
      key: 'tags',
      width: 200,
      sortAccessor: (row) => (row.tags ?? []).join(' '),
      render: (row) => {
        const tags = row.tags ?? [];
        if (tags.length === 0) return <span className="text-[11px] text-faint">—</span>;
        return (
          <span className="flex items-center gap-1" title={tags.join(', ')}>
            {tags.slice(0, 3).map((t) => (
              <button key={t} type="button" onClick={() => setTag(t)}
                className="rounded bg-accent-sky px-1.5 py-0.5 text-[11px] font-medium text-accent-sky-fg hover:opacity-80"
                title={`Filter by tag "${t}"`}>{t}</button>
            ))}
            {tags.length > 3 && <span className="text-[11px] text-faint">+{tags.length - 3}</span>}
          </span>
        );
      },
    },
    {
      header: 'Retention',
      key: 'retentionPolicyId',
      width: 160,
      sortAccessor: (row) => row.retentionPolicyName ?? '',
      render: (row) => row.retentionPolicyId ? (
        <span className="block truncate text-xs text-secondary" title={`Retention policy "${row.retentionPolicyName ?? 'unknown'}"`}>
          {row.retentionPolicyName ?? 'unknown policy'}
        </span>
      ) : (
        <span className="text-[11px] text-faint" title="No retention policy — this file is kept forever">no policy · kept forever</span>
      ),
    },
    {
      header: 'Size',
      key: 'sizeBytes',
      width: 100,
      sortAccessor: (row) => row.sizeBytes,
      render: (row) => <span className="font-mono text-xs text-secondary">{formatBytes(row.sizeBytes)}</span>,
    },
    {
      header: 'SHA-256',
      key: 'sha256',
      width: 180,
      hiddenByDefault: true,
      render: (row) => <span className="block truncate font-mono text-[11px] text-faint" title={row.sha256}>{row.sha256}</span>,
    },
    ...(multiRepo ? [
      {
        header: 'Repository',
        key: 'providerId',
        width: 140,
        sortAccessor: (row: RepoFileEntry) => providerName(row),
        render: (row: RepoFileEntry) => <span className="block truncate text-xs text-secondary" title={providerName(row)}>{providerName(row)}</span>,
      } satisfies DataTableColumn<RepoFileEntry>,
    ] : []),
    {
      header: 'Uploaded by',
      key: 'uploadedBy',
      width: 120,
      sortAccessor: (row) => row.uploadedByName ?? row.uploadedBy ?? 'plugin',
      render: (row) => <span className="text-xs text-secondary">{row.uploadedByName ?? row.uploadedBy ?? 'plugin'}</span>,
    },
    {
      header: 'Uploaded at',
      key: 'createdAt',
      width: 170,
      sortAccessor: (row) => new Date(row.createdAt).getTime(),
      render: (row) => <span className="whitespace-nowrap text-xs text-secondary" title={new Date(row.createdAt).toISOString()}>{formatDateTime(row.createdAt)}</span>,
    },
    {
      header: 'Actions',
      key: 'actions',
      sortable: false,
      filterable: false,
      excludeFromExport: true,
      width: 190,
      render: (row) => (
        <div className="flex items-center justify-end gap-0.5">
          <button type="button" aria-label={`Download ${row.name}`} title="Download" onClick={() => void download(row)}
            className="rounded-md p-1.5 text-secondary hover:bg-muted hover:text-foreground"><Download size={14} /></button>
          <button type="button" aria-label={`Usage history of ${row.name}`} title="Usage history" onClick={() => setUsesEntry(row)}
            className="rounded-md p-1.5 text-secondary hover:bg-muted hover:text-foreground"><History size={14} /></button>
          {canWrite && (
            <>
              <button type="button" aria-label={`Rename or recategorize ${row.name}`} title="Edit name & category (metadata only — stored bytes untouched)" onClick={() => setEditEntry(row)}
                className="rounded-md p-1.5 text-secondary hover:bg-muted hover:text-foreground"><Pencil size={13} /></button>
              <button type="button" aria-label={`Tags for ${row.name}`} title="Edit tags (flat feature metadata — never part of the storage path)" onClick={() => setTagsEntry(row)}
                className="rounded-md p-1.5 text-secondary hover:bg-muted hover:text-foreground"><Tag size={13} /></button>
              <button type="button" aria-label={`Retention policy for ${row.name}`} title="Set retention policy (no policy = kept forever)" onClick={() => setRetentionEntry(row)}
                className="rounded-md p-1.5 text-secondary hover:bg-muted hover:text-foreground"><Timer size={13} /></button>
              <button type="button" aria-label={`Delete ${row.name}`} title="Delete" onClick={() => remove(row)} disabled={deleteMutation.isPending}
                className="rounded-md p-1.5 text-danger-fg hover:bg-muted hover:text-danger-fg disabled:opacity-40"><Trash2 size={13} /></button>
            </>
          )}
        </div>
      ),
    },
  ];

  return (
    <Layout title="Files">
      <div className="flex h-full min-h-0 flex-col gap-3">
        {/* Toolbar — upload + category filter */}
        <div className="flex shrink-0 flex-wrap items-center gap-2 rounded-lg border border-border bg-card px-4 py-2.5">
          {canWrite && (
            <>
              <input ref={fileInputRef} type="file" className="hidden" onChange={(e) => pickFiles(e.target.files)} />
              <button
                type="button"
                onClick={() => fileInputRef.current?.click()}
                disabled={busy || uploadMutation.isPending}
                className="inline-flex items-center gap-1.5 rounded-md bg-primary px-3 py-1.5 text-xs font-medium text-primary-fg hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-50"
              >
                {busy || uploadMutation.isPending ? <Loader2 size={13} className="animate-spin" /> : <FileUp size={13} />}
                Upload file
              </button>
              <select
                value={uploadCategory}
                onChange={(e) => setUploadCategory(e.target.value)}
                title="Category for the uploaded file"
                className="rounded-md border border-border bg-background px-2 py-1.5 text-xs text-secondary focus:border-focus-ring focus:ring-1 focus:ring-focus-ring"
              >
                {CATEGORIES.map((c) => <option key={c} value={c}>{c}</option>)}
              </select>
              <input
                value={uploadTags}
                onChange={(e) => setUploadTags(e.target.value)}
                placeholder="tags (comma-separated, optional)"
                title="Flat feature tags for the uploaded file — group files by the feature that produced them"
                className="w-52 rounded-md border border-border bg-background px-2 py-1.5 text-xs text-secondary focus:border-focus-ring focus:ring-1 focus:ring-focus-ring"
              />
              {/* Target repository — only shown when multiple file-repo backends
                  exist. Preselected to the effective default (system setting),
                  so users normally don't need to change it per upload. */}
              {multiRepo && (
                <label className="inline-flex items-center gap-1 rounded-md border border-border bg-background px-2 py-1 text-xs text-secondary">
                  <Database size={13} className="text-muted-foreground" />
                  <select
                    value={uploadProvider}
                    onChange={(e) => chooseProvider(e.target.value)}
                    title="File repository to upload into (default is preserved from the system setting)"
                    className="bg-transparent text-xs text-secondary focus:outline-none"
                  >
                    {providers.map((p) => (
                      <option key={p.id} value={p.id} disabled={!p.online}>
                        {p.name}{!p.online ? ' (offline)' : ''}{p.id === defaultProviderId ? ' — default' : ''}
                      </option>
                    ))}
                  </select>
                </label>
              )}
            </>
          )}

          {/* Retention lifecycle templates — manage policies + run the sweep */}
          <button
            type="button"
            onClick={() => setPoliciesOpen(true)}
            className="inline-flex items-center gap-1.5 rounded-md border border-border px-3 py-1.5 text-xs font-medium text-secondary hover:bg-muted"
          >
            <Timer size={13} />
            Retention policies
          </button>

          {/* Filter chips — category row + flat feature-tag row */}
          <div className="ml-auto flex flex-col items-end gap-1">
            <div className="flex items-center gap-1">
              <button
                type="button"
                onClick={() => setCategory('')}
                className={clsx(
                  'rounded-full border px-2.5 py-0.5 text-xs',
                  category === '' ? 'border-focus-ring bg-accent-indigo/40 text-secondary' : 'border-border text-faint hover:text-secondary'
                )}
              >
                all
              </button>
              {CATEGORIES.map((c) => (
                <button
                  key={c}
                  type="button"
                  onClick={() => setCategory(c)}
                  className={clsx(
                    'rounded-full border px-2.5 py-0.5 text-xs',
                    category === c ? 'border-focus-ring bg-accent-indigo/40 text-secondary' : 'border-border text-faint hover:text-secondary'
                  )}
                >
                  {c}
                </button>
              ))}
            </div>
            {allTags.length > 0 && (
              <div className="flex max-w-lg flex-wrap items-center justify-end gap-1">
                <span className="text-[10px] uppercase tracking-wide text-faint">tags:</span>
                <button
                  type="button"
                  onClick={() => setTag('')}
                  className={clsx(
                    'rounded-full border px-2.5 py-0.5 text-xs',
                    tag === '' ? 'border-focus-ring bg-accent-sky text-accent-sky-fg' : 'border-border text-faint hover:text-secondary'
                  )}
                >
                  all
                </button>
                {allTags.map((t) => (
                  <button
                    key={t}
                    type="button"
                    onClick={() => setTag(t)}
                    className={clsx(
                      'rounded-full border px-2.5 py-0.5 text-xs',
                      tag === t ? 'border-focus-ring bg-accent-sky text-accent-sky-fg' : 'border-border text-faint hover:text-secondary'
                    )}
                  >
                    {t}
                  </button>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* Status banners */}
        {error && (
          <div className="flex shrink-0 items-center gap-2 rounded-lg border border-danger-border bg-danger px-4 py-2 text-xs text-danger-fg">
            <span className="flex-1">{error}</span>
            <button type="button" aria-label="Dismiss error" onClick={() => setError(null)}><X size={13} /></button>
          </div>
        )}
        {notice && (
          <div className="flex shrink-0 items-center gap-2 rounded-lg border border-success-border bg-success px-4 py-2 text-xs text-success-fg">
            <span className="flex-1">{notice}</span>
            <button type="button" aria-label="Dismiss notice" onClick={() => setNotice(null)}><X size={13} /></button>
          </div>
        )}

        {/* Summary strip */}
        {!filesQuery.isLoading && (
          <div className="flex shrink-0 items-center gap-x-6 rounded-lg border border-border bg-card px-4 py-2 text-xs">
            <span className="flex items-center gap-2 text-secondary">
              <FolderOpen size={13} className="text-accent-solid" />
              {files.length} file{files.length === 1 ? '' : 's'}
            </span>
            {totalBytes > 0 && (
              <span className="flex items-center gap-2 text-secondary">
                <FileUp size={13} className="text-muted-foreground" />
                <span className="font-mono">{formatBytes(totalBytes)}</span> total
              </span>
            )}
          </div>
        )}

        {/* File table */}
        {filesQuery.isLoading ? (
          <div className="min-h-0 flex-1 rounded-lg border border-border bg-card">
            <p className="px-4 py-6 text-sm text-muted-foreground">Loading repository…</p>
          </div>
        ) : (
          <div className="min-h-0 flex-1">
            <DataTable
              columns={columns}
              rows={files}
              rowKey={(row) => row.id}
              storageKey="files"
              fillHeight
              searchPlaceholder="Search files…"
              selectable={canWrite}
              bulkActions={canWrite ? [
                { label: 'Add tags', onClick: (rows) => setBulkTags({ rows, mode: 'add' }) },
                { label: 'Remove tags', onClick: (rows) => setBulkTags({ rows, mode: 'remove' }) },
                { label: 'Set category', onClick: (rows) => setBulkCategoryRows(rows) },
                {
                  label: 'Delete selected',
                  confirm: (count) => `Delete ${count} file${count === 1 ? '' : 's'} from the repository? This removes their stored content. Usage history is kept.`,
                  onClick: (rows) => bulkMutation.mutate({ ids: rows.map((r) => r.id), op: 'delete' }),
                },
              ] : undefined}
              emptyMessage={`The repository is empty${category ? ` for category "${category}"` : ''}${tag ? ` with tag "${tag}"` : ''}.${canWrite ? ' Upload an ISO, firmware image or config backup — it becomes available to every device and plugin through the API.' : ''}`}
            />
          </div>
        )}

        {usesEntry && <UsesDialog entry={usesEntry} onClose={() => setUsesEntry(null)} />}
        {retentionEntry && canWrite && <FileRetentionDialog entry={retentionEntry} onClose={() => setRetentionEntry(null)} />}
        {tagsEntry && canWrite && <TagsDialog entry={tagsEntry} onClose={() => setTagsEntry(null)} />}
        {editEntry && canWrite && <EditFileDialog entry={editEntry} onClose={() => setEditEntry(null)} />}
        {bulkTags && canWrite && (
          <BulkTagsDialog
            mode={bulkTags.mode}
            count={bulkTags.rows.length}
            busy={bulkMutation.isPending}
            onApply={(tags) => bulkMutation.mutate({ ids: bulkTags.rows.map((r) => r.id), op: bulkTags.mode === 'add' ? 'add-tags' : 'remove-tags', tags })}
            onClose={() => setBulkTags(null)}
          />
        )}
        {bulkCategoryRows && canWrite && (
          <BulkCategoryDialog
            rows={bulkCategoryRows}
            busy={bulkMutation.isPending}
            onApply={(category) => bulkMutation.mutate({ ids: bulkCategoryRows.map((r) => r.id), op: 'set-category', category })}
            onClose={() => setBulkCategoryRows(null)}
          />
        )}
        {policiesOpen && <RetentionPoliciesDialog onClose={() => setPoliciesOpen(false)} />}
      </div>
    </Layout>
  );
}

/** Edit the flat feature tags of one repo file (comma-separated input). Tags are
 * pure metadata for grouping/filtering — never part of the storage path, so they
 * stay portable across filesystem/S3/cloud file-repo backends. */
function TagsDialog({ entry, onClose }: { entry: RepoFileEntry; onClose: () => void }) {
  const queryClient = useQueryClient();
  const [tagsText, setTagsText] = useState((entry.tags ?? []).join(', '));
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function save() {
    if (saving) return;
    setSaving(true);
    setError(null);
    try {
      await api.setRepoFileTags(entry.id, tagsText.split(',').map((t) => t.trim()).filter(Boolean));
      queryClient.invalidateQueries({ queryKey: ['repoFiles'] });
      queryClient.invalidateQueries({ queryKey: ['repoFileTags'] });
      onClose();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setSaving(false);
    }
  }

  return (
    <DialogShell title={`Tags — ${entry.name}`} subtitle="Flat feature tags group files by the feature that produced them (e.g. log-rules, threat-intel). Comma-separated; leave empty to clear." onClose={onClose} maxWidth="max-w-md">
      <div className="space-y-3">
        {error && (
          <div className="rounded-md border border-danger-border bg-danger px-3 py-2 text-xs text-danger-fg">{error}</div>
        )}
        <label className={labelCls}>
          Tags
          <input
            value={tagsText}
            onChange={(e) => setTagsText(e.target.value)}
            placeholder="log-rules, my-feature"
            className={`${fieldCls} mt-1`}
          />
        </label>
        <div className="flex justify-end gap-2">
          <button type="button" onClick={onClose} className="rounded-md border border-border px-3 py-1.5 text-xs font-medium text-secondary hover:bg-muted">Cancel</button>
          <button type="button" onClick={() => void save()} disabled={saving}
            className="inline-flex items-center gap-2 rounded-md bg-primary px-3 py-1.5 text-xs font-medium text-primary-fg hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-50">
            {saving && <Loader2 size={12} className="animate-spin" />}
            Save tags
          </button>
        </div>
      </div>
    </DialogShell>
  );
}

/** Rename and/or recategorize one repo file. METADATA ONLY — the stored bytes
 * are never touched (provider blobs are content-addressed by sha256, local
 * files resolve via their storage path), so this is safe on every backend. */
function EditFileDialog({ entry, onClose }: { entry: RepoFileEntry; onClose: () => void }) {
  const queryClient = useQueryClient();
  const [name, setName] = useState(entry.name);
  const [category, setCategory] = useState(entry.category);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Categories are an open slug set — offer the known ones plus whatever this
  // file currently has (so a plugin-set category is not lost on save).
  const categories = (CATEGORIES as readonly string[]).includes(entry.category)
    ? [...CATEGORIES]
    : [entry.category, ...CATEGORIES];

  async function save() {
    if (saving) return;
    setSaving(true);
    setError(null);
    try {
      await api.updateRepoFile(entry.id, { name: name.trim(), category });
      queryClient.invalidateQueries({ queryKey: ['repoFiles'] });
      onClose();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setSaving(false);
    }
  }

  return (
    <DialogShell title={`Edit file — ${entry.name}`} subtitle="Rename and/or recategorize. Metadata only — the stored bytes are never touched." onClose={onClose} maxWidth="max-w-md">
      <div className="space-y-3">
        {error && (
          <div className="rounded-md border border-danger-border bg-danger px-3 py-2 text-xs text-danger-fg">{error}</div>
        )}
        <label className={labelCls}>
          Name
          <input
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="file.iso"
            maxLength={256}
            className={`${fieldCls} mt-1`}
          />
        </label>
        <label className={labelCls}>
          Category
          <select value={category} onChange={(e) => setCategory(e.target.value)} className={`${fieldCls} mt-1`}>
            {categories.map((c) => <option key={c} value={c}>{c}</option>)}
          </select>
        </label>
        <div className="flex justify-end gap-2">
          <button type="button" onClick={onClose} className="rounded-md border border-border px-3 py-1.5 text-xs font-medium text-secondary hover:bg-muted">Cancel</button>
          <button type="button" onClick={() => void save()} disabled={saving || name.trim().length === 0}
            className="inline-flex items-center gap-2 rounded-md bg-primary px-3 py-1.5 text-xs font-medium text-primary-fg hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-50">
            {saving && <Loader2 size={12} className="animate-spin" />}
            Save changes
          </button>
        </div>
      </div>
    </DialogShell>
  );
}

/** Add or remove flat feature tags on a SET of selected repo files at once.
 * The parent's bulk mutation performs the call — success closes this dialog,
 * errors surface in the page banner (the dialog stays open for a retry). */
function BulkTagsDialog({ mode, count, busy, onApply, onClose }: {
  mode: 'add' | 'remove';
  count: number;
  busy: boolean;
  onApply: (tags: string[]) => void;
  onClose: () => void;
}) {
  const [tagsText, setTagsText] = useState('');
  const [error, setError] = useState<string | null>(null);

  function apply() {
    if (busy) return;
    const tags = tagsText.split(',').map((t) => t.trim()).filter(Boolean);
    if (tags.length === 0) {
      setError('Enter at least one tag.');
      return;
    }
    onApply(tags);
  }

  return (
    <DialogShell
      title={`${mode === 'add' ? 'Add tags to' : 'Remove tags from'} ${count} file${count === 1 ? '' : 's'}`}
      subtitle="Comma-separated flat feature tags. Existing tags are kept; the repo cap of 10 tags per file applies."
      onClose={onClose}
      maxWidth="max-w-md"
    >
      <div className="space-y-3">
        {error && (
          <div className="rounded-md border border-danger-border bg-danger px-3 py-2 text-xs text-danger-fg">{error}</div>
        )}
        <label className={labelCls}>
          Tags
          <input
            value={tagsText}
            onChange={(e) => setTagsText(e.target.value)}
            placeholder="log-rules, my-feature"
            className={`${fieldCls} mt-1`}
          />
        </label>
        <div className="flex justify-end gap-2">
          <button type="button" onClick={onClose} className="rounded-md border border-border px-3 py-1.5 text-xs font-medium text-secondary hover:bg-muted">Cancel</button>
          <button type="button" onClick={apply} disabled={busy}
            className="inline-flex items-center gap-2 rounded-md bg-primary px-3 py-1.5 text-xs font-medium text-primary-fg hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-50">
            {busy && <Loader2 size={12} className="animate-spin" />}
            {mode === 'add' ? 'Add tags' : 'Remove tags'}
          </button>
        </div>
      </div>
    </DialogShell>
  );
}

/** Move a SET of selected repo files into one category at once (metadata only). */
function BulkCategoryDialog({ rows, busy, onApply, onClose }: {
  rows: RepoFileEntry[];
  busy: boolean;
  onApply: (category: string) => void;
  onClose: () => void;
}) {
  // Offer the known categories plus whatever the selection currently spans.
  const current = [...new Set(rows.map((r) => r.category))];
  const categories = [...new Set([...current, ...CATEGORIES])];
  const [category, setCategory] = useState(current.length === 1 ? current[0] : CATEGORIES[0]);

  return (
    <DialogShell
      title={`Set category for ${rows.length} file${rows.length === 1 ? '' : 's'}`}
      subtitle="Moves the selected files into one category. Metadata only — stored bytes are untouched."
      onClose={onClose}
      maxWidth="max-w-md"
    >
      <div className="space-y-3">
        <label className={labelCls}>
          Category
          <select value={category} onChange={(e) => setCategory(e.target.value)} className={`${fieldCls} mt-1`}>
            {categories.map((c) => <option key={c} value={c}>{c}</option>)}
          </select>
        </label>
        <div className="flex justify-end gap-2">
          <button type="button" onClick={onClose} className="rounded-md border border-border px-3 py-1.5 text-xs font-medium text-secondary hover:bg-muted">Cancel</button>
          <button type="button" onClick={() => onApply(category)} disabled={busy}
            className="inline-flex items-center gap-2 rounded-md bg-primary px-3 py-1.5 text-xs font-medium text-primary-fg hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-50">
            {busy && <Loader2 size={12} className="animate-spin" />}
            Set category
          </button>
        </div>
      </div>
    </DialogShell>
  );
}
