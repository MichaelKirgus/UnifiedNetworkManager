import { useEffect, useRef, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import clsx from 'clsx';
import { Database, Download, FileUp, FolderOpen, History, Loader2, Trash2, X } from 'lucide-react';
import { DialogShell } from '../components/DialogShell';
import { Layout } from '../components/Layout';
import { DataTable, DataTableColumn } from '../components/DataTable';
import { formatBytes } from '../components/formatMetric';
import { api, ApiError, RepoFileEntry, RepoFileUse } from '../api/client';
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
  const [uploadCategory, setUploadCategory] = useState<string>('iso');
  const [uploadProvider, setUploadProvider] = useState<string>(''); // '' = API default
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [usesEntry, setUsesEntry] = useState<RepoFileEntry | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const filesQuery = useQuery({
    queryKey: ['repoFiles', category],
    queryFn: () => api.repoFiles(category || undefined),
  });
  const files = filesQuery.data?.files ?? [];

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

  const invalidate = () => queryClient.invalidateQueries({ queryKey: ['repoFiles'] });

  const uploadMutation = useMutation({
    mutationFn: (file: File) => api.uploadRepoFile(file, uploadCategory || undefined, uploadProvider || undefined),
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
      width: 130,
      render: (row) => (
        <div className="flex items-center justify-end gap-0.5">
          <button type="button" aria-label={`Download ${row.name}`} title="Download" onClick={() => void download(row)}
            className="rounded-md p-1.5 text-secondary hover:bg-muted hover:text-foreground"><Download size={14} /></button>
          <button type="button" aria-label={`Usage history of ${row.name}`} title="Usage history" onClick={() => setUsesEntry(row)}
            className="rounded-md p-1.5 text-secondary hover:bg-muted hover:text-foreground"><History size={14} /></button>
          {canWrite && (
            <button type="button" aria-label={`Delete ${row.name}`} title="Delete" onClick={() => remove(row)} disabled={deleteMutation.isPending}
              className="rounded-md p-1.5 text-danger-fg hover:bg-muted hover:text-danger-fg disabled:opacity-40"><Trash2 size={13} /></button>
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

          {/* Category filter chips */}
          <div className="ml-auto flex items-center gap-1">
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
              emptyMessage={`The repository is empty${category ? ` for category "${category}"` : ''}.${canWrite ? ' Upload an ISO, firmware image or config backup — it becomes available to every device and plugin through the API.' : ''}`}
            />
          </div>
        )}

        {usesEntry && <UsesDialog entry={usesEntry} onClose={() => setUsesEntry(null)} />}
      </div>
    </Layout>
  );
}
