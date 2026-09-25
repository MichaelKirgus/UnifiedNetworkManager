import { useRef, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import clsx from 'clsx';
import { Download, FileUp, FolderOpen, History, Loader2, Trash2, X } from 'lucide-react';
import { Layout } from '../components/Layout';
import { formatBytes } from '../components/formatMetric';
import { api, ApiError, FileRepoEntry, FileRepoUse } from '../api/client';
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
function UsesDialog({ entry, onClose }: { entry: FileRepoEntry; onClose: () => void }) {
  const { formatDateTime } = useTimeFormat();
  const [uses, setUses] = useState<FileRepoUse[] | null>(null);
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
    <div className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto bg-primary/40 p-6" onClick={onClose}>
      <div className="mt-12 w-full max-w-lg rounded-md border border-border bg-card shadow-xl" onClick={(e) => e.stopPropagation()}>
        <header className="flex items-center justify-between border-b border-border px-4 py-3">
          <div>
            <h2 className="text-base font-semibold text-foreground">Usage history</h2>
            <p className="mt-0.5 truncate font-mono text-xs text-muted-foreground" title={entry.name}>{entry.name}</p>
          </div>
          <button type="button" aria-label="Close dialog" onClick={onClose} className="rounded p-1 text-faint hover:bg-muted">
            <X size={16} />
          </button>
        </header>
        <div className="max-h-[50vh] space-y-2 overflow-y-auto px-4 py-3">
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
              {u.usedBy && <p className="mt-0.5 text-[11px] text-faint">by {u.usedBy}</p>}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

export default function Files() {
  const { formatDateTime } = useTimeFormat();
  const queryClient = useQueryClient();
  const canWrite = can('files:write');

  const [category, setCategory] = useState<string>(''); // '' = all
  const [uploadCategory, setUploadCategory] = useState<string>('iso');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [usesEntry, setUsesEntry] = useState<FileRepoEntry | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const filesQuery = useQuery({
    queryKey: ['repo-files', category],
    queryFn: () => api.repoFiles(category || undefined),
  });
  const files = filesQuery.data?.files ?? [];

  const invalidate = () => queryClient.invalidateQueries({ queryKey: ['repo-files'] });

  const uploadMutation = useMutation({
    mutationFn: (file: File) => api.uploadRepoFile(file, uploadCategory || undefined),
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

  async function download(entry: FileRepoEntry) {
    setError(null);
    try {
      const blob = await api.downloadRepoFile(entry.id);
      saveBlob(blob, entry.name);
    } catch (err) {
      if (err instanceof ApiError && err.status === 404) setNotice('The file is missing from the repo volume — only its metadata remains.');
      else setError(err instanceof Error ? err.message : String(err));
    }
  }

  function remove(entry: FileRepoEntry) {
    if (!window.confirm(`Delete "${entry.name}" (${formatBytes(entry.sizeBytes)}) from the repository? This removes the stored file. Usage history is kept.`)) return;
    deleteMutation.mutate(entry.id);
  }

  const totalBytes = files.reduce((sum, f) => sum + (f.sizeBytes ?? 0), 0);

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
        <div className="min-h-0 flex-1 overflow-auto rounded-lg border border-border bg-card">
          {filesQuery.isLoading ? (
            <p className="px-4 py-6 text-sm text-muted-foreground">Loading repository…</p>
          ) : files.length === 0 ? (
            <div className="flex flex-col items-center gap-2 px-4 py-10 text-center">
              <FolderOpen size={28} className="text-faint" />
              <p className="text-sm text-secondary">The repository is empty{category ? ` for category "${category}"` : ''}.</p>
              {canWrite && <p className="text-xs text-faint">Upload an ISO, firmware image or config backup — it becomes available to every device and plugin through the API.</p>}
            </div>
          ) : (
            <table className="w-full border-collapse text-sm">
              <thead className="sticky top-0 bg-background">
                <tr className="border-b border-border text-left text-xs text-faint">
                  <th className="px-4 py-2 font-medium">Name</th>
                  <th className="px-3 py-2 font-medium">Category</th>
                  <th className="px-3 py-2 font-medium">Size</th>
                  <th className="hidden px-3 py-2 font-medium lg:table-cell">SHA-256</th>
                  <th className="hidden px-3 py-2 font-medium md:table-cell">Uploaded by</th>
                  <th className="px-3 py-2 font-medium">Uploaded at</th>
                  <th className="px-3 py-2 text-right font-medium">Actions</th>
                </tr>
              </thead>
              <tbody>
                {files.map((f) => (
                  <tr key={f.id} className="border-b border-border/60 hover:bg-muted/40">
                    <td className="max-w-[320px] truncate px-4 py-2 font-mono text-xs text-secondary" title={f.name}>{f.name}</td>
                    <td className="px-3 py-2">
                      <span className="rounded border border-border bg-background px-1.5 py-0.5 text-[11px] text-secondary">{f.category}</span>
                    </td>
                    <td className="whitespace-nowrap px-3 py-2 font-mono text-xs text-secondary">{formatBytes(f.sizeBytes)}</td>
                    <td className="hidden max-w-[160px] truncate px-3 py-2 font-mono text-[11px] text-faint lg:table-cell" title={f.sha256}>{f.sha256}</td>
                    <td className="hidden px-3 py-2 text-xs text-secondary md:table-cell">{f.uploadedBy ?? 'plugin'}</td>
                    <td className="whitespace-nowrap px-3 py-2 text-xs text-secondary" title={new Date(f.createdAt).toISOString()}>{formatDateTime(f.createdAt)}</td>
                    <td className="px-3 py-2">
                      <div className="flex items-center justify-end gap-0.5">
                        <button type="button" aria-label={`Download ${f.name}`} title="Download" onClick={() => void download(f)}
                          className="rounded-md p-1.5 text-secondary hover:bg-muted hover:text-foreground"><Download size={14} /></button>
                        <button type="button" aria-label={`Usage history of ${f.name}`} title="Usage history" onClick={() => setUsesEntry(f)}
                          className="rounded-md p-1.5 text-secondary hover:bg-muted hover:text-foreground"><History size={14} /></button>
                        {canWrite && (
                          <button type="button" aria-label={`Delete ${f.name}`} title="Delete" onClick={() => remove(f)} disabled={deleteMutation.isPending}
                            className="rounded-md p-1.5 text-danger-fg hover:bg-muted hover:text-danger-fg disabled:opacity-40"><Trash2 size={13} /></button>
                        )}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>

        {usesEntry && <UsesDialog entry={usesEntry} onClose={() => setUsesEntry(null)} />}
      </div>
    </Layout>
  );
}
