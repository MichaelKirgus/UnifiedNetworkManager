import { useCallback, useEffect, useRef, useState } from 'react';
import clsx from 'clsx';
import {
  ArrowUp,
  Eye,
  FileText,
  Folder,
  FolderOpen,
  FolderPlus,
  Loader2,
  Pencil,
  RefreshCw,
  Trash2,
  Upload,
} from 'lucide-react';
import { api, ApiError, type FilesystemEntry, type SessionCredentialCandidate } from '../api/client';
import { CredentialPicker } from './CredentialPicker';
import { DialogShell } from './DialogShell';
import { formatBytes } from './formatMetric';
import { ResizableDialog } from './ResizableDialog';
import { useTimeFormat } from '../utils/time';

/**
 * A generic, root-scoped file manager dialog driven by the API's filesystem broker
 * (POST /devices/:id/filesystem → plugin POST /filesystem, capability 'filesystem').
 * The caller passes a `context` naming WHAT to browse — e.g. `{ kind: 'dataset', name }`
 * for a Storage-page dataset or `{ kind: 'container-volume', source, target? }` for a
 * Containers-page volume mount. The plugin maps that context onto an SFTP root and
 * confines every path to it, so this dialog can only ever see the scoped tree — no raw
 * device-internal paths are passed here.
 *
 * Full file operations: browse (list), open/edit (read/write), create folder (mkdir),
 * upload (write), rename, delete (unlink/rmdir). Destructive ops use window.confirm;
 * rename uses window.prompt. All mutations go through the same broker route and are
 * gated on devices:write server-side.
 */

/** Decodes a base64 string into a UTF-8 JS string (handles multi-byte safely). */
function b64ToText(b64: string): string {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return new TextDecoder('utf-8').decode(bytes);
}

/** Encodes a UTF-8 JS string into base64 (chunked to avoid call-stack limits). */
function textToB64(text: string): string {
  const bytes = new TextEncoder().encode(text);
  let bin = '';
  for (let i = 0; i < bytes.length; i += 0x8000) {
    bin += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  }
  return btoa(bin);
}

/** Reads a File as base64 (binary-safe — no text decoding). */
function fileToB64(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const fr = new FileReader();
    fr.onload = () => {
      const url = String(fr.result ?? '');
      resolve(url.slice(url.indexOf(',') + 1));
    };
    fr.onerror = () => reject(new Error('Failed to read the selected file'));
    fr.readAsDataURL(file);
  });
}

/** Props of the core file-manager body (shared by dialog + full-window page). */
export interface FileBrowserProps {
  deviceId: string;
  pluginId?: string;
  /** Plugin-owned context naming what to browse (dataset / container-volume). */
  context: Record<string, unknown>;
  /** Initial directory to open (relative to the root); default = the root. */
  initialPath?: string;
}

export interface FileBrowserDialogProps extends FileBrowserProps {
  /** Dialog title (e.g. "Browse DATA01" or "Browse volume /mnt/tank/app"). */
  title: string;
  /** Subtitle shown under the title (device name, mountpoint hint, …). */
  subtitle?: string;
  onClose: () => void;
}

/** Core file-manager body — toolbar + listing + editor overlay. Shared by the
 * in-app dialog and the full-window /file-browser page so both stay in lockstep. */
/** The credential-selection prompt state (409 from the filesystem broker). */
interface FileCredentialPrompt {
  candidates: SessionCredentialCandidate[];
}

export function FileBrowser({ deviceId, pluginId, context, initialPath }: FileBrowserProps) {
  const { formatDateTime } = useTimeFormat();
  const [dir, setDir] = useState<string>(initialPath ?? '');
  const [entries, setEntries] = useState<FilesystemEntry[] | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  // Session-credential selection: when several eligible file-access credentials exist
  // and no stored default applies, the broker answers 409 → show the picker; picking
  // a secret re-runs every op with that id (and optionally persists it as the default).
  const [secretId, setSecretId] = useState<string | undefined>(undefined);
  const [credPrompt, setCredPrompt] = useState<FileCredentialPrompt | null>(null);

  // Editor state (read/write a file).
  const [editing, setEditing] = useState<{ name: string; content: string } | null>(null);
  const [savingEdit, setSavingEdit] = useState(false);

  // Upload input ref.
  const uploadRef = useRef<HTMLInputElement>(null);

  /** Performs one filesystem op through the broker, mapping errors to a banner.
   *  A 409 `credential_selection_required` opens the picker instead of just erroring. */
  const runOp = useCallback(
    async (op: Parameters<typeof api.filesystem>[1], params: Record<string, unknown> = {}) => {
      try {
        return await api.filesystem(deviceId, op, { ...params, context, ...(pluginId ? { pluginId } : {}), ...(secretId ? { secretId } : {}) });
      } catch (err) {
        if (err instanceof ApiError && err.code === 'credential_selection_required') {
          setCredPrompt({ candidates: err.candidates ?? [] });
          throw err;
        }
        const msg = err instanceof ApiError ? err.message : err instanceof Error ? err.message : String(err);
        setError(msg);
        throw err;
      }
    },
    [deviceId, pluginId, context, secretId],
  );

  /** Lists the current directory. */
  const refresh = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await runOp('list', dir ? { path: dir } : {});
      setEntries(res.result.entries ?? []);
    } catch {
      // error already surfaced in the banner
    } finally {
      setLoading(false);
    }
  }, [dir, runOp]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  /** Navigates into a subdirectory (or back up one level). */
  function navigate(target: string) {
    setDir(target);
  }

  const canGoUp = dir !== '' && dir !== '/';

  async function openFile(entry: FilesystemEntry) {
    setError(null);
    try {
      const res = await runOp('read', { path: joinPath(dir, entry.name) });
      setEditing({ name: entry.name, content: b64ToText(res.result.contentBase64 ?? '') });
    } catch {
      // surfaced in banner
    }
  }

  async function saveEdit() {
    if (!editing) return;
    setSavingEdit(true);
    setError(null);
    try {
      await runOp('write', { path: joinPath(dir, editing.name), contentBase64: textToB64(editing.content) });
      setEditing(null);
      void refresh();
    } catch {
      // surfaced in banner
    } finally {
      setSavingEdit(false);
    }
  }

  async function createFolder() {
    const name = window.prompt('New folder name:');
    if (!name || !name.trim()) return;
    setError(null);
    try {
      await runOp('mkdir', { path: joinPath(dir, name.trim()), parents: true });
      void refresh();
    } catch {
      // surfaced in banner
    }
  }

  async function uploadFile() {
    uploadRef.current?.click();
  }

  async function onUploadChange(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    e.target.value = ''; // allow re-selecting the same file later
    if (!file) return;
    setError(null);
    setBusy(true);
    try {
      const b64 = await fileToB64(file);
      await runOp('write', { path: joinPath(dir, file.name), contentBase64: b64 });
      void refresh();
    } catch {
      // surfaced in banner
    } finally {
      setBusy(false);
    }
  }

  async function renameEntry(entry: FilesystemEntry) {
    const newName = window.prompt(`Rename "${entry.name}" to:`, entry.name);
    if (!newName || !newName.trim() || newName === entry.name) return;
    setError(null);
    try {
      await runOp('rename', { path: joinPath(dir, entry.name), targetPath: joinPath(dir, newName.trim()) });
      void refresh();
    } catch {
      // surfaced in banner
    }
  }

  async function deleteEntry(entry: FilesystemEntry) {
    const verb = entry.isDirectory ? 'folder' : 'file';
    if (!window.confirm(`Permanently delete ${verb} "${entry.name}"? This cannot be undone.`)) return;
    setError(null);
    try {
      await runOp(entry.isDirectory ? 'rmdir' : 'unlink', { path: joinPath(dir, entry.name) });
      void refresh();
    } catch {
      // surfaced in banner
    }
  }

  // Directories first (so they're easy to find), then files — both alphabetical.
  const sorted = [...(entries ?? [])].sort((a, b) => {
    if (a.isDirectory !== b.isDirectory) return a.isDirectory ? -1 : 1;
    return a.name.localeCompare(b.name);
  });

  return (
    <>
      {/* Toolbar */}
        <div className="flex flex-wrap items-center gap-2 border-b border-border px-4 py-2.5">
          <button
            type="button"
            onClick={() => navigate(parentOf(dir))}
            disabled={!canGoUp || busy}
            title={canGoUp ? 'Go up one level' : 'Already at the root'}
            className="flex items-center gap-1 rounded-md border border-border px-2 py-1 text-xs text-secondary hover:bg-muted disabled:cursor-not-allowed disabled:opacity-40"
          >
            <ArrowUp size={13} /> Up
          </button>
          <span className="min-w-0 flex-1 truncate font-mono text-xs text-secondary" title={dir || '(root)'}>
            {dir ? `/${dir}` : '/ (root)'}
          </span>
          <div className="flex items-center gap-1">
            <button type="button" onClick={() => void refresh()} disabled={loading} title="Refresh listing" className="rounded-md p-1.5 text-secondary hover:bg-muted hover:text-foreground disabled:opacity-40">
              {loading ? <Loader2 size={14} className="animate-spin" /> : <RefreshCw size={14} />}
            </button>
            <button type="button" onClick={() => void createFolder()} disabled={busy} title="Create a new folder here" className="flex items-center gap-1 rounded-md border border-border px-2 py-1 text-xs text-secondary hover:bg-muted disabled:opacity-40">
              <FolderPlus size={13} /> New folder
            </button>
            <button type="button" onClick={() => void uploadFile()} disabled={busy} title="Upload a file here" className="flex items-center gap-1 rounded-md border border-border px-2 py-1 text-xs text-secondary hover:bg-muted disabled:opacity-40">
              {busy ? <Loader2 size={13} className="animate-spin" /> : <Upload size={13} />} Upload
            </button>
          </div>
        </div>

        {/* Hidden upload input */}
        <input ref={uploadRef} type="file" className="hidden" onChange={(e) => void onUploadChange(e)} />

        {/* Error banner */}
        {error && (
          <div className="mx-4 mt-3 rounded border border-danger-border bg-danger px-3 py-2 text-xs text-danger-fg">{error}</div>
        )}

        {/* File listing */}
        <div className="max-h-[50vh] overflow-y-auto">
          {loading && entries === null ? (
            <div className="flex items-center justify-center gap-2 px-4 py-10 text-sm text-muted-foreground">
              <Loader2 size={16} className="animate-spin" /> Loading…
            </div>
          ) : sorted.length === 0 ? (
            <div className="px-4 py-10 text-center text-sm text-faint">This directory is empty.</div>
          ) : (
            <table className="w-full border-collapse text-sm">
              <thead className="sticky top-0 bg-card">
                <tr className="border-b border-border text-left text-xs uppercase tracking-wide text-muted-foreground">
                  <th className="px-4 py-2 font-medium">Name</th>
                  <th className="w-28 px-3 py-2 text-right font-medium">Size</th>
                  <th className="w-44 px-3 py-2 font-medium">Modified</th>
                  <th className="w-28 px-3 py-2 text-right font-medium">Actions</th>
                </tr>
              </thead>
              <tbody>
                {sorted.map((entry) => (
                  <tr key={entry.name} className="border-b border-border/60 hover:bg-muted/40">
                    <td className="px-4 py-2">
                      <button
                        type="button"
                        onClick={() => (entry.isDirectory ? navigate(joinPath(dir, entry.name)) : void openFile(entry))}
                        onDoubleClick={() => entry.isDirectory && navigate(joinPath(dir, entry.name))}
                        title={entry.isDirectory ? `Open ${entry.name}` : `View / edit ${entry.name}`}
                        className="flex items-center gap-2 text-left font-medium text-foreground hover:underline"
                      >
                        {entry.isDirectory ? <Folder size={15} className="shrink-0 text-accent-sky-fg" /> : <FileText size={15} className="shrink-0 text-muted-foreground" />}
                        <span className="truncate">{entry.name}</span>
                      </button>
                    </td>
                    <td className="px-3 py-2 text-right font-mono text-xs text-secondary">
                      {entry.isDirectory ? '—' : formatBytes(entry.sizeBytes ?? 0)}
                    </td>
                    <td className="px-3 py-2 font-mono text-xs text-secondary">{entry.mtimeMs != null ? formatDateTime(entry.mtimeMs) : '—'}</td>
                    <td className="px-3 py-2">
                      <div className="flex items-center justify-end gap-0.5">
                        {!entry.isDirectory && (
                          <button type="button" onClick={() => void openFile(entry)} title={`View / edit ${entry.name}`} className="rounded-md p-1.5 text-secondary hover:bg-muted hover:text-foreground">
                            <Eye size={14} />
                          </button>
                        )}
                        <button type="button" onClick={() => void renameEntry(entry)} title={`Rename ${entry.name}`} className="rounded-md p-1.5 text-secondary hover:bg-muted hover:text-foreground">
                          <Pencil size={13} />
                        </button>
                        <button type="button" onClick={() => void deleteEntry(entry)} title={`Delete ${entry.name}`} className="rounded-md p-1.5 text-danger-fg hover:bg-muted">
                          <Trash2 size={13} />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>

      {/* Editor overlay */}
        {editing && (
          <DialogShell
            title={<span className="font-mono">{editing.name}</span>}
            onClose={() => setEditing(null)}
            zIndex="z-[60]"
            maxWidth="max-w-2xl"
            footer={
              <div className="flex items-center justify-end gap-2">
                <button type="button" onClick={() => setEditing(null)} disabled={savingEdit} className="rounded-md border border-border px-3 py-1.5 text-sm text-secondary hover:bg-muted disabled:opacity-40">
                  Cancel
                </button>
                <button type="button" onClick={() => void saveEdit()} disabled={savingEdit} className="flex items-center gap-2 rounded-md bg-primary px-3 py-1.5 text-sm font-medium text-primary-fg hover:opacity-90 disabled:opacity-40">
                  {savingEdit && <Loader2 size={14} className="animate-spin" />} Save file
                </button>
              </div>
            }
          >
            <textarea
              value={editing.content}
              onChange={(e) => setEditing({ ...editing, content: e.target.value })}
              spellCheck={false}
              className="h-[50vh] w-full resize-none rounded-md border border-border bg-background p-3 font-mono text-xs text-foreground"
            />
          </DialogShell>
        )}

      {/* Credential picker — shown when the broker needs a choice of file-access credential. */}
        {credPrompt && (
          <CredentialPicker
            deviceId={deviceId}
            purpose="filesystem"
            initialCandidates={credPrompt.candidates}
            title="Choose a file-access credential"
            onPick={(sid) => {
              setSecretId(sid);
              setError(null);
              setCredPrompt(null);
              void refresh(); // re-list with the chosen credential
            }}
            onClose={() => setCredPrompt(null)}
          />
        )}
    </>
  );
}

/**
 * Draggable + resizable file-manager dialog — wraps <FileBrowser> in the shared
 * ResizableDialog shell and offers "open in a new window" for full-screen browsing.
 */
export function FileBrowserDialog({ deviceId, pluginId, context, title, subtitle, initialPath, onClose }: FileBrowserDialogProps) {
  const openInWindow = () => {
    const params = new URLSearchParams();
    params.set('context', JSON.stringify(context));
    if (pluginId) params.set('plugin', pluginId);
    if (initialPath) params.set('path', initialPath);
    window.open(`${window.location.origin}/file-browser/${deviceId}?${params.toString()}`, '_blank');
  };

  return (
    <ResizableDialog
      title={title}
      subtitle={subtitle}
      icon={<FolderOpen size={16} />}
      onClose={onClose}
      onOpenInWindow={openInWindow}
      defaultSize={{ w: 896, h: 560 }}
      footer={
        <span className="text-[11px] text-faint">
          Double-click a folder to open it. Click a file (or the eye icon) to view/edit it. All operations are scoped to this location — you cannot navigate outside of it.
        </span>
      }
    >
      <FileBrowser deviceId={deviceId} pluginId={pluginId} context={context} initialPath={initialPath} />
    </ResizableDialog>
  );
}

/** Joins a directory path and an entry name into one relative path. */
function joinPath(dir: string, name: string): string {
  if (!dir) return name;
  return dir.endsWith('/') ? `${dir}${name}` : `${dir}/${name}`;
}

/** Returns the parent of a relative directory path ('' for root). */
function parentOf(dir: string): string {
  if (!dir || dir === '/') return '';
  const trimmed = dir.replace(/\/+$/, '');
  const idx = trimmed.lastIndexOf('/');
  return idx <= 0 ? '' : trimmed.slice(0, idx);
}
