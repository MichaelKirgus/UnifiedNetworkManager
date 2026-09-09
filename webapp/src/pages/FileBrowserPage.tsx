import { useMemo } from 'react';
import { useNavigate, useParams, useSearchParams } from 'react-router-dom';
import { FolderOpen, X } from 'lucide-react';
import { FileBrowser } from '../components/FileBrowserDialog';

/**
 * Standalone full-window file browser — the destination of the FileBrowserDialog's
 * "open in a new window" button. Lives at `/file-browser/:deviceId` (its own tab,
 * no app shell) so it can be tiled next to other windows like a real file manager.
 *
 * Query params (set by the opener): `context` (JSON), `plugin`, `path`.
 */
export default function FileBrowserPage() {
  const navigate = useNavigate();
  const { deviceId } = useParams<{ deviceId: string }>();
  const [params] = useSearchParams();

  const contextKey = useMemo(() => {
    try { return JSON.stringify(JSON.parse(params.get('context') || '{}')); } catch { return '{}'; }
  }, [params]);
  const pluginId = params.get('plugin') ?? undefined;
  const initialPath = params.get('path') ?? undefined;

  /** Close the tab (works because it was script-opened via window.open); fall back to history. */
  const closeWindow = () => {
    try { window.close(); } catch { /* noop */ }
    setTimeout(() => navigate(-1), 100);
  };

  return (
    <div className="flex h-screen flex-col bg-background">
      {/* Header */}
      <header className="flex items-center justify-between gap-3 border-b border-border bg-card px-4 py-2.5">
        <div className="flex min-w-0 items-center gap-2.5">
          <FolderOpen size={16} className="shrink-0 text-secondary" />
          <h1 className="truncate text-sm font-semibold text-foreground">File browser — {deviceId ? `device ${deviceId.slice(0, 8)}` : ''}</h1>
        </div>
        <button type="button" aria-label="Close file browser window" title="Close (ends the session)" onClick={closeWindow} className="rounded p-1 text-faint hover:bg-muted">
          <X size={16} />
        </button>
      </header>

      {/* Body — the shared core component; it manages its own scroll. */}
      <div className="min-h-0 flex-1 overflow-y-auto">
        {deviceId && (
          <FileBrowser deviceId={deviceId} pluginId={pluginId} context={JSON.parse(contextKey)} initialPath={initialPath} />
        )}
      </div>

      {/* Footer hint */}
      <footer className="border-t border-border bg-card px-4 py-1.5 text-[11px] text-faint">
        All operations are scoped to this location — you cannot navigate outside of it. Closing this window ends the session.
      </footer>
    </div>
  );
}
