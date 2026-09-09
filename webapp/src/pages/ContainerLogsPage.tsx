import { useMemo } from 'react';
import { useNavigate, useParams, useSearchParams } from 'react-router-dom';
import { ScrollText, X } from 'lucide-react';
import { ContainerLogsView } from '../components/ContainerLogs';

/**
 * Standalone full-window container-log viewer — the destination of the LogsDialog's
 * "open in a new window" button. Lives at `/container-logs/:deviceId` (its own tab,
 * no app shell) so it can be tiled next to other windows while tailing output.
 *
 * Query params (set by the opener): `app` (JSON — the ContainerRow), `plugin`.
 */
export default function ContainerLogsPage() {
  const navigate = useNavigate();
  const { deviceId } = useParams<{ deviceId: string }>();
  const [params] = useSearchParams();

  // The opener serializes the whole row; we only need identity + display fields.
  const app = useMemo(() => {
    try { return JSON.parse(params.get('app') || '{}'); } catch { return null; }
  }, [params]);

  /** Close the tab (works because it was script-opened via window.open); fall back to history. */
  const closeWindow = () => {
    try { window.close(); } catch { /* noop */ }
    setTimeout(() => navigate(-1), 100);
  };

  if (!app || !deviceId) {
    return (
      <div className="flex h-screen flex-col items-center justify-center gap-3 bg-background text-sm text-muted-foreground">
        Missing console parameters — open this page from the Containers page.
        <button type="button" onClick={() => navigate(-1)} className="rounded-md border border-border px-3 py-1.5 font-medium text-secondary hover:bg-muted">Go back</button>
      </div>
    );
  }

  return (
    <div className="flex h-screen flex-col bg-background">
      {/* Header */}
      <header className="flex items-center justify-between gap-3 border-b border-border bg-card px-4 py-2.5">
        <div className="flex min-w-0 items-center gap-2.5">
          <ScrollText size={16} className="shrink-0 text-secondary" />
          <div className="min-w-0">
            <h1 className="truncate text-sm font-semibold text-foreground">Logs — {app.name}</h1>
            <p className="mt-0.5 truncate text-xs text-muted-foreground">{app.deviceName ?? deviceId}</p>
          </div>
        </div>
        <button type="button" aria-label="Close logs window" title="Close (ends the session)" onClick={closeWindow} className="rounded p-1 text-faint hover:bg-muted">
          <X size={16} />
        </button>
      </header>

      {/* Body — shared viewer; it manages its own scroll. */}
      <div className="min-h-0 flex-1 overflow-y-auto">
        <ContainerLogsView app={app} />
      </div>
    </div>
  );
}
