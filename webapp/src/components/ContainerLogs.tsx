import { useEffect, useState } from 'react';
import { Loader2, RotateCw } from 'lucide-react';
import { api, ContainerRow } from '../api/client';

/** One container's log section as returned by `containers.logs.read`. Both the
 * TrueNAS plugin (SSH docker logs) and the Docker plugin (Engine API) emit this
 * same shape, so one renderer covers both. */
export interface LogSection { id?: string; service?: string; state?: string; logs: string; error?: string }

/**
 * The log-viewer body for a single app — tail control + refresh + per-container
 * sections. On open (and on tail-change / refresh) it calls the plugin's read-only
 * `containers.logs.read` action via the generic execute path (no plan row, no 2FA).
 * TrueNAS serves this over SSH (`docker logs --tail N`) because its API has no log
 * RPC; the Docker plugin uses the Engine API directly. Multi-container apps render
 * one section per container.
 *
 * Shared by the in-app LogsDialog (Containers page) and the full-window
 * /container-logs page so both surfaces stay in lockstep.
 */
export function ContainerLogsView({ app }: { app: ContainerRow }) {
  const [tail, setTail] = useState(300);
  const [refreshTick, setRefreshTick] = useState(0); // bump to re-fetch the same tail
  const [sections, setSections] = useState<LogSection[] | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      setLoading(true);
      setError(null);
      try {
        const res = await api.executePluginAction(app.pluginId, { deviceId: app.deviceId, actionId: 'containers.logs.read', input: { name: app.name, tail } });
        if (!cancelled) {
          const c = res.details.containers;
          setSections(Array.isArray(c) ? (c as LogSection[]) : []);
        }
      } catch (err) {
        if (!cancelled) setError(err instanceof Error ? err.message : String(err));
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => { cancelled = true; };
  }, [app.pluginId, app.deviceId, app.name, tail, refreshTick]);

  const totalLines = (sections ?? []).reduce((n, s) => n + (s.logs ? s.logs.split('\n').length : 0), 0);

  return (
    <>
      <div className="flex items-center gap-2 border-b border-border px-4 py-2">
        <label htmlFor="logs-tail" className="text-xs font-medium text-secondary">Tail</label>
        <select
          id="logs-tail"
          value={tail}
          onChange={(e) => setTail(Number(e.target.value))}
          className="rounded-md border border-border bg-background px-2 py-1 text-xs text-foreground focus:border-slate-500 focus:outline-none"
        >
          {[100, 300, 500, 1000].map((n) => <option key={n} value={n}>{n}</option>)}
        </select>
        <button type="button" onClick={() => setRefreshTick((t) => t + 1)} disabled={loading} className="inline-flex items-center gap-1.5 rounded-md border border-border px-2 py-1 text-xs font-medium text-secondary hover:bg-background disabled:opacity-40">
          {loading ? <Loader2 className="h-3 w-3 animate-spin" /> : <RotateCw className="h-3 w-3" />} Refresh
        </button>
        {!loading && !error && sections !== null && (
          <span className="ml-auto text-xs text-faint">{totalLines} line{totalLines === 1 ? '' : 's'}</span>
        )}
      </div>

      <div className="p-4">
        {loading && (
          <div className="flex items-center gap-2 py-8 text-sm text-secondary">
            <Loader2 className="h-4 w-4 animate-spin" /> Reading logs…
          </div>
        )}

        {!loading && error && (
          <div className="rounded-md border border-danger-border bg-danger px-3 py-2 text-xs text-danger-fg">{error}</div>
        )}

        {!loading && !error && sections !== null && sections.length === 0 && (
          <div className="py-6 text-center text-sm text-secondary">No log output available for this app.</div>
        )}

        {!loading && !error && sections !== null && sections.length > 0 && (
          <div className="space-y-3">
            {sections.map((s, i) => (
              <div key={s.id ?? i}>
                {sections.length > 1 && (
                  <div className="mb-1 flex items-center gap-2 text-xs font-medium text-secondary">
                    <span>{s.service || s.id?.slice(0, 12) || `container ${i + 1}`}</span>
                    {s.state && <span className="text-faint">({s.state})</span>}
                  </div>
                )}
                {s.error ? (
                  <div className="rounded-md border border-danger-border bg-danger px-3 py-2 font-mono text-xs text-danger-fg">{s.error}</div>
                ) : s.logs === '' ? (
                  <div className="rounded-md border border-border bg-background px-3 py-2 font-mono text-xs text-faint">(no output)</div>
                ) : (
                  <pre className="max-h-[52vh] overflow-auto rounded-md border border-border bg-background p-3 font-mono text-[11px] leading-relaxed">
                    {s.logs.split('\n').map((line, li) => (
                      line.startsWith('[err] ')
                        ? <span key={li} className="text-danger-fg">{line.slice(6)}{'\n'}</span>
                        : <span key={li}>{line}{'\n'}</span>
                    ))}
                  </pre>
                )}
              </div>
            ))}
          </div>
        )}
      </div>
    </>
  );
}
