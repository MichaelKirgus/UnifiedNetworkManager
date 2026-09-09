import { useEffect, useRef, useState, type PointerEvent as ReactPointerEvent } from 'react';
import clsx from 'clsx';
import { ExternalLink, Loader2, Terminal as TerminalIcon, X } from 'lucide-react';
import { Terminal } from '@xterm/xterm';
import { FitAddon } from '@xterm/addon-fit';
import '@xterm/xterm/css/xterm.css';
import { api, consoleSocketUrl } from '../api/client';

/**
 * A full interactive SSH terminal (capability 'sshConsole') — the web-UI
 * counterpart of connecting with PuTTY/ssh. The caller passes a plugin-owned
 * `context` naming WHAT to attach to: `{ kind: 'host' }` for a login shell on the
 * device, or `{ kind: 'container', name?, service? }` for an exec into a container.
 *
 * Flow (mirrors the API's console broker):
 *   1. mintConsoleTicket(deviceId) → single-use 60 s ticket (JWT + devices:write
 *      + capability checks happen server-side at mint time).
 *   2. Open ws(s)://…/devices/:id/console/ws?ticket=… — the API proxies it VERBATIM
 *      to the plugin's /console endpoint, which opens a PTY over the bound ssh slot.
 *   3. Binary frames = raw terminal I/O both directions; text frames carry JSON
 *      control messages (ready / resize / exit / error). xterm.js renders.
 *
 * Two shells share one session hook (`useConsoleSession`):
 *   - `ConsoleDialog` (this file) — in-app dialog, draggable + resizable by default;
 *     its header has an "open in new window" button that pops the same session out
 *     into a full-window tab.
 *   - `pages/ConsolePage.tsx` (`/console/:deviceId`) — the standalone full-window
 *     console for that popped-out tab.
 */

export interface ConsoleDialogProps {
  deviceId: string;
  pluginId?: string;
  /** Plugin-owned context naming what to attach to (host shell / container exec). */
  context: Record<string, unknown>;
  /** Dialog title (e.g. "Shell — KIRGUSBANDE" or "Console — mysql"). */
  title: string;
  /** Subtitle shown under the title (device address, container name hint, …). */
  subtitle?: string;
  onClose: () => void;
}

/** Connection lifecycle as surfaced in the status bar. */
type ConsoleStatus = 'connecting' | 'connected' | 'closed';

/**
 * Core SSH-console session: mints a ticket, opens the proxied WebSocket and wires
 * xterm.js to it. Returns the host element ref (mount the terminal here) plus the
 * status/error/exit-code state for the surrounding shell UI.
 */
export function useConsoleSession(deviceId: string, pluginId?: string, contextKey = '{}') {
  const hostRef = useRef<HTMLDivElement>(null);

  const [status, setStatus] = useState<ConsoleStatus>('connecting');
  const [error, setError] = useState<string | null>(null);
  /** Remote exit code (present once the shell/command finished). */
  const [exitCode, setExitCode] = useState<number | null>(null);
  // Ref mirror of exitCode — the ws.onclose closure must not read stale state.
  const exitCodeRef = useRef<number | null>(null);
  useEffect(() => { exitCodeRef.current = exitCode; }, [exitCode]);

  // Mint + connect exactly once per (device, plugin, context) tuple.
  useEffect(() => {
    let disposed = false;
    let ws: WebSocket | null = null;

    const term = new Terminal({
      cursorBlink: true,
      fontSize: 13,
      fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Consolas, monospace',
      theme: {
        background: '#0d1117',
        foreground: '#d8dee9',
        cursor: '#5aa9e6',
        selectionBackground: '#264f78',
      },
    });
    const fit = new FitAddon();
    term.loadAddon(fit);

    const host = hostRef.current;
    if (!host) return;
    term.open(host);
    // Fit after the layout settles (dialog animation / flex sizing).
    requestAnimationFrame(() => {
      try { fit.fit(); } catch { /* not laid out yet */ }
    });

    const sendResize = (): void => {
      if (ws && ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ type: 'resize', cols: term.cols, rows: term.rows }));
      }
    };

    // Keyboard → binary frames (xterm emits the exact escape sequences).
    const dataSub = term.onData((data) => {
      if (ws && ws.readyState === WebSocket.OPEN) {
        ws.send(new TextEncoder().encode(data));
      }
    });

    // ResizeObserver keeps the PTY in sync with the dialog size.
    let resizeTimer: number | undefined;
    const ro = new ResizeObserver(() => {
      window.clearTimeout(resizeTimer);
      resizeTimer = window.setTimeout(() => {
        try { fit.fit(); } catch { /* not laid out yet */ }
        sendResize();
      }, 120);
    });
    if (host) ro.observe(host);

    void (async () => {
      let ticket: string;
      try {
        const ctx = JSON.parse(contextKey) as Record<string, unknown>;
        const res = await api.mintConsoleTicket(deviceId, { ...(pluginId ? { pluginId } : {}), context: ctx });
        ticket = res.ticket;
      } catch (err) {
        if (!disposed) setError(err instanceof Error ? err.message : String(err));
        return;
      }
      if (disposed) return;

      try {
        ws = new WebSocket(consoleSocketUrl(deviceId, ticket));
      } catch (err) {
        if (!disposed) setError(err instanceof Error ? err.message : String(err));
        return;
      }

      ws.binaryType = 'arraybuffer';
      ws.onopen = () => {
        if (disposed) return;
        setStatus('connected');
        term.focus();
        sendResize(); // advertise the initial geometry immediately
      };
      ws.onmessage = (ev: MessageEvent) => {
        if (disposed) return;
        if (typeof ev.data === 'string') {
          // Control message.
          let msg: { type?: string; code?: number; message?: string };
          try { msg = JSON.parse(ev.data); } catch { return; }
          if (msg.type === 'ready') term.focus();
          else if (msg.type === 'exit') {
            setExitCode(typeof msg.code === 'number' ? msg.code : null);
            setStatus('closed');
          } else if (msg.type === 'error') setError(msg.message ?? 'Console error');
          return;
        }
        // Binary frame = raw terminal output.
        term.write(new Uint8Array(ev.data as ArrayBuffer));
      };
      ws.onerror = () => {
        if (!disposed) setError('WebSocket connection failed — check the plugin is reachable and an SSH credential is bound.');
      };
      ws.onclose = (ev: CloseEvent) => {
        if (disposed) return;
        setStatus((s) => (s === 'connected' ? 'closed' : s));
        if (exitCodeRef.current === null && ev.code !== 1000) {
          setError(ev.reason || `Connection closed (${ev.code})`);
        }
      };
    })();

    return () => {
      disposed = true;
      ro.disconnect();
      window.clearTimeout(resizeTimer);
      dataSub.dispose();
      if (ws) {
        ws.onclose = null; // suppress post-unmount state updates
        try { ws.close(1000, 'session closed'); } catch { /* noop */ }
      }
      term.dispose();
    };
  }, [deviceId, pluginId, contextKey]);

  return { hostRef, status, error, exitCode };
}

/** Dialog geometry — fixed positioning so the panel can be dragged + resized. */
interface Geom { x: number; y: number; w: number; h: number }

const MIN_W = 420;
const MIN_H = 300;

const clampNum = (v: number, lo: number, hi: number): number => Math.min(Math.max(v, lo), hi);

function defaultGeom(): Geom {
  const vw = window.innerWidth;
  const vh = window.innerHeight;
  const w = Math.min(960, vw - 48);
  const h = Math.min(720, vh - 96);
  return { x: (vw - w) / 2, y: Math.max(16, (vh - h) / 2), w, h };
}

/** Edge/corner resize handles (Tailwind ships all eight resize cursors). */
const RESIZE_HANDLES: Array<{ edge: string; cls: string }> = [
  { edge: 'n', cls: 'inset-x-3 top-0 h-1.5 cursor-n-resize' },
  { edge: 's', cls: 'inset-x-3 bottom-0 h-1.5 cursor-s-resize' },
  { edge: 'e', cls: 'top-3 bottom-3 right-0 w-1.5 cursor-e-resize' },
  { edge: 'w', cls: 'top-3 bottom-3 left-0 w-1.5 cursor-w-resize' },
  { edge: 'ne', cls: 'right-0 top-0 h-3 w-3 cursor-ne-resize' },
  { edge: 'nw', cls: 'left-0 top-0 h-3 w-3 cursor-nw-resize' },
  { edge: 'se', cls: 'bottom-0 right-0 h-3 w-3 cursor-se-resize' },
  { edge: 'sw', cls: 'bottom-0 left-0 h-3 w-3 cursor-sw-resize' },
];

export function ConsoleDialog({ deviceId, pluginId, context, title, subtitle, onClose }: ConsoleDialogProps) {
  // Stable key for the (caller-supplied) context object — it must reach the mint
  // endpoint but must not re-trigger the session effect on every render.
  const contextKey = JSON.stringify(context);
  const { hostRef, status, error, exitCode } = useConsoleSession(deviceId, pluginId, contextKey);

  // Draggable + resizable geometry (centered by default).
  const [geom, setGeom] = useState<Geom>(defaultGeom);
  const dragRef = useRef<{ px: number; py: number; gx: number; gy: number } | null>(null);
  const resizeRef = useRef<{ edge: string; px: number; py: number; g: Geom } | null>(null);

  // Keep the panel inside the viewport when the browser window is resized.
  useEffect(() => {
    const onWindowResize = () => setGeom((g) => {
      const vw = window.innerWidth;
      const vh = window.innerHeight;
      const w = Math.min(g.w, vw - 16);
      const h = Math.min(g.h, vh - 16);
      return { ...g, w, h, x: clampNum(g.x, -(w - 96), vw - 96), y: clampNum(g.y, 0, vh - 48) };
    });
    window.addEventListener('resize', onWindowResize);
    return () => window.removeEventListener('resize', onWindowResize);
  }, []);

  // Drag — pointer capture on the header keeps tracking even outside the panel.
  const startDrag = (e: ReactPointerEvent<HTMLElement>) => {
    if ((e.target as HTMLElement).closest('button')) return; // buttons keep their own clicks
    dragRef.current = { px: e.clientX, py: e.clientY, gx: geom.x, gy: geom.y };
    e.currentTarget.setPointerCapture(e.pointerId);
  };
  const onDragMove = (e: ReactPointerEvent<HTMLElement>) => {
    const d = dragRef.current;
    if (!d) return;
    setGeom((g) => ({
      ...g,
      x: clampNum(d.gx + e.clientX - d.px, -(g.w - 96), window.innerWidth - 96),
      y: clampNum(d.gy + e.clientY - d.py, 0, window.innerHeight - 48),
    }));
  };
  const endDrag = () => { dragRef.current = null; };

  // Resize — one handler for all eight handles; the edge string drives which
  // sides move ('ne' adjusts both north and east).
  const startResize = (edge: string) => (e: ReactPointerEvent<HTMLElement>) => {
    resizeRef.current = { edge, px: e.clientX, py: e.clientY, g: geom };
    e.currentTarget.setPointerCapture(e.pointerId);
    e.stopPropagation();
  };
  const onResizeMove = (e: ReactPointerEvent<HTMLElement>) => {
    const r = resizeRef.current;
    if (!r) return;
    const dx = e.clientX - r.px;
    const dy = e.clientY - r.py;
    setGeom(() => {
      let { x, y } = r.g;
      let w = r.g.w;
      let h = r.g.h;
      if (r.edge.includes('e')) w = clampNum(r.g.w + dx, MIN_W, window.innerWidth - r.g.x);
      if (r.edge.includes('s')) h = clampNum(r.g.h + dy, MIN_H, window.innerHeight - r.g.y);
      if (r.edge.includes('w')) { const nw = clampNum(r.g.w - dx, MIN_W, r.g.x + r.g.w); x += r.g.w - nw; w = nw; }
      if (r.edge.includes('n')) { const nh = clampNum(r.g.h - dy, MIN_H, r.g.y + r.g.h); y += r.g.h - nh; h = nh; }
      return { x, y, w, h };
    });
  };
  const endResize = () => { resizeRef.current = null; };

  /** Pop the session out into its own full-window tab (same ticket flow). */
  const openInWindow = () => {
    const params = new URLSearchParams();
    if (pluginId) params.set('plugin', pluginId);
    params.set('context', contextKey);
    params.set('title', title);
    if (subtitle) params.set('subtitle', subtitle);
    window.open(`${window.location.origin}/console/${deviceId}?${params.toString()}`, '_blank');
  };

  return (
    <div className="fixed inset-0 z-50 bg-primary/40" onClick={onClose}>
      <div
        className="absolute flex flex-col overflow-hidden rounded-md border border-border bg-card shadow-xl"
        style={{ left: geom.x, top: geom.y, width: geom.w, height: geom.h }}
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header — also the drag handle (cursor-move). */}
        <header
          className="flex cursor-move touch-none select-none items-center justify-between gap-3 border-b border-border px-4 py-3"
          onPointerDown={startDrag}
          onPointerMove={onDragMove}
          onPointerUp={endDrag}
          onPointerCancel={endDrag}
        >
          <div className="flex min-w-0 items-center gap-2.5">
            <TerminalIcon size={16} className="shrink-0 text-secondary" />
            <div className="min-w-0">
              <h2 className="truncate text-base font-semibold text-foreground">{title}</h2>
              {subtitle && <p className="mt-0.5 truncate text-xs text-muted-foreground">{subtitle}</p>}
            </div>
          </div>
          <div className="flex shrink-0 items-center gap-2">
            {/* Status pill */}
            <ConsoleStatusPill status={status} exitCode={exitCode} />
            <button type="button" aria-label="Open console in a new window" title="Open in a new window" onClick={openInWindow} className="rounded p-1 text-faint hover:bg-muted">
              <ExternalLink size={16} />
            </button>
            <button type="button" aria-label="Close console" onClick={onClose} className="rounded p-1 text-faint hover:bg-muted">
              <X size={16} />
            </button>
          </div>
        </header>

        {/* Error banner */}
        {error && (
          <div className="flex items-center justify-between gap-3 border-b border-danger-border bg-danger px-4 py-2 text-sm text-white">
            <span className="min-w-0 truncate" title={error}>{error}</span>
            <button type="button" onClick={onClose} className="shrink-0 rounded px-2 py-0.5 text-xs font-semibold hover:bg-white/10">Dismiss</button>
          </div>
        )}

        {/* Terminal host — xterm.js renders here; the dark theme is fixed (terminals are dark). */}
        <div className="min-h-0 flex-1 bg-[#0d1117] p-2">
          <div ref={hostRef} className="h-full w-full" />
        </div>

        {/* Footer hint */}
        <footer className="border-t border-border px-4 py-1.5 text-[11px] text-faint">
          Interactive session over the bound SSH credential — input goes straight to the device. Drag the header to move, pull an edge or corner to resize; close to end the session.
        </footer>

        {/* Resize handles (edges + corners). */}
        {RESIZE_HANDLES.map((h) => (
          <div
            key={h.edge}
            className={`absolute touch-none ${h.cls}`}
            onPointerDown={startResize(h.edge)}
            onPointerMove={onResizeMove}
            onPointerUp={endResize}
            onPointerCancel={endResize}
          />
        ))}
      </div>
    </div>
  );
}

/** Shared status pill (dialog + standalone window). */
export function ConsoleStatusPill({ status, exitCode }: { status: ConsoleStatus; exitCode: number | null }) {
  return (
    <span
      className={clsx(
        'inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 text-xs font-semibold',
        status === 'connected' && 'bg-green-100 text-green-800 dark:bg-green-950/60 dark:text-green-300',
        status === 'connecting' && 'bg-muted text-secondary',
        status === 'closed' && (exitCode !== null ? 'bg-amber-100 text-amber-800 dark:bg-amber-950/60 dark:text-amber-300' : 'bg-danger text-white'),
      )}
    >
      {status === 'connecting' && <Loader2 size={12} className="animate-spin" />}
      {status === 'connected' ? 'Connected' : status === 'closed' ? (exitCode !== null ? `Exited (${exitCode})` : 'Closed') : 'Connecting…'}
    </span>
  );
}
