import { useEffect, useRef, useState } from 'react';
import clsx from 'clsx';
import { Loader2, Terminal as TerminalIcon } from 'lucide-react';
import { Terminal } from '@xterm/xterm';
import { FitAddon } from '@xterm/addon-fit';
import '@xterm/xterm/css/xterm.css';
import { api, consoleSocketUrl } from '../api/client';
import { ResizableDialog } from './ResizableDialog';

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

    const sendResize = (): void => {
      if (ws && ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ type: 'resize', cols: term.cols, rows: term.rows }));
      }
    };

    // Fit until the layout has settled. The first measurement can run before
    // fonts/flex sizing are ready (dialog mount, new-window tab paint) and then
    // yields a grid SMALLER than the usable area — one that looks plausible but
    // is wrong, so "retry while at default 80x24" would stop too early. Keep
    // re-fitting on a short timer for ~2 s after open instead; any change
    // propagates to the PTY via the onResize subscription below (xterm dedupes
    // no-op resizes, so steady-state ticks are free).
    let fitTicks = 0;
    const tryFit = (): void => {
      if (disposed) return;
      try { fit.fit(); } catch { /* not laid out yet */ }
      if (++fitTicks < 20) window.setTimeout(tryFit, 100);
    };
    requestAnimationFrame(tryFit);
    // Font metrics change when web fonts finish loading (cell width/height shift) —
    // re-fit exactly at that moment too, in case it lands after the settle loop.
    if (typeof document !== 'undefined' && document.fonts?.ready) {
      void document.fonts.ready.then(() => tryFit()).catch(() => { /* noop */ });
    }

    // Keyboard → binary frames (xterm emits the exact escape sequences).
    const dataSub = term.onData((data) => {
      if (ws && ws.readyState === WebSocket.OPEN) {
        ws.send(new TextEncoder().encode(data));
      }
    });

    // THE resize path: whenever xterm's grid changes — initial fit, container
    // resize, font load — tell the remote PTY immediately. This is authoritative;
    // the ResizeObserver below only triggers re-fits.
    const resizeSub = term.onResize(({ cols, rows }) => {
      if (ws && ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ type: 'resize', cols, rows }));
      }
    });

    // ResizeObserver re-fits the grid when the container changes size; the
    // onResize subscription above then propagates the new geometry to the PTY.
    let resizeTimer: number | undefined;
    const ro = new ResizeObserver(() => {
      window.clearTimeout(resizeTimer);
      resizeTimer = window.setTimeout(() => {
        try { fit.fit(); } catch { /* not laid out yet */ }
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
          if (msg.type === 'ready') {
            term.focus();
            // Re-advertise the current geometry: our initial resize may have
            // reached the plugin before its SSH session existed. The SDK now
            // buffers + applies it, but sending again is harmless and removes
            // any residual race (xterm dedupes identical PTY sizes).
            sendResize();
          }
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
      resizeSub.dispose();
      if (ws) {
        ws.onclose = null; // suppress post-unmount state updates
        try { ws.close(1000, 'session closed'); } catch { /* noop */ }
      }
      term.dispose();
    };
  }, [deviceId, pluginId, contextKey]);

  return { hostRef, status, error, exitCode };
}

export function ConsoleDialog({ deviceId, pluginId, context, title, subtitle, onClose }: ConsoleDialogProps) {
  // Stable key for the (caller-supplied) context object — it must reach the mint
  // endpoint but must not re-trigger the session effect on every render.
  const contextKey = JSON.stringify(context);
  const { hostRef, status, error, exitCode } = useConsoleSession(deviceId, pluginId, contextKey);

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
    <ResizableDialog
      title={title}
      subtitle={subtitle}
      icon={<TerminalIcon size={16} />}
      onClose={onClose}
      onOpenInWindow={openInWindow}
      headerExtra={<ConsoleStatusPill status={status} exitCode={exitCode} />}
      defaultSize={{ w: 960, h: 720 }}
      bodyClassName="min-h-0 flex-1 flex flex-col"
      footer={
        <span className="text-[11px] text-faint">
          Interactive session over the bound SSH credential — input goes straight to the device. Drag the header to move, pull an edge or corner to resize; close to end the session.
        </span>
      }
    >
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
    </ResizableDialog>
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
