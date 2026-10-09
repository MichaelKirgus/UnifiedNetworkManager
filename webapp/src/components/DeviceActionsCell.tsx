import { useEffect, useMemo, useRef, useState } from 'react';
import { createPortal } from 'react-dom';
import { useQueries, useQueryClient } from '@tanstack/react-query';
import { AlertTriangle, CheckCircle2, FolderOpen, Globe, Loader2, MoreHorizontal, Terminal as TerminalIcon, X, Zap } from 'lucide-react';
import clsx from 'clsx';
import { api, ApiError, CatalogEntry, Device, QuickAction, pluginIconUrl } from '../api/client';
import { SchemaForm, validateSchema, defaultValues } from './SchemaForm';
import { DialogShell } from './DialogShell';
import { ConsoleDialog } from './ConsoleDialog';
import { FileBrowserDialog } from './FileBrowserDialog';
import { runAction, useExecutionMode, READONLY_MESSAGE } from '../executionMode';

/**
 * DeviceActionsCell — the "Device Actions" column of the Devices page. Renders a
 * compact dropdown of the quick actions the device's plugins propagate via /discover
 * `quickActions`. Four kinds:
 *   - url    → POST /devices/:id/quick-action resolves the management web-UI URL
 *              (the PLUGIN owns scheme/path + its configured webUiPort option) and
 *              opens it in a new tab.
 *   - shell  → reuses the SSH console dialog (capability 'sshConsole').
 *   - files  → reuses the filesystem browser dialog (capability 'filesystem').
 *   - action → runs a catalog entry through the plan workflow with risk gating:
 *              read = instant, write = confirm "Yes" (+ input form when needed),
 *              dangerous = never offered.
 * Rendering follows the Management Actions column pattern: up to three actions are
 * plain icon buttons in the row, anything beyond collapses into a "more" dropdown
 * (portaled to <body> so the table's sticky rows can never paint over it). Each
 * action may carry a plugin-provided `iconPath` (served via the API icon proxy);
 * without one, a generic per-kind glyph is shown.
 */

interface DeviceActionsCellProps {
  device: Device;
}

/** One quick action bound to the assignment that advertised it. */
interface BoundQuickAction extends QuickAction {
  pluginId: string;
}

const KIND_ICONS = {
  url: Globe,
  shell: TerminalIcon,
  files: FolderOpen,
  action: Zap,
} as const;

/** How many quick actions render as plain icon buttons before collapsing into the overflow menu. */
const INLINE_ACTION_LIMIT = 3;

/** Icon of a quick action: the plugin-provided image (via the API icon proxy) when
 * advertised, otherwise the generic per-kind glyph. A broken image falls back to
 * the glyph instead of rendering an empty box. */
function QuickActionIcon({ qa, className = 'h-4 w-4' }: { qa: BoundQuickAction; className?: string }) {
  const [broken, setBroken] = useState(false);
  if (qa.iconPath && !broken) {
    return (
      <img
        src={pluginIconUrl(qa.pluginId, qa.iconPath)}
        alt=""
        onError={() => setBroken(true)}
        className={clsx('shrink-0 object-contain', className)}
      />
    );
  }
  const Icon = KIND_ICONS[qa.kind];
  return <Icon className={clsx('shrink-0', className)} />;
}

export function DeviceActionsCell({ device }: DeviceActionsCellProps) {
  const queryClient = useQueryClient();
  const { mode } = useExecutionMode();
  const [menuOpen, setMenuOpen] = useState(false);
  const moreBtnRef = useRef<HTMLButtonElement>(null);
  /** Viewport position of the overflow menu (fixed, portaled to <body>). */
  const [menuPos, setMenuPos] = useState<{ top: number; left: number } | null>(null);

  // Which dialog (if any) is open for this row.
  const [active, setActive] = useState<BoundQuickAction | null>(null);
  const [urlError, setUrlError] = useState<string | null>(null);
  const [resolvingId, setResolvingId] = useState<string | null>(null);
  const [runningId, setRunningId] = useState<string | null>(null);

  // Merge the quick actions of every assignment, deduped by id (first wins —
  // primary plugin first). kind 'action' entries are resolved against each
  // plugin's persisted catalog below: unknown ids and dangerous risk levels are
  // DROPPED so they can never be offered.
  const boundActions = useMemo<BoundQuickAction[]>(() => {
    const out: BoundQuickAction[] = [];
    const seen = new Set<string>();
    for (const a of device.plugins ?? []) {
      for (const q of a.pluginQuickActions ?? []) {
        if (!q || !q.id || seen.has(q.id)) continue;
        seen.add(q.id);
        out.push({ ...q, pluginId: a.pluginId });
      }
    }
    return out;
  }, [device.plugins]);

  // Catalogs for every plugin that advertises an action-kind quick action —
  // fetched eagerly so the menu can gate items (unknown id / dangerous) before
  // anything is clicked.
  const actionPluginIds = useMemo(
    () => Array.from(new Set(boundActions.filter((q) => q.kind === 'action').map((q) => q.pluginId))),
    [boundActions]
  );
  const catalogQueries = useQueries({
    queries: actionPluginIds.map((pluginId) => ({
      // Canonical single-plugin key — shares the cache with every other
      // per-plugin catalog read (DeviceConfig, PlanDetail, Plans, …).
      queryKey: ['pluginActions', pluginId],
      queryFn: () => api.pluginActions(pluginId),
      staleTime: 5 * 60_000,
    })),
  });
  const catalogByPlugin = useMemo(() => {
    const m = new Map<string, CatalogEntry[]>();
    actionPluginIds.forEach((pluginId, i) => m.set(pluginId, catalogQueries[i]?.data?.actions ?? []));
    return m;
  }, [actionPluginIds, catalogQueries]);

  /** The usable catalog entry for an action-kind quick action — null = not offered. */
  function catalogEntryOf(qa: BoundQuickAction): CatalogEntry | null {
    if (qa.kind !== 'action' || !qa.actionId) return null;
    const list = catalogByPlugin.get(qa.pluginId);
    if (!list) return null; // catalog not loaded yet — item stays hidden until it is
    const entry = list.find((e) => e.id === qa.actionId);
    if (!entry || entry.deviceCount !== 1) return null;
    if (entry.riskLevel === 'dangerous') return null; // dangerous actions are never quick actions
    return entry;
  }

  // Close the overflow menu on outside click, scroll or resize — it is fixed-
  // positioned in a portal, so any viewport movement would leave it detached.
  useEffect(() => {
    if (!menuOpen) return;
    const onDown = (e: MouseEvent) => {
      if (moreBtnRef.current && !moreBtnRef.current.contains(e.target as Node)) setMenuOpen(false);
    };
    const close = () => setMenuOpen(false);
    document.addEventListener('mousedown', onDown);
    window.addEventListener('scroll', close, true);
    window.addEventListener('resize', close);
    return () => {
      document.removeEventListener('mousedown', onDown);
      window.removeEventListener('scroll', close, true);
      window.removeEventListener('resize', close);
    };
  }, [menuOpen]);

  /** Opens the overflow menu positioned at the "more" button (clamped to the viewport). */
  function toggleMoreMenu() {
    if (menuOpen) {
      setMenuOpen(false);
      return;
    }
    const r = moreBtnRef.current?.getBoundingClientRect();
    if (!r) return;
    const width = 256; // w-64
    const left = Math.max(8, Math.min(r.right - width, window.innerWidth - width - 8));
    let top = r.bottom + 4;
    if (top + 320 > window.innerHeight) top = Math.max(8, r.top - 4 - 280); // flip above when no room below
    setMenuPos({ top, left });
    setMenuOpen(true);
  }

  async function openUrl(qa: BoundQuickAction) {
    setMenuOpen(false);
    setResolvingId(qa.id);
    setUrlError(null);
    try {
      const res = await api.resolveQuickAction(device.id, qa.id, qa.pluginId);
      window.open(res.url, '_blank', 'noopener');
    } catch (err) {
      setUrlError(err instanceof Error ? err.message : String(err));
    } finally {
      setResolvingId(null);
    }
  }

  async function executeAction(qa: BoundQuickAction, entry: CatalogEntry, values?: Record<string, unknown>) {
    const input = { ...defaultValues(entry.inputSchema ?? {}), ...(qa.prefill ?? {}), ...(values ?? {}) };
    setRunningId(qa.id);
    try {
      await runAction(
        () => api.createPlan({ pluginId: qa.pluginId, intentActionId: entry.id, inputs: input, devices: [{ deviceId: device.id }] }),
        (id) => api.executePlan(id),
        mode,
      );
      setActive(null);
      queryClient.invalidateQueries({ queryKey: ['devices'] });
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) {
        setUrlError('Two-factor authentication required — sign in again and retry.');
      } else {
        let msg = err instanceof Error ? err.message : String(err);
        if (mode === 'plan') msg += ' The plan was saved and can be executed from the Plans center.';
        setUrlError(msg);
      }
    } finally {
      setRunningId(null);
    }
  }

  function onMenuClick(qa: BoundQuickAction) {
    setMenuOpen(false);
    if (qa.kind === 'url') void openUrl(qa);
    else if (qa.kind === 'action') {
      const entry = catalogEntryOf(qa);
      if (!entry) return; // unknown / dangerous — never offered
      if (mode === 'readonly') return;
      if (entry.riskLevel === 'write' && !window.confirm(`"${entry.label}" modifies this device. Continue?`)) return;
      const hasInput = Object.keys(entry.inputSchema ?? {}).length > 0;
      if (hasInput) {
        setActive(qa); // open the input form dialog
      } else {
        void executeAction(qa, entry);
      }
    } else {
      setMenuOpen(false);
      setActive(qa);
    }
  }

  const activeEntry = active?.kind === 'action' ? catalogEntryOf(active) : null;
  const viaName = (pluginId: string) => device.plugins?.find((p) => p.pluginId === pluginId)?.pluginName ?? '';

  // Action-kind items stay hidden until their catalog is loaded, and are dropped
  // entirely when the entry is unknown or dangerous — `visible` is what can be
  // offered right now.
  const visible = boundActions.filter((qa) => qa.kind !== 'action' || catalogEntryOf(qa));
  if (boundActions.length === 0 || visible.length === 0) return <span className="text-faint">—</span>;

  // Same pattern as the Management Actions column: up to INLINE_ACTION_LIMIT
  // actions render as plain icon buttons; anything beyond collapses into a menu.
  const inline = visible.slice(0, INLINE_ACTION_LIMIT);
  const overflow = visible.slice(INLINE_ACTION_LIMIT);

  return (
    <>
      <div className="flex items-center gap-1">
        {inline.map((qa) => (
          <button
            key={qa.id}
            type="button"
            aria-label={`${qa.label} — ${device.name}`}
            title={mode === 'readonly' ? READONLY_MESSAGE : qa.description || qa.label}
            disabled={mode === 'readonly' || runningId === qa.id}
            className="rounded-md p-1.5 text-secondary hover:bg-muted hover:text-foreground disabled:opacity-40"
            onClick={() => onMenuClick(qa)}
          >
            {runningId === qa.id ? <Loader2 className="h-4 w-4 animate-spin" /> : <QuickActionIcon qa={qa} />}
          </button>
        ))}
        {overflow.length > 0 && (
          <button
            ref={moreBtnRef}
            type="button"
            aria-label={`More device actions for ${device.name}`}
            title="More device actions"
            disabled={mode === 'readonly'}
            className={clsx('rounded-md p-1.5 text-secondary hover:bg-muted hover:text-foreground', menuOpen && 'bg-muted text-foreground')}
            onClick={toggleMoreMenu}
          >
            <MoreHorizontal className="h-4 w-4" />
          </button>
        )}
      </div>

      {/* Overflow menu — portaled to <body>: the table's sticky header rows carry
          z-10 inside their own stacking context, so an in-cell absolute menu can be
          painted over by later rows. A fixed-position portal at z-50 always wins. */}
      {menuOpen &&
        menuPos &&
        createPortal(
          <div className="fixed z-50 w-64 rounded-md border border-border bg-card p-1 shadow-lg" style={{ top: menuPos.top, left: menuPos.left }} role="menu">
            {overflow.map((qa) => {
              const write = qa.kind === 'action' && catalogEntryOf(qa)?.riskLevel === 'write';
              return (
                <button
                  key={qa.id}
                  type="button"
                  className="flex w-full items-center gap-2 rounded px-2 py-1.5 text-left text-sm text-secondary hover:bg-background hover:text-foreground disabled:opacity-40"
                  title={mode === 'readonly' ? READONLY_MESSAGE : qa.description || qa.label}
                  disabled={mode === 'readonly'}
                  onClick={() => onMenuClick(qa)}
                >
                  <QuickActionIcon qa={qa} className="h-3.5 w-3.5" />
                  <span className="flex-1 truncate">{qa.label}</span>
                  {write && (
                    <AlertTriangle className="h-3.5 w-3.5 shrink-0 text-warning" aria-label="Modifies the device — asks for confirmation" />
                  )}
                </button>
              );
            })}
          </div>,
          document.body,
        )}

      {urlError && (
        <div className="mt-1 max-w-[260px] rounded-md border border-danger-border bg-danger px-2 py-1 text-xs text-danger-fg">
          {urlError}
          <button type="button" aria-label="Dismiss error" className="ml-2 align-middle hover:text-white" onClick={() => setUrlError(null)}>
            <X className="inline h-3 w-3" />
          </button>
        </div>
      )}

      {resolvingId && (
        <span className="ml-1 inline-flex items-center gap-1 text-xs text-faint">
          <Loader2 className="h-3 w-3 animate-spin" /> opening…
        </span>
      )}

      {/* kind 'shell' — SSH console dialog (host login shell). */}
      {active && active.kind === 'shell' && (
        <ConsoleDialog
          deviceId={device.id}
          pluginId={active.pluginId}
          context={{ kind: 'host' }}
          title={`Shell — ${device.name}`}
          subtitle={`${device.managementAddress ?? ''}${viaName(active.pluginId) ? ` · via ${viaName(active.pluginId)}` : ''}`}
          onClose={() => setActive(null)}
        />
      )}

      {/* kind 'files' — filesystem browser dialog (root tree). */}
      {active && active.kind === 'files' && (
        <FileBrowserDialog
          deviceId={device.id}
          pluginId={active.pluginId}
          context={{ kind: 'root' }}
          title={`Files — ${device.name}`}
          subtitle={`${device.managementAddress ?? ''}${viaName(active.pluginId) ? ` · via ${viaName(active.pluginId)}` : ''}`}
          onClose={() => setActive(null)}
        />
      )}

      {/* kind 'action' with input — schema form dialog, risk-gated execution. */}
      {active && active.kind === 'action' && (
        <ActionQuickDialog
          qa={active}
          entry={activeEntry}
          onClose={() => setActive(null)}
          onExecute={(entry, values) => void executeAction(active, entry, values)}
        />
      )}
    </>
  );
}

/** Modal for a kind 'action' quick action that takes input: renders the schema form. */
function ActionQuickDialog({
  qa,
  entry,
  onClose,
  onExecute,
}: {
  qa: BoundQuickAction;
  entry: CatalogEntry | null;
  onClose: () => void;
  onExecute: (entry: CatalogEntry, values: Record<string, unknown>) => void;
}) {
  const [values, setValues] = useState<Record<string, unknown>>(() => ({
    ...defaultValues(entry?.inputSchema ?? {}),
    ...(qa.prefill ?? {}),
  }));
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({});

  function submit() {
    if (!entry) return;
    const errors = validateSchema(entry.inputSchema ?? {}, values);
    if (Object.keys(errors).length > 0) {
      setFieldErrors(errors);
      return;
    }
    onExecute(entry, values);
  }

  return (
    <DialogShell
      title={entry?.label ?? qa.label}
      onClose={onClose}
      footer={
        <div className="flex items-center justify-end gap-2">
          <button type="button" onClick={onClose} className="rounded-md border border-border px-3 py-1.5 text-sm font-medium text-secondary hover:bg-background">
            Cancel
          </button>
          {entry && (
            <button
              type="button"
              disabled={!entry}
              onClick={submit}
              className="flex items-center gap-1.5 rounded-md bg-primary px-3 py-1.5 text-sm font-semibold text-white hover:bg-primary-hover disabled:opacity-40"
            >
              <CheckCircle2 className="h-4 w-4" />
              {entry.riskLevel === 'write' ? 'Apply change' : 'Run'}
            </button>
          )}
        </div>
      }
    >
      <div className="space-y-3">
          {entry?.description ? (
            <p className="text-xs text-faint">{entry.description}</p>
          ) : null}
          {Object.keys(entry?.inputSchema ?? {}).length > 0 ? (
            <SchemaForm schema={entry?.inputSchema ?? {}} values={values} onChange={(v) => setValues(v)} fieldErrors={fieldErrors} />
          ) : (
            <p className="text-xs text-faint">This action takes no input.</p>
          )}
      </div>
    </DialogShell>
  );
}
