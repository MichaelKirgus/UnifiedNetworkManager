import { FormEvent, useEffect, useMemo, useRef, useState } from 'react';
import clsx from 'clsx';
import { useQueries } from '@tanstack/react-query';
import { CheckCircle2, Clock, Loader2, RefreshCw, X, XCircle } from 'lucide-react';
import { api, ApiError, CatalogEntry, DeviceTimeRow } from '../api/client';
import { ReauthDialog } from './ReauthDialog';

// The single shared clock action id — every plugin that can change a device's
// time exposes it under this exact id (see the actions modules in plugins/).
const CLOCK_ACTION_ID = 'system.clock.sync';

type Mode = 'sync' | 'set';

interface GroupResult {
  label: string;
  status: 'running' | 'ok' | 'failed';
  detail?: string;
}

/** Local-time value for <input type="datetime-local"> from an epoch-ms instant. */
function toLocalInputValue(ms: number): string {
  const d = new Date(ms);
  const pad = (n: number) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

/** <input type="datetime-local"> value → epoch ms (interpreted as local time), or null. */
function fromLocalInputValue(v: string): number | null {
  if (!v) return null;
  const t = new Date(v).getTime();
  return Number.isNaN(t) ? null : t;
}

/** True when the string is a valid IANA timezone identifier (best-effort, client-side). */
function isValidZone(zone: string): boolean {
  try {
    new Intl.DateTimeFormat('en-US', { timeZone: zone });
    return true;
  } catch {
    return false;
  }
}

export interface ClockSyncDialogProps {
  /** All device rows from GET /device-time — the dialog filters to clock-capable ones. */
  devices: DeviceTimeRow[];
  /** UNM's median drift vs international consensus (ms) — pre-fills the set-mode target. */
  consensusMs?: number | null;
  onClose: () => void;
}

/**
 * ClockSyncDialog — "Re-sync devices" from the Time page header. Lets the user
 * pick which devices to correct and HOW:
 *   - sync: re-trigger each device's native NTP client (the usual fix);
 *   - set:  push a specific wall-clock instant (UTC) and/or IANA timezone —
 *     for boxes without an NTP client, or when the drift is too large to wait
 *     out. The target defaults to "UNM now + consensus offset" so one value
 *     corrects every selected device at once.
 *
 * Selected devices are grouped by their assigned plugin (the action's inputs
 * differ per platform) and each group becomes ONE plan on the shared
 * `system.clock.sync` intent, created + executed immediately. Plan creation is
 * 2FA-gated server-side — a 401 opens the in-session ReauthDialog before retry.
 */
export function ClockSyncDialog({ devices, consensusMs, onClose }: ClockSyncDialogProps) {
  const [mode, setMode] = useState<Mode>('sync');
  // Set-mode inputs: both enabled by default (time pre-filled from the fleet
  // time base), each independently toggleable — some plugins only support one.
  const [timeEnabled, setTimeEnabled] = useState(true);
  const [zoneEnabled, setZoneEnabled] = useState(false);
  const [localValue, setLocalValue] = useState(() => toLocalInputValue(Date.now() + (consensusMs ?? 0)));
  const [zoneText, setZoneText] = useState('');

  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [results, setResults] = useState<GroupResult[]>([]);
  // Mirrors `results` for the async run loop — a reauth-resume must keep the
  // earlier groups' outcomes instead of rebuilding from scratch.
  const resultsRef = useRef<GroupResult[]>([]);
  useEffect(() => { resultsRef.current = results; }, [results]);
  const [reauth, setReauth] = useState<{ label: string; retry: () => Promise<void> } | null>(null);

  // Which of the visible devices' plugins expose the shared clock action?
  // Catalogs are fetched per distinct pluginId (only for rows that have one).
  const pluginIds = useMemo(
    () => Array.from(new Set(devices.map((d) => d.pluginId).filter((p): p is string => !!p))),
    [devices],
  );
  const catalogQueries = useQueries({
    queries: pluginIds.map((pid) => ({
      queryKey: ['plugin-actions', pid] as const,
      queryFn: () => api.pluginActions(pid),
      staleTime: 5 * 60_000,
      retry: false,
    })),
  });

  const clockCapable = useMemo(() => {
    const m = new Map<string, boolean>();
    pluginIds.forEach((pid, i) => {
      const actions: CatalogEntry[] | undefined = catalogQueries[i]?.data?.actions;
      if (actions === undefined) return; // still loading — treat as unknown for now
      m.set(pid, actions.some((a) => a.id === CLOCK_ACTION_ID));
    });
    return m;
  }, [pluginIds, catalogQueries]);

  const catalogsLoading = pluginIds.length > 0 && catalogQueries.some((q) => !q.data);
  const eligible = useMemo(
    () => devices.filter((d) => (d.pluginId ? clockCapable.get(d.pluginId) === true : false)),
    [devices, clockCapable],
  );
  const excludedCount = devices.length - eligible.length;

  const allSelected = eligible.length > 0 && eligible.every((r) => selected.has(r.deviceId));
  function toggleAll() {
    setSelected(allSelected ? new Set() : new Set(eligible.map((r) => r.deviceId)));
  }
  function toggleOne(deviceId: string) {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(deviceId)) next.delete(deviceId);
      else next.add(deviceId);
      return next;
    });
  }

  // The UTC instant that will be pushed in set mode (picker value, local time).
  const targetMs = fromLocalInputValue(localValue);
  const targetUtcIso = targetMs !== null ? new Date(targetMs).toISOString().replace('.000Z', 'Z') : null;

  /** Create+execute one plan per group, sequentially. Returns the index of the
   * first group that needs a 2FA revalidation (401), or groups.length when all
   * finished — the caller resumes from that index after ReauthDialog succeeds
   * (`startAt` keeps the earlier groups' outcomes visible). */
  async function runGroups(groups: Array<{ pluginId: string; label: string; deviceIds: string[] }>, inputs: Record<string, unknown>, startAt = 0): Promise<number> {
    const prev = resultsRef.current;
    const out: GroupResult[] = groups.map((g, i) => (i < startAt ? (prev[i] ?? { label: g.label, status: 'failed' as const, detail: 'interrupted' }) : { label: g.label, status: 'running' as const }));
    setResults(out);
    for (let i = startAt; i < groups.length; i++) {
      const g = groups[i];
      try {
        const plan = await api.createPlan({
          pluginId: g.pluginId,
          intentActionId: CLOCK_ACTION_ID,
          inputs,
          devices: g.deviceIds.map((deviceId) => ({ deviceId })),
        });
        await api.executePlan(plan.id);
        out[i] = { label: g.label, status: 'ok', detail: `${g.deviceIds.length} device${g.deviceIds.length === 1 ? '' : 's'}` };
      } catch (err) {
        if (err instanceof ApiError && err.status === 401) return i; // → reauth + resume at this group
        out[i] = { label: g.label, status: 'failed', detail: err instanceof Error ? err.message : String(err) };
      }
      setResults([...out]);
    }
    return groups.length;
  }

  function buildGroups(): Array<{ pluginId: string; label: string; deviceIds: string[] }> | null {
    const byPlugin = new Map<string, DeviceTimeRow[]>();
    for (const r of eligible) {
      if (!selected.has(r.deviceId)) continue;
      if (!r.pluginId) continue;
      const list = byPlugin.get(r.pluginId) ?? [];
      list.push(r);
      byPlugin.set(r.pluginId, list);
    }
    if (byPlugin.size === 0) return null;
    // Stable order: first-appearance in the device list.
    return Array.from(byPlugin.entries()).map(([pluginId, rows]) => ({
      pluginId,
      label: `${rows.length} device${rows.length === 1 ? '' : 's'} · ${pluginId}`,
      deviceIds: rows.map((r) => r.deviceId),
    }));
  }

  function buildInputs(): Record<string, unknown> | null {
    if (mode === 'sync') return { mode: 'sync' };
    const tz = zoneText.trim();
    let timeUtc: string | undefined;
    if (timeEnabled) {
      if (targetMs === null) {
        setError('Pick a valid date and time.');
        return null;
      }
      timeUtc = new Date(targetMs).toISOString().replace('.000Z', 'Z');
    }
    let timezone: string | undefined;
    if (zoneEnabled) {
      if (!tz) {
        setError('Enter a timezone (IANA id, e.g. Europe/Berlin) — or untick “Set timezone”.');
        return null;
      }
      if (!isValidZone(tz)) {
        setError(`“${tz}” is not a valid IANA timezone.`);
        return null;
      }
      timezone = tz;
    }
    if (!timeUtc && !timezone) {
      setError('Enable at least one of “Set time” or “Set timezone”.');
      return null;
    }
    return { mode: 'set', ...(timeUtc ? { timeUtc } : {}), ...(timezone ? { timezone } : {}) };
  }

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    const inputs = buildInputs();
    if (!inputs) return;
    const groups = buildGroups();
    if (!groups) {
      setError('Select at least one device.');
      return;
    }
    setBusy(true);
    try {
      const stopAt = await runGroups(groups, inputs);
      if (stopAt < groups.length) {
        // 2FA expired mid-flight — revalidate, then resume with the REMAINING groups.
        setReauth({ label: `Sync clocks on ${groups.length} device group${groups.length === 1 ? '' : 's'}`, retry: async () => { await runGroups(groups, inputs, stopAt); } });
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

  const done = results.length > 0 && results.every((r) => r.status !== 'running');

  return (
    <>
      <div className="fixed inset-0 z-[70] flex items-start justify-center overflow-y-auto bg-primary/40 p-6" onClick={onClose}>
        <form
          onSubmit={handleSubmit}
          onClick={(e) => e.stopPropagation()}
          className="mt-8 w-full max-w-lg rounded-lg border border-border bg-card p-5 shadow-xl"
        >
          <div className="mb-4 flex items-center justify-between">
            <h2 className="flex items-center gap-2 text-base font-semibold text-foreground">
              <RefreshCw className="h-4 w-4 text-primary" />
              Re-sync device clocks
            </h2>
            <button type="button" onClick={onClose} aria-label="Close" className="rounded p-1 text-faint hover:bg-muted hover:text-secondary">
              <X className="h-4 w-4" />
            </button>
          </div>

          {/* Mode: re-trigger native NTP vs push a specific time/timezone. */}
          <div className="mb-4">
            <label className="mb-1.5 block text-sm font-medium text-secondary">How</label>
            <div className="space-y-1.5">
              {(
                [
                  { value: 'sync', title: 'Re-sync via NTP', desc: "Restart each device's native time service (systemd-timesyncd / ntpd / chronyd …). Use this whenever the box has an NTP client." },
                  { value: 'set', title: 'Set specific time / timezone', desc: 'Push a wall-clock instant and/or IANA zone directly — for devices without an NTP client, or when the drift is too large to wait out.' },
                ] as Array<{ value: Mode; title: string; desc: string }>
              ).map((opt) => (
                <label
                  key={opt.value}
                  className={clsx(
                    'flex cursor-pointer items-start gap-2.5 rounded-md border px-3 py-2',
                    mode === opt.value ? 'border-primary bg-primary/10' : 'border-border hover:bg-muted'
                  )}
                >
                  <input type="radio" name="clock-mode" checked={mode === opt.value} onChange={() => setMode(opt.value)} className="mt-0.5 h-4 w-4 accent-current" />
                  <span>
                    <span className="block text-sm font-medium text-foreground">{opt.title}</span>
                    <span className="block text-xs text-secondary">{opt.desc}</span>
                  </span>
                </label>
              ))}
            </div>
          </div>

          {mode === 'set' && (
            <div className="mb-4 space-y-2.5 rounded-md border border-border bg-background p-3">
              <label className="flex items-center gap-2 text-sm text-secondary">
                <input type="checkbox" checked={timeEnabled} onChange={(e) => setTimeEnabled(e.target.checked)} className="h-4 w-4 accent-current" />
                Set time (UTC instant, picked in your local zone)
              </label>
              {timeEnabled && (
                <>
                  <input
                    type="datetime-local"
                    value={localValue}
                    onChange={(e) => setLocalValue(e.target.value)}
                    className="w-full rounded-md border border-border bg-card px-3 py-2 text-sm"
                  />
                  {targetUtcIso && (
                    <p className="text-xs text-faint">
                      → will be applied as <span className="font-mono">{targetUtcIso}</span>
                      {(consensusMs ?? 0) !== 0 && ' · pre-filled from the fleet time base'}
                    </p>
                  )}
                </>
              )}
              <label className="flex items-center gap-2 text-sm text-secondary">
                <input type="checkbox" checked={zoneEnabled} onChange={(e) => setZoneEnabled(e.target.checked)} className="h-4 w-4 accent-current" />
                Set timezone (IANA id)
              </label>
              {zoneEnabled && (
                <input
                  type="text"
                  value={zoneText}
                  onChange={(e) => setZoneText(e.target.value)}
                  placeholder="Europe/Berlin"
                  className="w-full rounded-md border border-border bg-card px-3 py-2 font-mono text-sm"
                />
              )}
            </div>
          )}

          {/* Device selection — only rows whose plugin exposes the clock action. */}
          <div className="mb-4">
            <label className="mb-1.5 flex items-center justify-between text-sm font-medium text-secondary">
              <span>Devices ({eligible.length})</span>
              {eligible.length > 0 && (
                <button type="button" onClick={toggleAll} className="text-xs font-normal text-primary hover:underline">
                  {allSelected ? 'Clear all' : 'Select all'}
                </button>
              )}
            </label>
            <div className="max-h-56 space-y-0.5 overflow-y-auto rounded-md border border-border bg-background p-2">
              {catalogsLoading && (
                <p className="flex items-center gap-2 px-1 py-2 text-xs text-faint">
                  <Loader2 size={13} className="animate-spin" /> Checking which plugins can set the clock…
                </p>
              )}
              {!catalogsLoading && eligible.length === 0 && (
                <p className="px-1 py-2 text-xs text-faint">
                  No selected device's plugin exposes a clock action yet — rebuild/restart the plugin images first.
                </p>
              )}
              {eligible.map((r) => (
                <label key={r.deviceId} className="flex cursor-pointer items-center gap-2 rounded px-1.5 py-1 hover:bg-muted">
                  <input type="checkbox" checked={selected.has(r.deviceId)} onChange={() => toggleOne(r.deviceId)} className="h-4 w-4 accent-current" />
                  <span className="min-w-0 flex-1 truncate text-sm text-foreground">{r.name}</span>
                  {typeof r.driftMs === 'number' && (
                    <span className={clsx('shrink-0 font-mono text-[11px] tabular-nums', Math.abs(r.driftMs) < 1_000 ? 'text-success-fg' : Math.abs(r.driftMs) < 60_000 ? 'text-warning-fg' : 'text-danger-fg')}>
                      {r.driftMs >= 0 ? '+' : '−'}{Math.round(Math.abs(r.driftMs))} ms
                    </span>
                  )}
                </label>
              ))}
            </div>
            {excludedCount > 0 && (
              <p className="mt-1 text-[11px] text-faint">
                {excludedCount} device{excludedCount === 1 ? '' : 's'} hidden — their plugin has no clock action.
              </p>
            )}
          </div>

          {/* Per-group execution results (one plan per plugin group). */}
          {results.length > 0 && (
            <div className="mb-3 space-y-1 rounded-md border border-border bg-background p-2">
              {results.map((r) => (
                <div key={r.label} className="flex items-center gap-2 text-xs">
                  {r.status === 'running' && <Loader2 size={13} className="shrink-0 animate-spin text-secondary" />}
                  {r.status === 'ok' && <CheckCircle2 size={13} className="shrink-0 text-success-fg" />}
                  {r.status === 'failed' && <XCircle size={13} className="shrink-0 text-danger-fg" />}
                  <span className="min-w-0 flex-1 truncate font-mono">{r.label}</span>
                  <span className={clsx('shrink-0', r.status === 'ok' ? 'text-success-fg' : r.status === 'failed' ? 'text-danger-fg' : 'text-faint')}>
                    {r.status === 'running' ? 'executing…' : r.detail ?? ''}
                  </span>
                </div>
              ))}
            </div>
          )}

          {error && (
            <div className="mb-3 rounded-md border border-danger-border bg-danger px-3 py-2 text-sm text-danger-fg">{error}</div>
          )}

          <div className="flex items-center justify-end gap-2">
            <button type="button" onClick={onClose} className="rounded-md border border-border px-3 py-1.5 text-sm font-medium text-secondary hover:bg-muted">
              {done ? 'Done' : 'Cancel'}
            </button>
            {!done && (
              <button
                type="submit"
                disabled={busy || catalogsLoading || eligible.length === 0}
                className="flex items-center gap-1.5 rounded-md bg-primary px-4 py-1.5 text-sm font-semibold text-white hover:bg-primary-hover disabled:opacity-50"
              >
                <Clock className="h-4 w-4" />
                {busy ? 'Executing…' : mode === 'sync' ? 'Re-sync clocks' : 'Apply time'}
              </button>
            )}
          </div>
        </form>
      </div>

      {reauth && (
        <ReauthDialog
          contextLabel={reauth.label}
          onClose={() => setReauth(null)}
          onSuccess={async () => {
            const retry = reauth.retry;
            setReauth(null);
            await retry();
          }}
        />
      )}
    </>
  );
}
