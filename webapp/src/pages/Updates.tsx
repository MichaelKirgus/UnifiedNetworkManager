import { useQuery, useQueryClient } from '@tanstack/react-query';
import { ArrowUpCircle, CheckCircle2, Loader2, RefreshCw, Rocket } from 'lucide-react';
import { useEffect, useMemo, useRef, useState } from 'react';
import { Layout } from '../components/Layout';
import { DataTable, DataTableColumn } from '../components/DataTable';
import { DeviceChip } from '../components/DeviceChip';
import { ReauthDialog } from '../components/ReauthDialog';
import { runAction, useExecutionMode, type ExecutionMode } from '../executionMode';
import { api, ApiError, UpdateRow } from '../api/client';
import { can } from '../auth/permissions';

// ---------------------------------------------------------------------------
// Kind badge + helpers (same visual language as the other inventory pages)
// ---------------------------------------------------------------------------

const KIND_STYLES: Record<string, string> = {
  firmware: 'bg-indigo-100 text-indigo-700',
  'os-package': 'bg-sky-100 text-sky-700',
  'docker-image': 'bg-teal-100 text-teal-700',
  app: 'bg-violet-100 text-violet-700',
};

function KindBadge({ kind }: { kind: string }) {
  return (
    <span className={`inline-flex rounded px-1.5 py-0.5 text-xs font-medium ${KIND_STYLES[kind] ?? 'bg-muted text-secondary'}`}>
      {kind}
    </span>
  );
}

function orDash(v?: string | null): string {
  return v && v.trim() !== '' ? v : '—';
}

// ---------------------------------------------------------------------------
// Plan helpers (same contract as the Storage / Containers pages)
// ---------------------------------------------------------------------------

/** Creates a plan for ONE plugin + action. In Execute mode it is also executed;
 * in Plan mode it is saved without executing. Throws on failure — callers catch
 * ApiError 401 to offer two-factor revalidation. */
async function createAndExecutePlan(
  pluginId: string,
  actionId: string,
  steps: Array<{ deviceId: string; input: Record<string, unknown> }>,
  mode: ExecutionMode,
): Promise<string> {
  const first = steps[0];
  const create = async () => {
    const plan = await api.createPlan({
      pluginId,
      intentActionId: actionId,
      inputs: first.input,
      devices: [{ deviceId: first.deviceId }],
    });
    if (steps.length > 1) {
      await api.addPlanStepsBulk(plan.id, steps.slice(1).map((s) => ({ deviceId: s.deviceId, actionId, input: s.input })));
    }
    return plan;
  };
  return runAction(create, (id) => api.executePlan(id), mode);
}

/** Groups update rows into plans by (pluginId, deviceId, applyActionId). Rows in a
 * group share one intent action but may carry DIFFERENT per-row inputs (e.g. one
 * packages.update step per package name) — those become separate steps of the same plan. */
function groupUpdatePlans(rows: UpdateRow[]): Array<{ pluginId: string; deviceId: string; actionId: string; steps: { deviceId: string; input: Record<string, unknown> }[] }> {
  const m = new Map<string, { pluginId: string; deviceId: string; actionId: string; steps: { deviceId: string; input: Record<string, unknown> }[] }>();
  for (const r of rows) {
    if (!r.applyActionId) continue; // no safe apply path → not updatable from here
    const key = `${r.pluginId}|${r.deviceId}|${r.applyActionId}`;
    let g = m.get(key);
    if (!g) {
      g = { pluginId: r.pluginId, deviceId: r.deviceId, actionId: r.applyActionId, steps: [] };
      m.set(key, g);
    }
    g.steps.push({ deviceId: r.deviceId, input: r.applyInput ?? {} });
  }
  return Array.from(m.values());
}

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

export default function Updates() {
  const queryClient = useQueryClient();
  const { mode } = useExecutionMode();
  const readOnly = mode === 'readonly';
  const canApply = can('configs:apply'); // server enforces it too; this only gates the UI

  const updatesQuery = useQuery({
    queryKey: ['updates'],
    queryFn: () => api.updates(),
    refetchInterval: 30_000,
  });

  const rows: UpdateRow[] = updatesQuery.data?.rows ?? [];
  const stack = updatesQuery.data?.stack;

  // --- Plan tracking → auto-refresh (same contract as Storage) -----------------
  const [reauth, setReauth] = useState<{ label: string; retry: () => void | Promise<void> } | null>(null);
  const [notice, setNotice] = useState<{ kind: 'ok' | 'info' | 'error'; text: string } | null>(null);
  const [pendingPlans, setPendingPlans] = useState<Record<string, { deviceIds: string[] }>>({});
  const pendingRef = useRef(pendingPlans);
  useEffect(() => { pendingRef.current = pendingPlans; }, [pendingPlans]);

  function trackPlan(planId: string, deviceIds: string[]) {
    setPendingPlans((prev) => ({ ...prev, [planId]: { deviceIds } }));
  }

  useEffect(() => {
    if (Object.keys(pendingPlans).length === 0) return;
    const timer = setInterval(async () => {
      for (const [planId, entry] of Object.entries(pendingRef.current)) {
        let p;
        try {
          p = await api.getPlan(planId);
        } catch { continue; } // transient API error — keep waiting
        if (!['succeeded', 'failed', 'cancelled'].includes(p.status)) continue;
        setPendingPlans((prev) => { const next = { ...prev }; delete next[planId]; return next; });
        try { await api.refreshDevices(entry.deviceIds); } catch { /* fall back to the 30s poll */ }
        void queryClient.invalidateQueries({ queryKey: ['updates'] });
        if (p.status !== 'succeeded') setNotice({ kind: 'error', text: `An update plan finished with errors — check the Plans page.` });
      }
    }, 3000);
    return () => clearInterval(timer);
  }, [pendingPlans, queryClient]);

  /** Fire update plans for the given rows (one plan per plugin+device+action group). */
  async function applyUpdates(selected: UpdateRow[]) {
    const groups = groupUpdatePlans(selected);
    if (groups.length === 0) return;
    try {
      for (const g of groups) {
        const planId = await createAndExecutePlan(g.pluginId, g.actionId, g.steps, mode);
        trackPlan(planId, [g.deviceId]);
      }
      setNotice({ kind: 'ok', text: `Update ${groups.length === 1 ? 'plan saved' : `${groups.length} plans saved`} — see the Plans page for progress.` });
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) {
        setReauth({ label: 'Apply updates', retry: () => applyUpdates(selected) });
      } else {
        setNotice({ kind: 'error', text: `Could not start update plan: ${(err as Error).message}` });
      }
    }
  }

  // --- "Check now" — force a fresh poll of the devices that report updates ------
  const [checking, setChecking] = useState(false);
  async function checkNow() {
    const deviceIds = Array.from(new Set(rows.map((r) => r.deviceId)));
    if (deviceIds.length === 0) return;
    setChecking(true);
    try {
      await api.refreshDevices(deviceIds);
      // The forced poll lands on the next telemetry beat — refetch shortly after.
      setTimeout(() => void updatesQuery.refetch(), 4000);
    } catch (err) {
      setNotice({ kind: 'error', text: `Refresh failed: ${(err as Error).message}` });
    } finally {
      setChecking(false);
    }
  }

  // --- Summary strip -----------------------------------------------------------
  const byKind = useMemo(() => {
    const m: Record<string, number> = {};
    for (const r of rows) m[r.kind] = (m[r.kind] ?? 0) + 1;
    return m;
  }, [rows]);
  const deviceCount = new Set(rows.map((r) => r.deviceId)).size;

  // --- Columns -----------------------------------------------------------------
  const columns: DataTableColumn<UpdateRow>[] = [
    { header: 'Kind', key: 'kind', width: 120, render: (row) => <KindBadge kind={row.kind} /> },
    { header: 'Name', key: 'name', width: 240, render: (row) => <span className="font-medium text-foreground">{row.name}</span> },
    {
      header: 'Device', key: 'deviceName', width: 260,
      exportValue: (row) => `${row.deviceName ?? '?'} (${row.managementAddress ?? '?'})`,
      render: (row) => <DeviceChip deviceName={row.deviceName} managementAddress={row.managementAddress} pluginName={row.pluginName} siteName={row.siteName} interfaces={[]} />,
    },
    {
      header: 'Version', key: 'latestVersion', width: 200,
      exportValue: (row) => `${orDash(row.currentVersion)} → ${orDash(row.latestVersion)}`,
      render: (row) => (
        <span className="font-mono text-xs">
          {row.currentVersion ? <>{row.currentVersion} <span className="text-faint">→</span> </> : null}
          <span className="text-foreground">{orDash(row.latestVersion)}</span>
        </span>
      ),
    },
    {
      header: 'Reboot', key: 'rebootRequired', width: 80, excludeFromExport: true,
      render: (row) => (row.rebootRequired ? <span className="text-warning-fg text-xs">yes</span> : <span className="text-faint">—</span>),
    },
    {
      header: 'Action', key: '__action', width: 120, excludeFromExport: true,
      render: (row) =>
        row.applyActionId && canApply && !readOnly ? (
          <button
            type="button"
            onClick={() => void applyUpdates([row])}
            className="inline-flex items-center gap-1 rounded border border-border bg-card px-2 py-1 text-xs font-medium hover:bg-muted"
          >
            <ArrowUpCircle size={13} /> Update
          </button>
        ) : row.applyActionId ? (
          <span className="text-faint text-xs">read-only</span>
        ) : (
          <span className="text-faint text-xs" title="No safe apply path — update manually on the device">manual</span>
        ),
    },
  ];

  const updatableSelected = (sel: UpdateRow[]) => sel.filter((r) => r.applyActionId);

  return (
    <Layout
      title="Updates"
      actions={
        rows.length > 0 ? (
          <button
            type="button"
            onClick={() => void checkNow()}
            disabled={checking}
            className="inline-flex items-center gap-1.5 rounded border border-border bg-card px-2.5 py-1.5 text-xs font-medium hover:bg-muted disabled:opacity-60"
          >
            {checking ? <Loader2 size={13} className="animate-spin" /> : <RefreshCw size={13} />} Check now
          </button>
        ) : undefined
      }
    >
      <div className="flex flex-col gap-4 p-6">
        {/* Stack self-update card ("UNM itself") */}
        {stack && (
          <div className="rounded-lg border border-border bg-card p-4">
            <div className="flex items-center justify-between gap-3">
              <div className="flex items-center gap-2">
                <Rocket size={16} className="text-secondary" />
                <span className="font-semibold text-foreground">UnifiedNetworkManager</span>
                <span className="rounded bg-muted px-1.5 py-0.5 font-mono text-xs">{stack.apiVersion}</span>
              </div>
              {stack.available ? (
                <span className="inline-flex items-center gap-1 rounded bg-warning/20 px-2 py-1 text-xs font-medium text-warning-fg">
                  <ArrowUpCircle size={13} /> Update available → {stack.latestApiVersion}
                </span>
              ) : stack.feedConfigured ? (
                <span className="inline-flex items-center gap-1 rounded bg-success/20 px-2 py-1 text-xs font-medium text-success-fg">
                  <CheckCircle2 size={13} /> Up to date
                </span>
              ) : (
                <span className="text-xs text-faint" title="Set the updateFeedUrl system setting to enable release checks">feed not configured</span>
              )}
            </div>
            {stack.notesUrl && stack.available && (
              <a href={stack.notesUrl} target="_blank" rel="noreferrer" className="mt-2 inline-block text-xs text-info underline">
                Release notes →
              </a>
            )}
            <p className="mt-2 text-xs text-secondary">
              {stack.plugins.length} plugin{stack.plugins.length === 1 ? '' : 's'}: {stack.plugins.map((p) => `${p.name} ${p.version}`).join(' · ')}
            </p>
          </div>
        )}

        {/* Dismissible status banner */}
        {notice && (
          <div className={`flex items-center justify-between rounded border px-3 py-2 text-sm ${notice.kind === 'error' ? 'border-danger/40 bg-danger/10 text-danger-fg' : 'border-success/40 bg-success/10 text-success-fg'}`}>
            <span>{notice.text}</span>
            <button type="button" onClick={() => setNotice(null)} className="text-xs underline">dismiss</button>
          </div>
        )}

        {/* Summary strip */}
        {rows.length > 0 && (
          <div className="flex flex-wrap items-center gap-3 text-sm text-secondary">
            <span><strong className="text-foreground">{deviceCount}</strong> device{deviceCount === 1 ? '' : 's'}</span>
            <span className="text-faint">·</span>
            {Object.entries(byKind).map(([k, n]) => (
              <span key={k} className="inline-flex items-center gap-1"><KindBadge kind={k} /> {n}</span>
            ))}
          </div>
        )}

        {/* Updates table */}
        <DataTable<UpdateRow>
          columns={columns}
          rows={rows}
          rowKey={(r) => `${r.deviceId}|${r.pluginId}|${r.kind}|${r.name}`}
          storageKey="updates"
          searchPlaceholder="Search updates…"
          emptyMessage="No available updates — all devices are up to date."
          selectable={canApply && !readOnly}
          bulkActions={[
            {
              label: 'Update selected',
              confirm: (count) => `Start update plans for ${count} selected item(s)? This runs through the plan workflow and may require 2FA.`,
              onClick: (sel) => void applyUpdates(updatableSelected(sel)),
            },
          ]}
        />

        {reauth && (
          <ReauthDialog
            contextLabel={reauth.label}
            onClose={() => setReauth(null)}
            onSuccess={async () => {
              const r = reauth;
              setReauth(null);
              if (r) await r.retry();
            }}
          />
        )}
      </div>
    </Layout>
  );
}
