import { useMemo, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { ChevronDown, ChevronRight, FlaskConical, Pencil, Plus, Trash2, Workflow } from 'lucide-react';
import { api, Automation, AutomationActionBlock, AutomationRun, AutomationTriggerBlock } from '../api/client';
import { can } from '../auth/permissions';
import { DataTable, DataTableColumn } from '../components/DataTable';
import { Layout } from '../components/Layout';
import { useTimeFormat } from '../utils/time';
import RuleBuilderDialog from './RuleBuilderDialog';

/** Short human summary of a trigger block for the list's chip column. */
function triggerSummary(t: AutomationTriggerBlock): string {
  switch (t.type) {
    case 'schedule': {
      if (t.schedule.kind === 'cron') return `cron ${t.schedule.expr}`;
      if (t.schedule.kind === 'interval') return `every ${t.schedule.everyMinutes} min`;
      return `daily at ${t.schedule.time}`;
    }
    case 'metric':
      return t.mode === 'compare' ? `${t.metricKey} ${t.comparator ?? ''} ${String(t.value ?? '')}`.trim() : `${t.metricKey} ~ /${t.pattern}/`;
    case 'log':
      return `${t.source} log ~ /${t.pattern}/`;
    case 'deviceStatus':
      return `status → ${t.toStatuses.join(', ')}`;
    case 'flow': {
      const win = t.windowSec ?? 300;
      const ip = t.ip ? ` ${t.ip}` : '';
      return `traffic${ip} ${t.comparator} ${Math.round(t.thresholdBytes / 1_048_576 * 10) / 10} MB/${win >= 3600 ? `${Math.round(win / 3600)}h` : win >= 60 ? `${Math.round(win / 60)}m` : `${win}s`}`;
    }
    case 'containerLog':
      return `logs ${t.appName} ~ /${t.pattern}/`;
    case 'updateAvailable': {
      const kinds = t.kinds?.length ? `${t.kinds.join('/')} ` : '';
      const defer = t.defer ? (t.defer.schedule.kind === 'dailyAt' ? `, deferred to ${t.defer.schedule.time}` : ', deferred') : '';
      return `update ${t.condition} (${kinds}${t.namePattern ? `~ /${t.namePattern}/` : ''})${defer}`;
    }
  }
}

/** Short human summary of an action block for the list's chip column. */
function actionSummary(a: AutomationActionBlock): string {
  switch (a.type) {
    case 'intent': {
      const what = a.resolveFromTrigger === 'update' ? 'apply update (from trigger)' : `${a.actionId ?? '?'} on ${a.devices.deviceIds?.length ?? 'scope'} device(s)`;
      return a.requireNoReboot ? `${what} (no-reboot only)` : what;
    }
    case 'webhook':
      return `${(a.method ?? 'POST').toLowerCase()} ${a.url}`;
    case 'notification':
      return `notify (${a.severity})`;
    case 'internal':
      return a.kind === 'backup' ? `backup ${a.preset ?? 'config'}` : `replication sync`;
  }
}

const TRIGGER_CHIP: Record<AutomationTriggerBlock['type'], string> = {
  schedule: 'bg-accent-indigo/60 text-accent-indigo-fg',
  metric: 'bg-status-ok/20 text-status-ok',
  log: 'bg-muted text-secondary',
  deviceStatus: 'bg-status-warning/20 text-status-warning',
  flow: 'bg-accent-sky/60 text-accent-sky-fg',
  containerLog: 'bg-accent-teal/60 text-accent-teal-fg',
  updateAvailable: 'bg-status-warning/20 text-status-warning',
};

/** Run-history panel rendered under an expanded rule row. */
function RunHistory({ runs, loading, formatDateTime }: { runs: AutomationRun[]; loading: boolean; formatDateTime: (iso: string) => string }) {
  return (
    <div className="px-4 py-2">
      <div className="mb-1 text-xs font-medium uppercase tracking-wide text-faint">Recent runs</div>
      {loading ? (
        <div className="text-sm text-faint">Loading…</div>
      ) : runs.length === 0 ? (
        <div className="text-sm text-faint">No runs yet.</div>
      ) : (
        <table className="w-full text-sm">
          <tbody>
            {runs.map((run) => (
              <tr key={run.id} className="border-t border-border/50">
                <td className="py-1 pr-3 whitespace-nowrap">{formatDateTime(run.firedAt)}</td>
                <td className="py-1 pr-3"><span className={`rounded-full px-2 py-0.5 text-xs font-medium ${TRIGGER_CHIP[run.triggerType] ?? 'bg-muted'}`}>{run.triggerType}</span></td>
                <td className="py-1 pr-3">
                  {run.status === 'succeeded' ? (
                    <span className="text-status-ok">{run.status}</span>
                  ) : run.status === 'partial' || run.status === 'skipped' ? (
                    <span className="text-status-warning" title={run.error ?? ''}>{run.status}{run.error ? ` — ${run.error}` : ''}</span>
                  ) : (
                    <span className="text-danger" title={run.error ?? ''}>{run.status}{run.error ? ` — ${run.error}` : ''}</span>
                  )}
                </td>
                {run.planIds.length > 0 && (
                  <td className="py-1">
                    {run.planIds.map((pid) => (
                      <a key={pid} href={`/plans/${pid}`} className="mr-2 text-accent-indigo hover:underline" title={`Plan ${pid}`}>plan</a>
                    ))}
                  </td>
                )}
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

/**
 * Actions & Schedules — ITTT-style automation rules. A rule has one or more
 * TRIGGER blocks (schedule / metric / log / device status) and one or more
 * ACTION blocks (intent plan, webhook, notification, internal operation). The
 * API's leader worker evaluates triggers every 15 s; each firing writes a run
 * row that is listed under the rule. Read-gated on automations:read, mutating
 * controls on automations:write.
 */
export default function Automations() {
  const { formatDateTime } = useTimeFormat();
  const queryClient = useQueryClient();
  const canWrite = can('automations:write');

  const [builderOpen, setBuilderOpen] = useState(false);
  const [editing, setEditing] = useState<Automation | null>(null);

  const automationsQuery = useQuery({ queryKey: ['automations'], queryFn: () => api.automations() });
  const rows = useMemo(() => automationsQuery.data?.automations ?? [], [automationsQuery.data]);

  // Run history is fetched lazily for the one expanded rule (chevron column).
  const [openRunsFor, setOpenRunsFor] = useState<string | null>(null);
  const runsQuery = useQuery({
    queryKey: ['automation-runs', openRunsFor],
    queryFn: () => api.automationRuns(openRunsFor!, 20),
    enabled: openRunsFor !== null,
  });

  const invalidate = () => {
    queryClient.invalidateQueries({ queryKey: ['automations'] });
    if (openRunsFor) queryClient.invalidateQueries({ queryKey: ['automation-runs', openRunsFor] });
  };

  const toggleMutation = useMutation({
    mutationFn: (id: string) => {
      const row = rows.find((r) => r.id === id);
      return api.updateAutomation(id, { enabled: !row?.enabled });
    },
    onSuccess: invalidate,
  });

  const testMutation = useMutation({
    mutationFn: (id: string) => api.testAutomation(id),
    onSuccess: (res, id) => {
      queryClient.invalidateQueries({ queryKey: ['automation-runs', id] });
      alert(res.run.status === 'succeeded' ? `Test run succeeded.` : `Test run ${res.run.status}: ${res.run.error ?? ''}`);
    },
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => api.deleteAutomation(id),
    onSuccess: invalidate,
  });

  function openCreate() { setEditing(null); setBuilderOpen(true); }
  function openEdit(row: Automation) { setEditing(row); setBuilderOpen(true); }

  const columns: DataTableColumn<Automation>[] = [
    {
      header: '',
      key: 'runsToggle',
      width: 40,
      sortable: false,
      filterable: false,
      excludeFromExport: true,
      render: (row) => (
        <button
          type="button"
          onClick={() => setOpenRunsFor(openRunsFor === row.id ? null : row.id)}
          aria-expanded={openRunsFor === row.id}
          title={openRunsFor === row.id ? 'Hide run history' : 'Show recent runs'}
          className="flex h-6 w-6 items-center justify-center rounded text-faint hover:bg-muted hover:text-secondary"
        >
          {openRunsFor === row.id ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
        </button>
      ),
    },
    {
      header: 'Name',
      key: 'name',
      width: 260,
      render: (row) => (
        <div>
          <div className="font-medium text-foreground">{row.name}</div>
          {row.description ? <div className="text-xs text-faint">{row.description}</div> : null}
        </div>
      ),
    },
    {
      header: 'Triggers',
      key: 'triggers',
      width: 300,
      render: (row) => (
        <div className="flex flex-wrap gap-1">
          {row.triggers.map((t) => (
            <span key={t.id} title={`trigger ${t.type}`} className={`rounded-full px-2 py-0.5 text-xs font-medium ${TRIGGER_CHIP[t.type]}`}>
              {triggerSummary(t)}
            </span>
          ))}
        </div>
      ),
      exportValue: (row) => row.triggers.map(triggerSummary).join('; '),
    },
    {
      header: 'Actions',
      key: 'actions',
      width: 260,
      render: (row) => (
        <div className="flex flex-wrap gap-1">
          {row.actions.map((a) => (
            <span key={a.id} title={`action ${a.type}`} className="rounded-full bg-muted px-2 py-0.5 text-xs text-secondary">
              {actionSummary(a)}
            </span>
          ))}
        </div>
      ),
      exportValue: (row) => row.actions.map(actionSummary).join('; '),
    },
    {
      header: 'Enabled',
      key: 'enabled',
      width: 90,
      sortable: false,
      filterable: false,
      render: (row) => (
        <input
          type="checkbox"
          checked={row.enabled}
          disabled={!canWrite || toggleMutation.isPending}
          onChange={() => canWrite && toggleMutation.mutate(row.id)}
          aria-label={`Toggle ${row.name}`}
        />
      ),
    },
    {
      header: 'Last fired',
      key: 'lastFiredAt',
      width: 170,
      sortAccessor: (row) => row.lastFiredAt ?? '',
      render: (row) => (row.lastFiredAt ? formatDateTime(row.lastFiredAt) : <span className="text-faint">never</span>),
    },
    {
      header: 'Next run',
      key: 'nextRun',
      width: 170,
      sortAccessor: (row) => Object.values(row.schedulePreviews ?? {}).find(Boolean) ?? '',
      render: (row) => {
        const next = Object.values(row.schedulePreviews ?? {}).find(Boolean);
        return next ? formatDateTime(next as string) : <span className="text-faint">—</span>;
      },
    },
    {
      header: 'Actions',
      key: 'rowActions',
      width: 130,
      sortable: false,
      filterable: false,
      excludeFromExport: true,
      render: (row) => (
        <div className="flex items-center gap-1">
          {canWrite && (
            <>
              <button aria-label={`Test ${row.name}`} title="Run the actions once now" disabled={testMutation.isPending} onClick={() => testMutation.mutate(row.id)} className="rounded-md p-1.5 text-faint hover:bg-accent-indigo/20 hover:text-accent-indigo">
                <FlaskConical className="h-4 w-4" />
              </button>
              <button aria-label={`Edit ${row.name}`} title="Edit rule" onClick={() => openEdit(row)} className="rounded-md p-1.5 text-faint hover:bg-accent-indigo/20 hover:text-accent-indigo">
                <Pencil className="h-4 w-4" />
              </button>
            </>
          )}
          {canWrite && (
            <button aria-label={`Delete ${row.name}`} title="Delete rule (run history is kept)" onClick={() => { if (confirm(`Delete "${row.name}"? Its run history is kept for audit.`)) deleteMutation.mutate(row.id); }} className="rounded-md p-1.5 text-faint hover:bg-danger hover:text-danger-fg">
              <Trash2 className="h-4 w-4" />
            </button>
          )}
        </div>
      ),
    },
  ];

  return (
    <Layout
      title="Actions & Schedules"
      actions={canWrite ? (
        <button type="button" onClick={openCreate} className="inline-flex items-center gap-2 rounded-md bg-primary px-3 py-1.5 text-sm font-medium text-white hover:bg-primary-hover">
          <Plus className="h-4 w-4" /> New Rule
        </button>
      ) : undefined}
    >
      {automationsQuery.isLoading ? (
        <div className="p-6 text-sm text-faint">Loading rules…</div>
      ) : automationsQuery.isError ? (
        <div className="rounded-md border border-danger/40 bg-danger/10 p-4 text-sm text-danger">{(automationsQuery.error as Error).message}</div>
      ) : (
        <>
          <p className="mb-3 flex items-center gap-2 text-xs text-faint">
            <Workflow className="h-3.5 w-3.5" />
            Rules are evaluated by the automation worker every 15 seconds. A firing runs all of a rule's actions and records one run row (expand a row for history).
          </p>
          <DataTable<Automation>
            columns={columns}
            rows={rows}
            rowKey={(r) => r.id}
            storageKey="automations-table"
            searchPlaceholder="Search rules…"
            emptyMessage="No automation rules yet — create one to schedule or react to events."
            renderRowDetail={(row) => (openRunsFor === row.id ? <RunHistory runs={runsQuery.data?.runs ?? []} loading={runsQuery.isLoading} formatDateTime={formatDateTime} /> : null)}
          />
        </>
      )}

      {builderOpen && (
        <RuleBuilderDialog
          existing={editing}
          onClose={() => setBuilderOpen(false)}
          onSaved={() => { setBuilderOpen(false); invalidate(); }}
        />
      )}
    </Layout>
  );
}
