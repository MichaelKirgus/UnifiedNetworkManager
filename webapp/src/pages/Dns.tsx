import { useEffect, useMemo, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import clsx from 'clsx';
import { Globe2, Loader2, Pencil, Plus, Trash2, X } from 'lucide-react';
import { Layout } from '../components/Layout';
import { DataTable, DataTableColumn } from '../components/DataTable';
import { DeviceChip } from '../components/DeviceChip';
import { DialogShell } from '../components/DialogShell';
import { ReauthDialog } from '../components/ReauthDialog';
import { READONLY_MESSAGE, runAction, useExecutionMode, type ExecutionMode } from '../executionMode';
import { api, ApiError, DnsRow } from '../api/client';

/** Canonical intent ids the dns-capable plugins advertise (plugin-sdk). */
const INTENT_DELETE = 'dns.delete';
const INTENT_SET = 'dns.set';

/** IPv4 or IPv6 literal (same pattern the plugins' dns.set schema enforces). */
const IP_PATTERN = /^\d{1,3}(\.\d{1,3}){3}$|^[0-9a-fA-F:.]*:[0-9a-fA-F:.]*$/;

/** Record type derived from the address shape — v4 = A record, v6 = AAAA. */
function ipType(ip: string): 'A' | 'AAAA' {
  return ip.includes(':') ? 'AAAA' : 'A';
}

// ---------------------------------------------------------------------------
// Plan helpers (same contract as the Services / Shares pages)
// ---------------------------------------------------------------------------

/** Creates a plan for ONE plugin. In Execute mode it is also executed in the
 * background; in Plan mode it is saved WITHOUT executing and only its id is
 * returned — callers surface a "saved" notice instead of tracking execution.
 * Throws on failure — callers catch ApiError 401 to offer two-factor revalidation. */
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

/** One device chip with per-address remove (X) and edit (pencil) buttons.
 * The X deletes ONLY this address on THIS device (dns.delete with name+ip
 * scope); the pencil opens the IP editor to change which addresses THIS device
 * holds for the name. */
function DnsDeviceChip({
  row,
  member,
  canDelete,
  canEdit,
  busy,
  readOnly,
  onDelete,
  onEdit,
}: {
  row: DnsRow;
  member: DnsRow['devices'][number];
  canDelete: boolean;
  canEdit: boolean;
  busy: boolean;
  readOnly: boolean;
  onDelete: (row: DnsRow, member: DnsRow['devices'][number]) => void;
  onEdit: (row: DnsRow, member: DnsRow['devices'][number]) => void;
}) {
  const disabled = busy || readOnly;
  return (
    <span className="relative inline-flex max-w-[260px] flex-col gap-0.5 rounded border border-border bg-card px-1.5 py-1 text-xs">
      <DeviceChip
        deviceName={member.deviceName}
        managementAddress={member.managementAddress}
        pluginName={member.pluginName}
        siteName={member.siteName}
        interfaces={[]}
        extraTooltip={[...member.ips, ...(member.descriptions ?? [])]}
      />
      {(canDelete || canEdit) && (
        <span className="absolute -right-1.5 -top-1.5 flex gap-0.5">
          {canEdit && (
            <button
              type="button"
              aria-label={`Edit IPs of ${row.name} on ${member.deviceName ?? 'device'}`}
              title={readOnly ? READONLY_MESSAGE : `Change which addresses ${row.name} resolves to on ${member.deviceName ?? 'this device'} only`}
              disabled={disabled}
              onClick={() => onEdit(row, member)}
              className={clsx(
                'rounded-full border border-border bg-card p-0.5 text-faint hover:bg-muted',
                readOnly && !busy ? 'cursor-not-allowed opacity-40' : '',
              )}
            >
              <Pencil className="h-3 w-3" />
            </button>
          )}
          {canDelete && (
            <button
              type="button"
              aria-label={`Remove ${row.name} (${member.ips.join(', ')}) from ${member.deviceName ?? 'device'}`}
              title={readOnly ? READONLY_MESSAGE : `Remove ${row.name} → ${member.ips.join(', ')} on ${member.deviceName ?? 'this device'} only`}
              disabled={disabled}
              onClick={() => onDelete(row, member)}
              className={clsx(
                'rounded-full border border-border bg-card p-0.5 text-faint hover:bg-muted',
                readOnly && !busy ? 'cursor-not-allowed opacity-40' : '',
              )}
            >
              <X className="h-3 w-3" />
            </button>
          )}
        </span>
      )}
    </span>
  );
}

/** Dialog to change which addresses ONE device holds for a name. The diff is
 * applied as dns.delete (removed) + dns.set (added) steps on that device only —
 * other devices keeping the same name are untouched. */
function EditDnsIpsDialog({
  row,
  member,
  busy,
  onClose,
  onSave,
}: {
  row: DnsRow;
  member: DnsRow['devices'][number];
  busy: boolean;
  onClose: () => void;
  onSave: (newIps: string[]) => void;
}) {
  const [items, setItems] = useState<string[]>(member.ips);
  const [draft, setDraft] = useState('');
  const draftError = draft !== '' && !IP_PATTERN.test(draft.trim()) ? 'Not a valid IPv4/IPv6 address' : null;

  function addDraft() {
    const ip = draft.trim();
    if (!ip || items.includes(ip)) return;
    setItems((prev) => [...prev, ip]);
    setDraft('');
  }

  const changed = items.length !== member.ips.length || items.some((ip) => !member.ips.includes(ip));

  return (
    <DialogShell
      title={`Edit IPs — ${row.name}`}
      subtitle={`${member.deviceName ?? 'device'} only (other devices are untouched)`}
      icon={<Pencil className="h-4 w-4 text-primary" />}
      onClose={onClose}
      maxWidth="max-w-md"
      footer={
        <div className="flex items-center justify-end gap-2">
          <button type="button" onClick={onClose} disabled={busy} className="rounded-md border border-border px-3 py-1.5 text-sm hover:bg-muted">Cancel</button>
          <button
            type="button"
            onClick={() => onSave(items)}
            disabled={!changed || busy}
            className={clsx('rounded-md bg-primary px-3 py-1.5 text-sm font-medium text-white hover:bg-primary-hover', (!changed || busy) && 'cursor-not-allowed opacity-40')}
          >
            {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : `Apply (${items.length} address${items.length === 1 ? '' : 'es'})`}
          </button>
        </div>
      }
    >
      <p className="mb-3 text-xs text-muted-foreground">
        Remove addresses to delete them on this device; add new ones (IPv4 or IPv6) to create records. The change is applied as a plan of dns.delete / dns.set steps.
      </p>
      <ul className="flex flex-col gap-1.5">
        {items.map((ip) => (
          <li key={ip} className="flex items-center justify-between rounded border border-border bg-card px-2 py-1 text-sm">
            <span className="font-mono">{ip}</span>
            <span className="flex items-center gap-2">
              <span className={clsx('rounded px-1.5 py-0.5 font-mono text-[10px]', ipType(ip) === 'A' ? 'bg-muted text-secondary' : 'bg-info/20 text-info-fg')}>{ipType(ip)}</span>
              {member.ips.includes(ip)
                ? <button type="button" aria-label={`Remove ${ip}`} onClick={() => setItems((prev) => prev.filter((x) => x !== ip))} className="rounded p-0.5 text-danger-fg hover:bg-muted"><X size={13} /></button>
                : <span className="text-[10px] uppercase tracking-wide text-success-fg">new</span>}
            </span>
          </li>
        ))}
      </ul>
      {items.length === 0 && <p className="mt-2 text-xs text-danger-fg">At least one address is required — add a new one below.</p>}
      <div className="mt-3 flex items-center gap-2">
        <input
          value={draft}
          onChange={(e) => setDraft(e.target.value)}
          onKeyDown={(e) => { if (e.key === 'Enter') addDraft(); }}
          placeholder="Add address, e.g. 10.0.0.5 or fd00::5"
          className={clsx('flex-1 rounded-md border bg-background px-2 py-1.5 font-mono text-sm', draftError ? 'border-danger-border' : 'border-border')}
        />
        <button type="button" onClick={addDraft} disabled={!draft.trim() || !!draftError || items.includes(draft.trim())} className={clsx('rounded-md border border-border p-1.5 text-faint hover:bg-muted', (!draft.trim() || !!draftError) && 'cursor-not-allowed opacity-40')}><Plus size={14} /></button>
      </div>
      {draftError && <p className="mt-1 text-xs text-danger-fg">{draftError}</p>}
    </DialogShell>
  );
}

export default function Dns() {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const { mode } = useExecutionMode();
  const isPlanMode = mode === 'plan';
  const isReadOnly = mode === 'readonly';

  // Rows are upserted by the API's telemetry worker (30s poll) — refresh at the
  // same cadence so the view tracks live static-DNS tables.
  const dnsQuery = useQuery({
    queryKey: ['dns'],
    queryFn: () => api.dns(),
    refetchInterval: 30_000,
  });

  // --- Action catalogs (drives delete availability GENERICALLY) ---------------
  // A chip's X / the row trash only render when that plugin advertises dns.delete.
  const catalogPluginIds = useMemo(
    () => Array.from(new Set((dnsQuery.data ?? []).flatMap((r) => r.devices.map((d) => d.pluginId)))),
    [dnsQuery.data],
  );
  const catalogsQuery = useQuery({
    queryKey: ['pluginActionCatalogs', 'dns', catalogPluginIds.join('|')],
    queryFn: async () => {
      const entries = await Promise.all(
        catalogPluginIds.map(async (pluginId) => [pluginId, (await api.pluginActions(pluginId)).actions] as const),
      );
      return Object.fromEntries(entries);
    },
    enabled: catalogPluginIds.length > 0,
  });

  /** True when the plugin's advertised action catalog contains `actionId`. */
  function hasAction(pluginId: string, actionId: string): boolean {
    const actions = catalogsQuery.data?.[pluginId];
    return Array.isArray(actions) && actions.some((a) => a.id === actionId);
  }

  // --- Action feedback + plan tracking ---------------------------------------
  const [notice, setNotice] = useState<{ kind: 'ok' | 'info' | 'error'; text: string } | null>(null);
  const [reauth, setReauth] = useState<{ label: string; retry: () => void | Promise<void> } | null>(null);
  // Per-device IP editor target (row + the device chip being edited).
  const [editing, setEditing] = useState<{ row: DnsRow; member: DnsRow['devices'][number] } | null>(null);
  // Plans kicked off in Execute mode — polled until they settle so the touched
  // devices force-refresh and the table catches up.
  const [pendingPlans, setPendingPlans] = useState<Record<string, { deviceIds: string[]; names: string[] }>>({});
  const pendingRef = useRef(pendingPlans);
  useEffect(() => { pendingRef.current = pendingPlans; }, [pendingPlans]);

  function trackPlan(planId: string, deviceIds: string[], names: string[]) {
    setPendingPlans((prev) => ({ ...prev, [planId]: { deviceIds, names } }));
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
        setPendingPlans((prev) => {
          const next = { ...prev };
          delete next[planId];
          return next;
        });
        try { await api.refreshDevices(entry.deviceIds); } catch { /* fall back to the 30s poll */ }
        void queryClient.invalidateQueries({ queryKey: ['dns'] });
        if (p.status !== 'succeeded') {
          const what = entry.names[0] ?? entry.deviceIds.join(', ');
          setNotice({ kind: 'error', text: `A plan for ${what} finished with errors — check the Plans page.` });
        }
      }
    }, 3000);
    return () => clearInterval(timer);
  }, [pendingPlans, queryClient]);

  /** Delete a whole entry (all addresses) on every device that holds it and
   * supports dns.delete — one plan per plugin. */
  async function deleteRow(row: DnsRow) {
    const attempt = async () => {
      if (isReadOnly) { setNotice({ kind: 'info', text: READONLY_MESSAGE }); return; }
      // Group the row's device members by supporting plugin.
      const byPlugin = new Map<string, string[]>();
      for (const m of row.devices) {
        if (!hasAction(m.pluginId, INTENT_DELETE)) continue;
        const list = byPlugin.get(m.pluginId) ?? [];
        list.push(m.deviceId);
        byPlugin.set(m.pluginId, list);
      }
      if (byPlugin.size === 0) {
        setNotice({ kind: 'info', text: `No device holding "${row.name}" supports dns.delete.` });
        return;
      }
      const created: string[] = [];
      for (const [pluginId, deviceIds] of byPlugin.entries()) {
        const planId = await createAndExecutePlan(
          pluginId, INTENT_DELETE,
          deviceIds.map((deviceId) => ({ deviceId, input: { name: row.name } })),
          mode,
        );
        created.push(planId);
      }
      if (isPlanMode) {
        setNotice({ kind: 'ok', text: `Delete "${row.name}": saved as ${created.length} plan(s) — not executed. Open the Plans center to run them later.` });
        return;
      }
      for (const planId of created) trackPlan(planId, row.devices.map((d) => d.deviceId), [row.name]);
    };
    try {
      await attempt();
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) setReauth({ label: `Delete DNS entry ${row.name}`, retry: attempt });
      else setNotice({ kind: 'error', text: `Delete failed: ${err instanceof Error ? err.message : String(err)}` });
    }
  }

  /** Change which addresses ONE device holds for the name — diff against the
   * current chip IPs and apply as dns.delete (removed) + dns.set (added) steps
   * on that single device. */
  async function saveMemberIps(row: DnsRow, member: DnsRow['devices'][number], newIps: string[]) {
    const attempt = async () => {
      if (isReadOnly) { setNotice({ kind: 'info', text: READONLY_MESSAGE }); return; }
      if (!hasAction(member.pluginId, INTENT_SET)) return;
      const removed = member.ips.filter((ip) => !newIps.includes(ip));
      const added = newIps.filter((ip) => !member.ips.includes(ip));
      if (removed.length === 0 && added.length === 0) { setEditing(null); return; }
      // One plan for this device: dns.delete steps (removed IPs) first, then
      // dns.set steps (added IPs). The two are separate actions — the plan is
      // created with the first step's action and the rest appended explicitly.
      const steps = [
        ...removed.map((ip) => ({ deviceId: member.deviceId, actionId: INTENT_DELETE as string, input: { name: row.name, ip } as Record<string, unknown> })),
        ...added.map((ip) => ({ deviceId: member.deviceId, actionId: INTENT_SET as string, input: { name: row.name, ip } as Record<string, unknown> })),
      ];
      const create = async () => {
        const plan = await api.createPlan({
          pluginId: member.pluginId,
          intentActionId: steps[0].actionId,
          inputs: steps[0].input,
          devices: [{ deviceId: member.deviceId }],
        });
        for (const s of steps.slice(1)) {
          await api.addPlanStepsBulk(plan.id, [{ deviceId: s.deviceId, actionId: s.actionId, input: s.input }]);
        }
        return plan;
      };
      const planId = await runAction(create, (id) => api.executePlan(id), mode);
      setEditing(null);
      if (isPlanMode) {
        setNotice({ kind: 'ok', text: `IP change for ${row.name} on ${member.deviceName ?? 'device'}: saved as a plan — not executed.` });
        return;
      }
      trackPlan(planId, [member.deviceId], [`${row.name} @ ${member.deviceName ?? member.deviceId}`]);
    };
    try {
      await attempt();
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) setReauth({ label: `Edit IPs of DNS entry ${row.name}`, retry: attempt });
      else { setNotice({ kind: 'error', text: `IP change failed: ${err instanceof Error ? err.message : String(err)}` }); setEditing(null); }
    }
  }

  /** Delete ONE address of the name on ONE device (chip-level X). */
  async function deleteChip(row: DnsRow, member: DnsRow['devices'][number]) {
    const attempt = async () => {
      if (isReadOnly) { setNotice({ kind: 'info', text: READONLY_MESSAGE }); return; }
      if (!hasAction(member.pluginId, INTENT_DELETE)) return;
      // ip-scoped delete — one step per address of this name on this device
      // (dns.delete takes a single optional `ip`; a dual-stack chip = 2 steps).
      const planId = await createAndExecutePlan(
        member.pluginId, INTENT_DELETE,
        member.ips.map((ip) => ({ deviceId: member.deviceId, input: { name: row.name, ip } })),
        mode,
      );
      if (isPlanMode) {
        setNotice({ kind: 'ok', text: `Delete ${row.name} → ${member.ips.join(', ')} on ${member.deviceName ?? 'device'}: saved as a plan — not executed.` });
        return;
      }
      trackPlan(planId, [member.deviceId], [`${row.name} @ ${member.deviceName ?? member.deviceId}`]);
    };
    try {
      await attempt();
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) setReauth({ label: `Delete DNS entry ${row.name}`, retry: attempt });
      else setNotice({ kind: 'error', text: `Delete failed: ${err instanceof Error ? err.message : String(err)}` });
    }
  }

  const columns: DataTableColumn<DnsRow>[] = [
    {
      header: 'Name',
      key: 'name',
      width: 240,
      render: (row) => (
        <div className="flex flex-col gap-0.5">
          <span className="font-mono text-sm font-medium text-foreground">{row.name}</span>
          {(row.descriptions ?? []).length > 0 && (
            <span className="line-clamp-2 max-w-[240px] text-xs text-muted-foreground" title={row.descriptions!.join('\n')}>{row.descriptions!.join(' · ')}</span>
          )}
        </div>
      ),
    },
    {
      // Record type derived from the address shape: v4 = A, v6 = AAAA.
      header: 'Type',
      key: 'type',
      width: 110,
      exportValue: (row) => [...new Set(row.ips.map(ipType))].join(' '),
      render: (row) => (
        <span className="flex flex-wrap gap-1">
          {[...new Set(row.ips.map(ipType))].map((t) => (
            <span key={t} className={clsx('rounded px-1.5 py-0.5 font-mono text-xs', t === 'A' ? 'bg-muted text-secondary' : 'bg-info/20 text-info-fg')}>{t}</span>
          ))}
        </span>
      ),
    },
    {
      // All addresses of this name anywhere — IPv4 first. Drift across devices
      // shows up as extra chips here that no single device holds alone.
      header: 'IPs',
      key: 'ips',
      width: 260,
      exportValue: (row) => row.ips.join(' '),
      render: (row) => (
        <span className="flex flex-wrap gap-1">
          {row.ips.map((ip) => (
            <span key={ip} className="rounded bg-muted px-1.5 py-0.5 font-mono text-xs text-secondary">{ip}</span>
          ))}
        </span>
      ),
    },
    {
      // Every device+plugin that holds the entry — one chip each, with a
      // per-chip remove (X) when that plugin supports dns.delete.
      header: 'Devices',
      key: 'devices',
      width: 380,
      exportValue: (row) => row.devices.map((d) => `${d.deviceName ?? '?'} [${d.ips.join(',')}]`).join('; '),
      render: (row) => (
        <div className="flex flex-wrap gap-1.5">
          {row.devices.map((m) => (
            <DnsDeviceChip
              key={`${m.deviceId}|${m.pluginId}`}
              row={row}
              member={m}
              canDelete={hasAction(m.pluginId, INTENT_DELETE)}
              canEdit={hasAction(m.pluginId, INTENT_SET)}
              busy={Object.keys(pendingPlans).length > 0}
              readOnly={isReadOnly}
              onDelete={deleteChip}
              onEdit={(r, m2) => setEditing({ row: r, member: m2 })}
            />
          ))}
        </div>
      ),
    },
    {
      // Whole-entry delete — fans out to every supporting device of the row.
      header: 'Actions',
      key: 'actions',
      width: 90,
      render: (row) => {
        const anyDelete = row.devices.some((m) => hasAction(m.pluginId, INTENT_DELETE));
        if (!anyDelete) return <span className="text-faint">—</span>;
        return (
          <button
            type="button"
            aria-label={`Delete ${row.name} on all devices`}
            title={isReadOnly ? READONLY_MESSAGE : `Remove "${row.name}" from every device that holds it (${row.devices.length})`}
            disabled={isReadOnly || Object.keys(pendingPlans).length > 0}
            onClick={() => {
              if (window.confirm(`Delete DNS entry "${row.name}" on ${row.devices.length} device(s)?\n\nThis removes the static host record from each device's DNS configuration.`)) {
                void deleteRow(row);
              }
            }}
            className={clsx(
              'rounded-md p-1.5 text-danger-fg hover:bg-muted',
              (isReadOnly || Object.keys(pendingPlans).length > 0) && 'cursor-not-allowed opacity-30',
            )}
          >
            <Trash2 size={14} />
          </button>
        );
      },
    },
  ];

  return (
    <Layout
      title="DNS"
      actions={
        <>
          <button
            type="button"
            onClick={() => navigate('/dns/rollout', { state: { from: '/dns' } })}
            className="inline-flex items-center gap-2 rounded-md bg-primary px-3 py-1.5 text-sm font-medium text-white hover:bg-primary-hover"
          >
            <Globe2 className="h-4 w-4" /> Roll out DNS entry
          </button>
        </>
      }
    >
      {dnsQuery.isLoading && <p className="text-sm text-muted-foreground">Loading DNS entries...</p>}
      {dnsQuery.isError && (
        <p className="text-sm text-danger-fg">Failed to load DNS entries: {(dnsQuery.error as Error).message}</p>
      )}

      {notice && (
        <div
          className={clsx(
            'mb-3 rounded-md border px-3 py-2 text-sm',
            notice.kind === 'ok' && 'border-success-border bg-success text-success-fg',
            notice.kind === 'info' && 'border-info-border bg-info text-info-fg',
            notice.kind === 'error' && 'border-danger-border bg-danger text-danger-fg',
          )}
        >
          {notice.text}
        </div>
      )}

      {Object.keys(pendingPlans).length > 0 && (
        <div className="mb-3 flex items-center gap-2 rounded-md border border-info-border bg-info px-3 py-2 text-sm text-info-fg">
          <Loader2 className="h-4 w-4 animate-spin" />
          Waiting for plan execution to settle — the table refreshes automatically.
        </div>
      )}

      {dnsQuery.data && (
        <DataTable
          columns={columns}
          rows={dnsQuery.data}
          rowKey={(row) => row.name}
          storageKey="dns"
          autoRefresh={{ intervalMs: 30_000, queries: [dnsQuery] }}
          searchPlaceholder="Search DNS entries…"
          emptyMessage="No static DNS entries collected yet — assign a dns-capable plugin (OPNsense, OpenWrt, RouterOS or LCOS) to a device and wait for the next poll."
        />
      )}

      {/* Per-device IP editor. */}
      {editing && (
        <EditDnsIpsDialog
          row={editing.row}
          member={editing.member}
          busy={Object.keys(pendingPlans).length > 0}
          onClose={() => setEditing(null)}
          onSave={(newIps) => void saveMemberIps(editing.row, editing.member, newIps)}
        />
      )}

      {/* In-session 2FA revalidation (plan create/execute returned 401). */}
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
    </Layout>
  );
}
