import { useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import clsx from 'clsx';
import { CheckCircle2, ChevronRight, EyeOff, Loader2, Mail as MailIcon, Pencil, Plus, Trash2, X } from 'lucide-react';
import { Layout } from '../components/Layout';
import { DataTable, DataTableColumn } from '../components/DataTable';
import { DeviceChip } from '../components/DeviceChip';
import { formatBytes } from '../components/formatMetric';
import { ReauthDialog } from '../components/ReauthDialog';
import { READONLY_MESSAGE, runAction, useExecutionMode, type ExecutionMode } from '../executionMode';
import { api, ApiError, MailAliasRow, MailDomainRow, MailMailboxRow } from '../api/client';

// ---------------------------------------------------------------------------
// Action-id mapping (GENERIC contract — a button only renders when the row's
// plugin advertises the matching id in its catalog).
// ---------------------------------------------------------------------------

const ACTION_IDS = {
  domain: { create: 'mail.domain.create', update: 'mail.domain.update', delete: 'mail.domain.delete' },
  mailbox: { create: 'mail.mailbox.create', update: 'mail.mailbox.update', delete: 'mail.mailbox.delete' },
  alias: { create: 'mail.alias.create', update: 'mail.alias.update', delete: 'mail.alias.delete' },
} as const;

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

/** Groups rows by (pluginId, deviceId), collecting a per-row value. */
function groupByDevice<T>(rows: T[], keyOf: (r: T) => { pluginId: string; deviceId: string }, valOf: (r: T) => unknown): Map<string, { pluginId: string; deviceId: string; values: unknown[] }> {
  const m = new Map<string, { pluginId: string; deviceId: string; values: unknown[] }>();
  for (const r of rows) {
    const k = keyOf(r);
    const entry = m.get(`${k.pluginId}|${k.deviceId}`) ?? { pluginId: k.pluginId, deviceId: k.deviceId, values: [] };
    entry.values.push(valOf(r));
    m.set(`${k.pluginId}|${k.deviceId}`, entry);
  }
  return m;
}

// ---------------------------------------------------------------------------
// Small display helpers
// ---------------------------------------------------------------------------

/** "—" for empty/unknown values (the API stores '' / null for unknown fields). */
function orDash(v?: string | null): string {
  return v && v.trim() !== '' ? v : '—';
}

/** Quota cell: used/total with a percent, or just the total. Null = unlimited. */
function quotaCell(usedBytes?: number | null, totalBytes?: number | null): ReactNode {
  if (totalBytes === null || totalBytes === undefined) return <span className="text-faint">unlimited</span>;
  const used = usedBytes ?? 0;
  const pct = totalBytes > 0 ? Math.min(100, Math.round((used / totalBytes) * 100)) : 0;
  return (
    <div className="flex flex-col gap-0.5">
      <span className="font-mono text-xs">{formatBytes(used)} / {formatBytes(totalBytes)}</span>
      <div className="h-1 w-full max-w-[120px] overflow-hidden rounded bg-muted">
        <div
          className={clsx('h-full', pct >= 90 ? 'bg-danger-fg' : pct >= 75 ? 'bg-warning' : 'bg-success')}
          style={{ width: `${pct}%` }}
        />
      </div>
    </div>
  );
}

/** Active/inactive pill (mail objects are binary — no StatusBadge states). */
function ActivePill({ active }: { active: boolean }) {
  return (
    <span className={clsx(
      'inline-flex rounded px-1.5 py-0.5 text-xs font-medium',
      active ? 'bg-success text-success-fg' : 'bg-muted text-secondary',
    )}>
      {active ? 'active' : 'inactive'}
    </span>
  );
}

// ---------------------------------------------------------------------------
// Form state + dialogs (2FA-gated via the plan workflow, same as Shares)
// ---------------------------------------------------------------------------

/** One distinct mail server (device + plugin instance) present in the data. */
interface MailDevice {
  deviceId: string;
  pluginId: string;
  deviceName?: string | null;
}

type Tab = 'domains' | 'mailboxes' | 'aliases';

type DialogState =
  | { kind: 'domain'; mode: 'create' | 'edit'; row?: MailDomainRow }
  | { kind: 'mailbox'; mode: 'create' | 'edit'; row?: MailMailboxRow; presetDevice?: MailDevice; presetDomain?: string }
  | { kind: 'alias'; mode: 'create' | 'edit'; row?: MailAliasRow; presetDevice?: MailDevice };

interface DomainForm {
  deviceId: string;
  pluginId: string;
  domain: string;
  description: string;
  quotaMB: string;
  maxQuotaPerMailboxMB: string;
  defaultQuotaMB: string;
  mailboxLimit: string;
  aliasLimit: string;
  backupMx: boolean;
  active: boolean;
}

interface MailboxForm {
  deviceId: string;
  pluginId: string;
  domain: string;
  localPart: string;
  name: string;
  password: string; // create: required initial password; edit: optional new password
  quotaMB: string;
  forcePwUpdate: boolean;
  forceTfa: boolean;
  active: boolean;
}

interface AliasForm {
  deviceId: string;
  pluginId: string;
  address: string;
  goto: string;
  sogoVisible: boolean;
  active: boolean;
}

/** Parses a form numeric field — '' = omit (undefined), invalid = NaN. */
function parseNum(s: string): number | undefined {
  const t = s.trim();
  if (t === '') return undefined;
  const n = Number(t);
  return Number.isFinite(n) ? n : NaN;
}

/** Shared dialog shell — header, body slot, footer buttons. */
function DialogShell({
  title, subtitle, onClose, children, footer,
}: {
  title: string;
  subtitle?: ReactNode;
  onClose: () => void;
  children: ReactNode;
  footer: ReactNode;
}) {
  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto bg-primary/40 p-6" onClick={onClose}>
      <div className="mt-8 w-full max-w-md rounded-md border border-border bg-card shadow-xl" onClick={(e) => e.stopPropagation()}>
        <header className="flex items-center justify-between border-b border-border px-4 py-3">
          <div>
            <h2 className="text-base font-semibold text-foreground">{title}</h2>
            {subtitle && <p className="mt-0.5 text-xs text-muted-foreground">{subtitle}</p>}
          </div>
          <button type="button" aria-label="Close dialog" onClick={onClose} className="rounded p-1 text-faint hover:bg-muted">
            <X size={16} />
          </button>
        </header>
        {children}
        {footer}
      </div>
    </div>
  );
}

/** "Mail server" select — only rendered when more than one mail device exists. */
function DeviceSelect({ devices, value, onChange }: { devices: MailDevice[]; value: string; onChange: (deviceId: string) => void }) {
  if (devices.length <= 1) return null;
  const current = devices.find((d) => d.deviceId === value);
  return (
    <div>
      <label className="mb-1 block text-xs font-medium text-secondary">Mail server</label>
      <select
        value={value}
        onChange={(e) => onChange(e.target.value)}
        className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm text-foreground"
      >
        {devices.map((d) => (
          <option key={`${d.deviceId}|${d.pluginId}`} value={d.deviceId}>{d.deviceName ?? d.deviceId}</option>
        ))}
      </select>
      {current && <p className="mt-1 text-[11px] text-faint">{current.deviceName ?? current.deviceId}</p>}
    </div>
  );
}

function Field({ label, hint, children }: { label: string; hint?: string; children: ReactNode }) {
  return (
    <div>
      <label className="mb-1 block text-xs font-medium text-secondary">{label}</label>
      {children}
      {hint && <p className="mt-1 text-[11px] text-faint">{hint}</p>}
    </div>
  );
}

const inputCls = 'w-full rounded-md border border-border bg-background px-3 py-2 font-mono text-sm text-foreground placeholder:text-faint';
const inputClsPlain = 'w-full rounded-md border border-border bg-background px-3 py-2 text-sm text-foreground placeholder:text-faint';

// --- Domain dialog -----------------------------------------------------------

function DomainDialog({ state, devices, hasAction, onClose }: { state: Extract<DialogState, { kind: 'domain' }>; devices: MailDevice[]; hasAction: (pluginId: string, actionId: string) => boolean; onClose: () => void }) {
  const { mode: execMode } = useExecutionMode();
  const isPlanMode = execMode === 'plan';
  const isReadOnly = execMode === 'readonly';
  const row = state.row;

  const [form, setForm] = useState<DomainForm>(() => ({
    deviceId: row?.deviceId ?? devices[0]?.deviceId ?? '',
    pluginId: row?.pluginId ?? devices.find((d) => d.deviceId === (row?.deviceId ?? devices[0]?.deviceId))?.pluginId ?? '',
    domain: row?.domain ?? '',
    description: row?.description ?? '',
    quotaMB: row?.quotaBytes != null ? String(Math.round(row.quotaBytes / 1048576)) : '',
    maxQuotaPerMailboxMB: row?.maxQuotaPerMailboxBytes != null ? String(Math.round(row.maxQuotaPerMailboxBytes / 1048576)) : '',
    defaultQuotaMB: row?.defaultQuotaBytes != null ? String(Math.round(row.defaultQuotaBytes / 1048576)) : '',
    mailboxLimit: '',
    aliasLimit: '',
    backupMx: row?.backupMx ?? false,
    active: row?.active ?? true,
  }));

  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [reauth, setReauth] = useState(false);
  const [saved, setSaved] = useState(false);

  function selectDevice(deviceId: string) {
    const d = devices.find((x) => x.deviceId === deviceId);
    if (!d) return;
    setForm((f) => ({ ...f, deviceId: d.deviceId, pluginId: d.pluginId }));
  }

  async function submit() {
    if (form.domain.trim() === '') { setError('A domain name is required.'); return; }
    const quotaMB = parseNum(form.quotaMB);
    if (quotaMB !== undefined && Number.isNaN(quotaMB)) { setError('"Total quota" must be a number (MB).'); return; }
    setSaving(true);
    setError(null);

    const actionId = state.mode === 'edit' ? ACTION_IDS.domain.update : ACTION_IDS.domain.create;
    if (!hasAction(form.pluginId, actionId)) { setSaving(false); setError('This plugin does not advertise the required mail action.'); return; }

    const input: Record<string, unknown> = { domain: form.domain.trim() };
    if (state.mode === 'edit') {
      input['active'] = form.active;
      input['description'] = form.description.trim(); // '' clears it on edit
    } else if (form.description.trim() !== '') {
      input['description'] = form.description.trim();
    }
    const quota = parseNum(form.quotaMB);
    if (quota !== undefined && !Number.isNaN(quota)) input['quotaMB'] = quota;
    const maxQ = parseNum(form.maxQuotaPerMailboxMB);
    if (maxQ !== undefined && !Number.isNaN(maxQ)) input['maxQuotaPerMailboxMB'] = maxQ;
    const defQ = parseNum(form.defaultQuotaMB);
    if (defQ !== undefined && !Number.isNaN(defQ)) input['defaultQuotaMB'] = defQ;
    const mLimit = parseNum(form.mailboxLimit);
    if (mLimit !== undefined && !Number.isNaN(mLimit)) input['mailboxLimit'] = Math.round(mLimit);
    const aLimit = parseNum(form.aliasLimit);
    if (aLimit !== undefined && !Number.isNaN(aLimit)) input['aliasLimit'] = Math.round(aLimit);
    if (state.mode === 'create' || form.backupMx) input['backupMx'] = form.backupMx;

    const attempt = async () => {
      await createAndExecutePlan(form.pluginId, actionId, [{ deviceId: form.deviceId, input }], execMode);
      if (isPlanMode) { setSaved(true); return; }
      onClose();
    };
    try {
      await attempt();
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) setReauth(true);
      else setError(err instanceof Error ? err.message : String(err));
      setSaving(false);
    }
  }

  const title = state.mode === 'edit' ? `Edit domain ${row?.domain}` : 'New mail domain';

  if (saved) {
    return (
      <DialogShell title={title} onClose={onClose} footer={
        <footer className="flex items-center justify-end gap-2 border-t border-border px-4 py-3">
          <button type="button" onClick={onClose} className="rounded-md bg-primary px-3 py-1.5 text-xs font-medium text-primary-fg hover:opacity-90">Close</button>
        </footer>
      }>
        <div className="space-y-3 px-4 py-4">
          <div className="flex items-start gap-2 rounded-md border border-success-border bg-success px-3 py-2 text-xs text-success-fg">
            <CheckCircle2 size={14} className="mt-0.5 shrink-0" />
            Domain change saved as a plan — it was NOT executed. Open the Plans center to run it later (or schedule it).
          </div>
        </div>
      </DialogShell>
    );
  }

  return (
    <DialogShell
      title={title}
      subtitle={row ? `Applies on ${row.deviceName ?? row.deviceId}.` : undefined}
      onClose={onClose}
      footer={
        <footer className="flex items-center justify-end gap-2 border-t border-border px-4 py-3">
          <button type="button" onClick={onClose} className="rounded-md px-3 py-1.5 text-xs font-medium text-secondary hover:bg-muted">Cancel</button>
          <button
            type="button"
            disabled={saving || isReadOnly}
            title={isReadOnly ? 'Read-only mode — switch to Plan or Execute to make changes' : undefined}
            onClick={() => void submit()}
            className="inline-flex items-center gap-1.5 rounded-md bg-primary px-3 py-1.5 text-xs font-medium text-primary-fg hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-50"
          >
            {saving && <Loader2 size={12} className="animate-spin" />}
            {isPlanMode ? 'Save as plan' : state.mode === 'edit' ? 'Save changes' : 'Create domain'}
          </button>
        </footer>
      }
    >
      <div className="space-y-4 px-4 py-4">
        {isReadOnly && (
          <div className="flex items-start gap-2 rounded border border-warning-border bg-warning px-3 py-2 text-xs text-warning-fg">
            <EyeOff size={14} className="mt-0.5 shrink-0" />
            Read-only mode is active — this change cannot be saved or executed. Switch to Plan or Execute in the top bar.
          </div>
        )}
        {error && !reauth && (
          <div className="rounded border border-danger-border bg-danger px-3 py-2 text-xs text-danger-fg">{error}</div>
        )}

        {state.mode === 'create' && devices.length > 1 && (
          <DeviceSelect devices={devices} value={form.deviceId} onChange={selectDevice} />
        )}

        <Field label="Domain">
          <input
            type="text"
            value={form.domain}
            disabled={state.mode === 'edit'}
            onChange={(e) => setForm((f) => ({ ...f, domain: e.target.value }))}
            placeholder="mail.example.org"
            className={clsx(inputCls, state.mode === 'edit' && 'opacity-60')}
          />
        </Field>

        <Field label="Description">
          <input
            type="text"
            value={form.description}
            onChange={(e) => setForm((f) => ({ ...f, description: e.target.value }))}
            placeholder="Optional description"
            className={inputClsPlain}
          />
        </Field>

        <div className="grid grid-cols-3 gap-3">
          <Field label="Total quota (MB)" hint="0 = unlimited">
            <input type="text" inputMode="numeric" value={form.quotaMB} onChange={(e) => setForm((f) => ({ ...f, quotaMB: e.target.value }))} placeholder="10240" className={inputCls} />
          </Field>
          <Field label="Max per mailbox (MB)">
            <input type="text" inputMode="numeric" value={form.maxQuotaPerMailboxMB} onChange={(e) => setForm((f) => ({ ...f, maxQuotaPerMailboxMB: e.target.value }))} placeholder="2048" className={inputCls} />
          </Field>
          <Field label="Default per mailbox (MB)">
            <input type="text" inputMode="numeric" value={form.defaultQuotaMB} onChange={(e) => setForm((f) => ({ ...f, defaultQuotaMB: e.target.value }))} placeholder="1024" className={inputCls} />
          </Field>
        </div>

        <div className="grid grid-cols-2 gap-3">
          <Field label="Max mailboxes">
            <input type="text" inputMode="numeric" value={form.mailboxLimit} onChange={(e) => setForm((f) => ({ ...f, mailboxLimit: e.target.value }))} placeholder="50" className={inputCls} />
          </Field>
          <Field label="Max aliases">
            <input type="text" inputMode="numeric" value={form.aliasLimit} onChange={(e) => setForm((f) => ({ ...f, aliasLimit: e.target.value }))} placeholder="50" className={inputCls} />
          </Field>
        </div>

        {state.mode === 'edit' && (
          <label className="flex items-center gap-2 text-xs text-secondary">
            <input type="checkbox" checked={form.active} onChange={(e) => setForm((f) => ({ ...f, active: e.target.checked }))} />
            Domain is active (accepts mail)
          </label>
        )}

        <label className="flex items-center gap-2 text-xs text-secondary">
          <input type="checkbox" checked={form.backupMx} onChange={(e) => setForm((f) => ({ ...f, backupMx: e.target.checked }))} />
          Backup MX (relay domain — accepts mail without local delivery)
        </label>
      </div>

      {reauth && (
        <ReauthDialog
          contextLabel={title}
          onClose={() => setReauth(false)}
          onSuccess={async () => {
            setReauth(false);
            try { await submit(); } catch { /* dialog stays open */ }
          }}
        />
      )}
    </DialogShell>
  );
}

// --- Mailbox dialog -----------------------------------------------------------

function MailboxDialog({ state, devices, domains, hasAction, onClose }: {
  state: Extract<DialogState, { kind: 'mailbox' }>;
  devices: MailDevice[];
  domains: MailDomainRow[];
  hasAction: (pluginId: string, actionId: string) => boolean;
  onClose: () => void;
}) {
  const { mode: execMode } = useExecutionMode();
  const isPlanMode = execMode === 'plan';
  const isReadOnly = execMode === 'readonly';
  const row = state.row;

  const [form, setForm] = useState<MailboxForm>(() => ({
    deviceId: row?.deviceId ?? state.presetDevice?.deviceId ?? devices[0]?.deviceId ?? '',
    pluginId: row?.pluginId ?? state.presetDevice?.pluginId ?? devices.find((d) => d.deviceId === (row?.deviceId ?? state.presetDevice?.deviceId))?.pluginId ?? '',
    domain: row?.domain ?? state.presetDomain ?? domains[0]?.domain ?? '',
    localPart: row?.localPart ?? '',
    name: row?.name ?? '',
    password: '',
    quotaMB: row?.quotaBytes != null ? String(Math.round(row.quotaBytes / 1048576)) : '',
    forcePwUpdate: row?.forcePwUpdate ?? false,
    forceTfa: row?.forceTfa ?? false,
    active: row?.active ?? true,
  }));

  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [reauth, setReauth] = useState(false);
  const [saved, setSaved] = useState(false);

  // Domain options for the selected device (fall back to all when none match).
  const domainOptions = useMemo(() => {
    const scoped = domains.filter((d) => d.deviceId === form.deviceId);
    return scoped.length > 0 ? scoped : domains;
  }, [domains, form.deviceId]);

  function selectDevice(deviceId: string) {
    const d = devices.find((x) => x.deviceId === deviceId);
    if (!d) return;
    setForm((f) => ({ ...f, deviceId: d.deviceId, pluginId: d.pluginId }));
  }

  async function submit() {
    if (form.localPart.trim() === '') { setError('A local part is required.'); return; }
    if (form.domain.trim() === '') { setError('A domain is required.'); return; }
    const quotaMB = parseNum(form.quotaMB);
    if (quotaMB !== undefined && Number.isNaN(quotaMB)) { setError('"Quota" must be a number (MB).'); return; }

    const username = `${form.localPart.trim()}@${form.domain.trim()}`;
    const actionId = state.mode === 'edit' ? ACTION_IDS.mailbox.update : ACTION_IDS.mailbox.create;
    if (!hasAction(form.pluginId, actionId)) { setSaving(false); setError('This plugin does not advertise the required mail action.'); return; }

    const input: Record<string, unknown> = {};
    if (state.mode === 'create') {
      input['localPart'] = form.localPart.trim();
      input['domain'] = form.domain.trim();
      if (form.password.length < 8) { setError('The initial password must be at least 8 characters.'); return; }
      input['password'] = form.password;
    } else {
      input['username'] = username;
      input['active'] = form.active;
      if (form.password !== '') {
        if (form.password.length < 8) { setError('The new password must be at least 8 characters.'); return; }
        input['newPassword'] = form.password; // sent as password+password2 by the plugin
      }
    }
    const name = form.name.trim();
    if (name !== '') input['name'] = name;
    if (quotaMB !== undefined && !Number.isNaN(quotaMB)) input['quotaMB'] = quotaMB;
    if (state.mode === 'edit' || form.forcePwUpdate) input['forcePwUpdate'] = form.forcePwUpdate;
    if (state.mode === 'edit' || form.forceTfa) input['forceTfa'] = form.forceTfa;

    setSaving(true);
    setError(null);
    const attempt = async () => {
      await createAndExecutePlan(form.pluginId, actionId, [{ deviceId: form.deviceId, input }], execMode);
      if (isPlanMode) { setSaved(true); return; }
      onClose();
    };
    try {
      await attempt();
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) setReauth(true);
      else setError(err instanceof Error ? err.message : String(err));
      setSaving(false);
    }
  }

  const title = state.mode === 'edit' ? `Edit mailbox ${row?.username}` : 'New mailbox';

  if (saved) {
    return (
      <DialogShell title={title} onClose={onClose} footer={
        <footer className="flex items-center justify-end gap-2 border-t border-border px-4 py-3">
          <button type="button" onClick={onClose} className="rounded-md bg-primary px-3 py-1.5 text-xs font-medium text-primary-fg hover:opacity-90">Close</button>
        </footer>
      }>
        <div className="space-y-3 px-4 py-4">
          <div className="flex items-start gap-2 rounded-md border border-success-border bg-success px-3 py-2 text-xs text-success-fg">
            <CheckCircle2 size={14} className="mt-0.5 shrink-0" />
            Mailbox change saved as a plan — it was NOT executed. Open the Plans center to run it later (or schedule it).
          </div>
        </div>
      </DialogShell>
    );
  }

  return (
    <DialogShell
      title={title}
      subtitle={row ? `Applies on ${row.deviceName ?? row.deviceId}.` : undefined}
      onClose={onClose}
      footer={
        <footer className="flex items-center justify-end gap-2 border-t border-border px-4 py-3">
          <button type="button" onClick={onClose} className="rounded-md px-3 py-1.5 text-xs font-medium text-secondary hover:bg-muted">Cancel</button>
          <button
            type="button"
            disabled={saving || isReadOnly}
            title={isReadOnly ? 'Read-only mode — switch to Plan or Execute to make changes' : undefined}
            onClick={() => void submit()}
            className="inline-flex items-center gap-1.5 rounded-md bg-primary px-3 py-1.5 text-xs font-medium text-primary-fg hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-50"
          >
            {saving && <Loader2 size={12} className="animate-spin" />}
            {isPlanMode ? 'Save as plan' : state.mode === 'edit' ? 'Save changes' : 'Create mailbox'}
          </button>
        </footer>
      }
    >
      <div className="space-y-4 px-4 py-4">
        {isReadOnly && (
          <div className="flex items-start gap-2 rounded border border-warning-border bg-warning px-3 py-2 text-xs text-warning-fg">
            <EyeOff size={14} className="mt-0.5 shrink-0" />
            Read-only mode is active — this change cannot be saved or executed. Switch to Plan or Execute in the top bar.
          </div>
        )}
        {error && !reauth && (
          <div className="rounded border border-danger-border bg-danger px-3 py-2 text-xs text-danger-fg">{error}</div>
        )}

        {state.mode === 'create' && devices.length > 1 && (
          <DeviceSelect devices={devices} value={form.deviceId} onChange={selectDevice} />
        )}

        <Field label="Address">
          <div className="flex items-center gap-1.5">
            <input
              type="text"
              value={form.localPart}
              disabled={state.mode === 'edit'}
              onChange={(e) => setForm((f) => ({ ...f, localPart: e.target.value }))}
              placeholder="info"
              className={clsx(inputCls, state.mode === 'edit' && 'opacity-60')}
            />
            <span className="text-sm text-faint">@</span>
            {state.mode === 'create' ? (
              <select
                value={form.domain}
                onChange={(e) => setForm((f) => ({ ...f, domain: e.target.value }))}
                className="w-full rounded-md border border-border bg-background px-2 py-2 font-mono text-sm text-foreground"
              >
                {domainOptions.length === 0 && <option value="">no domains known</option>}
                {domainOptions.map((d) => (
                  <option key={d.domain} value={d.domain}>{d.domain}</option>
                ))}
              </select>
            ) : (
              <span className="font-mono text-sm text-foreground">{form.domain}</span>
            )}
          </div>
        </Field>

        <Field label="Full name">
          <input type="text" value={form.name} onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))} placeholder="Optional display name" className={inputClsPlain} />
        </Field>

        <Field
          label={state.mode === 'create' ? 'Password' : 'New password (optional)'}
          hint={state.mode === 'create' ? 'Minimum 8 characters.' : 'Leave empty to keep the current password.'}
        >
          <input
            type="password"
            value={form.password}
            onChange={(e) => setForm((f) => ({ ...f, password: e.target.value }))}
            placeholder={state.mode === 'create' ? '••••••••' : 'unchanged'}
            className={inputCls}
          />
        </Field>

        <div className="grid grid-cols-2 gap-3">
          <Field label="Quota (MB)" hint="0 = unlimited">
            <input type="text" inputMode="numeric" value={form.quotaMB} onChange={(e) => setForm((f) => ({ ...f, quotaMB: e.target.value }))} placeholder="2048" className={inputCls} />
          </Field>
        </div>

        <label className="flex items-center gap-2 text-xs text-secondary">
          <input type="checkbox" checked={form.forcePwUpdate} onChange={(e) => setForm((f) => ({ ...f, forcePwUpdate: e.target.checked }))} />
          Force password change on first login
        </label>
        <label className="flex items-center gap-2 text-xs text-secondary">
          <input type="checkbox" checked={form.forceTfa} onChange={(e) => setForm((f) => ({ ...f, forceTfa: e.target.checked }))} />
          Force 2FA enrollment at next login
        </label>

        {state.mode === 'edit' && (
          <label className="flex items-center gap-2 text-xs text-secondary">
            <input type="checkbox" checked={form.active} onChange={(e) => setForm((f) => ({ ...f, active: e.target.checked }))} />
            Mailbox is active (accepts mail)
          </label>
        )}
      </div>

      {reauth && (
        <ReauthDialog
          contextLabel={title}
          onClose={() => setReauth(false)}
          onSuccess={async () => {
            setReauth(false);
            try { await submit(); } catch { /* dialog stays open */ }
          }}
        />
      )}
    </DialogShell>
  );
}

// --- Alias dialog -----------------------------------------------------------

function AliasDialog({ state, devices, hasAction, onClose }: { state: Extract<DialogState, { kind: 'alias' }>; devices: MailDevice[]; hasAction: (pluginId: string, actionId: string) => boolean; onClose: () => void }) {
  const { mode: execMode } = useExecutionMode();
  const isPlanMode = execMode === 'plan';
  const isReadOnly = execMode === 'readonly';
  const row = state.row;

  const [form, setForm] = useState<AliasForm>(() => ({
    deviceId: row?.deviceId ?? state.presetDevice?.deviceId ?? devices[0]?.deviceId ?? '',
    pluginId: row?.pluginId ?? state.presetDevice?.pluginId ?? devices.find((d) => d.deviceId === (row?.deviceId ?? state.presetDevice?.deviceId))?.pluginId ?? '',
    address: row?.address ?? '',
    goto: row?.goto ?? '',
    sogoVisible: true,
    active: row?.active ?? true,
  }));

  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [reauth, setReauth] = useState(false);
  const [saved, setSaved] = useState(false);

  function selectDevice(deviceId: string) {
    const d = devices.find((x) => x.deviceId === deviceId);
    if (!d) return;
    setForm((f) => ({ ...f, deviceId: d.deviceId, pluginId: d.pluginId }));
  }

  async function submit() {
    if (form.address.trim() === '') { setError('An alias address is required.'); return; }
    const actionId = state.mode === 'edit' ? ACTION_IDS.alias.update : ACTION_IDS.alias.create;
    if (!hasAction(form.pluginId, actionId)) { setSaving(false); setError('This plugin does not advertise the required mail action.'); return; }

    const input: Record<string, unknown> = {};
    if (state.mode === 'create') {
      input['address'] = form.address.trim();
      if (form.goto.trim() === '') { setError('At least one forwarding destination is required.'); return; }
      input['goto'] = form.goto.trim();
      input['sogoVisible'] = form.sogoVisible;
    } else {
      const id = row?.mailcowId ?? null;
      if (id === null) { setError('This alias has no numeric mailcow id — it cannot be edited. Refresh the device and try again.'); return; }
      input['id'] = id;
      input['active'] = form.active;
      const goto = form.goto.trim();
      if (goto !== '') input['goto'] = goto;
    }

    setSaving(true);
    setError(null);
    const attempt = async () => {
      await createAndExecutePlan(form.pluginId, actionId, [{ deviceId: form.deviceId, input }], execMode);
      if (isPlanMode) { setSaved(true); return; }
      onClose();
    };
    try {
      await attempt();
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) setReauth(true);
      else setError(err instanceof Error ? err.message : String(err));
      setSaving(false);
    }
  }

  const title = state.mode === 'edit' ? `Edit alias ${row?.address}` : 'New mail alias';

  if (saved) {
    return (
      <DialogShell title={title} onClose={onClose} footer={
        <footer className="flex items-center justify-end gap-2 border-t border-border px-4 py-3">
          <button type="button" onClick={onClose} className="rounded-md bg-primary px-3 py-1.5 text-xs font-medium text-primary-fg hover:opacity-90">Close</button>
        </footer>
      }>
        <div className="space-y-3 px-4 py-4">
          <div className="flex items-start gap-2 rounded-md border border-success-border bg-success px-3 py-2 text-xs text-success-fg">
            <CheckCircle2 size={14} className="mt-0.5 shrink-0" />
            Alias change saved as a plan — it was NOT executed. Open the Plans center to run it later (or schedule it).
          </div>
        </div>
      </DialogShell>
    );
  }

  return (
    <DialogShell
      title={title}
      subtitle={row ? `Applies on ${row.deviceName ?? row.deviceId}.` : undefined}
      onClose={onClose}
      footer={
        <footer className="flex items-center justify-end gap-2 border-t border-border px-4 py-3">
          <button type="button" onClick={onClose} className="rounded-md px-3 py-1.5 text-xs font-medium text-secondary hover:bg-muted">Cancel</button>
          <button
            type="button"
            disabled={saving || isReadOnly}
            title={isReadOnly ? 'Read-only mode — switch to Plan or Execute to make changes' : undefined}
            onClick={() => void submit()}
            className="inline-flex items-center gap-1.5 rounded-md bg-primary px-3 py-1.5 text-xs font-medium text-primary-fg hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-50"
          >
            {saving && <Loader2 size={12} className="animate-spin" />}
            {isPlanMode ? 'Save as plan' : state.mode === 'edit' ? 'Save changes' : 'Create alias'}
          </button>
        </footer>
      }
    >
      <div className="space-y-4 px-4 py-4">
        {isReadOnly && (
          <div className="flex items-start gap-2 rounded border border-warning-border bg-warning px-3 py-2 text-xs text-warning-fg">
            <EyeOff size={14} className="mt-0.5 shrink-0" />
            Read-only mode is active — this change cannot be saved or executed. Switch to Plan or Execute in the top bar.
          </div>
        )}
        {error && !reauth && (
          <div className="rounded border border-danger-border bg-danger px-3 py-2 text-xs text-danger-fg">{error}</div>
        )}

        {state.mode === 'create' && devices.length > 1 && (
          <DeviceSelect devices={devices} value={form.deviceId} onChange={selectDevice} />
        )}

        <Field label="Alias address" hint='Use "@domain.tld" for a catch-all alias.'>
          <input
            type="text"
            value={form.address}
            disabled={state.mode === 'edit'}
            onChange={(e) => setForm((f) => ({ ...f, address: e.target.value }))}
            placeholder="info@example.org or @example.org"
            className={clsx(inputCls, state.mode === 'edit' && 'opacity-60')}
          />
        </Field>

        <Field label="Forward to (comma-separated)">
          <input
            type="text"
            value={form.goto}
            onChange={(e) => setForm((f) => ({ ...f, goto: e.target.value }))}
            placeholder="admin@example.org, backup@other.org"
            className={inputCls}
          />
        </Field>

        {state.mode === 'create' && (
          <label className="flex items-center gap-2 text-xs text-secondary">
            <input type="checkbox" checked={form.sogoVisible} onChange={(e) => setForm((f) => ({ ...f, sogoVisible: e.target.checked }))} />
            Selectable as sender in SOGo webmail
          </label>
        )}

        {state.mode === 'edit' && (
          <label className="flex items-center gap-2 text-xs text-secondary">
            <input type="checkbox" checked={form.active} onChange={(e) => setForm((f) => ({ ...f, active: e.target.checked }))} />
            Alias is active (forwards mail)
          </label>
        )}
      </div>

      {reauth && (
        <ReauthDialog
          contextLabel={title}
          onClose={() => setReauth(false)}
          onSuccess={async () => {
            setReauth(false);
            try { await submit(); } catch { /* dialog stays open */ }
          }}
        />
      )}
    </DialogShell>
  );
}

// ---------------------------------------------------------------------------
// Page component
// ---------------------------------------------------------------------------

export default function Mail() {
  // Global Execute/Plan mode — decides whether page actions run immediately or
  // are saved as (unexecuted) plans for later execution/scheduling.
  const { mode } = useExecutionMode();
  const isReadOnly = mode === 'readonly';
  const queryClient = useQueryClient();

  const [tab, setTab] = useState<Tab>('domains');
  const [domainFilter, setDomainFilter] = useState('');
  const [dialog, setDialog] = useState<DialogState | null>(null);

  // The API polls plugins every ~30 s and upserts these rows — refresh at the
  // same cadence so all three views track live mail state.
  const domainsQuery = useQuery({ queryKey: ['mail', 'domains'], queryFn: () => api.mailDomains(), refetchInterval: 30_000 });
  const mailboxesQuery = useQuery({ queryKey: ['mail', 'mailboxes'], queryFn: () => api.mailMailboxes(), refetchInterval: 30_000 });
  const aliasesQuery = useQuery({ queryKey: ['mail', 'aliases'], queryFn: () => api.mailAliases(), refetchInterval: 30_000 });

  const allDomains: MailDomainRow[] = domainsQuery.data ?? [];
  const allMailboxes: MailMailboxRow[] = mailboxesQuery.data ?? [];
  const allAliases: MailAliasRow[] = aliasesQuery.data ?? [];

  // Distinct mail servers (device + plugin) across all three inventories —
  // drives the "mail server" select in create dialogs.
  const mailDevices: MailDevice[] = useMemo(() => {
    const m = new Map<string, MailDevice>();
    for (const r of [...allDomains, ...allMailboxes, ...allAliases]) {
      if (!m.has(r.deviceId)) m.set(r.deviceId, { deviceId: r.deviceId, pluginId: r.pluginId, deviceName: r.deviceName });
    }
    return Array.from(m.values());
  }, [allDomains, allMailboxes, allAliases]);

  // --- Action catalogs (drive per-row action availability GENERICALLY) -------
  const catalogPluginIds = useMemo(
    () => Array.from(new Set([...allDomains, ...allMailboxes, ...allAliases].map((r) => r.pluginId))),
    [allDomains, allMailboxes, allAliases],
  );
  const catalogsQuery = useQuery({
    queryKey: ['plugin-actions-catalogs', 'mail', catalogPluginIds.join('|')],
    queryFn: async () => {
      const entries = await Promise.all(
        catalogPluginIds.map(async (pid) => [pid, (await api.pluginActions(pid)).actions] as const),
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

  // --- Plan tracking → auto-refresh -------------------------------------------
  const [notice, setNotice] = useState<{ kind: 'ok' | 'info' | 'error'; text: string } | null>(null);
  const [reauth, setReauth] = useState<{ label: string; retry: () => void | Promise<void> } | null>(null);

  /** Plan id → the devices its steps touch. */
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
        setPendingPlans((prev) => {
          const next = { ...prev };
          delete next[planId];
          return next;
        });
        try { await api.refreshDevices(entry.deviceIds); } catch { /* fall back to the 30s poll */ }
        void queryClient.invalidateQueries({ queryKey: ['mail'] });
        if (p.status !== 'succeeded') {
          setNotice({ kind: 'error', text: `A mail plan finished with errors — check the Plans page.` });
        }
      }
    }, 3000);
    return () => clearInterval(timer);
  }, [pendingPlans, queryClient]);

  // --- Single deletes (per-row trash button) ----------------------------------

  async function deleteDomain(row: MailDomainRow) {
    const actionId = ACTION_IDS.domain.delete;
    if (!hasAction(row.pluginId, actionId)) return;
    if (!window.confirm(`Permanently delete the domain "${row.domain}" including ALL of its mailboxes and aliases? This is irreversible.`)) return;
    const attempt = async () => {
      if (isReadOnly) { setNotice({ kind: 'info', text: READONLY_MESSAGE }); return; }
      const planId = await createAndExecutePlan(row.pluginId, actionId, [{ deviceId: row.deviceId, input: { domains: [row.domain] } }], mode);
      if (mode === 'plan') { setNotice({ kind: 'ok', text: `Delete ${row.domain}: saved as a plan — not executed. Open the Plans center to run it later.` }); return; }
      trackPlan(planId, [row.deviceId]);
    };
    try { await attempt(); } catch (err) {
      if (err instanceof ApiError && err.status === 401) setReauth({ label: `Delete ${row.domain}`, retry: attempt });
      else setNotice({ kind: 'error', text: `Delete failed: ${err instanceof Error ? err.message : String(err)}` });
    }
  }

  async function deleteMailbox(row: MailMailboxRow) {
    const actionId = ACTION_IDS.mailbox.delete;
    if (!hasAction(row.pluginId, actionId)) return;
    if (!window.confirm(`Permanently delete the mailbox "${row.username}" including all of its mail? This is irreversible.`)) return;
    const attempt = async () => {
      if (isReadOnly) { setNotice({ kind: 'info', text: READONLY_MESSAGE }); return; }
      const planId = await createAndExecutePlan(row.pluginId, actionId, [{ deviceId: row.deviceId, input: { usernames: [row.username] } }], mode);
      if (mode === 'plan') { setNotice({ kind: 'ok', text: `Delete ${row.username}: saved as a plan — not executed. Open the Plans center to run it later.` }); return; }
      trackPlan(planId, [row.deviceId]);
    };
    try { await attempt(); } catch (err) {
      if (err instanceof ApiError && err.status === 401) setReauth({ label: `Delete ${row.username}`, retry: attempt });
      else setNotice({ kind: 'error', text: `Delete failed: ${err instanceof Error ? err.message : String(err)}` });
    }
  }

  async function deleteAlias(row: MailAliasRow) {
    const actionId = ACTION_IDS.alias.delete;
    if (!hasAction(row.pluginId, actionId)) return;
    if (row.mailcowId === null || row.mailcowId === undefined) { setNotice({ kind: 'info', text: `Cannot delete ${row.address} — no numeric mailcow id available. Refresh the device and try again.` }); return; }
    if (!window.confirm(`Permanently delete the alias "${row.address}"?`)) return;
    const attempt = async () => {
      if (isReadOnly) { setNotice({ kind: 'info', text: READONLY_MESSAGE }); return; }
      const planId = await createAndExecutePlan(row.pluginId, actionId, [{ deviceId: row.deviceId, input: { ids: [row.mailcowId] } }], mode);
      if (mode === 'plan') { setNotice({ kind: 'ok', text: `Delete ${row.address}: saved as a plan — not executed. Open the Plans center to run it later.` }); return; }
      trackPlan(planId, [row.deviceId]);
    };
    try { await attempt(); } catch (err) {
      if (err instanceof ApiError && err.status === 401) setReauth({ label: `Delete ${row.address}`, retry: attempt });
      else setNotice({ kind: 'error', text: `Delete failed: ${err instanceof Error ? err.message : String(err)}` });
    }
  }

  // --- Bulk deletes (selection bar) --------------------------------------------

  async function bulkDeleteDomains(rows: MailDomainRow[]) {
    const sel = rows.filter((r) => hasAction(r.pluginId, ACTION_IDS.domain.delete));
    if (sel.length === 0) { setNotice({ kind: 'info', text: 'No selected domains are deletable on their plugin.' }); return; }
    const attempt = async () => {
      if (isReadOnly) { setNotice({ kind: 'info', text: READONLY_MESSAGE }); return; }
      let savedCount = 0;
      for (const g of Array.from(groupByDevice(sel, (r) => ({ pluginId: r.pluginId, deviceId: r.deviceId }), (r) => r.domain).values())) {
        const planId = await createAndExecutePlan(g.pluginId, ACTION_IDS.domain.delete, [{ deviceId: g.deviceId, input: { domains: g.values as string[] } }], mode);
        if (mode === 'plan') { savedCount += 1; continue; }
        trackPlan(planId, [g.deviceId]);
      }
      if (mode === 'plan' && savedCount > 0) setNotice({ kind: 'ok', text: `Delete selected domains: ${savedCount} plan${savedCount === 1 ? '' : 's'} saved without executing — open the Plans center to run them later.` });
    };
    try { await attempt(); } catch (err) {
      if (err instanceof ApiError && err.status === 401) setReauth({ label: 'Delete selected domains', retry: attempt });
      else setNotice({ kind: 'error', text: `Delete failed: ${err instanceof Error ? err.message : String(err)}` });
    }
  }

  async function bulkDeleteMailboxes(rows: MailMailboxRow[]) {
    const sel = rows.filter((r) => hasAction(r.pluginId, ACTION_IDS.mailbox.delete));
    if (sel.length === 0) { setNotice({ kind: 'info', text: 'No selected mailboxes are deletable on their plugin.' }); return; }
    const attempt = async () => {
      if (isReadOnly) { setNotice({ kind: 'info', text: READONLY_MESSAGE }); return; }
      let savedCount = 0;
      for (const g of Array.from(groupByDevice(sel, (r) => ({ pluginId: r.pluginId, deviceId: r.deviceId }), (r) => r.username).values())) {
        const planId = await createAndExecutePlan(g.pluginId, ACTION_IDS.mailbox.delete, [{ deviceId: g.deviceId, input: { usernames: g.values as string[] } }], mode);
        if (mode === 'plan') { savedCount += 1; continue; }
        trackPlan(planId, [g.deviceId]);
      }
      if (mode === 'plan' && savedCount > 0) setNotice({ kind: 'ok', text: `Delete selected mailboxes: ${savedCount} plan${savedCount === 1 ? '' : 's'} saved without executing — open the Plans center to run them later.` });
    };
    try { await attempt(); } catch (err) {
      if (err instanceof ApiError && err.status === 401) setReauth({ label: 'Delete selected mailboxes', retry: attempt });
      else setNotice({ kind: 'error', text: `Delete failed: ${err instanceof Error ? err.message : String(err)}` });
    }
  }

  async function bulkDeleteAliases(rows: MailAliasRow[]) {
    const sel = rows.filter((r) => hasAction(r.pluginId, ACTION_IDS.alias.delete));
    if (sel.length === 0) { setNotice({ kind: 'info', text: 'No selected aliases are deletable on their plugin.' }); return; }
    const attempt = async () => {
      if (isReadOnly) { setNotice({ kind: 'info', text: READONLY_MESSAGE }); return; }
      let savedCount = 0;
      for (const g of Array.from(groupByDevice(sel, (r) => ({ pluginId: r.pluginId, deviceId: r.deviceId }), (r) => r.mailcowId).values())) {
        const ids = (g.values as (number | null | undefined)[]).filter((v): v is number => typeof v === 'number');
        if (ids.length === 0) continue; // no numeric ids — nothing to delete in this group
        const planId = await createAndExecutePlan(g.pluginId, ACTION_IDS.alias.delete, [{ deviceId: g.deviceId, input: { ids } }], mode);
        if (mode === 'plan') { savedCount += 1; continue; }
        trackPlan(planId, [g.deviceId]);
      }
      const skipped = sel.filter((r) => r.mailcowId === null || r.mailcowId === undefined).length;
      if (skipped > 0) setNotice({ kind: 'info', text: `${skipped} selected alias${skipped === 1 ? '' : 'es'} skipped — no numeric mailcow id available.` });
      else if (mode === 'plan' && savedCount > 0) setNotice({ kind: 'ok', text: `Delete selected aliases: ${savedCount} plan${savedCount === 1 ? '' : 's'} saved without executing — open the Plans center to run them later.` });
    };
    try { await attempt(); } catch (err) {
      if (err instanceof ApiError && err.status === 401) setReauth({ label: 'Delete selected aliases', retry: attempt });
      else setNotice({ kind: 'error', text: `Delete failed: ${err instanceof Error ? err.message : String(err)}` });
    }
  }

  // --- Filtered rows ------------------------------------------------------------

  const filteredMailboxes = useMemo(
    () => allMailboxes.filter((r) => !domainFilter || r.domain === domainFilter),
    [allMailboxes, domainFilter],
  );
  const filteredAliases = useMemo(
    () => allAliases.filter((r) => !domainFilter || r.domain === domainFilter),
    [allAliases, domainFilter],
  );

  // --- Columns -------------------------------------------------------------------

  const deviceCol = <T extends { deviceId: string; pluginId: string; deviceName?: string | null; managementAddress?: string | null; siteName?: string | null; pluginName?: string | null }>(row: T) => (
    <DeviceChip
      deviceName={row.deviceName}
      managementAddress={row.managementAddress}
      pluginName={row.pluginName}
      siteName={row.siteName}
      interfaces={[]}
    />
  );

  const domainColumns: DataTableColumn<MailDomainRow>[] = [
    {
      header: 'Domain',
      key: 'domain',
      width: 240,
      render: (row) => (
        <div className="flex flex-col gap-0.5">
          <span className="font-mono text-sm font-medium text-foreground">{row.domain}</span>
          {row.description && row.description.trim() !== '' && <span className="text-xs text-faint">{row.description}</span>}
        </div>
      ),
    },
    { header: 'Device', key: 'deviceName', width: 240, exportValue: (r) => `${r.deviceName ?? '?'} (${r.managementAddress ?? '?'})`, render: deviceCol },
    { header: 'Status', key: 'active', width: 90, exportValue: (r) => (r.active ? 'active' : 'inactive'), render: (row) => <ActivePill active={row.active} /> },
    {
      header: 'Quota',
      key: 'quotaBytes',
      width: 150,
      sortAccessor: (row) => row.quotaBytes ?? -1,
      exportValue: (r) => (r.quotaBytes != null ? formatBytes(r.quotaBytes) : 'unlimited'),
      render: (row) => <span className="font-mono text-xs">{row.quotaBytes != null ? formatBytes(row.quotaBytes) : '—'}</span>,
    },
    { header: 'Mailboxes', key: 'mailboxCount', width: 90, sortAccessor: (r) => r.mailboxCount ?? -1, render: (row) => <span className="font-mono text-xs">{row.mailboxCount ?? '—'}</span> },
    { header: 'Aliases', key: 'aliasCount', width: 80, sortAccessor: (r) => r.aliasCount ?? -1, render: (row) => <span className="font-mono text-xs">{row.aliasCount ?? '—'}</span> },
    {
      header: 'Backup MX',
      key: 'backupMx',
      width: 90,
      exportValue: (r) => (r.backupMx ? 'yes' : 'no'),
      render: (row) => row.backupMx ? <span className="font-mono text-xs text-accent-sky-fg">relay</span> : <span className="text-faint">—</span>,
    },
    {
      header: 'Actions',
      key: 'actions',
      width: 150,
      excludeFromExport: true,
      render: (row) => (
        <div className="flex items-center gap-0.5">
          {!isReadOnly && hasAction(row.pluginId, ACTION_IDS.mailbox.create) && (
            <button type="button" aria-label={`Add mailbox to ${row.domain}`} title={`New mailbox in ${row.domain}`} onClick={() => setDialog({ kind: 'mailbox', mode: 'create', presetDevice: { deviceId: row.deviceId, pluginId: row.pluginId, deviceName: row.deviceName }, presetDomain: row.domain })} className="rounded-md p-1.5 text-secondary hover:bg-muted hover:text-foreground">
              <Plus size={14} />
            </button>
          )}
          {!isReadOnly && hasAction(row.pluginId, ACTION_IDS.alias.create) && (
            <button type="button" aria-label={`Add alias to ${row.domain}`} title={`New alias in ${row.domain}`} onClick={() => setDialog({ kind: 'alias', mode: 'create', presetDevice: { deviceId: row.deviceId, pluginId: row.pluginId, deviceName: row.deviceName } })} className="rounded-md p-1.5 text-secondary hover:bg-muted hover:text-foreground">
              <ChevronRight size={14} />
            </button>
          )}
          {!isReadOnly && hasAction(row.pluginId, ACTION_IDS.domain.update) && (
            <button type="button" aria-label={`Edit ${row.domain}`} title={`Edit this domain`} onClick={() => setDialog({ kind: 'domain', mode: 'edit', row })} className="rounded-md p-1.5 text-secondary hover:bg-muted hover:text-foreground">
              <Pencil size={14} />
            </button>
          )}
          {!isReadOnly && hasAction(row.pluginId, ACTION_IDS.domain.delete) && (
            <button type="button" aria-label={`Delete ${row.domain}`} title={`Delete this domain and everything in it`} onClick={() => void deleteDomain(row)} className="rounded-md p-1.5 text-danger-fg hover:bg-muted hover:text-danger-fg">
              <Trash2 size={14} />
            </button>
          )}
        </div>
      ),
    },
  ];

  const mailboxColumns: DataTableColumn<MailMailboxRow>[] = [
    {
      header: 'Mailbox',
      key: 'username',
      width: 260,
      render: (row) => (
        <div className="flex flex-col gap-0.5">
          <span className="font-mono text-sm font-medium text-foreground">{row.username}</span>
          {row.name && row.name.trim() !== '' && <span className="text-xs text-faint">{row.name}</span>}
        </div>
      ),
    },
    { header: 'Device', key: 'deviceName', width: 240, exportValue: (r) => `${r.deviceName ?? '?'} (${r.managementAddress ?? '?'})`, render: deviceCol },
    { header: 'Status', key: 'active', width: 90, exportValue: (r) => (r.active ? 'active' : 'inactive'), render: (row) => <ActivePill active={row.active} /> },
    {
      header: 'Quota used',
      key: 'quotaUsedBytes',
      width: 170,
      sortAccessor: (row) => row.quotaUsedBytes ?? -1,
      exportValue: (r) => `${formatBytes(r.quotaUsedBytes ?? 0)} / ${r.quotaBytes != null ? formatBytes(r.quotaBytes) : 'unlimited'}`,
      render: (row) => quotaCell(row.quotaUsedBytes, row.quotaBytes),
    },
    { header: 'Messages', key: 'messageCount', width: 90, sortAccessor: (r) => r.messageCount ?? -1, render: (row) => <span className="font-mono text-xs">{row.messageCount ?? '—'}</span> },
    {
      header: 'Flags',
      key: 'flags',
      width: 120,
      excludeFromExport: true,
      render: (row) => (
        <div className="flex items-center gap-1">
          {row.forcePwUpdate && <span title="Password change forced on next login" className="rounded bg-warning px-1 py-0.5 text-[10px] font-semibold text-warning-fg">PW</span>}
          {row.forceTfa && <span title="2FA enrollment forced at next login" className="rounded bg-accent-indigo px-1 py-0.5 text-[10px] font-semibold text-accent-indigo-fg">2FA</span>}
        </div>
      ),
    },
    {
      header: 'Actions',
      key: 'actions',
      width: 90,
      excludeFromExport: true,
      render: (row) => (
        <div className="flex items-center gap-0.5">
          {!isReadOnly && hasAction(row.pluginId, ACTION_IDS.mailbox.update) && (
            <button type="button" aria-label={`Edit ${row.username}`} title={`Edit this mailbox`} onClick={() => setDialog({ kind: 'mailbox', mode: 'edit', row })} className="rounded-md p-1.5 text-secondary hover:bg-muted hover:text-foreground">
              <Pencil size={14} />
            </button>
          )}
          {!isReadOnly && hasAction(row.pluginId, ACTION_IDS.mailbox.delete) && (
            <button type="button" aria-label={`Delete ${row.username}`} title={`Delete this mailbox`} onClick={() => void deleteMailbox(row)} className="rounded-md p-1.5 text-danger-fg hover:bg-muted hover:text-danger-fg">
              <Trash2 size={14} />
            </button>
          )}
        </div>
      ),
    },
  ];

  const aliasColumns: DataTableColumn<MailAliasRow>[] = [
    {
      header: 'Address',
      key: 'address',
      width: 260,
      render: (row) => (
        <span className={clsx('font-mono text-sm font-medium', row.isCatchAll ? 'text-accent-purple-fg' : 'text-foreground')}>
          {row.address}
        </span>
      ),
    },
    { header: 'Device', key: 'deviceName', width: 240, exportValue: (r) => `${r.deviceName ?? '?'} (${r.managementAddress ?? '?'})`, render: deviceCol },
    { header: 'Status', key: 'active', width: 90, exportValue: (r) => (r.active ? 'active' : 'inactive'), render: (row) => <ActivePill active={row.active} /> },
    {
      header: 'Forwards to',
      key: 'goto',
      width: 280,
      render: (row) => <span className="font-mono text-xs">{orDash(row.goto)}</span>,
    },
    {
      header: 'Catch-all',
      key: 'isCatchAll',
      width: 90,
      exportValue: (r) => (r.isCatchAll ? 'yes' : 'no'),
      render: (row) => row.isCatchAll ? <span className="font-mono text-xs text-accent-purple-fg">yes</span> : <span className="text-faint">—</span>,
    },
    {
      header: 'Actions',
      key: 'actions',
      width: 90,
      excludeFromExport: true,
      render: (row) => (
        <div className="flex items-center gap-0.5">
          {!isReadOnly && hasAction(row.pluginId, ACTION_IDS.alias.update) && (
            <button
              type="button"
              aria-label={`Edit ${row.address}`}
              title={row.mailcowId != null ? 'Edit this alias' : 'No numeric mailcow id available — refresh the device to enable editing'}
              disabled={row.mailcowId === null || row.mailcowId === undefined}
              onClick={() => setDialog({ kind: 'alias', mode: 'edit', row })}
              className="rounded-md p-1.5 text-secondary hover:bg-muted hover:text-foreground disabled:cursor-not-allowed disabled:opacity-30"
            >
              <Pencil size={14} />
            </button>
          )}
          {!isReadOnly && hasAction(row.pluginId, ACTION_IDS.alias.delete) && (
            <button
              type="button"
              aria-label={`Delete ${row.address}`}
              title={row.mailcowId != null ? 'Delete this alias' : 'No numeric mailcow id available — refresh the device to enable deletion'}
              disabled={row.mailcowId === null || row.mailcowId === undefined}
              onClick={() => void deleteAlias(row)}
              className="rounded-md p-1.5 text-danger-fg hover:bg-muted hover:text-danger-fg disabled:cursor-not-allowed disabled:opacity-30"
            >
              <Trash2 size={14} />
            </button>
          )}
        </div>
      ),
    },
  ];

  // --- Tab bar -------------------------------------------------------------------

  const tabs: { id: Tab; label: string; count: number }[] = [
    { id: 'domains', label: 'Domains', count: allDomains.length },
    { id: 'mailboxes', label: 'Mailboxes', count: allMailboxes.length },
    { id: 'aliases', label: 'Aliases', count: allAliases.length },
  ];

  const anyLoading = domainsQuery.isLoading || mailboxesQuery.isLoading || aliasesQuery.isLoading;
  const anyError = domainsQuery.isError || mailboxesQuery.isError || aliasesQuery.isError;

  return (
    <Layout title="Mail">
      {anyLoading && <p className="text-sm text-muted-foreground">Loading mail inventory...</p>}
      {anyError && !anyLoading && (
        <p className="text-sm text-danger-fg">Failed to load mail inventory: {(domainsQuery.error ?? mailboxesQuery.error ?? aliasesQuery.error)?.message}</p>
      )}

      {/* Tab bar */}
      <div className="mb-3 flex items-center gap-1 border-b border-border">
        {tabs.map((t) => (
          <button
            key={t.id}
            type="button"
            onClick={() => setTab(t.id)}
            className={clsx(
              'flex items-center gap-1.5 rounded-t-md px-3 py-2 text-sm font-medium',
              tab === t.id ? 'border-b-2 border-primary text-foreground' : 'text-secondary hover:text-foreground',
            )}
          >
            <MailIcon size={14} />
            {t.label}
            <span className="rounded-full bg-muted px-1.5 text-[10px] font-semibold leading-4 text-secondary">{t.count}</span>
          </button>
        ))}

        {/* Per-tab create buttons (right-aligned) */}
        {!isReadOnly && mailDevices.length > 0 && (
          <div className="ml-auto flex items-center gap-1.5 pb-1">
            {tab === 'domains' && hasAction(mailDevices[0].pluginId, ACTION_IDS.domain.create) && (
              <button type="button" onClick={() => setDialog({ kind: 'domain', mode: 'create' })} className="inline-flex items-center gap-1 rounded-md bg-primary px-2.5 py-1 text-xs font-medium text-primary-fg hover:opacity-90">
                <Plus size={12} /> New domain
              </button>
            )}
            {tab === 'mailboxes' && hasAction(mailDevices[0].pluginId, ACTION_IDS.mailbox.create) && (
              <button type="button" onClick={() => setDialog({ kind: 'mailbox', mode: 'create' })} className="inline-flex items-center gap-1 rounded-md bg-primary px-2.5 py-1 text-xs font-medium text-primary-fg hover:opacity-90">
                <Plus size={12} /> New mailbox
              </button>
            )}
            {tab === 'aliases' && hasAction(mailDevices[0].pluginId, ACTION_IDS.alias.create) && (
              <button type="button" onClick={() => setDialog({ kind: 'alias', mode: 'create' })} className="inline-flex items-center gap-1 rounded-md bg-primary px-2.5 py-1 text-xs font-medium text-primary-fg hover:opacity-90">
                <Plus size={12} /> New alias
              </button>
            )}
          </div>
        )}
      </div>

      {/* Domain filter for the mailbox/alias tabs */}
      {tab !== 'domains' && (
        <div className="mb-3 flex items-center gap-2">
          <label className="flex items-center gap-2 text-sm text-secondary">
            Domain
            <select value={domainFilter} onChange={(e) => setDomainFilter(e.target.value)} className="rounded border border-border bg-background px-2 py-1 font-mono text-sm">
              <option value="">All</option>
              {Array.from(new Set(allDomains.map((d) => d.domain))).sort().map((d) => (
                <option key={d} value={d}>{d}</option>
              ))}
            </select>
          </label>
        </div>
      )}

      {notice && (
        <div className={clsx(
          'mb-3 rounded-md border px-3 py-2 text-sm',
          notice.kind === 'ok' && 'border-success-border bg-success text-success-fg',
          notice.kind === 'info' && 'border-info-border bg-info text-info-fg',
          notice.kind === 'error' && 'border-danger-border bg-danger text-danger-fg',
        )}>
          {notice.text}
        </div>
      )}

      {/* Tab content */}
      {tab === 'domains' && (
        <DataTable
          columns={domainColumns}
          rows={allDomains}
          rowKey={(row) => `${row.deviceId}|${row.pluginId}|${row.domain}`}
          storageKey="mail-domains"
          autoRefresh={{ intervalMs: 30_000, queries: [domainsQuery] }}
          searchPlaceholder="Search domains…"
          selectable={!isReadOnly}
          bulkActions={[{
            label: 'Delete selected',
            confirm: (n) => `Permanently delete ${n} domain(s) including ALL of their mailboxes and aliases? This is irreversible.`,
            onClick: (rows) => void bulkDeleteDomains(rows),
            enabled: (rows) => rows.some((r) => hasAction(r.pluginId, ACTION_IDS.domain.delete)),
          }]}
          emptyMessage={
            allDomains.length === 0
              ? 'No mail domains collected yet — assign the Mailcow plugin to a device and wait for the next poll.'
              : 'No domains match the current search.'
          }
        />
      )}

      {tab === 'mailboxes' && (
        <DataTable
          columns={mailboxColumns}
          rows={filteredMailboxes}
          rowKey={(row) => `${row.deviceId}|${row.pluginId}|${row.username}`}
          storageKey="mail-mailboxes"
          autoRefresh={{ intervalMs: 30_000, queries: [mailboxesQuery] }}
          searchPlaceholder="Search mailboxes…"
          selectable={!isReadOnly}
          bulkActions={[{
            label: 'Delete selected',
            confirm: (n) => `Permanently delete ${n} mailbox(es) including all of their mail? This is irreversible.`,
            onClick: (rows) => void bulkDeleteMailboxes(rows),
            enabled: (rows) => rows.some((r) => hasAction(r.pluginId, ACTION_IDS.mailbox.delete)),
          }]}
          emptyMessage={
            allMailboxes.length === 0
              ? 'No mailboxes collected yet — assign the Mailcow plugin to a device and wait for the next poll.'
              : 'No mailboxes match the current filters.'
          }
        />
      )}

      {tab === 'aliases' && (
        <DataTable
          columns={aliasColumns}
          rows={filteredAliases}
          rowKey={(row) => `${row.deviceId}|${row.pluginId}|${row.address}`}
          storageKey="mail-aliases"
          autoRefresh={{ intervalMs: 30_000, queries: [aliasesQuery] }}
          searchPlaceholder="Search aliases…"
          selectable={!isReadOnly}
          bulkActions={[{
            label: 'Delete selected',
            confirm: (n) => `Permanently delete ${n} alias(es)?`,
            onClick: (rows) => void bulkDeleteAliases(rows),
            enabled: (rows) => rows.some((r) => hasAction(r.pluginId, ACTION_IDS.alias.delete)),
          }]}
          emptyMessage={
            allAliases.length === 0
              ? 'No aliases collected yet — assign the Mailcow plugin to a device and wait for the next poll.'
              : 'No aliases match the current filters.'
          }
        />
      )}

      {/* Dialogs */}
      {dialog?.kind === 'domain' && <DomainDialog state={dialog} devices={mailDevices} hasAction={hasAction} onClose={() => setDialog(null)} />}
      {dialog?.kind === 'mailbox' && <MailboxDialog state={dialog} devices={mailDevices} domains={allDomains} hasAction={hasAction} onClose={() => setDialog(null)} />}
      {dialog?.kind === 'alias' && <AliasDialog state={dialog} devices={mailDevices} hasAction={hasAction} onClose={() => setDialog(null)} />}

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
