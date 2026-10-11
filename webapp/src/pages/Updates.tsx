import { useQuery, useQueryClient } from '@tanstack/react-query';
import { ArrowUpCircle, CheckCircle2, ExternalLink, Layers, Loader2, Lock, RefreshCw, Rocket, ShieldCheck, Unlock, Zap } from 'lucide-react';
import { useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import { DialogShell } from '../components/DialogShell';
import { Layout } from '../components/Layout';
import { DataTable, DataTableColumn, type ExpandChildContext } from '../components/DataTable';
import { DeviceChip } from '../components/DeviceChip';
import { ReauthDialog } from '../components/ReauthDialog';
import { runAction, useExecutionMode, type ExecutionMode } from '../executionMode';
import { api, ApiError, UpdateRow } from '../api/client';
import { can } from '../auth/permissions';

// ---------------------------------------------------------------------------
// Kind badge + helpers (same visual language as the other inventory pages)
// ---------------------------------------------------------------------------

const KIND_STYLES: Record<string, string> = {
  firmware: 'bg-accent-indigo text-accent-indigo-fg',
  'os-package': 'bg-accent-sky text-accent-sky-fg',
  'docker-image': 'bg-accent-teal text-accent-teal-fg',
  app: 'bg-accent-violet text-accent-violet-fg',
  stack: 'bg-accent-purple text-accent-purple-fg',
};

function KindBadge({ kind }: { kind: string }) {
  return (
    <span className={`inline-flex rounded px-1.5 py-0.5 text-xs font-medium ${KIND_STYLES[kind] ?? 'bg-muted text-secondary'}`}>
      {kind}
    </span>
  );
}

/** Icon-only action button — matches the UX language of the Containers/Storage
 * pages (no text label; the tooltip + aria-label carry it). */
function ActionIconButton({ label, onClick, icon }: { label: string; onClick: () => void; icon: ReactNode }) {
  return (
    <button type="button" aria-label={label} title={label} onClick={onClick} className="rounded-md p-1 text-secondary hover:bg-muted hover:text-foreground">
      {icon}
    </button>
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

// ---------------------------------------------------------------------------
// Device → updates hierarchy (the page's row model)
// ---------------------------------------------------------------------------

/** One kind-group of a device: all rows sharing (kind, applyActionId). A group
 * with an action becomes ONE bulk plan step — e.g. every os-package row of a
 * generic-ssh host shares `packages.update`, and the merged input drops the
 * per-row package name, so the distro's BULK upgrade command runs once instead
 * of one step per package. */
interface KindGroup {
  kind: string;
  actionId?: string | null;
  rows: UpdateRow[];
}

/** One node in the device → updates display tree. Top-level (device) nodes
 * carry their kind-groups + children; child nodes carry one source row so the
 * main columns keep working for both levels. */
interface UpdateNode {
  key: string;
  isDevice: boolean;
  /** Source update row — set on `isDevice === false` nodes only. */
  row?: UpdateRow;
  deviceId?: string;
  pluginId?: string;
  deviceName?: string | null;
  managementAddress?: string | null;
  siteName?: string | null;
  pluginName?: string | null;
  /** Device nodes: the kind-groups (sorted by KIND_ORDER, then action id). */
  groups?: KindGroup[];
}

/** Display order of kind groups on a device row (UNM itself first, packages last). */
const KIND_ORDER: Record<string, number> = { stack: -1, firmware: 0, app: 1, 'docker-image': 2, 'os-package': 3 };

const KIND_LABELS: Record<string, string> = {
  stack: 'UNM itself',
  firmware: 'firmware',
  'os-package': 'packages',
  'docker-image': 'images',
  app: 'apps',
};

/** Merges per-row apply inputs into a single bulk input and reports whether the
 * merge is unambiguous. Array-valued fields are concatenated (TrueNAS
 * `containers.upgrade` takes `names: string[]`, `images.update` takes
 * `refs: string[]`). Scalar fields keep their value when every row agrees
 * (`system.firmware.update` carries `{ version }`); a conflicting scalar is
 * dropped and the merge marked DIRTY — dropping it would let the action's own
 * default apply (e.g. generic-ssh `packages.update` with no input means "upgrade
 * ALL"), so callers must fall back to per-row steps for dirty merges. */
function mergeInputsSafe(rows: UpdateRow[]): { input: Record<string, unknown>; clean: boolean } {
  const out: Record<string, unknown> = {};
  let clean = true;
  for (const r of rows) {
    const inp = r.applyInput;
    if (!inp || typeof inp !== 'object') continue;
    for (const [k, v] of Object.entries(inp)) {
      if (Array.isArray(v)) out[k] = [...(Array.isArray(out[k]) ? (out[k] as unknown[]) : []), ...v];
      else if (!(k in out)) out[k] = v;
      else if (!Object.is(out[k], v)) { delete out[k]; clean = false; } // conflicting scalars → dirty merge
    }
  }
  return { input: out, clean };
}

/** Merges the per-row apply inputs of one kind-group into a single bulk input.
 * Conflicting scalars are dropped — for device-level "update all" that is the
 * intended semantics (e.g. the per-package `package` name of a generic-ssh host,
 * where an empty input means "upgrade ALL" in the action's own terms). */
function mergeGroupInputs(rows: UpdateRow[]): Record<string, unknown> {
  return mergeInputsSafe(rows).input;
}

/** The bulk plan steps for one device: ONE step per kind-group — with identical
 * (actionId, merged input) pairs collapsed into a single step. That matters for
 * plugins whose rows all apply through the SAME job (OPNsense: the firmware row
 * and every package row point at `firmware.update` with an empty input — one
 * plan step starts the appliance's update job once, not N times). */
function bulkStepsForDevice(node: UpdateNode): Array<{ pluginId: string; actionId: string; deviceId: string; input: Record<string, unknown> }> {
  const steps: Array<{ pluginId: string; actionId: string; deviceId: string; input: Record<string, unknown> }> = [];
  const seen = new Set<string>();
  for (const g of node.groups ?? []) {
    if (!g.actionId || !node.deviceId) continue; // no safe apply path → manual on the device
    const input = mergeGroupInputs(g.rows);
    const key = `${g.actionId}|${JSON.stringify(input)}`;
    if (seen.has(key)) continue;
    seen.add(key);
    steps.push({ pluginId: node.pluginId!, actionId: g.actionId, deviceId: node.deviceId, input });
  }
  return steps;
}

/** The branch of one node — for device rows the first row carrying a branch
 * (firmware groups first: the branch is a property of the DEVICE, e.g. TrueNAS
 * update profile GENERAL/EARLY_ADOPTER; other kinds may carry their own track).
 * Null when no plugin on this device exposes a branch concept. */
function branchOf(n: UpdateNode): string | null {
  if (!n.isDevice) return n.row?.branch ?? null;
  const fw = (n.groups ?? []).find((g) => g.kind === 'firmware');
  for (const r of fw?.rows ?? []) if (r.branch) return r.branch;
  for (const g of n.groups ?? []) for (const r of g.rows) if (r.branch) return r.branch;
  return null;
}

/** The "no reboot needed" subset of a device's package rows — everything whose
 * `rebootRequired` is not set (kernel/firmware/initramfs packages are excluded).
 * Becomes ONE plan step with an explicit `packages: string[]` list, so the host
 * upgrades exactly those in a single lock acquisition. HELD and KEPT-BACK rows
 * are excluded too: an explicit list containing a held package makes apt hard-fail
 * the whole run (a full upgrade skips them on purpose). They stay visible with
 * their badge — unhold first, or use "Force all". Empty when there is no safe
 * subset (e.g. only kernel updates pending) or the plugin has no apply path. */
function noRebootStepsForDevice(node: UpdateNode): Array<{ pluginId: string; actionId: string; deviceId: string; input: Record<string, unknown> }> {
  const pkgs = (node.groups ?? [])
    .filter((g) => g.kind === 'os-package' && g.actionId === 'packages.update')
    .flatMap((g) => g.rows)
    .filter((r) => r.rebootRequired !== true)
    .filter((r) => r.extra?.['held'] !== true && r.extra?.['keptBack'] !== true)
    .map((r) => r.name);
  if (pkgs.length === 0 || !node.deviceId || !node.pluginId) return [];
  return [{ pluginId: node.pluginId, actionId: 'packages.update', deviceId: node.deviceId, input: { packages: pkgs } }];
}

/** Plan steps for individually-selected child updates — merged where SAFE.
 * Rows are grouped by (device, plugin, apply action). Per group:
 *  - os-package rows applying via `packages.update` collapse into ONE step with
 *    an explicit `{ packages: [...] }` list (the action's documented list mode)
 *    — never the empty input that would mean "upgrade ALL";
 *  - other groups merge their per-row inputs when unambiguous (arrays
 *    concatenate, scalars must agree — e.g. TrueNAS `containers.upgrade` rows
 *    `{ names: [app] }` collapse to one step with all selected app names);
 *  - a DIRTY merge (conflicting non-array scalar dropped) falls back to one
 *    step per row with its exact prefilled input, so scope never widens. */
function mergedStepsForRows(rows: UpdateRow[]): Array<{ pluginId: string; actionId: string; deviceId: string; input: Record<string, unknown> }> {
  const groups = new Map<string, UpdateRow[]>();
  for (const r of rows) {
    if (!r.applyActionId) continue; // no safe apply path → manual on the device
    const gk = `${r.deviceId}|${r.pluginId}|${r.applyActionId}`;
    let arr = groups.get(gk);
    if (!arr) { arr = []; groups.set(gk, arr); }
    arr.push(r);
  }

  const steps: Array<{ pluginId: string; actionId: string; deviceId: string; input: Record<string, unknown> }> = [];
  for (const list of groups.values()) {
    const first = list[0];
    if (list.length === 1) {
      steps.push({ pluginId: first.pluginId, actionId: first.applyActionId!, deviceId: first.deviceId, input: first.applyInput ?? {} });
      continue;
    }
    // Explicit package-list mode — the only merge that is safe for os-packages.
    // Held / kept-back rows are EXCLUDED: an explicit list containing a held
    // package makes apt hard-fail the whole run (a full upgrade skips them on
    // purpose). They stay visible with their badge; unhold first or force all.
    if (first.kind === 'os-package' && first.applyActionId === 'packages.update') {
      const pkgs = [...new Set(
        list.filter((r) => r.extra?.['held'] !== true && r.extra?.['keptBack'] !== true).map((r) => r.name),
      )];
      if (pkgs.length > 0) steps.push({ pluginId: first.pluginId, actionId: 'packages.update', deviceId: first.deviceId, input: { packages: pkgs } });
      continue;
    }
    const merged = mergeInputsSafe(list);
    if (merged.clean) {
      steps.push({ pluginId: first.pluginId, actionId: first.applyActionId!, deviceId: first.deviceId, input: merged.input });
    } else {
      for (const r of list) steps.push({ pluginId: r.pluginId, actionId: r.applyActionId!, deviceId: r.deviceId, input: r.applyInput ?? {} });
    }
  }
  return steps;
}

/** Groups flat update rows into device parent nodes (collapsed by default),
 * each carrying its kind-groups and one child per individual update. */
function buildDeviceTree(rows: UpdateRow[]): { devices: UpdateNode[]; childrenByParentKey: Map<string, UpdateNode[]> } {
  const byDevice = new Map<string, UpdateRow[]>();
  for (const r of rows) {
    const key = `${r.deviceId}|${r.pluginId}`;
    let arr = byDevice.get(key);
    if (!arr) { arr = []; byDevice.set(key, arr); }
    arr.push(r);
  }

  const devices: UpdateNode[] = [];
  const childrenByParentKey = new Map<string, UpdateNode[]>();
  for (const [key, list] of byDevice) {
    const first = list[0];
    // Kind-groups: same kind + same apply action merge into one bulk step.
    const groupMap = new Map<string, KindGroup>();
    for (const r of list) {
      const gk = `${r.kind}|${r.applyActionId ?? ''}`;
      let g = groupMap.get(gk);
      if (!g) { g = { kind: r.kind, actionId: r.applyActionId ?? null, rows: [] }; groupMap.set(gk, g); }
      g.rows.push(r);
    }
    const groups = [...groupMap.values()].sort(
      (a, b) => (KIND_ORDER[a.kind] ?? 99) - (KIND_ORDER[b.kind] ?? 99) || String(a.actionId).localeCompare(String(b.actionId))
    );

    devices.push({
      key,
      isDevice: true,
      deviceId: first.deviceId,
      pluginId: first.pluginId,
      deviceName: first.deviceName ?? null,
      managementAddress: first.managementAddress ?? null,
      siteName: first.siteName ?? null,
      pluginName: first.pluginName ?? null,
      groups,
    });

    const children = list.map((r) => ({ key: `${key}|${r.kind}|${r.name}`, isDevice: false as const, row: r }));
    children.sort(
      (a, b) => (KIND_ORDER[a.row!.kind] ?? 99) - (KIND_ORDER[b.row!.kind] ?? 99) || a.row!.name.localeCompare(b.row!.name)
    );
    childrenByParentKey.set(key, children);
  }

  devices.sort((a, b) => String(a.deviceName).localeCompare(String(b.deviceName)));
  return { devices, childrenByParentKey };
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

  // Action catalogs of the plugins reporting updates — used to offer actions a
  // plugin actually advertises (e.g. generic-ssh's `packages.dist-upgrade`).
  const catalogPluginIds = useMemo(() => [...new Set(rows.map((r) => r.pluginId))], [rows]);
  // Distinct key family from the single-plugin `['pluginActions', pluginId]` read:
  // this is a BATCH that stores only action-id lists (not full catalog entries).
  const catalogsQuery = useQuery({
    queryKey: ['pluginActionIds', catalogPluginIds.join('|')],
    queryFn: async () => {
      const out = new Map<string, string[]>();
      await Promise.all(catalogPluginIds.map(async (pluginId) => {
        try {
          const body = await api.pluginActions(pluginId);
          out.set(pluginId, body.actions.map((a) => a.id));
        } catch { /* plugin unreachable — no extra actions offered */ }
      }));
      return out;
    },
    enabled: catalogPluginIds.length > 0,
    staleTime: 5 * 60_000,
  });

  /** True when the plugin advertising this device's updates also offers a
   * distro-level upgrade (generic-ssh `packages.dist-upgrade`). */
  function hasDistUpgrade(pluginId?: string): boolean {
    if (!pluginId) return false;
    const ids = catalogsQuery.data?.get(pluginId);
    return !!ids && ids.includes('packages.dist-upgrade');
  }

  /** True when the plugin offers hold/unhold for OS packages (generic-ssh
   * `packages.hold` / `packages.unhold`). Gates the per-row lock buttons. */
  function hasPackageHold(pluginId?: string): boolean {
    if (!pluginId) return false;
    const ids = catalogsQuery.data?.get(pluginId);
    return !!ids && ids.includes('packages.hold');
  }

  /** True when the plugin's package update action supports `force` (generic-ssh
   * `packages.update` with --allow-change-held-packages). Gates "Force all". */
  function hasForcePackages(pluginId?: string): boolean {
    if (!pluginId) return false;
    const ids = catalogsQuery.data?.get(pluginId);
    return !!ids && ids.includes('packages.update');
  }

  /** Total os-package rows of a device (any apply path). */
  function osPackageCount(node: UpdateNode): number {
    return (node.groups ?? []).filter((g) => g.kind === 'os-package').reduce((n, g) => n + g.rows.length, 0);
  }

  // --- Device → updates hierarchy ---------------------------------------------
  const { devices, childrenByParentKey } = useMemo(() => buildDeviceTree(rows), [rows]);

  // Child-row (individual update) selection — separate from the device-level
  // checkboxes DataTable manages. Lets a user tick several specific apps/packages
  // under one or more devices and update them together instead of clicking each.
  const [selectedChildKeys, setSelectedChildKeys] = useState<Set<string>>(new Set());

  /** The concrete update rows behind the selected child keys (stale keys drop out). */
  const selectedChildren: UpdateRow[] = useMemo(() => {
    if (selectedChildKeys.size === 0) return [];
    const out: UpdateRow[] = [];
    for (const kids of childrenByParentKey.values()) {
      for (const k of kids) if (k.row && selectedChildKeys.has(k.key)) out.push(k.row);
    }
    return out;
  }, [childrenByParentKey, selectedChildKeys]);

  /** How many plan steps the selection would collapse into — shown in the
   * selection bar so the merge effect is visible before confirming. */
  const selectedStepCount = useMemo(
    () => mergedStepsForRows(selectedChildren.filter((r) => r.applyActionId)).length,
    [selectedChildren]
  );

  function toggleChild(key: string) {
    setSelectedChildKeys((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key); else next.add(key);
      return next;
    });
  }

  // Prune child selections whose rows vanished (device deleted / update applied).
  useEffect(() => {
    if (selectedChildKeys.size === 0) return;
    const valid = new Set<string>();
    for (const kids of childrenByParentKey.values()) for (const k of kids) valid.add(k.key);
    setSelectedChildKeys((prev) => {
      let changed = false;
      const next = new Set<string>();
      for (const key of prev) if (valid.has(key)) next.add(key); else changed = true;
      return changed ? next : prev;
    });
  }, [childrenByParentKey, selectedChildKeys]);

  /** The row that summarizes a node's versions/notes: the device's firmware row
   * (falling back to the first row carrying notes) for parent rows, the source
   * row itself for child rows. */
  function summaryRowOf(n: UpdateNode): UpdateRow | undefined {
    if (!n.isDevice) return n.row;
    for (const g of n.groups ?? []) if (g.kind === 'firmware' && g.rows[0]) return g.rows[0];
    return (n.groups ?? []).flatMap((g) => g.rows).find((r) => r.releaseNotesUrl || r.releaseNotes);
  }

  // Release-notes text viewer (TrueNAS propagates its feed's notes verbatim).
  const [notesView, setNotesView] = useState<{ title: string; text: string } | null>(null);

  /** Notes cell: a link to the vendor release notes and/or an inline "notes"
   * button opening the device-provided release-notes text. */
  function NotesCell({ row }: { row?: UpdateRow }) {
    const url = row?.releaseNotesUrl ?? null;
    const text = row?.releaseNotes ?? null;
    if (!url && !text) return <span className="text-faint">—</span>;
    return (
      <span className="inline-flex items-center gap-1.5">
        {url ? (
          <a href={url} target="_blank" rel="noreferrer" title={`Release notes: ${url}`} className="rounded p-0.5 text-info hover:bg-muted">
            <ExternalLink size={14} />
          </a>
        ) : null}
        {text ? (
          <button
            type="button"
            onClick={() => setNotesView({ title: `Release notes — ${row!.name}`, text })}
            className="rounded border border-border bg-card px-1.5 py-0.5 text-xs font-medium hover:bg-muted"
          >
            notes
          </button>
        ) : null}
      </span>
    );
  }

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
        // 'unverified' is terminal too (e.g. a detached dist-upgrade still running) —
        // stop tracking it and let the Plans page show progress.
        if (!['succeeded', 'failed', 'cancelled', 'unverified'].includes(p.status)) continue;
        setPendingPlans((prev) => { const next = { ...prev }; delete next[planId]; return next; });
        try { await api.refreshDevices(entry.deviceIds); } catch { /* fall back to the 30s poll */ }
        void queryClient.invalidateQueries({ queryKey: ['updates'] });
        if (p.status === 'failed' || p.status === 'cancelled') setNotice({ kind: 'error', text: `An update plan finished with errors — check the Plans page.` });
        else if (p.status === 'unverified') setNotice({ kind: 'info', text: `An update plan applied but could not be fully verified yet (e.g. a dist-upgrade still running) — check the Plans page.` });
      }
    }, 3000);
    return () => clearInterval(timer);
  }, [pendingPlans, queryClient]);

  /** Fire ONE plan per (plugin, action) across the given steps — one step per
   * device. In Plan mode plans are saved without executing; in Execute mode
   * they run immediately through the plan workflow (2FA-gated). */
  async function firePlanSteps(
    label: string,
    steps: Array<{ pluginId: string; actionId: string; deviceId: string; input: Record<string, unknown> }>,
  ) {
    if (steps.length === 0) return;
    const byGroup = new Map<string, { pluginId: string; actionId: string; deviceIds: Set<string>; steps: { deviceId: string; input: Record<string, unknown> }[] }>();
    for (const s of steps) {
      const key = `${s.pluginId}|${s.actionId}`;
      let g = byGroup.get(key);
      if (!g) { g = { pluginId: s.pluginId, actionId: s.actionId, deviceIds: new Set(), steps: [] }; byGroup.set(key, g); }
      g.deviceIds.add(s.deviceId);
      g.steps.push({ deviceId: s.deviceId, input: s.input });
    }
    const attempt = async () => {
      let count = 0;
      for (const g of byGroup.values()) {
        const planId = await createAndExecutePlan(g.pluginId, g.actionId, g.steps, mode);
        trackPlan(planId, [...g.deviceIds]);
        count += 1;
      }
      setNotice({ kind: 'ok', text: `${label}: ${count === 1 ? 'plan saved' : `${count} plans saved`} — see the Plans page for progress.` });
    };
    try {
      await attempt();
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) setReauth({ label, retry: attempt });
      else setNotice({ kind: 'error', text: `Could not start update plan: ${(err as Error).message}` });
    }
  }

  /** Parent-row action: one bulk step per kind-group (firmware / all packages /
   * all apps / all images) — the whole device updates with a single click. */
  function applyDevice(node: UpdateNode) {
    void firePlanSteps(`Update ${node.deviceName ?? 'device'}`, bulkStepsForDevice(node));
  }

  /** Parent-row action (secondary): only packages that do NOT need a reboot —
   * the safe subset for scheduled fleet maintenance without service interruption. */
  function applyNoReboot(node: UpdateNode) {
    void firePlanSteps(`Update ${node.deviceName ?? 'device'} (no reboot needed)`, noRebootStepsForDevice(node));
  }

  /** Parent-row action (secondary): distro-level upgrade as a detached job. */
  function applyDistUpgrade(node: UpdateNode) {
    if (!node.deviceId || !node.pluginId) return;
    void firePlanSteps(`Distro upgrade ${node.deviceName ?? 'device'}`, [
      { pluginId: node.pluginId, actionId: 'packages.dist-upgrade', deviceId: node.deviceId, input: {} },
    ]);
  }

  /** Parent-row action (secondary): force ALL packages including held/kept-back.
   * The hold flags stay set afterwards — this upgrades the version once. */
  function applyForceAll(node: UpdateNode) {
    if (!node.deviceId || !node.pluginId) return;
    void firePlanSteps(`Force all packages on ${node.deviceName ?? 'device'}`, [
      { pluginId: node.pluginId, actionId: 'packages.update', deviceId: node.deviceId, input: { force: true } },
    ]);
  }

  /** Child-row action: hold one package against updates (apt-mark hold). */
  function applyHold(row: UpdateRow) {
    void firePlanSteps(`Hold ${row.name}`, [
      { pluginId: row.pluginId, actionId: 'packages.hold', deviceId: row.deviceId, input: { package: row.name } },
    ]);
  }

  /** Child-row action: release one package from a hold (apt-mark unhold). */
  function applyUnhold(row: UpdateRow) {
    void firePlanSteps(`Release ${row.name} from hold`, [
      { pluginId: row.pluginId, actionId: 'packages.unhold', deviceId: row.deviceId, input: { package: row.name } },
    ]);
  }

  /** Child-row action: just this one update, with its own prefilled input. */
  function applySingle(row: UpdateRow) {
    if (!row.applyActionId) return;
    void firePlanSteps(`Update ${row.name}`, [
      { pluginId: row.pluginId, actionId: row.applyActionId, deviceId: row.deviceId, input: row.applyInput ?? {} },
    ]);
  }

  /** Selection-bar bulk action: every kind-group of every selected device. */
  function applySelectedDevices(selected: UpdateNode[]) {
    const steps = selected.flatMap((d) => (d.isDevice ? bulkStepsForDevice(d) : []));
    void firePlanSteps('Update selected devices', steps);
  }

  /** Selection-bar bulk action: only the no-reboot package subset, fleet-wide. */
  function applySelectedNoReboot(selected: UpdateNode[]) {
    const steps = selected.flatMap((d) => (d.isDevice ? noRebootStepsForDevice(d) : []));
    void firePlanSteps('Update selected devices (no reboot needed)', steps);
  }

  /** Bulk action for individually-selected child updates (apps/packages/images).
   * Rows are merged into fewer plan steps where safe (see `mergedStepsForRows`):
   * e.g. N TrueNAS app rows → ONE `containers.upgrade` step with all names, and
   * os-package rows → one explicit `{ packages: [...] }` list — never the empty
   * input that would mean "upgrade ALL". Groups whose inputs conflict keep one
   * step per row with its exact prefilled input. */
  function applySelectedChildren() {
    const actionable = selectedChildren.filter((r) => r.applyActionId);
    if (actionable.length === 0) return;
    const steps = mergedStepsForRows(actionable);
    if (steps.length === 0) {
      setNotice({ kind: 'info', text: 'All selected packages are held or kept back — release them first (unhold button on the row), or use "Force all" on the device.' });
      return;
    }
    const ok = window.confirm(
      `Start update plans for ${actionable.length} specific update(s)? They are grouped into ${steps.length} plan step${steps.length === 1 ? '' : 's'} where safe (held/kept-back packages excluded) and may require 2FA.`
    );
    if (!ok) return;
    void firePlanSteps('Update selected updates', steps);
  }

  // --- "Check now" — force a fresh poll of the devices that report updates ------
  const [checking, setChecking] = useState(false);
  async function checkNow() {
    // 'unm-stack' is the synthetic UNM-itself row — it has no device to poll.
    const deviceIds = Array.from(new Set(rows.map((r) => r.deviceId))).filter((id) => id !== 'unm-stack');
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

  // --- Columns -----------------------------------------------------------------
  const columns: DataTableColumn<UpdateNode>[] = [
    {
      header: 'Device', key: 'deviceName', width: 280, sortable: false, filterable: false,
      exportValue: (n) => (n.isDevice ? `${n.deviceName ?? '?'} (${n.managementAddress ?? '?'})` : ''),
      searchText: (n) => (n.isDevice ? `${n.deviceName ?? ''} ${n.managementAddress ?? ''}`.trim() : ''),
      render: (n) => {
        if (!n.isDevice) return <span className="text-faint">—</span>; // children repeat the device — keep it quiet
        return <DeviceChip deviceName={n.deviceName} managementAddress={n.managementAddress} pluginName={n.pluginName} siteName={n.siteName} interfaces={[]} />;
      },
    },
    {
      header: 'Updates', key: 'kind', width: 240, sortable: false, filterable: false,
      exportValue: (n) => (n.isDevice ? (n.groups ?? []).map((g) => `${KIND_LABELS[g.kind] ?? g.kind} ×${g.rows.length}`).join(', ') : n.row?.kind),
      searchText: (n) => (n.isDevice ? (n.groups ?? []).map((g) => KIND_LABELS[g.kind] ?? g.kind).join(' ') : n.row?.kind ?? ''),
      render: (n) => {
        if (!n.isDevice) return <KindBadge kind={n.row!.kind} />;
        // Parent row: one badge per kind with its count.
        const byKindCount = new Map<string, number>();
        for (const g of n.groups ?? []) byKindCount.set(g.kind, (byKindCount.get(g.kind) ?? 0) + g.rows.length);
        return (
          <span className="flex flex-wrap items-center gap-1">
            {[...byKindCount.entries()].map(([k, c]) => (
              <span key={k} className={`inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-xs font-medium ${KIND_STYLES[k] ?? 'bg-muted text-secondary'}`}>
                {KIND_LABELS[k] ?? k} ×{c}
              </span>
            ))}
          </span>
        );
      },
    },
    {
      header: 'Name', key: 'name', width: 240, sortable: false, filterable: false,
      exportValue: (n) => (n.isDevice ? '' : n.row?.name ?? ''),
      searchText: (n) => (n.isDevice ? '' : n.row?.name ?? ''),
      render: (n) => <span className="font-medium text-foreground">{n.isDevice ? '' : n.row!.name}</span>,
    },
    {
      header: 'Current version', key: 'currentVersion', width: 140, sortable: false, filterable: false,
      exportValue: (n) => orDash(summaryRowOf(n)?.currentVersion),
      searchText: (n) => summaryRowOf(n)?.currentVersion ?? '',
      render: (n) => <span className="font-mono text-xs">{orDash(summaryRowOf(n)?.currentVersion)}</span>,
    },
    {
      header: 'New version', key: 'latestVersion', width: 160, sortable: false, filterable: false,
      exportValue: (n) => orDash(summaryRowOf(n)?.latestVersion),
      searchText: (n) => summaryRowOf(n)?.latestVersion ?? '',
      render: (n) => <span className="font-mono text-xs font-medium text-foreground">{orDash(summaryRowOf(n)?.latestVersion)}</span>,
    },
    {
      header: 'Branch', key: 'branch', width: 130, sortable: false, filterable: false,
      exportValue: (n) => branchOf(n) ?? '',
      searchText: (n) => branchOf(n) ?? '',
      render: (n) => {
        const b = branchOf(n);
        return b ? (
          <span className="rounded bg-muted px-1.5 py-0.5 text-xs font-medium uppercase tracking-wide text-secondary" title={`Current update branch of ${n.isDevice ? n.deviceName ?? 'device' : n.row?.name}`}>{b}</span>
        ) : (
          <span className="text-faint">—</span>
        );
      },
    },
    {
      header: 'Notes', key: 'notes', width: 100, sortable: false, filterable: false, excludeFromExport: true,
      render: (n) => <NotesCell row={summaryRowOf(n)} />,
    },
    {
      header: 'Reboot', key: 'rebootRequired', width: 80, sortable: false, filterable: false, excludeFromExport: true,
      render: (n) => {
        const any = n.isDevice ? (n.groups ?? []).some((g) => g.rows.some((r) => r.rebootRequired)) : !!n.row?.rebootRequired;
        return any ? <span className="text-warning-fg text-xs">yes</span> : <span className="text-faint">—</span>;
      },
    },
    {
      header: 'Action', key: '__action', width: 150, sortable: false, filterable: false, excludeFromExport: true,
      render: (n) => {
        if (!canApply || readOnly) return <span className="text-faint text-xs">read-only</span>;
        if (n.isDevice) {
          const actionable = bulkStepsForDevice(n).length > 0;
          const noRebootCount = noRebootStepsForDevice(n).reduce((c, s) => c + ((s.input['packages'] as string[] | undefined)?.length ?? 0), 0);
          if (!actionable && !hasDistUpgrade(n.pluginId)) {
            return <span className="text-faint text-xs" title="No safe apply path — update manually on the device">manual</span>;
          }
          const pkgCount = osPackageCount(n);
          return (
            <div className="flex items-center gap-0.5">
              {actionable && (
                <ActionIconButton label={`Update all on ${n.deviceName ?? 'device'} — one plan step per kind-group (firmware, packages, apps/images); held/kept-back packages are skipped by the manager`} onClick={() => applyDevice(n)} icon={<ArrowUpCircle size={14} />} />
              )}
              {noRebootCount > 0 && (
                <ActionIconButton label={`Update ${noRebootCount} package(s) that do not need a reboot (held/kept-back excluded)`} onClick={() => applyNoReboot(n)} icon={<ShieldCheck size={14} />} />
              )}
              {pkgCount > 0 && hasForcePackages(n.pluginId) && (
                <ActionIconButton label={`Force-update ALL ${pkgCount} package(s) including held/kept-back — may restart services; hold flags stay set`} onClick={() => applyForceAll(n)} icon={<Zap size={14} />} />
              )}
              {hasDistUpgrade(n.pluginId) && (
                <ActionIconButton label="Distro upgrade (dist-upgrade) — runs detached, may take hours; re-check via the Plans page" onClick={() => applyDistUpgrade(n)} icon={<Layers size={14} />} />
              )}
            </div>
          );
        }
        const row = n.row!;
        return row.applyActionId ? (
          <ActionIconButton label={`Update ${row.name}`} onClick={() => applySingle(row)} icon={<ArrowUpCircle size={14} />} />
        ) : (
          <span className="text-faint text-xs" title="No safe apply path — update manually on the device">manual</span>
        );
      },
    },
  ];

  /** One expanded child rendered as a FULL `<tr>` — an empty chevron cell plus
   * one cell per visible column (ctx.columns), so it stays aligned with the
   * header. Children are leaves: no recursive expansion on this page. */
  function UpdateChildRow({ child, ctx }: { child: UpdateNode; ctx: ExpandChildContext }) {
    return (
      <tr className="bg-accent-sky/40 dark:bg-muted/70">
        <td className="px-1 py-2 align-middle">
          <span className="inline-block h-6 w-6" />
        </td>
        {/* Selection cell — children ARE individually selectable (bulk-update a
         * few specific apps/packages), so render a real checkbox here; the cell is
         * only present when the table itself is selectable. */}
        {ctx.selectable && (
          <td className="px-3 py-2">
            <input
              type="checkbox"
              aria-label={`Select ${child.row?.name ?? 'update'}`}
              checked={selectedChildKeys.has(child.key)}
              onChange={() => toggleChild(child.key)}
              className="h-3.5 w-3.5 rounded border-border text-foreground focus:ring-focus-ring"
            />
          </td>
        )}
        {ctx.columns.map((col) => (
          <td key={col.key} className="overflow-hidden px-4 py-2 text-secondary">
            {childCell(col.key, child)}
          </td>
        ))}
      </tr>
    );
  }

  /** Cell content for one child row column — mirrors the parent columns' render. */
  function childCell(key: string, n: UpdateNode): ReactNode {
    const row = n.row!;
    switch (key) {
      case 'deviceName': return <span className="text-faint">—</span>;
      case 'kind': return <KindBadge kind={row.kind} />;
      case 'name': {
        // apt skips some "upgradable" rows on purpose and they stay listed forever —
        // flag them so the row doesn't look like it's stuck / failing.
        const held = row.extra?.['held'] === true;
        const phased = row.extra?.['phased'] === true;
        const keptBack = row.extra?.['keptBack'] === true;
        return (
          <span className="inline-flex items-center gap-1.5">
            <span className="font-medium text-foreground">{row.name}</span>
            {held && (
              <span className="rounded bg-muted px-1 py-0.5 text-[10px] font-medium uppercase tracking-wide text-faint" title="Held by the admin (apt-mark hold) — bulk upgrades skip it on purpose">
                held
              </span>
            )}
            {phased && (
              <span className="rounded bg-muted px-1 py-0.5 text-[10px] font-medium uppercase tracking-wide text-faint" title="Deferred by Ubuntu's phased rollout — this host is not in the version's cohort yet">
                phased
              </span>
            )}
            {keptBack && (
              <span className="rounded bg-muted px-1 py-0.5 text-[10px] font-medium uppercase tracking-wide text-faint" title="Kept back by apt — a dependency is blocked, so it cannot be upgraded alone">
                kept back
              </span>
            )}
          </span>
        );
      }
      case 'currentVersion':
        return <span className="font-mono text-xs">{orDash(row.currentVersion)}</span>;
      case 'latestVersion':
        return <span className="font-mono text-xs font-medium text-foreground">{orDash(row.latestVersion)}</span>;
      case 'branch': {
        const b = row.branch ?? null;
        return b ? (
          <span className="rounded bg-muted px-1.5 py-0.5 text-xs font-medium uppercase tracking-wide text-secondary" title={`Current update branch of ${row.name}`}>{b}</span>
        ) : (
          <span className="text-faint">—</span>
        );
      }
      case 'notes':
        return <NotesCell row={row} />;
      case 'rebootRequired':
        return row.rebootRequired ? <span className="text-warning-fg text-xs">yes</span> : <span className="text-faint">—</span>;
      case '__action': {
        if (!canApply || readOnly) return <span className="text-faint text-xs">read-only</span>;
        const held = row.extra?.['held'] === true;
        const canHold = row.kind === 'os-package' && hasPackageHold(row.pluginId);
        return (
          <div className="flex items-center gap-0.5">
            {row.applyActionId ? (
              <ActionIconButton label={`Update ${row.name}`} onClick={() => applySingle(row)} icon={<ArrowUpCircle size={14} />} />
            ) : (
              <span className="text-faint text-xs" title="No safe apply path — update manually on the device">manual</span>
            )}
            {canHold && held ? (
              <ActionIconButton label={`Release ${row.name} from hold — bulk updates will install it again`} onClick={() => applyUnhold(row)} icon={<Unlock size={14} />} />
            ) : canHold ? (
              <ActionIconButton label={`Hold ${row.name} against updates — bulk upgrades skip it on purpose`} onClick={() => applyHold(row)} icon={<Lock size={14} />} />
            ) : null}
          </div>
        );
      }
      default: return null;
    }
  }

  return (
    <Layout
      title="Updates"
      actions={
        rows.length > 0 ? (
          <button
            type="button"
            onClick={() => void checkNow()}
            disabled={checking}
            className="inline-flex items-center gap-2 rounded-md border border-border px-3 py-1.5 text-sm font-medium text-secondary hover:bg-muted disabled:opacity-60"
          >
            {checking ? <Loader2 className="h-4 w-4 animate-spin" /> : <RefreshCw className="h-4 w-4" />} Check now
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
            {(() => {
              const releaseHref = stack.releaseUrl ?? stack.notesUrl ?? undefined;
              return releaseHref && stack.available ? (
                <a href={releaseHref} target="_blank" rel="noreferrer" className="mt-2 inline-block text-xs text-info underline">
                  Release page →
                </a>
              ) : null;
            })()}
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
            <span><strong className="text-foreground">{devices.length}</strong> device{devices.length === 1 ? '' : 's'} with updates</span>
            <span className="text-faint">·</span>
            {Object.entries(byKind).map(([k, n]) => (
              <span key={k} className="inline-flex items-center gap-1"><KindBadge kind={k} /> {n}</span>
            ))}
          </div>
        )}

        {/* Child-update selection bar — appears when specific apps/packages are
            ticked in expanded rows (separate from the device-level checkboxes). */}
        {selectedChildren.length > 0 && canApply && !readOnly && (
          <div className="flex flex-wrap items-center gap-2 rounded-md border border-border bg-info/60 px-3 py-1.5 text-sm">
            <span className="font-medium text-secondary">
              {selectedChildren.length} update{selectedChildren.length === 1 ? '' : 's'} selected
              {selectedStepCount > 0 && (
                <span className="text-muted-foreground"> · grouped into {selectedStepCount} plan step{selectedStepCount === 1 ? '' : 's'}</span>
              )}
            </span>
            <button
              type="button"
              onClick={() => applySelectedChildren()}
              disabled={selectedStepCount === 0}
              title={selectedStepCount === 0 ? 'All selected packages are held or kept back — unhold them first, or use "Force all" on the device' : undefined}
              className="rounded-md border border-border bg-card px-2.5 py-1 text-xs font-medium text-secondary hover:bg-background disabled:opacity-50"
            >
              Update selected ({selectedStepCount})
            </button>
            <button
              type="button"
              onClick={() => setSelectedChildKeys(new Set())}
              className="ml-auto text-xs font-medium text-muted-foreground underline-offset-2 hover:text-secondary hover:underline"
            >
              Clear selection
            </button>
          </div>
        )}

        {/* Updates table — one collapsed row per device; expand to see and update
            each package/app/image individually. */}
        <DataTable<UpdateNode>
          columns={columns}
          rows={devices}
          rowKey={(n) => n.key}
          storageKey="updates"
          searchPlaceholder="Search devices or updates…"
          emptyMessage="No available updates — all devices are up to date."
          selectable={canApply && !readOnly}
          bulkActions={[
            {
              label: 'Update selected devices',
              confirm: (count) => `Start update plans for ${count} device(s)? Each kind-group (firmware, packages, apps/images) becomes one plan step and may require 2FA.`,
              onClick: (sel) => applySelectedDevices(sel),
            },
            {
              label: 'Update selected — no reboot needed',
              confirm: (count) => `Start update plans for ${count} device(s) covering ONLY packages that do not need a reboot? Good for scheduled fleet maintenance without service interruption.`,
              onClick: (sel) => applySelectedNoReboot(sel),
            },
          ]}
          expandable={{
            childrenOf: (n) => (n.isDevice ? childrenByParentKey.get(n.key) ?? [] : []),
            renderChild: (child, _parent, ctx) => <UpdateChildRow child={child} ctx={ctx} />,
          }}
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

        {/* Release-notes text viewer — device-provided notes (e.g. TrueNAS feed). */}
        {notesView && (
          <DialogShell
            title={notesView.title}
            onClose={() => setNotesView(null)}
            maxWidth="max-w-2xl"
            bodyMaxHeight="80vh"
          >
            <pre className="whitespace-pre-wrap font-mono text-xs text-secondary">{notesView.text}</pre>
          </DialogShell>
        )}
      </div>
    </Layout>
  );
}
