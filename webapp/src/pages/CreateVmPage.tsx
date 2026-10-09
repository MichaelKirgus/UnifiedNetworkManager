import { useEffect, useMemo, useRef, useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { Loader2, Monitor, RefreshCw } from 'lucide-react';
import { SchemaForm, validateSchema } from '../components/SchemaForm';
import { ReauthDialog } from '../components/ReauthDialog';
import { WizardLayout } from '../components/Wizard';
import { createAndExecutePlan, useExecutionMode } from '../executionMode';
import { api, ApiError, CatalogEntry, Device, InputSchema } from '../api/client';

/**
 * CreateVmPage — "Create VM" as a full-page wizard on the shared <WizardLayout>
 * shell (replaces the old modal dialog). Hypervisor-generic: the form is driven
 * by the plugin's `vms.create` inputSchema (rendered via SchemaForm), so any
 * future hypervisor plugin implementing that id gets this wizard for free.
 * Custom controls on top: an appliance picker (multi-appliance fleets), a
 * disk-dataset picker and a NIC section — all fed by read-only catalog actions
 * (vms.create-choices / vms.nic-choices) on the SELECTED device, so choices
 * always match the target. Submission flows through the plan workflow
 * (2FA-gated, audited).
 *
 * Two steps: CONFIGURE → DONE (executed / saved-as-plan summary with a link to
 * the created plan and back to VMs).
 */

export interface CreateVmTarget {
  /** The appliance device (UNM device row) the VM will be created on. */
  device: Device;
  pluginId: string;
}

/** Generates a random locally-administered unicast MAC (02:xx:…). */
function generateMac(): string {
  const b = [0x02, ...Array.from({ length: 5 }, () => Math.floor(Math.random() * 256))];
  return b.map((x) => x.toString(16).padStart(2, '0')).join(':').toUpperCase();
}

/** Human-readable size for a MiB value (memory fields). */
function humanMiB(mib: number): string {
  if (mib >= 1024) return `${(mib / 1024).toLocaleString()} GiB`;
  return `${mib} MiB`;
}

/** Human-readable size for a byte value (disk fields). */
function humanBytes(b: number): string {
  const gb = b / 1073741824;
  if (gb >= 1024) return `${(gb / 1024).toLocaleString()} TiB`;
  return `${gb.toLocaleString()} GiB`;
}

/** Common memory presets in MiB, labelled with friendly GB values. */
const MEMORY_PRESETS: { value: number; label: string }[] = [512, 1024, 2048, 4096, 8192, 16384, 32768, 65536].map((v) => ({ value: v, label: humanMiB(v) }));

/** Common disk presets in bytes, labelled with friendly GB/TB values. */
const DISK_PRESETS: { value: number; label: string }[] = [
  ...[10, 20, 50, 100, 200, 500].map((g) => ({ value: g * 1073741824, label: `${g} GB` })),
  ...[1, 2, 4, 8].map((t) => ({ value: t * 1099511627776, label: `${t} TB` })),
];

/** A size combobox: friendly preset options (GB/TB labels) that resolve to the
 * integer MiB/bytes value; a non-preset current value is kept as an extra option
 * so custom sizes are never lost. */
function SizeSelect({ value, presets, format, onChange }: { value: number | undefined; presets: { value: number; label: string }[]; format: (n: number) => string; onChange: (v: number | undefined) => void }) {
  const opts = value !== undefined && !presets.some((p) => p.value === value) ? [{ value, label: format(value) }, ...presets] : presets;
  return (
    <select value={value ?? ''} onChange={(e) => onChange(e.target.value === '' ? undefined : Number(e.target.value))}
      className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm text-foreground">
      <option value="">Select a size…</option>
      {opts.map((o) => (<option key={o.value} value={o.value}>{o.label}</option>))}
    </select>
  );
}

/** Outcome of a successful submit — drives the DONE step. */
interface CreateResult {
  kind: 'executed' | 'saved';
  name: string;
  deviceName: string;
  planId?: string;
}

export default function CreateVmPage() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  // Where "Cancel" returns to (set by the entry point).
  const from = searchParams.get('from') ?? '/vms';
  const { mode } = useExecutionMode();
  const isPlanMode = mode === 'plan';
  const isReadOnly = mode === 'readonly';

  // --- Targets: hypervisor devices advertising vms.create -----------------------
  // Computed from the DEVICES list (not the VM inventory) so a fresh appliance
  // with zero VMs still shows up. Catalogs are react-query cached.
  const devicesQuery = useQuery({ queryKey: ['devices'], queryFn: api.devices });
  const allPluginIds = useMemo(
    () => Array.from(new Set((devicesQuery.data ?? []).flatMap((d) => (d.plugins ?? []).map((p) => p.pluginId)))),
    [devicesQuery.data],
  );
  // Same data as the Containers/Create-app "all plugins" catalog — share that
  // key family so a fresh fetch on one page is reused by the other.
  const catalogsQuery = useQuery({
    queryKey: ['pluginActionCatalogsAll', allPluginIds.join('|')],
    queryFn: async () => {
      const entries = await Promise.all(
        allPluginIds.map(async (pluginId) => [pluginId, (await api.pluginActions(pluginId)).actions] as const),
      );
      return Object.fromEntries(entries);
    },
    enabled: allPluginIds.length > 0,
  });

  const targets = useMemo<CreateVmTarget[]>(() => {
    const out: CreateVmTarget[] = [];
    for (const d of devicesQuery.data ?? []) {
      for (const a of d.plugins ?? []) {
        if (!a.pluginId) continue;
        const actions = catalogsQuery.data?.[a.pluginId];
        if (Array.isArray(actions) && actions.some((x) => x.id === 'vms.create')) out.push({ device: d, pluginId: a.pluginId });
      }
    }
    return out;
  }, [devicesQuery.data, catalogsQuery.data]);

  // --- Wizard state -------------------------------------------------------------
  const [step, setStep] = useState<1 | 2>(1);
  const [result, setResult] = useState<CreateResult | null>(null);
  /** Bumped to remount the form fresh for "create another VM". */
  const [formKey, setFormKey] = useState(0);

  const targetsLoading = devicesQuery.isLoading || (allPluginIds.length > 0 && !catalogsQuery.data);

  return (
    <WizardLayout
      title="Create VM"
      icon={<Monitor className="h-4 w-4 text-primary" />}
      steps={[{ label: 'Configure' }, { label: 'Done' }]}
      current={step - 1}
      onExit={() => navigate(from)}
    >
      {/* ================= STEP 1 — configure ================= */}
      {step === 1 && (
        targetsLoading ? (
          <div className="rounded-md border border-border bg-background p-6 text-center">
            <Loader2 className="mx-auto h-6 w-6 animate-spin text-primary" />
            <p className="mt-3 text-sm font-medium text-secondary">Checking which appliances can create VMs…</p>
          </div>
        ) : targets.length === 0 ? (
          <div className="space-y-4">
            <p className="text-sm text-secondary">
              No registered device currently advertises a VM-create action. Assign a hypervisor plugin to a device
              first — the wizard will appear here automatically.
            </p>
            <div className="flex justify-end border-t border-border pt-3">
              <button type="button" onClick={() => navigate(from)} className="inline-flex items-center gap-2 rounded-md bg-primary px-4 py-1.5 text-sm font-medium text-white hover:bg-primary-hover">
                Back to VMs
              </button>
            </div>
          </div>
        ) : (
          <CreateVmForm
            key={formKey}
            targets={targets}
            isPlanMode={isPlanMode}
            isReadOnly={isReadOnly}
            onCancel={() => navigate(from)}
            onDone={(r) => { setResult(r); setStep(2); }}
          />
        )
      )}

      {/* ================= STEP 2 — done ================= */}
      {step === 2 && result && (
        <div className="space-y-4">
          {result.kind === 'saved' ? (
            <div className="flex items-start gap-2 rounded-md border border-success-border bg-success px-3 py-2 text-sm text-success-fg">
              <Monitor size={16} className="mt-0.5 shrink-0" />
              <span>
                VM creation for <span className="font-mono font-medium">{result.name}</span> on {result.deviceName} was saved as a plan — it was NOT executed.
                Open the Plans center to run it later (or schedule it).
              </span>
            </div>
          ) : (
            <div className="flex items-start gap-2 rounded-md border border-success-border bg-success px-3 py-2 text-sm text-success-fg">
              <Monitor size={16} className="mt-0.5 shrink-0" />
              <span>
                VM creation for <span className="font-mono font-medium">{result.name}</span> on {result.deviceName} started — the plan is running in the background.
                Track its progress via the plans icon in the top bar; the VMs page refreshes when it settles.
              </span>
            </div>
          )}
          <p className="text-sm text-secondary">
            The creation ran through the standard plan workflow (2FA-gated, audited).
          </p>
          {result.planId && (
            <button type="button" onClick={() => navigate(`/plans/${result.planId}`)} className="text-primary hover:underline">
              View plan →
            </button>
          )}
          <div className="flex justify-end gap-2 border-t border-border pt-3">
            <button
              type="button"
              onClick={() => { setResult(null); setFormKey((k) => k + 1); setStep(1); }}
              className="rounded-md px-3 py-1.5 text-sm text-secondary hover:bg-muted"
            >
              Create another VM
            </button>
            <button
              type="button"
              onClick={() => navigate(from)}
              className="inline-flex items-center gap-2 rounded-md bg-primary px-4 py-1.5 text-sm font-medium text-white hover:bg-primary-hover"
            >
              Back to VMs
            </button>
          </div>
        </div>
      )}
    </WizardLayout>
  );
}

// ---------------------------------------------------------------------------
// Step-1 form — appliance picker + schema-driven fields + memory/disk/NIC
// sections. Ported from the old CreateVmDialog modal; all state lives here so
// "create another" can remount it fresh via a key bump.
// ---------------------------------------------------------------------------

interface CreateVmFormProps {
  targets: CreateVmTarget[];
  isPlanMode: boolean;
  isReadOnly: boolean;
  onCancel: () => void;
  /** Called with the outcome once the plan was created (and executed, if not in plan mode). */
  onDone: (r: CreateResult) => void;
}

function CreateVmForm({ targets, isPlanMode, isReadOnly, onCancel, onDone }: CreateVmFormProps) {
  const { mode } = useExecutionMode();
  // Which appliance to create on — the form owns this selection so multi-
  // appliance fleets work (the entry button just opens the wizard).
  const [targetIdx, setTargetIdx] = useState(0);
  const target = targets[Math.min(targetIdx, Math.max(targets.length - 1, 0))] ?? null;
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [schema, setSchema] = useState<InputSchema | null>(null);
  const [values, setValues] = useState<Record<string, unknown>>({});
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({});
  // Per-appliance choices (re-fetched when the appliance changes).
  const [datasets, setDatasets] = useState<{ name: string; mountpoint: string }[]>([]);
  const [bridges, setBridges] = useState<string[]>([]);
  const [macvlans, setMacvlans] = useState<string[]>([]);
  const [saving, setSaving] = useState(false);
  const [reauth, setReauth] = useState(false);
  // Form defaults are applied ONCE — switching appliance must not wipe user input.
  const initializedRef = useRef(false);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      if (!target) return;
      try {
        setLoading(true);
        setError(null);
        // The action's inputSchema IS the form — read it from the catalog.
        const cat = await api.pluginActions(target.pluginId);
        const entry: CatalogEntry | undefined = cat.actions.find((a) => a.id === 'vms.create');
        if (!entry) {
          setSchema(null); // can't happen in practice — the wizard is gated on vms.create
          return;
        }
        setSchema(entry.inputSchema ?? {});
        if (!initializedRef.current) {
          // Pre-fill defaults from the schema itself (first load only).
          const init: Record<string, unknown> = {};
          for (const [k, p] of Object.entries(entry.inputSchema ?? {})) {
            if (p?.default !== undefined) init[k] = p.default;
          }
          setValues(init);
          initializedRef.current = true;
        }
        // Dataset + NIC pickers — read-only catalog actions on the SELECTED device.
        const [choicesRes, nicRes] = await Promise.all([
          api.executePluginAction(target.pluginId, { deviceId: target.device.id, actionId: 'vms.create-choices', input: {} }),
          api.executePluginAction(target.pluginId, { deviceId: target.device.id, actionId: 'vms.nic-choices', input: {} }).catch(() => null),
        ]);
        if (cancelled) return;
        const dsList = Array.isArray(choicesRes.details.datasets) ? (choicesRes.details.datasets as { name: string; mountpoint: string }[]) : [];
        setDatasets(dsList);
        const b = nicRes?.details.bridges;
        const m = nicRes?.details.macvlans;
        const brList = Array.isArray(b) ? (b as string[]) : [];
        const mvList = Array.isArray(m) ? (m as string[]) : [];
        setBridges(brList);
        setMacvlans(mvList);
        // Dataset + NIC selections are appliance-specific — drop them when they
        // don't exist on the newly selected appliance.
        setValues((v) => {
          const ds = typeof v['dataset'] === 'string' ? (v['dataset'] as string) : '';
          const na = typeof v['nicAttach'] === 'string' ? (v['nicAttach'] as string) : '';
          if ((ds && !dsList.some((d) => d.name === ds)) || (na && !brList.includes(na) && !mvList.includes(na))) {
            const next = { ...v };
            if (ds && !dsList.some((d) => d.name === ds)) delete next['dataset'];
            if (na && !brList.includes(na) && !mvList.includes(na)) delete next['nicAttach'];
            return next;
          }
          return v;
        });
      } catch (err) {
        if (!cancelled) setError(err instanceof Error ? err.message : String(err));
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => { cancelled = true; };
  }, [target?.pluginId, target?.device.id]); // eslint-disable-line react-hooks/exhaustive-deps

  function setField(key: string, value: unknown) {
    const next = { ...values, [key]: value };
    if (key === 'nicAttach' && typeof value === 'string' && value !== '') {
      // Auto-generate a MAC when empty. The bridge/MACVLAN kind is inferred by
      // the appliance from the chosen interface (TrueNAS v26) — no selector needed.
      if (!next['mac']) next['mac'] = generateMac();
    } else if (key === 'nicAttach') {
      // No NIC selected — drop the now-irrelevant MAC.
      delete next['mac'];
    } else if (key === 'diskMode') {
      // Switching disk mode clears the fields of the other mode.
      if (value === 'path') { delete next['dataset']; delete next['sizeBytes']; delete next['zvolName']; }
      else { delete next['diskPath']; }
    }
    setValues(next);
  }

  async function submit() {
    if (isReadOnly || !schema || !target) return; // Read-Only / no target — safety nets.
    const errs = validateSchema(schema, values);
    // The custom controls aren't covered by the schema validator — check them here.
    const dm = typeof values['diskMode'] === 'string' ? (values['diskMode'] as string) : 'zvol';
    if (dm === 'zvol') {
      if (!datasetValue) errs['dataset'] = 'Select a dataset for the new ZVOL';
      if (!(typeof values['sizeBytes'] === 'number')) errs['sizeBytes'] = 'Select a disk size';
    } else {
      const dp = typeof values['diskPath'] === 'string' ? (values['diskPath'] as string) : '';
      if (!dp.startsWith('/dev/zvol/')) errs['diskPath'] = 'Must be an existing /dev/zvol/… path';
    }
    setFieldErrors(errs);
    if (Object.keys(errs).length > 0) return;
    setSaving(true);
    setError(null);
    const attempt = async () => {
      const planId = await createAndExecutePlan(target.pluginId, 'vms.create', [{ deviceId: target.device.id, input: values }], mode);
      onDone({ kind: isPlanMode ? 'saved' : 'executed', name: String(values['name'] ?? ''), deviceName: target.device.name, planId });
    };
    try {
      await attempt();
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) setReauth(true);
      else setError(err instanceof Error ? err.message : String(err));
      setSaving(false);
    }
  }

  // The schema-driven part of the form — everything EXCEPT the custom controls
  // rendered explicitly below (appliance/disk/memory/NIC pickers with live
  // choices + friendly size comboboxes). Keeps name/vcpus/etc. generic.
  const CUSTOM_KEYS = ['dataset', 'nicAttach', 'mac', 'nicType', 'memoryMiB', 'minMemoryMiB', 'sizeBytes', 'diskPath', 'diskMode', 'zvolName', 'diskType'];
  const formSchema = useMemo(() => {
    if (!schema) return null;
    const out: InputSchema = {};
    for (const [k, p] of Object.entries(schema)) {
      if (CUSTOM_KEYS.includes(k)) continue;
      out[k] = p;
    }
    return out;
  }, [schema]);

  const nicAttach = typeof values['nicAttach'] === 'string' ? (values['nicAttach'] as string) : '';
  const macValue = typeof values['mac'] === 'string' ? (values['mac'] as string) : '';
  const datasetValue = typeof values['dataset'] === 'string' ? (values['dataset'] as string) : '';
  const vmName = typeof values['name'] === 'string' ? (values['name'] as string) : '';
  const diskMode = typeof values['diskMode'] === 'string' ? (values['diskMode'] as string) : 'zvol';
  const sizeBytesVal = typeof values['sizeBytes'] === 'number' ? (values['sizeBytes'] as number) : undefined;
  const memVal = typeof values['memoryMiB'] === 'number' ? (values['memoryMiB'] as number) : undefined;
  const minMemVal = typeof values['minMemoryMiB'] === 'number' ? (values['minMemoryMiB'] as number) : undefined;
  const zvolNameVal = typeof values['zvolName'] === 'string' ? (values['zvolName'] as string) : '';
  const diskTypeVal = typeof values['diskType'] === 'string' ? (values['diskType'] as string) : 'VIRTIO';
  // The ZVOL leaf that will be created — override if given, else derived from the VM name.
  // Case is preserved (ZFS dataset names are case-sensitive); only invalid chars stripped.
  const zvolLeaf = (zvolNameVal || vmName).replace(/[^a-zA-Z0-9_]/g, '');

  return (
    <div className="space-y-4">
      <p className="text-sm text-secondary">
        {targets.length === 1 && target ? `Applies via the plan workflow on ${target.device.name}.` : 'Applies via the plan workflow — pick an appliance below.'}
      </p>

      {isReadOnly && (
        <div className="flex items-start gap-2 rounded-md border border-warning-border bg-warning px-3 py-2 text-xs text-warning-fg">
          Read-only mode is active — this change cannot be saved or applied. Switch to Plan or Execute in the top bar.
        </div>
      )}
      {loading && (
        <p className="flex items-center gap-2 text-sm text-muted-foreground"><Loader2 size={14} className="animate-spin" /> Loading VM creation form…</p>
      )}
      {error && !reauth && (
        <div className="rounded-md border border-danger-border bg-danger px-3 py-2 text-xs text-danger-fg">{error}</div>
      )}

      {!loading && !error && schema && target && (
        <>
          {/* Appliance picker — multi-appliance fleets. */}
          {targets.length > 1 && (
            <div>
              <label className="mb-1 block text-xs font-medium text-secondary">Appliance</label>
              <select value={targetIdx} onChange={(e) => setTargetIdx(Number(e.target.value))}
                className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm text-foreground">
                {targets.map((t, i) => (
                  <option key={`${t.device.id}|${t.pluginId}`} value={i}>{t.device.name}</option>
                ))}
              </select>
            </div>
          )}

          {/* VM basics — schema-driven (name, description, vCPUs, firmware…). */}
          {formSchema && Object.keys(formSchema).length > 0 && (
            <SchemaForm schema={formSchema} values={values} onChange={(v) => setValues(v)} fieldErrors={fieldErrors} />
          )}

          {/* Memory — friendly GB comboboxes. */}
          <div className="space-y-2 rounded-md border border-border bg-background/60 p-3">
            <label className="block text-xs font-medium text-secondary">Memory</label>
            <SizeSelect value={memVal} presets={MEMORY_PRESETS} format={humanMiB} onChange={(v) => setField('memoryMiB', v)} />
            {fieldErrors['memoryMiB'] && <p className="text-xs text-danger-fg">{fieldErrors['memoryMiB']}</p>}
            <div>
              <label className="mb-1 block text-xs font-medium text-secondary">Minimum memory (optional)</label>
              <SizeSelect value={minMemVal} presets={MEMORY_PRESETS} format={humanMiB} onChange={(v) => setField('minMemoryMiB', v)} />
            </div>
          </div>

          {/* Disk — mode + zvol/path specifics. */}
          <div className="space-y-2 rounded-md border border-border bg-background/60 p-3">
            <label className="block text-xs font-medium text-secondary">Disk</label>
            <select value={diskMode} onChange={(e) => setField('diskMode', e.target.value)}
              className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm text-foreground">
              <option value="zvol">New ZVOL (recommended)</option>
              <option value="path">Existing disk path</option>
            </select>

            {diskMode === 'zvol' ? (
              <>
                {datasets.length > 0 && (
                  <div>
                    <label className="mb-1 block text-xs font-medium text-secondary">Disk dataset</label>
                    <select value={datasetValue} onChange={(e) => setField('dataset', e.target.value || undefined)}
                      className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm text-foreground">
                      <option value="">Select a dataset…</option>
                      {datasets.map((d) => (<option key={d.name} value={d.name}>{d.name}</option>))}
                    </select>
                    {fieldErrors['dataset'] && <p className="mt-1 text-xs text-danger-fg">{fieldErrors['dataset']}</p>}
                  </div>
                )}
                <div>
                  <label className="mb-1 block text-xs font-medium text-secondary">Disk size</label>
                  <SizeSelect value={sizeBytesVal} presets={DISK_PRESETS} format={humanBytes} onChange={(v) => setField('sizeBytes', v)} />
                  {fieldErrors['sizeBytes'] && <p className="mt-1 text-xs text-danger-fg">{fieldErrors['sizeBytes']}</p>}
                </div>
                <div>
                  <label className="mb-1 block text-xs font-medium text-secondary">ZVOL name (optional)</label>
                  <input type="text" value={zvolNameVal} onChange={(e) => setField('zvolName', e.target.value || undefined)}
                    placeholder={vmName ? vmName.replace(/[^a-zA-Z0-9_]/g, '') : 'derived from VM name'}
                    className="w-full rounded-md border border-border bg-background px-3 py-2 font-mono text-sm text-foreground placeholder:text-faint" />
                  {datasetValue && zvolLeaf && (
                    <p className="mt-1 text-xs text-faint">Will create ZVOL <span className="font-mono">{datasetValue}/{zvolLeaf}</span></p>
                  )}
                </div>
              </>
            ) : (
              <div>
                <label className="mb-1 block text-xs font-medium text-secondary">Disk path</label>
                <input type="text" value={typeof values['diskPath'] === 'string' ? (values['diskPath'] as string) : ''} onChange={(e) => setField('diskPath', e.target.value || undefined)}
                  placeholder="/dev/zvol/POOL/disk" pattern="^/dev/zvol/.+"
                  className="w-full rounded-md border border-border bg-background px-3 py-2 font-mono text-sm text-foreground placeholder:text-faint" />
                {fieldErrors['diskPath'] && <p className="mt-1 text-xs text-danger-fg">{fieldErrors['diskPath']}</p>}
              </div>
            )}

            <div>
              <label className="mb-1 block text-xs font-medium text-secondary">Controller</label>
              <select value={diskTypeVal} onChange={(e) => setField('diskType', e.target.value)}
                className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm text-foreground">
                <option value="VIRTIO">VIRTIO (performance)</option>
                <option value="AHCI">AHCI (compatibility)</option>
              </select>
            </div>
          </div>

          {/* NIC — interface selection (bridges + MACVLANs in optgroups); the
              attachment kind is inferred by the appliance from the interface,
              and a MAC is auto-generated. */}
          <div className="space-y-2 rounded-md border border-border bg-background/60 p-3">
            <label className="block text-xs font-medium text-secondary">Network (optional)</label>
            <div>
              <label className="mb-1 block text-xs font-medium text-secondary">Interface</label>
              <select value={nicAttach} onChange={(e) => setField('nicAttach', e.target.value || undefined)}
                disabled={bridges.length === 0 && macvlans.length === 0}
                className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm text-foreground disabled:opacity-50">
                <option value="">No NIC — attach later</option>
                {bridges.length > 0 && (<optgroup label="Bridges">{bridges.map((b) => (<option key={b} value={b}>{b}</option>))}</optgroup>)}
                {macvlans.length > 0 && (<optgroup label="MACVLANs">{macvlans.map((m) => (<option key={m} value={m}>{m}</option>))}</optgroup>)}
              </select>
            </div>
            {nicAttach !== '' && (
              <div className="flex items-center gap-2">
                <input type="text" value={macValue} onChange={(e) => setField('mac', e.target.value || undefined)}
                  pattern="^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$" placeholder="MAC address (auto-generated)"
                  className="flex-1 rounded-md border border-border bg-background px-3 py-1.5 font-mono text-sm text-foreground placeholder:text-faint" />
                <button type="button" onClick={() => setField('mac', generateMac())} title="Generate a new MAC address" aria-label="Generate a new MAC address"
                  className="rounded-md border border-border bg-background p-1.5 text-secondary hover:bg-muted">
                  <RefreshCw size={13} />
                </button>
              </div>
            )}
          </div>
        </>
      )}

      {/* Step footer — Cancel (top bar has one too) + primary CTA. */}
      <div className="flex justify-end gap-2 border-t border-border pt-3">
        <button type="button" onClick={onCancel} className="rounded-md px-3 py-1.5 text-sm text-secondary hover:bg-muted">
          Cancel
        </button>
        <button
          type="button"
          disabled={!schema || saving || isReadOnly}
          title={isReadOnly ? 'Read-only mode — switch to Plan or Execute to make changes' : undefined}
          onClick={() => void submit()}
          className="inline-flex items-center gap-2 rounded-md bg-primary px-4 py-1.5 text-sm font-medium text-white hover:bg-primary-hover disabled:cursor-not-allowed disabled:opacity-50"
        >
          {saving && <Loader2 size={14} className="animate-spin" />}
          {isPlanMode ? 'Save as plan' : 'Create VM'}
        </button>
      </div>

      {reauth && (
        <ReauthDialog
          contextLabel={`Create VM on ${target?.device.name ?? ''}`}
          onClose={() => setReauth(false)}
          onSuccess={async () => {
            setReauth(false);
            try { await submit(); } catch { /* the form surfaces its own error state */ }
          }}
        />
      )}
    </div>
  );
}
