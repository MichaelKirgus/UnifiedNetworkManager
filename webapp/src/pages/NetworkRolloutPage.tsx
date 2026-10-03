import { useEffect, useMemo, useRef, useState } from 'react';
import { useLocation, useNavigate, useSearchParams } from 'react-router-dom';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { ChevronDown, Globe, Loader2, Settings2 } from 'lucide-react';
import clsx from 'clsx';
import { api, CatalogEntry, Device, DocumentedNetwork, NetworkCheckResultDto, NetworkLayer, PreflightInterfaceOptionDto, PreflightPortDto, PreflightResultDto, Site, TopologyResponse } from '../api/client';
import { useExecutionMode } from '../executionMode';
import { WizardLayout } from '../components/Wizard';

/**
 * NetworkRolloutPage — the fleet abstraction for "create Network XY with VLAN
 * ID on all devices at site/tag/LAYER", as a FULL PAGE (not a dialog) so large
 * fleets stay usable on small screens. Two steps:
 *   1. SCOPE + shared inputs: pick targets by site, tags, TOPOLOGY LAYER or
 *      manually; enter the network (name/VLAN/L3 v4+v6); optionally auto-assign
 *      each device's next free IP. No generic interface field — interfaces differ
 *      per device and are resolved in step 2.
 *   2. PREFLIGHT: each supporting plugin probes its devices' live state
 *      (read-only) with a live progress bar + per-plugin detail, then the user
 *      reviews/overrides per device and one plan per plugin is created.
 *
 * Reuses the shared <WizardLayout> shell so future wizards (WiFi rollout,
 * plugin-driven tasks) can adopt the same chrome.
 */

const INTENT_ID = 'network.create';

/** Plugins whose devices are L2-only by default (switches) — the IP toggle starts OFF there. */
const L2_ONLY_PLUGINS = new Set(['mikrotik-swos']);

type PortMode = 'all' | 'trunk' | 'uplink' | 'custom';

/** Per-device rollout state, keyed `${pluginId}:${deviceId}`. */
interface DeviceRolloutState {
  /** null = untouched → smart default (L2-only plugins OFF, others ON). */
  ipEnabled: boolean | null;
  portMode: PortMode;
  customPorts: string[];
  vlanId?: string;
  interface?: string;
  cidr?: string;
  cidrV6?: string;
}

const EMPTY_DEVICE_STATE: DeviceRolloutState = { ipEnabled: null, portMode: 'all', customPorts: [] };

function effectiveIpEnabled(pid: string, st: DeviceRolloutState | undefined): boolean {
  if (st?.ipEnabled != null) return st.ipEnabled;
  return !L2_ONLY_PLUGINS.has(pid);
}

/** Port names selected for a device given its mode + the preflight port list. */
function selectedPorts(mode: PortMode, custom: string[], ports?: PreflightPortDto[]): string[] {
  if (!ports || ports.length === 0) return [];
  if (mode === 'all') return ports.map((p) => p.name);
  if (mode === 'trunk') return ports.filter((p) => p.trunk).map((p) => p.name);
  if (mode === 'uplink') return ports.filter((p) => p.uplink).map((p) => p.name);
  return custom;
}

/** The suggested `interface` value from a preflight result (for the select default). */
function suggestedInterface(r?: PreflightResultDto): string {
  const v = r?.values.find((x) => x.key === 'interface');
  return typeof v?.value === 'string' ? v.value : '';
}

/** Renders the `interface` input — a dropdown of candidates when the plugin
 *  enumerated them, else a free-text override. */
function InterfaceField({ r, value, onCommit }: { r?: PreflightResultDto; value: string; onCommit: (v: string) => void }) {
  const opts = r?.interfaces ?? [];
  if (opts.length === 0) return null; // caller falls back to a free-text field
  // Ensure the current/suggested value is always selectable even if not listed.
  const extra: PreflightInterfaceOptionDto[] = !value || opts.some((o) => o.name === value) ? [] : [{ name: value }];
  const all = [...extra, ...opts];
  return (
    <label className="block min-w-0 flex-1">
      <span className="mb-0.5 block truncate text-[11px] font-medium uppercase tracking-wide text-faint">interface</span>
      <select value={value} onChange={(e) => onCommit(e.target.value)} className="w-full rounded border border-border bg-background px-2 py-1 text-sm">
        {all.map((o, i) => (
          <option key={`${o.name}-${i}`} value={o.name}>
            {o.kind ? `[${o.kind}] ` : ''}{o.name}{o.note ? ` — ${o.note}` : ''}
          </option>
        ))}
      </select>
    </label>
  );
}

/** Renders one preflight value as an editable field (commits on blur). */
function PreflightField({ label, initial, onCommit }: { label: string; initial: unknown; onCommit: (v: string) => void }) {
  const [text, setText] = useState(typeof initial === 'string' ? initial : initial == null ? '' : String(initial));
  return (
    <label className="block min-w-0 flex-1">
      <span className="mb-0.5 block truncate text-[11px] font-medium uppercase tracking-wide text-faint">{label}</span>
      <input
        type="text"
        value={text}
        onChange={(e) => setText(e.target.value)}
        onBlur={() => onCommit(text.trim())}
        className="w-full rounded border border-border bg-background px-2 py-1 text-sm"
      />
    </label>
  );
}

/** Live progress of the step-2 preflight fan-out (per-plugin + overall). */
interface ProbeProgress {
  totalPlugins: number;
  donePlugins: number;
  totalDevices: number;
  doneDevices: number;
  /** pluginId → status while probing. */
  status: Record<string, 'probing' | 'done' | 'degraded'>;
}

export default function NetworkRolloutPage() {
  const navigate = useNavigate();
  const location = useLocation();
  const [searchParams] = useSearchParams();
  const { mode } = useExecutionMode();
  const isReadOnly = mode === 'readonly';

  // Where "Cancel" returns to (set by the entry point via location.state).
  const from = (location.state as { from?: string } | null)?.from ?? '/networks';
  function handleExit() { navigate(from); }

  // --- Step 1: scope -----------------------------------------------------------
  const [siteId, setSiteId] = useState('');
  const [tagInput, setTagInput] = useState('');
  const [layerId, setLayerId] = useState('');
  const tags = useMemo(() => tagInput.split(',').map((t) => t.trim()).filter(Boolean), [tagInput]);

  // --- Step 1: shared intent inputs (canonical network.create schema) -----------
  const [name, setName] = useState('');
  const [vlanId, setVlanId] = useState('');
  const [cidr, setCidr] = useState('');
  const [cidrV6, setCidrV6] = useState('');

  // Auto-assignment: UNM fills each device's L3 address with the next free host of
  // the rollout subnet(s), skipping addresses already in use. Default ON.
  const [autoAssign, setAutoAssign] = useState(true);

  // --- Step 2: per-device rollout state (keyed `${pluginId}:${deviceId}`) --------
  const [deviceState, setDeviceState] = useState<Record<string, DeviceRolloutState>>({});
  const [expandedIds, setExpandedIds] = useState<Set<string>>(new Set());
  const [step, setStep] = useState<1 | 2>(1);

  // Documented network to pre-fill from (the selector in the Network section).
  const [docNetId, setDocNetId] = useState('');

  const devicesQuery = useQuery({ queryKey: ['devices'], queryFn: api.devices });
  const sitesQuery = useQuery({ queryKey: ['sites'], queryFn: api.sites });
  const layersQuery = useQuery({ queryKey: ['layers'], queryFn: api.layers });
  const pluginsQuery = useQuery({ queryKey: ['plugins'], queryFn: api.plugins });
  // Documented networks — prefill selector (name collisions are checked server-side).
  const docNetsQuery = useQuery({ queryKey: ['documentedNetworks'], queryFn: () => api.documentedNetworks() });
  // Free-range suggestions from gaps in the live inventory (one-click fills).
  const suggestionsQuery = useQuery({ queryKey: ['networksSuggestions'], queryFn: api.networksSuggestions, staleTime: 60_000 });
  // Topology gives the RESOLVED layer per device (override > suggestion > heuristic).
  const topologyQuery = useQuery({ queryKey: ['topology'], queryFn: () => api.topology() as Promise<TopologyResponse> });

  // Topology device node ids are prefixed `device:<deviceId>` — strip it to
  // key the map by the raw device id.
  const layerOfDevice = useMemo(() => {
    const m = new Map<string, string>();
    for (const n of (topologyQuery.data?.nodes ?? [])) if (n.kind === 'device') m.set(n.id.replace(/^device:/, ''), n.layer);
    return m;
  }, [topologyQuery.data]);

  // Devices matching the scope — every non-empty dimension must match.
  const scopedDevices: Device[] = useMemo(() => {
    const all = devicesQuery.data ?? [];
    return all.filter((d) => {
      if (siteId && d.siteId !== siteId) return false;
      if (layerId && layerOfDevice.get(d.id) !== layerId) return false;
      if (tags.length > 0 && !tags.some((t) => d.tags.includes(t))) return false;
      return true;
    });
  }, [devicesQuery.data, siteId, layerId, tags, layerOfDevice]);

  // Manual selection: once the user touches it, only checked devices count.
  const [manualMode, setManualMode] = useState(false);
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
  const targetDevices = useMemo(() => {
    if (!manualMode) return scopedDevices;
    return scopedDevices.filter((d) => selectedIds.has(d.id));
  }, [scopedDevices, manualMode, selectedIds]);

  // Candidate plugins: every plugin assigned to a target device.
  const candidatePluginIds = useMemo(() => {
    const s = new Set<string>();
    for (const d of targetDevices) for (const p of d.plugins ?? []) s.add(p.pluginId);
    return [...s];
  }, [targetDevices]);

  // Catalog per candidate plugin — only plugins implementing network.create count.
  const catalogQueries = useQuery({
    queryKey: ['rollout-catalogs', candidatePluginIds],
    queryFn: async () => {
      const out = new Map<string, CatalogEntry | null>();
      for (const pid of candidatePluginIds) {
        try {
          const res = await api.pluginActions(pid);
          out.set(pid, res.actions.find((a) => a.id === INTENT_ID) ?? null);
        } catch {
          out.set(pid, null);
        }
      }
      return out;
    },
    enabled: candidatePluginIds.length > 0,
  });

  const supporting = useMemo(() => {
    const m = catalogQueries.data;
    if (!m) return new Map<string, CatalogEntry>();
    const out = new Map<string, CatalogEntry>();
    for (const [pid, entry] of m.entries()) if (entry) out.set(pid, entry);
    return out;
  }, [catalogQueries.data]);

  // Target devices grouped by supporting plugin.
  const groups = useMemo(() => {
    const g = new Map<string, Device[]>();
    for (const d of targetDevices) {
      for (const p of d.plugins ?? []) {
        if (!supporting.has(p.pluginId)) continue;
        let list = g.get(p.pluginId);
        if (!list) { list = []; g.set(p.pluginId, list); }
        list.push(d);
      }
    }
    return g;
  }, [targetDevices, supporting]);

  const skippedDevices = useMemo(
    () => targetDevices.filter((d) => !d.plugins?.some((p) => supporting.has(p.pluginId))),
    [targetDevices, supporting]
  );

  // --- Shared inputs object (sent to preflight + plans) --------------------------
  const sharedInputs = useMemo(() => {
    const out: Record<string, unknown> = {};
    if (name.trim()) out.name = name.trim();
    if (vlanId.trim() && Number.isInteger(Number(vlanId))) out.vlanId = Number(vlanId);
    if (cidr.trim()) out.cidr = cidr.trim();
    if (cidrV6.trim()) out.cidrV6 = cidrV6.trim();
    return out;
  }, [name, vlanId, cidr, cidrV6]);

  /** Copies the selected documented network's fields into the form. */
  function applyDocumentedNetwork(id: string) {
    setDocNetId(id);
    const n = (docNetsQuery.data ?? []).find((x) => x.id === id);
    if (!n) return;
    setName(n.name);
    setVlanId(n.vlanId != null ? String(n.vlanId) : '');
    // First IPv4 subnet becomes the L3 address (v6-only rows leave it empty).
    const v4 = n.subnets.find((s) => s.includes('/') && !s.includes(':'));
    setCidr(v4 ?? '');
    const v6 = n.subnets.find((s) => s.includes('/') && s.includes(':'));
    setCidrV6(v6 ?? '');
    if (n.siteId) setSiteId(n.siteId);
    if (n.layerId) setLayerId(n.layerId);
  }

  // Deep link: /networks/rollout?net=<documentedNetId> pre-fills from that network.
  const netParam = searchParams.get('net');
  const appliedNetRef = useRef<string | null>(null);
  useEffect(() => {
    if (!netParam || !docNetsQuery.data) return;
    if (appliedNetRef.current === netParam) return;
    if ((docNetsQuery.data ?? []).some((x) => x.id === netParam)) {
      applyDocumentedNetwork(netParam);
      appliedNetRef.current = netParam;
    }
  }, [netParam, docNetsQuery.data]);

  // --- Server-side overlap check (debounced while typing) ------------------------
  const [checkResult, setCheckResult] = useState<NetworkCheckResultDto | null>(null);
  const [checking, setChecking] = useState(false);
  const checkSeq = useRef(0);
  const targetDeviceIds = useMemo(() => targetDevices.map((d) => d.id), [targetDevices]);

  useEffect(() => {
    if (step !== 1) return;
    const seq = ++checkSeq.current;
    setChecking(true);
    const t = window.setTimeout(async () => {
      try {
        const r = await api.plansNetworkCheck({ inputs: sharedInputs, deviceIds: targetDeviceIds, autoAssign });
        if (seq === checkSeq.current) setCheckResult(r);
      } catch {
        // Advisory feature — a transient failure must not block the wizard.
      } finally {
        if (seq === checkSeq.current) setChecking(false);
      }
    }, 400);
    return () => window.clearTimeout(t);
  }, [step, name, vlanId, cidr, sharedInputs, targetDeviceIds, autoAssign]);

  // --- Step 2: preflight (with live progress + cancel) ---------------------------
  const abortRef = useRef<AbortController | null>(null);
  const cancelledRef = useRef(false);
  const [probeProgress, setProbeProgress] = useState<ProbeProgress | null>(null);

  const preflightQuery = useMutation({
    mutationFn: async (signal?: AbortSignal) => {
      // Parallel fan-out — one plugin's probe failure must not sink the whole
      // wizard; its devices are marked degraded and fall back to defaults.
      cancelledRef.current = false;
      const perPlugin = new Map<string, PreflightResultDto[]>();
      setProbeProgress({ totalPlugins: groups.size, donePlugins: 0, totalDevices: totalTargets, doneDevices: 0, status: {} });

      await Promise.all([...groups.entries()].map(async ([pid, devs]) => {
        setProbeProgress((p) => p ? { ...p, status: { ...p.status, [pid]: 'probing' } } : p);
        try {
          const r = await api.plansPreflight({ pluginId: pid, intentActionId: INTENT_ID, inputs: sharedInputs, deviceIds: devs.map((d) => d.id) }, signal ? { signal } : undefined);
          perPlugin.set(pid, r.results);
        } catch (e) {
          if (cancelledRef.current || (signal?.aborted)) throw e; // let the whole run abort cleanly
          perPlugin.set(pid, devs.map((d) => ({ deviceId: d.id, values: [], degraded: true, error: e instanceof Error ? e.message : String(e) })));
        }
        if (cancelledRef.current || signal?.aborted) throw new Error('cancelled');
        setProbeProgress((p) => p ? { ...p, donePlugins: p.donePlugins + 1, doneDevices: p.doneDevices + devs.length, status: { ...p.status, [pid]: perPlugin.get(pid)?.some((x) => x.degraded) ? 'degraded' : 'done' } } : p);
      }));

      if (cancelledRef.current || signal?.aborted) throw new Error('cancelled');
      return perPlugin;
    },
    // The whole point of the mutation is to advance the wizard — without this
    // onSuccess the UI stays on step 1 forever ("resolve does nothing").
    onSuccess: () => { setStep(2); setProbeProgress(null); abortRef.current = null; },
    onError: (e) => {
      if ((e as Error).message === 'cancelled') {
        // User cancelled — stay on step 1, clear the progress panel.
        setProbeProgress(null);
        abortRef.current = null;
        return;
      }
      // A hard failure: surface it (the dialog previously showed this inline too).
    },
  });

  function cancelResolve() {
    cancelledRef.current = true;
    abortRef.current?.abort();
  }

  const [formError, setFormError] = useState<string | null>(null);

  function handleResolve(e: React.FormEvent) {
    e.preventDefault();
    if (!name.trim()) { setFormError('Network name is required.'); return; }
    if (vlanId.trim() !== '') {
      const v = Number(vlanId);
      if (!Number.isInteger(v) || v < 1 || v > 4094) { setFormError('VLAN ID must be an integer 1..4094.'); return; }
    } else if (!cidr.trim() && !cidrV6.trim()) {
      setFormError('Provide at least one of VLAN ID or L3 address (v4/v6) — there is nothing to create otherwise.');
      return;
    }
    if (groups.size === 0) { setFormError('No target device has a plugin that implements network.create.'); return; }
    setDeviceState(buildPrefilledDeviceState());
    setExpandedIds(new Set());
    const controller = new AbortController();
    abortRef.current = controller;
    preflightQuery.mutate(controller.signal);
  }

  /** Step-2 initial state: when auto-assignment is on, pre-fill each IP-enabled
   *  device's CIDR override with the API-computed next free host address(es)
   *  (`<addr>/<prefix>` — the canonical per-device override form). Devices whose
   *  subnet is exhausted are left untouched (user decides). */
  function buildPrefilledDeviceState(): Record<string, DeviceRolloutState> {
    const out: Record<string, DeviceRolloutState> = {};
    if (!autoAssign) return out;
    const sug = checkResult?.ipSuggestions;
    if (!sug) return out;
    const p4 = cidr.trim().split('/').pop();
    const p6 = cidrV6.trim().split('/').pop();
    for (const [pid, devs] of groups.entries()) {
      for (const d of devs) {
        const s = sug[d.id];
        if (!s) continue;
        const patch: Partial<DeviceRolloutState> = {};
        // Only pre-fill when the device will actually get an IP (smart default
        // is ON except L2-only plugins — respect an explicit toggle choice too).
        if (effectiveIpEnabled(pid, undefined)) {
          if (s.v4 && p4) patch.cidr = `${s.v4}/${p4}`;
          if (s.v6 && p6) patch.cidrV6 = `${s.v6}/${p6}`;
        }
        if (Object.keys(patch).length > 0) out[`${pid}:${d.id}`] = { ...EMPTY_DEVICE_STATE, ...patch };
      }
    }
    return out;
  }

  function handleBack() {
    setStep(1);
    preflightQuery.reset();
    setProbeProgress(null);
  }

  // --- Persistent port roles (uplink/trunk markers) ---------------------------------
  const queryClient = useQueryClient();
  /** Mark/clear a port's role — then re-run the preflight so the merged live+role
   *  flags refresh immediately (the API ORs device_port_roles into ports). */
  const markRole = useMutation({
    mutationFn: async ({ pid, deviceId, portName, role }: { pid: string; deviceId: string; portName: string; role: 'uplink' | 'trunk' | null }) => {
      await api.setDevicePortRole(deviceId, { pluginId: pid, portName, role });
    },
    onSuccess: () => { void queryClient.invalidateQueries({ queryKey: ['rollout-preflight'] }); preflightQuery.mutate(undefined); },
  });

  // Which chip's role menu is open (keyed `${deviceId}:${portName}`), if any.
  const [roleMenu, setRoleMenu] = useState<string | null>(null);
  useEffect(() => {
    if (!roleMenu) return;
    const close = () => setRoleMenu(null);
    document.addEventListener('click', close);
    return () => document.removeEventListener('click', close);
  }, [roleMenu]);

  // --- Submit: one plan per supporting plugin with confirmed per-device inputs ----
  const createPlans = useMutation({
    mutationFn: async () => {
      const deviceInputs: Record<string, Record<string, unknown>> = {};
      for (const [pid, devs] of groups.entries()) {
        for (const d of devs) {
          const st = deviceState[`${pid}:${d.id}`];
          if (!st) continue;
          const r = preflightQuery.data?.get(pid)?.find((x) => x.deviceId === d.id);
          const perDevice: Record<string, unknown> = {};
          // IP toggle — explicit nulls clear the shared L3 address for this
          // device only (L2-only rollout: e.g. a switch gets the VLAN but no
          // IP). Plugins treat null as "absent" in their input validation.
          if (!effectiveIpEnabled(pid, st)) {
            perDevice['cidr'] = null;
            perDevice['cidrV6'] = null;
          } else {
            if (st.cidr !== undefined) perDevice['cidr'] = st.cidr === '' ? null : st.cidr;
            if (st.cidrV6 !== undefined) perDevice['cidrV6'] = st.cidrV6 === '' ? null : st.cidrV6;
          }
          // Port selection — only for plugins that advertise the capability.
          if (r?.capabilities?.vlanPorts && r.ports && r.ports.length > 0) {
            const names = selectedPorts(st.portMode, st.customPorts, r.ports);
            if (names.length > 0) perDevice['vlanPorts'] = names;
          }
          if (st.vlanId !== undefined && st.vlanId !== '' && Number.isInteger(Number(st.vlanId))) perDevice['vlanId'] = Number(st.vlanId);
          if (st.interface !== undefined && st.interface !== '') perDevice['interface'] = st.interface;
          if (Object.keys(perDevice).length > 0) deviceInputs[d.id] = perDevice;
        }
      }

      const created: Array<{ pluginId: string; planId: string; deviceCount: number }> = [];
      for (const [pluginId, devs] of groups.entries()) {
        const plan = await api.createPlan({
          pluginId,
          intentActionId: INTENT_ID,
          inputs: sharedInputs,
          devices: devs.map((d) => ({ deviceId: d.id })),
          ...(Object.keys(deviceInputs).length > 0 ? { deviceInputs } : {}),
        });
        created.push({ pluginId, planId: plan.id, deviceCount: devs.length });
      }
      if (mode === 'execute') {
        for (const c of created) await api.executePlan(c.planId);
      }
      return created;
    },
  });

  const totalTargets = [...groups.values()].reduce((n, l) => n + l.length, 0);
  const sites: Site[] = sitesQuery.data ?? [];
  const layers: NetworkLayer[] = (layersQuery.data ?? []).slice().sort((a, b) => a.sort - b.sort);
  const pluginName = (id: string) => pluginsQuery.data?.find((p) => p.id === id)?.name ?? id;

  // --- Step 2 bulk controls -------------------------------------------------------
  /** Any device in step 2 that supports explicit port lists? */
  const anyPortCapable = useMemo(() => {
    if (!preflightQuery.data) return false;
    for (const results of preflightQuery.data.values()) {
      if (results.some((r) => r.capabilities?.vlanPorts && (r.ports?.length ?? 0) > 0)) return true;
    }
    return false;
  }, [preflightQuery.data]);

  /** Any port in step 2 persistently marked as an uplink? */
  const anyUplinkMarked = useMemo(() => {
    if (!preflightQuery.data) return false;
    for (const results of preflightQuery.data.values()) {
      if (results.some((r) => r.ports?.some((p) => p.uplink))) return true;
    }
    return false;
  }, [preflightQuery.data]);

  /** Bulk IP toggle across every device of step 2. */
  function bulkSetIp(on: boolean) {
    setDeviceState((prev) => {
      const next = { ...prev };
      for (const [pid, devs] of groups.entries()) for (const d of devs) {
        const k = `${pid}:${d.id}`;
        next[k] = { ...(next[k] ?? EMPTY_DEVICE_STATE), ipEnabled: on };
      }
      return next;
    });
  }

  /** Bulk port mode across every device that supports vlanPorts. */
  function bulkSetMode(mode: PortMode) {
    setDeviceState((prev) => {
      const next = { ...prev };
      for (const [pid, devs] of groups.entries()) {
        for (const d of devs) {
          const r = preflightQuery.data?.get(pid)?.find((x) => x.deviceId === d.id);
          if (!r?.capabilities?.vlanPorts || !r.ports?.length) continue;
          const k = `${pid}:${d.id}`;
          next[k] = { ...(next[k] ?? EMPTY_DEVICE_STATE), portMode: mode, customPorts: [] };
        }
      }
      return next;
    });
  }

  const bulkBtnCls = 'rounded-md border border-border px-2 py-1 text-secondary hover:bg-muted';

  // Progress percentage for the resolving bar.
  const progressPct = probeProgress && probeProgress.totalDevices > 0
    ? Math.round((probeProgress.doneDevices / probeProgress.totalDevices) * 100)
    : 0;

  return (
    <WizardLayout
      title="Roll out network across the fleet"
      icon={<Globe className="h-4 w-4 text-primary" />}
      steps={[{ label: 'Scope & network' }, { label: 'Per-device review' }]}
      current={step - 1}
      onExit={handleExit}
    >
      {formError && (
        <div className="rounded-md border border-danger-border bg-danger px-3 py-2 text-sm text-danger-fg">{formError}</div>
      )}

      {/* ================= STEP 1 — scope + shared inputs ================= */}
      {step === 1 && (
        <form onSubmit={handleResolve} className="space-y-4">
          <section className="rounded-md border border-border bg-background p-3 sm:p-4">
            <div className="mb-2 flex items-center justify-between">
              <h3 className="text-sm font-semibold text-secondary">Target scope</h3>
              {scopedDevices.length > 0 && (
                <button type="button" onClick={() => setManualMode((m) => !m)} className={clsx('rounded-md border px-2 py-1 text-xs', manualMode ? 'border-primary bg-primary/10 text-primary' : 'border-border text-secondary hover:bg-muted')}>
                  {manualMode ? `Picking ${selectedIds.size}/${scopedDevices.length} manually` : 'Pick devices manually'}
                </button>
              )}
            </div>
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
              <label className="block text-sm">
                <span className="mb-1 block font-medium text-secondary">Site</span>
                <select value={siteId} onChange={(e) => setSiteId(e.target.value)} className="w-full rounded-md border border-border px-2 py-2 text-sm">
                  <option value="">All sites</option>
                  {sites.map((s) => (<option key={s.id} value={s.id}>{s.name}</option>))}
                </select>
              </label>
              <label className="block text-sm">
                <span className="mb-1 block font-medium text-secondary">Topology layer</span>
                <select value={layerId} onChange={(e) => setLayerId(e.target.value)} className="w-full rounded-md border border-border px-2 py-2 text-sm">
                  <option value="">All layers</option>
                  {layers.map((l) => (<option key={l.id} value={l.id}>{l.name}</option>))}
                </select>
              </label>
              <label className="block text-sm">
                <span className="mb-1 block font-medium text-secondary">Tags (comma-separated, OR)</span>
                <input type="text" value={tagInput} onChange={(e) => setTagInput(e.target.value)} placeholder="router, site-hq" className="w-full rounded-md border border-border px-2 py-2 text-sm" />
              </label>
            </div>

            {manualMode && (
              <div className="mt-3 max-h-48 space-y-1 overflow-y-auto rounded-md border border-border p-2">
                {scopedDevices.map((d) => (
                  <label key={d.id} className="flex items-center gap-2 text-sm">
                    <input
                      type="checkbox"
                      checked={selectedIds.has(d.id)}
                      onChange={(e) => setSelectedIds((prev) => { const next = new Set(prev); if (e.target.checked) next.add(d.id); else next.delete(d.id); return next; })}
                    />
                    <span className="text-foreground">{d.name}</span>
                    <span className="text-xs text-faint">
                      {layerOfDevice.get(d.id) ? `· ${layers.find((l) => l.id === layerOfDevice.get(d.id))?.name ?? ''}` : ''}
                      {d.tags.length > 0 && ` · ${d.tags.join(', ')}`}
                    </span>
                  </label>
                ))}
              </div>
            )}

            <p className="mt-2 text-xs text-faint">
              {targetDevices.length} device{targetDevices.length === 1 ? '' : 's'} in scope — {totalTargets} target{totalTargets === 1 ? '' : 's'} on supporting plugin(s)
              {skippedDevices.length > 0 && `, ${skippedDevices.length} skipped (no network.create support: ${skippedDevices.map((d) => d.name).join(', ')})`}.
            </p>
          </section>

          <section className="rounded-md border border-border bg-background p-3 sm:p-4">
            <h3 className="mb-2 text-sm font-semibold text-secondary">Network</h3>
            {(docNetsQuery.data ?? []).length > 0 && (
              <label className="mb-3 block text-sm">
                <span className="mb-1 block font-medium text-secondary">Pre-fill from documented network (optional)</span>
                <select value={docNetId} onChange={(e) => applyDocumentedNetwork(e.target.value)} className="w-full rounded-md border border-border px-2 py-2 text-sm">
                  <option value="">— none —</option>
                  {(docNetsQuery.data ?? []).map((n) => (
                    <option key={n.id} value={n.id}>
                      {n.name}{n.vlanId != null ? ` · VLAN ${n.vlanId}` : ''}{(n.subnets.find((s) => s.includes('/')) ? ` · ${n.subnets.find((s) => s.includes('/')!)}` : '')}{!n.isActive ? ' (stale)' : ''}
                    </option>
                  ))}
                </select>
              </label>
            )}
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
              <label className="block text-sm">
                <span className="mb-1 block font-medium text-secondary">Name *</span>
                <input type="text" value={name} onChange={(e) => setName(e.target.value)} placeholder="NET_XY" className="w-full rounded-md border border-border px-3 py-2 text-sm" />
              </label>
              <label className="block text-sm">
                <span className="mb-1 flex items-center justify-between font-medium text-secondary">VLAN ID (optional)
                  {suggestionsQuery.data?.lowestFreeVlanId != null && (
                    <button type="button" onClick={() => setVlanId(String(suggestionsQuery.data!.lowestFreeVlanId))} className="text-xs font-normal text-primary hover:underline">
                      suggest free ({suggestionsQuery.data.lowestFreeVlanId})
                    </button>
                  )}
                </span>
                <input type="number" min={1} max={4094} value={vlanId} onChange={(e) => setVlanId(e.target.value)} placeholder="42 — omit for L3-only on default VLAN" className="w-full rounded-md border border-border px-2 py-2 text-sm" />
              </label>
              <label className="block text-sm">
                <span className="mb-1 flex items-center justify-between font-medium text-secondary">L3 address IPv4 (CIDR, optional)
                  {suggestionsQuery.data?.nextFreeSubnetV4 && (
                    <button type="button" onClick={() => setCidr(suggestionsQuery.data!.nextFreeSubnetV4!)} className="text-xs font-normal text-primary hover:underline">
                      suggest free ({suggestionsQuery.data.nextFreeSubnetV4})
                    </button>
                  )}
                </span>
                <input type="text" value={cidr} onChange={(e) => setCidr(e.target.value)} placeholder="10.42.0.1/24 — per-device override in step 2" className="w-full rounded-md border border-border px-3 py-2 text-sm" />
              </label>
              <label className="block text-sm">
                <span className="mb-1 flex items-center justify-between font-medium text-secondary">L3 address IPv6 (CIDR, optional)
                  {suggestionsQuery.data?.nextFreeSubnetV6 && (
                    <button type="button" onClick={() => setCidrV6(suggestionsQuery.data!.nextFreeSubnetV6!)} className="text-xs font-normal text-primary hover:underline">
                      suggest free ({suggestionsQuery.data.nextFreeSubnetV6})
                    </button>
                  )}
                </span>
                <input type="text" value={cidrV6} onChange={(e) => setCidrV6(e.target.value)} placeholder="fd00:42::1/64 — dual-stack when both are set" className="w-full rounded-md border border-border px-3 py-2 text-sm" />
              </label>
            </div>
            <label className="mt-3 flex items-start gap-2 text-sm">
              <input type="checkbox" checked={autoAssign} onChange={(e) => setAutoAssign(e.target.checked)} className="mt-0.5 h-4 w-4 rounded border-border accent-primary" />
              <span>
                <span className="font-medium text-secondary">Auto-assign IP addresses</span>
                <span className="block text-xs text-faint">
                  UNM fills each device's L3 address with the next free host of the subnet(s) above, skipping every address already in use (live interfaces, ARP/NDP leases, management IPs). Works for IPv4 and IPv6. Turn off to enter addresses manually in step 2.
                </span>
              </span>
            </label>
            <p className="mt-2 text-xs text-faint">
              No generic interface field on purpose — each router decides its own L2 port. Step 2 resolves the best-guess per device from live state and lets you override it. Clearing a CIDR for one device in step 2 makes that device L2-only (VLAN without an IP address) — e.g. a switch or an appliance that only needs to know the VLAN.
            </p>
          </section>

          {(checkResult?.warnings.length ?? 0) > 0 && (
            <div className="rounded-md border border-warning/40 bg-warning/10 p-3">
              <h3 className="mb-1 text-sm font-semibold text-warning-fg">Possible overlap with existing networks</h3>
              <ul className="list-disc space-y-1 pl-4 text-xs text-secondary">
                {checkResult!.warnings.map((w) => (<li key={w.kind + w.networkKey}>{w.message}</li>))}
              </ul>
              <p className="mt-2 text-xs text-faint">
                Warnings only — NAT'd remote sites and multi-site designs legitimately reuse names, subnets or VLAN IDs. Continue when the overlap is intentional; step 2 shows what already exists on each device.
              </p>
            </div>
          )}

          {/* Resolve action + live progress panel (replaces a bare "Resolving…"). */}
          <div className="space-y-3">
            {preflightQuery.isPending && probeProgress ? (
              <div className="rounded-md border border-border bg-background p-4">
                <div className="mb-2 flex items-center justify-between text-sm">
                  <span className="flex items-center gap-2 font-medium text-secondary">
                    <Loader2 className="h-4 w-4 animate-spin text-primary" />
                    Resolving per-device settings…
                  </span>
                  <span className="text-xs tabular-nums text-faint">{probeProgress.doneDevices}/{probeProgress.totalDevices} devices · {progressPct}%</span>
                </div>
                {/* Overall progress bar. */}
                <div className="h-2 w-full overflow-hidden rounded-full bg-muted">
                  <div className="h-full rounded-full bg-primary transition-all duration-300" style={{ width: `${progressPct}%` }} />
                </div>
                {/* Detail steps — one row per supporting plugin. */}
                <ul className="mt-3 space-y-1">
                  {[...groups.entries()].map(([pid, devs]) => {
                    const st = probeProgress.status[pid] ?? 'probing';
                    return (
                      <li key={pid} className="flex items-center gap-2 text-xs">
                        {st === 'done' && <span className="h-1.5 w-1.5 shrink-0 rounded-full bg-success" />}
                        {st === 'degraded' && <span className="h-1.5 w-1.5 shrink-0 rounded-full bg-warning" title="probe failed — defaults apply" />}
                        {st === 'probing' && <Loader2 className="h-3 w-3 shrink-0 animate-spin text-primary" />}
                        <span className={clsx('truncate', st === 'probing' ? 'text-secondary' : 'text-faint')}>
                          {pluginName(pid)} — {devs.length} device{devs.length === 1 ? '' : 's'}
                        </span>
                        {st === 'degraded' && <span className="ml-auto shrink-0 text-warning-fg">probe failed</span>}
                      </li>
                    );
                  })}
                </ul>
                <p className="mt-3 text-xs text-faint">Probing device state is read-only and can take a while on large fleets — you can cancel at any time.</p>
                <div className="mt-2 flex justify-end">
                  <button type="button" onClick={cancelResolve} className="rounded-md border border-border px-3 py-1.5 text-xs font-medium text-secondary hover:bg-muted">Cancel</button>
                </div>
              </div>
            ) : (
              <div className="flex items-center gap-3">
                <button type="submit" disabled={preflightQuery.isPending || isReadOnly || groups.size === 0} className={clsx('rounded-md px-4 py-2 text-sm font-semibold text-white', isReadOnly ? 'bg-muted opacity-50' : 'bg-primary hover:bg-primary-hover disabled:opacity-50')}>
                  {preflightQuery.isPending ? 'Resolving…' : `Resolve per-device settings (${totalTargets})`}
                </button>
                {checking && (checkResult?.warnings.length ?? 0) === 0 && <span className="text-xs text-faint">Checking inventory for overlaps…</span>}
              </div>
            )}
          </div>
        </form>
      )}

      {/* ================= STEP 2 — preflight review ================= */}
      {step === 2 && (
        <div className="space-y-4">
          {!preflightQuery.isPending && preflightQuery.data && (
            <>
              {/* Bulk controls — operate on every device of step 2 at once. */}
              <div className="flex flex-wrap items-center gap-2 rounded-md border border-border bg-background p-2 text-xs">
                <span className="font-medium uppercase tracking-wide text-faint">Apply to all:</span>
                <button type="button" onClick={() => bulkSetIp(true)} className={bulkBtnCls}>IP on</button>
                <button type="button" onClick={() => bulkSetIp(false)} className={bulkBtnCls}>IP off (L2-only)</button>
                {anyPortCapable && (<>
                  <span className="mx-1 h-4 w-px bg-border" />
                  <button type="button" onClick={() => bulkSetMode('all')} className={bulkBtnCls}>All ports</button>
                  <button type="button" onClick={() => bulkSetMode('trunk')} className={bulkBtnCls}>Trunk ports only</button>
                  {anyUplinkMarked && (
                    <button type="button" onClick={() => bulkSetMode('uplink')} title="Every port the user has persistently marked as an uplink" className={bulkBtnCls}>Uplinks</button>
                  )}
                </>)}
              </div>

              {[...groups.entries()].map(([pid, devs]) => {
                const results = preflightQuery.data?.get(pid) ?? [];
                return (
                  <section key={pid} className="rounded-md border border-border bg-background p-3">
                    <h3 className="mb-2 text-sm font-semibold text-secondary">{pluginName(pid)} — {devs.length} device{devs.length === 1 ? '' : 's'}</h3>
                    <div className="space-y-1.5">
                      {devs.map((d) => {
                        const r = results.find((x) => x.deviceId === d.id);
                        const k = `${pid}:${d.id}`;
                        const st = deviceState[k] ?? EMPTY_DEVICE_STATE;
                        const setSt = (patch: Partial<DeviceRolloutState>) =>
                          setDeviceState((prev) => ({ ...prev, [k]: { ...(prev[k] ?? EMPTY_DEVICE_STATE), ...patch } }));
                        const ipOn = effectiveIpEnabled(pid, st);
                        const portCapable = !!r?.capabilities?.vlanPorts && (r.ports?.length ?? 0) > 0;
                        const expanded = expandedIds.has(d.id);
                        return (
                          <div key={d.id} className="rounded-md border border-border">
                            {/* Row header — always visible. */}
                            <div className="flex items-center gap-2 px-3 py-2">
                              <button
                                type="button"
                                aria-label={expanded ? 'Collapse' : 'Expand'}
                                onClick={() => setExpandedIds((prev) => { const next = new Set(prev); if (next.has(d.id)) next.delete(d.id); else next.add(d.id); return next; })}
                                className="rounded p-0.5 text-faint hover:bg-muted"
                              >
                                <ChevronDown className={clsx('h-4 w-4 transition-transform', !expanded && '-rotate-90')} />
                              </button>
                              <span className="font-medium text-foreground">{d.name}</span>
                              {(r?.check?.deployed ?? checkResult?.devices.find((x) => x.deviceId === d.id)?.status === 'deployed') && (
                                <span title="The live inventory already shows this network on the device — the step will be a no-op there." className="rounded-full bg-success/15 px-2 py-0.5 text-xs text-success">already deployed</span>
                              )}
                              {r?.degraded && (
                                <span title={r.error} className="rounded-full bg-danger/15 px-2 py-0.5 text-xs text-danger-fg">probe failed — defaults apply</span>
                              )}
                              <span className="ml-auto flex items-center gap-3">
                                {/* IP toggle — off = L2-only (explicit null cidrs). */}
                                <label className="flex cursor-pointer items-center gap-1.5 text-xs text-secondary" title={ipOn ? 'This device gets the shared L3 address' : 'L2-only — VLAN without an IP address'}>
                                  <input type="checkbox" checked={ipOn} onChange={(e) => setSt({ ipEnabled: e.target.checked })} className="h-3.5 w-3.5 accent-[var(--color-primary)]" />
                                  Set IP
                                </label>
                                {/* Port quick-select — only when the plugin supports vlanPorts. */}
                                {portCapable ? (
                                  <span className="flex items-center gap-1">
                                    {(['all', 'trunk', 'uplink', 'custom'] as const).map((m) => {
                                      if (m === 'uplink' && !(r!.ports!.some((p) => p.uplink))) return null;
                                      const chosen = selectedPorts(st.portMode, st.customPorts, r?.ports);
                                      return (
                                        <button
                                          key={m}
                                          type="button"
                                          onClick={() => {
                                            if (m === 'custom' && st.portMode !== 'custom') {
                                              // Seed the custom selection with what the current mode would pick.
                                              setSt({ portMode: m, customPorts: selectedPorts(st.portMode, st.customPorts, r?.ports) });
                                            } else {
                                              setSt({ portMode: m });
                                            }
                                          }}
                                          className={clsx('rounded px-1.5 py-0.5 text-xs', st.portMode === m ? 'bg-primary/15 font-medium text-primary' : 'text-faint hover:bg-muted')}
                                        >
                                          {m === 'all' ? `All (${r!.ports!.length})` : m === 'trunk' ? `Trunk only (${r!.ports!.filter((p) => p.trunk).length})` : m === 'uplink' ? `Uplinks (${r!.ports!.filter((p) => p.uplink).length})` : `Select (${chosen.length})`}
                                        </button>
                                      );
                                    })}
                                  </span>
                                ) : (
                                  <span className="text-xs text-faint" title={portCapable ? '' : 'This platform creates the VLAN on its parent interface — no per-port selection.'}>interface-only</span>
                                )}
                              </span>
                            </div>

                            {/* Expanded area — port chips, notes, overrides. */}
                            {expanded && (
                              <div className="space-y-2 border-t border-border px-3 py-2">
                                {portCapable && r!.ports!.length > 0 && (
                                  <div>
                                    <p className="mb-1 text-[11px] font-medium uppercase tracking-wide text-faint">Ports carrying VLAN{st.portMode === 'custom' ? ' (click to toggle)' : ''}</p>
                                    <div className="flex flex-wrap gap-1">
                                      {r!.ports!.map((p) => {
                                        const active = st.portMode !== 'custom' || st.customPorts.includes(p.name);
                                        const menuKey = `${d.id}:${p.name}`;
                                        return (
                                          <span key={p.name} className="relative inline-flex items-center gap-0.5">
                                            <button
                                              type="button"
                                              disabled={st.portMode !== 'custom'}
                                              onClick={() => setSt({ customPorts: active ? st.customPorts.filter((x) => x !== p.name) : [...st.customPorts, p.name] })}
                                              title={`${p.name}${p.uplink ? ' · marked uplink' : ''}${!p.uplink && p.trunk ? ' · trunk/uplink' : ''}${p.pvid != null ? ` · PVID ${p.pvid}` : ''}`}
                                              className={clsx('flex items-center gap-1 rounded border px-1.5 py-0.5 text-xs', active ? 'border-primary/40 bg-primary/10 text-foreground' : 'border-border text-faint', st.portMode === 'custom' && !active && 'opacity-60')}
                                            >
                                              {p.uplink && <span className="h-1.5 w-1.5 rounded-full bg-primary" title="marked uplink" />}
                                              {!p.uplink && p.trunk && <span className="h-1.5 w-1.5 rounded-full bg-warning" title="trunk/uplink port (live detection)" />}
                                              {p.name}
                                              {p.pvid != null && <span className="text-[10px] text-faint">{p.pvid}</span>}
                                            </button>
                                            {/* Persistent role marker — survives across rollouts. */}
                                            <button
                                              type="button"
                                              onClick={(e) => { e.stopPropagation(); setRoleMenu(roleMenu === menuKey ? null : menuKey); }}
                                              title={p.uplink ? 'Marked uplink — click to change/clear' : p.trunk ? 'Trunk (live) — click to mark persistently' : 'Click to mark as uplink/trunk'}
                                              className="rounded p-0.5 text-faint hover:bg-muted"
                                            >
                                              <Settings2 className={clsx('h-3 w-3', (p.uplink || p.trunk) && 'text-secondary')} />
                                            </button>
                                            {roleMenu === menuKey && (
                                              <div className="absolute right-0 top-full z-10 mt-0.5 w-40 rounded-md border border-border bg-card p-1 text-xs shadow-lg" onClick={(e) => e.stopPropagation()}>
                                                <p className="px-2 py-1 font-medium text-secondary">{p.name}</p>
                                                <button type="button" onClick={() => { setRoleMenu(null); markRole.mutate({ pid, deviceId: d.id, portName: p.name, role: 'uplink' }); }} className={clsx('block w-full rounded px-2 py-1 text-left hover:bg-muted', p.uplink && 'font-medium text-primary')}>Mark as uplink</button>
                                                <button type="button" onClick={() => { setRoleMenu(null); markRole.mutate({ pid, deviceId: d.id, portName: p.name, role: 'trunk' }); }} className={clsx('block w-full rounded px-2 py-1 text-left hover:bg-muted', !p.uplink && p.trunk && 'font-medium text-primary')}>Mark as trunk</button>
                                                {(p.uplink || p.trunk) && (
                                                  <button type="button" onClick={() => { setRoleMenu(null); markRole.mutate({ pid, deviceId: d.id, portName: p.name, role: null }); }} className={clsx('block w-full rounded px-2 py-1 text-left hover:bg-muted', !p.uplink && !p.trunk ? 'hidden' : '')}>Clear role</button>
                                                )}
                                              </div>
                                            )}
                                          </span>
                                        );
                                      })}
                                    </div>
                                  </div>
                                )}

                                {/* Suggested values as editable fields, pre-filled from the probe. */}
                                <div className="flex flex-wrap gap-2">
                                  {r?.values.filter((v) => v.key !== 'vlanPorts').map((v) => (
                                    <PreflightField key={v.key} label={`${v.key}${v.confidence !== 'high' ? ` (${v.confidence})` : ''}`} initial={st[v.key as keyof DeviceRolloutState] ?? v.value} onCommit={(val) => setSt({ [v.key]: val } as Partial<DeviceRolloutState>)} />
                                  ))}
                                  {(!r || !r.values.some((v) => v.key === 'vlanId')) && (
                                    <PreflightField label="vlanId (override)" initial={st.vlanId ?? sharedInputs.vlanId ?? ''} onCommit={(val) => setSt({ vlanId: val })} />
                                  )}
                                  {ipOn && (!r || !r.values.some((v) => v.key === 'cidr')) && (
                                    <PreflightField label="cidr (override)" initial={st.cidr ?? sharedInputs.cidr ?? ''} onCommit={(val) => setSt({ cidr: val })} />
                                  )}
                                  {ipOn && (!r || !r.values.some((v) => v.key === 'cidrV6')) && (
                                    <PreflightField label="cidrV6 (override)" initial={st.cidrV6 ?? sharedInputs.cidrV6 ?? ''} onCommit={(val) => setSt({ cidrV6: val })} />
                                  )}
                                  {ipOn && r?.interfaces && r.interfaces.length > 0 ? (
                                    <InterfaceField r={r} value={st.interface ?? suggestedInterface(r)} onCommit={(v) => setSt({ interface: v })} />
                                  ) : (!r || !r.values.some((v) => v.key === 'interface')) && (
                                    <PreflightField label="interface (override)" initial={st.interface ?? ''} onCommit={(val) => setSt({ interface: val })} />
                                  )}
                                </div>

                                {/* Notes from the probe — why each value was chosen. */}
                                {r?.values.filter((v) => v.note).map((v) => (
                                  <p key={`note-${v.key}`} className="mt-1 text-xs text-faint">• {v.key}: {v.note}</p>
                                ))}
                              </div>
                            )}
                          </div>
                        );
                      })}
                    </div>
                  </section>
                );
              })}

              {/* Rollout diff summary — what will happen per device before anything is written. */}
              {checkResult && checkResult.devices.length > 0 && (() => {
                const plannedIds = new Set<string>();
                for (const devs of groups.values()) for (const d of devs) plannedIds.add(d.id);
                const relevant = checkResult.devices.filter((d) => plannedIds.has(d.deviceId));
                if (relevant.length === 0) return null;
                const deployed = relevant.filter((d) => d.status === 'deployed');
                const fresh = relevant.filter((d) => d.status === 'new');
                return (
                  <section className="rounded-md border border-border bg-background p-3">
                    <h3 className="mb-2 text-sm font-semibold text-secondary">Rollout summary</h3>
                    {deployed.length > 0 && (
                      <p className="text-xs text-success">No-op (already deployed): {deployed.map((d) => d.deviceName).join(', ')}</p>
                    )}
                    <p className={clsx('mt-1 text-xs', fresh.length > 0 ? 'text-secondary' : 'text-faint')}>
                      Will create: {fresh.length > 0 ? fresh.map((d) => d.deviceName).join(', ') : '— (nothing new)'}
                    </p>
                  </section>
                );
              })()}

              <div className="flex items-center gap-3">
                <button type="button" onClick={handleBack} className="rounded-md border border-border px-4 py-2 text-sm font-medium text-secondary hover:bg-muted">← Back</button>
                <button
                  type="button"
                  disabled={createPlans.isPending || isReadOnly}
                  onClick={() => createPlans.mutate()}
                  className={clsx('rounded-md px-4 py-2 text-sm font-semibold text-white', isReadOnly ? 'bg-muted opacity-50' : 'bg-primary hover:bg-primary-hover disabled:opacity-50')}
                >
                  {createPlans.isPending ? 'Creating…' : mode === 'execute' ? `Create + execute plans (${groups.size})` : `Save as plan(s) (${groups.size})`}
                </button>
              </div>

              {createPlans.isSuccess && (
                <div className="rounded-md border border-border bg-background p-3 text-sm">
                  <p className="mb-2 font-medium text-secondary">Created {createPlans.data.length} plan(s):</p>
                  <ul className="space-y-1">
                    {createPlans.data.map((c) => (
                      <li key={c.planId}>
                        <button type="button" onClick={() => navigate(`/plans/${c.planId}`)} className="text-primary hover:underline">
                          {pluginName(c.pluginId)} — {c.deviceCount} device(s){mode === 'execute' ? ' (executing)' : ''}
                        </button>
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </>
          )}
        </div>
      )}
    </WizardLayout>
  );
}
