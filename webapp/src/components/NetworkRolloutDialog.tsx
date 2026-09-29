import { useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useMutation, useQuery } from '@tanstack/react-query';
import { Globe, X } from 'lucide-react';
import clsx from 'clsx';
import { api, CatalogEntry, Device, DocumentedNetwork, NetworkLayer, NetworkRow, PreflightResultDto, Site, TopologyResponse } from '../api/client';
import { cidrsOverlap } from '../utils/ip';
import { useExecutionMode } from '../executionMode';

/**
 * NetworkRolloutDialog — the fleet abstraction for "create Network XY with VLAN
 * ID on all devices at site/tag/LAYER". Two steps:
 *   1. SCOPE + shared inputs: pick targets by site, tags, TOPOLOGY LAYER or
 *      manually; enter the network (name/VLAN/L3/SSID). No generic interface
 *      field — interfaces differ per device and are resolved in step 2.
 *   2. PREFLIGHT: each supporting plugin probes its devices' live state
 *      (read-only) and returns best-guess values with confidence + notes
 *      (which LAN port carries L3 here, which SSID slot is free…). The user
 *      reviews/overrides per device, then one plan per plugin is created with
 *      the confirmed per-device inputs (2FA + audit trail unchanged).
 */

interface NetworkRolloutDialogProps {
  onClose: () => void;
  /** Optional documented network to pre-fill the shared inputs from (e.g. "Roll out" on the Documented Networks page). */
  initialNetwork?: DocumentedNetwork | null;
}

const INTENT_ID = 'network.create';

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

export function NetworkRolloutDialog({ onClose, initialNetwork }: NetworkRolloutDialogProps) {
  const navigate = useNavigate();
  const { mode } = useExecutionMode();
  const isReadOnly = mode === 'readonly';

  // --- Step 1: scope -----------------------------------------------------------
  const [siteId, setSiteId] = useState(initialNetwork?.siteId ?? '');
  const [tagInput, setTagInput] = useState('');
  const [layerId, setLayerId] = useState(initialNetwork?.layerId ?? '');
  const tags = useMemo(() => tagInput.split(',').map((t) => t.trim()).filter(Boolean), [tagInput]);

  // --- Step 1: shared intent inputs (canonical network.create schema) -----------
  // Pre-filled from the selected documented network when one was passed in.
  const [name, setName] = useState(initialNetwork?.name ?? '');
  const [vlanId, setVlanId] = useState(initialNetwork?.vlanId != null ? String(initialNetwork.vlanId) : '');
  // First IPv4 subnet becomes the L3 address (v6-only rows leave it empty).
  const [cidr, setCidr] = useState(() => initialNetwork?.subnets.find((s) => s.includes('/') && !s.includes(':')) ?? '');
  const [ssidName, setSsidName] = useState('');
  const [passphrase, setPassphrase] = useState('');

  // --- Step 2: per-device overrides (keyed `${pluginId}:${deviceId}`) -----------
  const [overrides, setOverrides] = useState<Record<string, Record<string, string>>>({});
  const [step, setStep] = useState<1 | 2>(1);

  // Documented network to pre-fill from (the selector in the Network section).
  const [docNetId, setDocNetId] = useState(initialNetwork?.id ?? '');

  const devicesQuery = useQuery({ queryKey: ['devices'], queryFn: api.devices });
  const sitesQuery = useQuery({ queryKey: ['sites'], queryFn: api.sites });
  const layersQuery = useQuery({ queryKey: ['layers'], queryFn: api.layers });
  const pluginsQuery = useQuery({ queryKey: ['plugins'], queryFn: api.plugins });
  // Documented networks — prefill selector + name-collision warnings.
  const docNetsQuery = useQuery({ queryKey: ['documentedNetworks'], queryFn: () => api.documentedNetworks() });
  // Live logical network inventory — overlap warnings + "already deployed" hints.
  const liveNetsQuery = useQuery({ queryKey: ['networks'], queryFn: () => api.networks() as Promise<NetworkRow[]> });
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
    if (ssidName.trim()) out.ssid = { name: ssidName.trim(), ...(passphrase ? { passphrase } : {}) };
    return out;
  }, [name, vlanId, cidr, ssidName, passphrase]);

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
    if (n.siteId) setSiteId(n.siteId);
    if (n.layerId) setLayerId(n.layerId);
  }

  // --- Overlap warnings against the live inventory -------------------------------
  // Name / subnet / VLAN collisions with ALREADY-DETECTED networks. These are
  // warnings, not blockers: NAT'd remote sites legitimately reuse names and
  // subnets, and a rollout may intentionally extend an existing network.
  const overlapWarnings = useMemo(() => {
    const out: string[] = [];
    const live = liveNetsQuery.data ?? [];
    const docNets = (docNetsQuery.data ?? []).filter((d) => d.id !== docNetId);

    // 1. Name collision — same name, different network.
    if (name.trim()) {
      const nm = name.trim().toLowerCase();
      for (const n of live) {
        if (n.name.toLowerCase() !== nm || cidr.trim()) continue;
        const where =
          (n.subnets ?? []).join(', ') ||
          `VLAN ${n.vlanId ?? '?'} on ${Array.from(new Set(n.devices.map((d) => d.deviceName))).slice(0, 3).join(', ')}…`;
        out.push(`Name "${n.name}" already exists in the live inventory (${where}).`);
      }
      for (const n of docNets) if (n.name.toLowerCase() === nm && !cidr.trim()) out.push(`Documented network "${n.name}" already uses this name.`);
    }

    // 2. Subnet overlap — the target CIDR intersects an existing live subnet.
    const tCidr = cidr.trim();
    if (tCidr) {
      for (const n of live) {
        const hit = (n.subnets ?? []).find((s) => s.includes('/') && cidrsOverlap(tCidr, s));
        if (!hit) continue;
        const devs = Array.from(new Set(n.devices.map((d) => d.deviceName))).slice(0, 4).join(', ');
        out.push(`Subnet ${tCidr} overlaps existing live network "${n.name}" (${hit}) on ${devs}${n.devices.length > 4 ? ` +${n.devices.length - 4}` : ''}. Fine for NAT'd remote sites — otherwise pick a free range.`);
      }
    }

    // 3. VLAN reuse — same VLAN ID, different (non-overlapping) subnet.
    const v = Number(vlanId);
    if (Number.isInteger(v) && v >= 1 && v <= 4094) {
      for (const n of live) {
        if (n.vlanId !== v) continue;
        const sameSubnet = tCidr ? (n.subnets ?? []).some((s) => s.includes('/') && cidrsOverlap(tCidr, s)) : false;
        if (!sameSubnet) out.push(`VLAN ${v} is already used by live network "${n.name}" (${(n.subnets ?? []).join(', ') || 'no subnet known'}) — extending it on more devices is usually intended; a different subnet with the same VLAN ID will not route between sites.`);
      }
    }

    // De-duplicate (a row can hit both name and subnet).
    return Array.from(new Set(out)).slice(0, 6);
  }, [name, cidr, vlanId, docNetId, liveNetsQuery.data, docNetsQuery.data]);

  /** True when the live inventory already shows this network on the device. */
  function isDeployedOn(deviceId: string): boolean {
    const tCidr = cidr.trim();
    const v = Number(vlanId);
    for (const n of liveNetsQuery.data ?? []) {
      if (!n.devices.some((m) => m.deviceId === deviceId)) continue;
      if (tCidr && (n.subnets ?? []).some((s) => s.includes('/') && cidrsOverlap(tCidr, s))) return true;
      if (!tCidr && Number.isInteger(v) && v >= 1 && n.vlanId === v) return true;
    }
    return false;
  }

  // --- Step 2: preflight ---------------------------------------------------------
  const preflightQuery = useMutation({
    mutationFn: async () => {
      const perPlugin = new Map<string, PreflightResultDto[]>();
      for (const [pid, devs] of groups.entries()) {
        const r = await api.plansPreflight({ pluginId: pid, intentActionId: INTENT_ID, inputs: sharedInputs, deviceIds: devs.map((d) => d.id) });
        perPlugin.set(pid, r.results);
      }
      return perPlugin;
    },
  });

  const [formError, setFormError] = useState<string | null>(null);

  function handleResolve(e: React.FormEvent) {
    e.preventDefault();
    if (!name.trim()) { setFormError('Network name is required.'); return; }
    if (vlanId.trim() !== '') {
      const v = Number(vlanId);
      if (!Number.isInteger(v) || v < 1 || v > 4094) { setFormError('VLAN ID must be an integer 1..4094.'); return; }
    } else if (!cidr.trim() && !ssidName.trim()) {
      setFormError('Provide at least one of VLAN ID, L3 address or SSID — there is nothing to create otherwise.');
      return;
    }
    if (groups.size === 0) { setFormError('No target device has a plugin that implements network.create.'); return; }
    setOverrides({});
    preflightQuery.mutate();
  }

  function handleBack() {
    setStep(1);
    preflightQuery.reset();
  }

  // --- Submit: one plan per supporting plugin with confirmed per-device inputs ----
  const createPlans = useMutation({
    mutationFn: async () => {
      const deviceInputs: Record<string, Record<string, unknown>> = {};
      for (const [pid, devs] of groups.entries()) {
        for (const d of devs) {
          const ov = overrides[`${pid}:${d.id}`];
          if (!ov) continue;
          const perDevice: Record<string, unknown> = {};
          if (ov.vlanId !== undefined && ov.vlanId !== '' && Number.isInteger(Number(ov.vlanId))) perDevice['vlanId'] = Number(ov.vlanId);
          if (ov.interface !== undefined && ov.interface !== '') perDevice['interface'] = ov.interface;
          if (ov.cidr !== undefined && ov.cidr !== '') perDevice['cidr'] = ov.cidr;
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

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto bg-black/40 p-4">
      <div className="mt-8 w-full max-w-3xl rounded-lg border border-border bg-card p-5 shadow-xl">
        <div className="mb-4 flex items-center justify-between">
          <h2 className="flex items-center gap-2 text-base font-semibold text-foreground">
            <Globe className="h-4 w-4" /> Roll out network across the fleet
            <span className={clsx('rounded-full px-2 py-0.5 text-xs', step === 1 ? 'bg-primary/15 text-primary' : 'bg-success/15 text-success')}>
              {step === 1 ? 'Step 1 — scope & network' : 'Step 2 — per-device review'}
            </span>
          </h2>
          <button type="button" onClick={onClose} className="rounded p-1 text-secondary hover:bg-muted"><X className="h-4 w-4" /></button>
        </div>

        {formError && (
          <div className="mb-3 rounded-md border border-danger-border bg-danger px-3 py-2 text-sm text-danger-fg">{formError}</div>
        )}
        {(preflightQuery.isError || createPlans.isError) && (
          <div className="mb-3 rounded-md border border-danger-border bg-danger px-3 py-2 text-sm text-danger-fg">
            {((preflightQuery.error ?? createPlans.error) as Error).message}
          </div>
        )}

        {/* ================= STEP 1 — scope + shared inputs ================= */}
        {step === 1 && (
          <form onSubmit={handleResolve} className="space-y-4">
            <section className="rounded-md border border-border bg-background p-3">
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

            <section className="rounded-md border border-border bg-background p-3">
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
                  <span className="mb-1 block font-medium text-secondary">VLAN ID (optional)</span>
                  <input type="number" min={1} max={4094} value={vlanId} onChange={(e) => setVlanId(e.target.value)} placeholder="42 — omit for L3-only on default VLAN" className="w-full rounded-md border border-border px-3 py-2 text-sm" />
                </label>
                <label className="block text-sm">
                  <span className="mb-1 block font-medium text-secondary">L3 address (CIDR, optional)</span>
                  <input type="text" value={cidr} onChange={(e) => setCidr(e.target.value)} placeholder="10.42.0.1/24 — per-device override in step 2" className="w-full rounded-md border border-border px-3 py-2 text-sm" />
                </label>
                <div className="grid grid-cols-2 gap-3">
                  <label className="block text-sm">
                    <span className="mb-1 block font-medium text-secondary">WLAN SSID (optional)</span>
                    <input type="text" value={ssidName} onChange={(e) => setSsidName(e.target.value)} placeholder="XY-WIFI" className="w-full rounded-md border border-border px-3 py-2 text-sm" />
                  </label>
                  <label className="block text-sm">
                    <span className="mb-1 block font-medium text-secondary">WPA2 passphrase</span>
                    <input type="text" value={passphrase} onChange={(e) => setPassphrase(e.target.value)} placeholder="min. 8 chars" className="w-full rounded-md border border-border px-3 py-2 text-sm" />
                  </label>
                </div>
              </div>
              <p className="mt-2 text-xs text-faint">
                No generic interface field on purpose — each router decides its own L2 port. Step 2 resolves the best-guess per device from live state and lets you override it.
              </p>
            </section>

            {overlapWarnings.length > 0 && (
              <div className="rounded-md border border-warning/40 bg-warning/10 p-3">
                <h3 className="mb-1 text-sm font-semibold text-warning-fg">Possible overlap with existing networks</h3>
                <ul className="list-disc space-y-1 pl-4 text-xs text-secondary">
                  {overlapWarnings.map((w) => (<li key={w}>{w}</li>))}
                </ul>
                <p className="mt-2 text-xs text-faint">
                  Warnings only — NAT'd remote sites and multi-site designs legitimately reuse names, subnets or VLAN IDs. Continue when the overlap is intentional; step 2 shows what already exists on each device.
                </p>
              </div>
            )}

            <div className="flex items-center gap-3">
              <button type="submit" disabled={preflightQuery.isPending || isReadOnly || groups.size === 0} className={clsx('rounded-md px-4 py-2 text-sm font-semibold text-white', isReadOnly ? 'bg-muted opacity-50' : 'bg-primary hover:bg-primary-hover disabled:opacity-50')}>
                {preflightQuery.isPending ? 'Resolving…' : `Resolve per-device settings (${totalTargets})`}
              </button>
            </div>
          </form>
        )}

        {/* ================= STEP 2 — preflight review ================= */}
        {step === 2 && (
          <div className="space-y-4">
            {preflightQuery.isPending && <p className="text-sm text-muted-foreground">Probing device state (read-only)…</p>}

            {!preflightQuery.isPending && preflightQuery.data && [...groups.entries()].map(([pid, devs]) => {
              const results = preflightQuery.data?.get(pid) ?? [];
              return (
                <section key={pid} className="rounded-md border border-border bg-background p-3">
                  <h3 className="mb-2 text-sm font-semibold text-secondary">{pluginName(pid)} — {devs.length} device{devs.length === 1 ? '' : 's'}</h3>
                  <div className="space-y-2">
                    {devs.map((d) => {
                      const r = results.find((x) => x.deviceId === d.id);
                      const ovKey = `${pid}:${d.id}`;
                      const ov = overrides[ovKey] ?? {};
                      const setOv = (k: string, v: string) => setOverrides((prev) => ({ ...prev, [ovKey]: { ...(prev[ovKey] ?? {}), [k]: v } }));
                      return (
                        <div key={d.id} className="rounded-md border border-border p-2">
                          <div className="mb-1.5 flex items-center gap-2 text-sm">
                            <span className="font-medium text-foreground">{d.name}</span>
                            {isDeployedOn(d.id) && (
                              <span title="The live inventory already shows this network on the device — the step will be a no-op there." className="rounded-full bg-success/15 px-2 py-0.5 text-xs text-success">already deployed</span>
                            )}
                            {r?.degraded && (
                              <span title={r.error} className="rounded-full bg-danger/15 px-2 py-0.5 text-xs text-danger-fg">probe failed — defaults apply</span>
                            )}
                          </div>
                          {/* Suggested values as editable fields, pre-filled from the probe. */}
                          <div className="flex flex-wrap gap-2">
                            {r?.values.map((v) => (
                              <PreflightField key={v.key} label={`${v.key}${v.confidence !== 'high' ? ` (${v.confidence})` : ''}`} initial={ov[v.key] ?? v.value} onCommit={(val) => setOv(v.key, val)} />
                            ))}
                            {(!r || !r.values.some((v) => v.key === 'vlanId')) && (
                              <PreflightField label="vlanId (override)" initial={ov.vlanId ?? sharedInputs.vlanId ?? ''} onCommit={(val) => setOv('vlanId', val)} />
                            )}
                            {(!r || !r.values.some((v) => v.key === 'cidr')) && (
                              <PreflightField label="cidr (override)" initial={ov.cidr ?? sharedInputs.cidr ?? ''} onCommit={(val) => setOv('cidr', val)} />
                            )}
                            {(!r || !r.values.some((v) => v.key === 'interface')) && (
                              <PreflightField label="interface (override)" initial={ov.interface ?? ''} onCommit={(val) => setOv('interface', val)} />
                            )}
                          </div>
                          {r?.values.filter((v) => v.note).map((v) => (
                            <p key={`note-${v.key}`} className="mt-1 text-xs text-faint">• {v.key}: {v.note}</p>
                          ))}
                        </div>
                      );
                    })}
                  </div>
                </section>
              );
            })}

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
          </div>
        )}
      </div>
    </div>
  );
}
