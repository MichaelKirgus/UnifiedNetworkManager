import { useEffect, useMemo, useRef, useState } from 'react';
import { useLocation, useNavigate, useSearchParams } from 'react-router-dom';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { ChevronDown, Globe2, Loader2 } from 'lucide-react';
import clsx from 'clsx';
import { api, CatalogEntry, Device, DnsRow, NetworkLayer, PreflightResultDto, Site, TopologyResponse } from '../api/client';
import { useExecutionMode } from '../executionMode';
import { WizardLayout } from '../components/Wizard';

/**
 * DnsRolloutPage — the fleet abstraction for "create static DNS entry NAME → IP
 * on all devices at site/tag/LAYER", as a FULL PAGE (not a dialog) so large
 * fleets stay usable on small screens. Two steps:
 *   1. SCOPE + shared inputs: pick targets by site, tags, TOPOLOGY LAYER or
 *      manually; enter the entry (hostname + IPv4/IPv6 address).
 *   2. REVIEW: each supporting plugin's devices are listed with their live
 *      state from the DNS inventory ("already deployed" / "will replace"), then
 *      one plan per plugin is created (dns.set — canonical fan-out intent).
 *
 * Reuses the shared <WizardLayout> shell and the same scoping machinery as the
 * network rollout page.
 */

const INTENT_ID = 'dns.set';

/** IPv4 or IPv6 literal (same pattern the plugins' dns.set schema enforces). */
const IP_PATTERN = /^\d{1,3}(\.\d{1,3}){3}$|^[0-9a-fA-F:.]*:[0-9a-fA-F:.]*$/;

/** Live-inventory state of one target device for the entry being rolled out. */
type DnsDeployState = 'new' | 'deployed' | 'replace';

export default function DnsRolloutPage() {
  const navigate = useNavigate();
  const location = useLocation();
  const [searchParams] = useSearchParams();
  const queryClient = useQueryClient();
  const { mode } = useExecutionMode();
  const isReadOnly = mode === 'readonly';

  // Where "Cancel" returns to (set by the entry point via location.state).
  const from = (location.state as { from?: string } | null)?.from ?? '/dns';
  function handleExit() { navigate(from); }

  // --- Step 1: scope -----------------------------------------------------------
  const [siteId, setSiteId] = useState('');
  const [tagInput, setTagInput] = useState('');
  const [layerId, setLayerId] = useState('');
  const tags = useMemo(() => tagInput.split(',').map((t) => t.trim()).filter(Boolean), [tagInput]);

  // --- Step 1: shared intent inputs (canonical dns.set schema) ------------------
  const [name, setName] = useState('');
  const [ip, setIp] = useState('');
  // Optional note for the entry — persisted only by vendors with a native field
  // (RouterOS `comment`); other plugins ignore it.
  const [description, setDescription] = useState('');
  // Per-device IP override in the review step: adding an EXISTING entry to other
  // devices may need a different address per target than the shared one.
  const [overrides, setOverrides] = useState<Record<string, string>>({});

  /** The effective IP for one target device (override wins over the shared one). */
  const effIpFor = (deviceId: string): string => (overrides[deviceId] ?? '').trim() || ip.trim();

  // --- Step 2 -------------------------------------------------------------------
  const [expandedIds, setExpandedIds] = useState<Set<string>>(new Set());
  const [step, setStep] = useState<1 | 2>(1);

  const devicesQuery = useQuery({ queryKey: ['devices'], queryFn: api.devices });
  const sitesQuery = useQuery({ queryKey: ['sites'], queryFn: api.sites });
  const layersQuery = useQuery({ queryKey: ['layers'], queryFn: api.layers });
  const pluginsQuery = useQuery({ queryKey: ['plugins'], queryFn: api.plugins });
  // Live DNS inventory — drives the "already deployed / will replace" badges.
  const dnsQuery = useQuery({ queryKey: ['dns'], queryFn: () => api.dns(), staleTime: 30_000 });
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

  // Catalog per candidate plugin — only plugins implementing dns.set count.
  const catalogQueries = useQuery({
    queryKey: ['pluginActionsIntent', INTENT_ID, candidatePluginIds.join('|')],
    queryFn: async () => {
      const out = new Map<string, CatalogEntry | null>();
      for (const pluginId of candidatePluginIds) {
        try {
          const res = await api.pluginActions(pluginId);
          out.set(pluginId, res.actions.find((a) => a.id === INTENT_ID) ?? null);
        } catch {
          out.set(pluginId, null);
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
    for (const [pluginId, entry] of m.entries()) if (entry) out.set(pluginId, entry);
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
    if (name.trim()) out.name = name.trim().toLowerCase();
    if (ip.trim()) out.ip = ip.trim();
    if (description.trim()) out.description = description.trim();
    return out;
  }, [name, ip, description]);

  // Deep link: /dns/rollout?name=foo&ip=1.2.3.4 pre-fills the entry fields.
  const nameParam = searchParams.get('name');
  const ipParam = searchParams.get('ip');
  useEffect(() => {
    if (nameParam) setName(nameParam.toLowerCase());
    if (ipParam) setIp(ipParam);
  }, [nameParam, ipParam]);

  // --- Live-inventory state per target device -----------------------------------
  /** For each deviceId: how the entry currently looks on that device. */
  const deployState = useMemo(() => {
    const m = new Map<string, DnsDeployState>();
    if (!dnsQuery.data || !name.trim() || !ip.trim()) return m;
    const n = name.trim().toLowerCase();
    for (const row of dnsQuery.data as DnsRow[]) {
      if (row.name !== n) continue;
      for (const d of row.devices) {
        // Per-device effective IP — an override may make this target a no-op
        // even when the shared address is not on the device.
        const eff = (overrides[d.deviceId] ?? '').trim() || ip.trim();
        if (!d.ips.includes(eff)) continue;
        m.set(d.deviceId, 'deployed'); // exact name+ip already there → no-op
      }
    }
    // Same name with a DIFFERENT address on the device → will be replaced in place.
    for (const row of dnsQuery.data as DnsRow[]) {
      if (row.name !== n) continue;
      for (const d of row.devices) {
        if (!m.has(d.deviceId)) m.set(d.deviceId, 'replace');
      }
    }
    return m;
  }, [dnsQuery.data, name, ip, overrides]);

  // --- Step 2: preflight (with live progress + cancel) ---------------------------
  const abortRef = useRef<AbortController | null>(null);
  const cancelledRef = useRef(false);

  interface ProbeProgress {
    totalPlugins: number;
    donePlugins: number;
    totalDevices: number;
    doneDevices: number;
    status: Record<string, 'probing' | 'done' | 'degraded'>;
  }
  const [probeProgress, setProbeProgress] = useState<ProbeProgress | null>(null);

  const preflightQuery = useMutation({
    mutationFn: async (signal?: AbortSignal) => {
      // Parallel fan-out — one plugin's probe failure must not sink the whole
      // wizard; its devices are marked degraded and fall back to defaults.
      cancelledRef.current = false;
      const perPlugin = new Map<string, PreflightResultDto[]>();
      setProbeProgress({ totalPlugins: groups.size, donePlugins: 0, totalDevices: totalTargets, doneDevices: 0, status: {} });

      await Promise.all([...groups.entries()].map(async ([pluginId, devs]) => {
        setProbeProgress((p) => p ? { ...p, status: { ...p.status, [pluginId]: 'probing' } } : p);
        try {
          const r = await api.plansPreflight({ pluginId, intentActionId: INTENT_ID, inputs: sharedInputs, deviceIds: devs.map((d) => d.id) }, signal ? { signal } : undefined);
          perPlugin.set(pluginId, r.results);
        } catch (e) {
          if (cancelledRef.current || (signal?.aborted)) throw e; // let the whole run abort cleanly
          perPlugin.set(pluginId, devs.map((d) => ({ deviceId: d.id, values: [], degraded: true, error: e instanceof Error ? e.message : String(e) })));
        }
        if (cancelledRef.current || signal?.aborted) throw new Error('cancelled');
        setProbeProgress((p) => p ? { ...p, donePlugins: p.donePlugins + 1, doneDevices: p.doneDevices + devs.length, status: { ...p.status, [pluginId]: perPlugin.get(pluginId)?.some((x) => x.degraded) ? 'degraded' : 'done' } } : p);
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
    if (!name.trim()) { setFormError('Hostname is required.'); return; }
    if (name.trim().length > 253 || /\s/.test(name.trim())) { setFormError('Hostname must be a single label of at most 253 characters.'); return; }
    const ipTrimmed = ip.trim();
    if (!ipTrimmed) { setFormError('IP address is required.'); return; }
    if (!IP_PATTERN.test(ipTrimmed)) { setFormError('Not a valid IPv4 or IPv6 address.'); return; }
    if (groups.size === 0) { setFormError('No target device has a plugin that implements dns.set.'); return; }
    setExpandedIds(new Set());
    const controller = new AbortController();
    abortRef.current = controller;
    preflightQuery.mutate(controller.signal);
  }

  function handleBack() {
    setStep(1);
    preflightQuery.reset();
    setProbeProgress(null);
  }

  // --- Submit: one plan per supporting plugin ------------------------------------
  const createPlans = useMutation({
    mutationFn: async () => {
      // Per-device inputs — a review-step IP override changes the address for
      // that target only, so each step carries its own input object.
      const stepInputs = (deviceId: string): Record<string, unknown> => {
        const out: Record<string, unknown> = { name: name.trim().toLowerCase(), ip: effIpFor(deviceId) };
        if (description.trim()) out.description = description.trim();
        return out;
      };
      const created: Array<{ pluginId: string; planId: string; deviceCount: number }> = [];
      for (const [pluginId, devs] of groups.entries()) {
        const steps = devs.map((d) => ({ deviceId: d.id, input: stepInputs(d.id) }));
        const plan = await api.createPlan({
          pluginId,
          intentActionId: INTENT_ID,
          inputs: steps[0].input,
          devices: [{ deviceId: steps[0].deviceId }],
        });
        if (steps.length > 1) {
          await api.addPlanStepsBulk(plan.id, steps.slice(1).map((s) => ({ deviceId: s.deviceId, actionId: INTENT_ID, input: s.input })));
        }
        created.push({ pluginId, planId: plan.id, deviceCount: devs.length });
      }
      if (mode === 'execute') {
        for (const c of created) await api.executePlan(c.planId);
      }
      return created;
    },
    onSuccess: () => {
      // The inventory refreshes on the next poll — nudge it now.
      void queryClient.invalidateQueries({ queryKey: ['dns'] });
    },
  });

  const totalTargets = [...groups.values()].reduce((n, l) => n + l.length, 0);
  const sites: Site[] = sitesQuery.data ?? [];
  const layers: NetworkLayer[] = (layersQuery.data ?? []).slice().sort((a, b) => a.sort - b.sort);
  const pluginName = (id: string) => pluginsQuery.data?.find((p) => p.id === id)?.name ?? id;

  // Progress percentage for the resolving bar.
  const progressPct = probeProgress && probeProgress.totalDevices > 0
    ? Math.round((probeProgress.doneDevices / probeProgress.totalDevices) * 100)
    : 0;

  return (
    <WizardLayout
      title="Roll out DNS entry across the fleet"
      icon={<Globe2 className="h-4 w-4 text-primary" />}
      steps={[{ label: 'Scope & entry' }, { label: 'Per-device review' }]}
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
              {skippedDevices.length > 0 && `, ${skippedDevices.length} skipped (no dns.set support: ${skippedDevices.map((d) => d.name).join(', ')})`}.
            </p>
          </section>

          <section className="rounded-md border border-border bg-background p-3 sm:p-4">
            <h3 className="mb-2 text-sm font-semibold text-secondary">DNS entry</h3>
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
              <label className="block text-sm">
                <span className="mb-1 block font-medium text-secondary">Hostname *</span>
                <input type="text" value={name} onChange={(e) => setName(e.target.value)} placeholder="printer.local" className="w-full rounded-md border border-border px-3 py-2 font-mono text-sm" />
              </label>
              <label className="block text-sm">
                <span className="mb-1 block font-medium text-secondary">IP address *</span>
                <input type="text" value={ip} onChange={(e) => setIp(e.target.value)} placeholder="10.25.0.42 or fd00::42 — one family per rollout" className="w-full rounded-md border border-border px-3 py-2 font-mono text-sm" />
              </label>
            </div>
            <label className="mt-3 block text-sm">
              <span className="mb-1 block font-medium text-secondary">Description (optional)</span>
              <input type="text" value={description} onChange={(e) => setDescription(e.target.value)} maxLength={255} placeholder="Free-text note — stored where the vendor has a native field (RouterOS comment), ignored elsewhere" className="w-full rounded-md border border-border px-3 py-2 text-sm" />
            </label>
            <p className="mt-2 text-xs text-faint">
              One address per rollout (IPv4 or IPv6). If the name already exists on a device with a different address, the plugin replaces it in place; an identical entry is skipped as a no-op. Dual-stack entries are two rollouts. In the review step you can override the IP per target device.
            </p>
          </section>

          {/* Resolve action + live progress panel (replaces a bare "Resolving…"). */}
          <div className="space-y-3">
            {preflightQuery.isPending && probeProgress ? (
              <div className="rounded-md border border-border bg-background p-4">
                <div className="mb-2 flex items-center justify-between text-sm">
                  <span className="flex items-center gap-2 font-medium text-secondary">
                    <Loader2 className="h-4 w-4 animate-spin text-primary" />
                    Resolving per-device state…
                  </span>
                  <span className="text-xs tabular-nums text-faint">{probeProgress.doneDevices}/{probeProgress.totalDevices} devices · {progressPct}%</span>
                </div>
                {/* Overall progress bar. */}
                <div className="h-2 w-full overflow-hidden rounded-full bg-muted">
                  <div className="h-full rounded-full bg-primary transition-all duration-300" style={{ width: `${progressPct}%` }} />
                </div>
                {/* Detail steps — one row per supporting plugin. */}
                <ul className="mt-3 space-y-1">
                  {[...groups.entries()].map(([pluginId, devs]) => {
                    const st = probeProgress.status[pluginId] ?? 'probing';
                    return (
                      <li key={pluginId} className="flex items-center gap-2 text-xs">
                        {st === 'done' && <span className="h-1.5 w-1.5 shrink-0 rounded-full bg-success" />}
                        {st === 'degraded' && <span className="h-1.5 w-1.5 shrink-0 rounded-full bg-warning" title="probe failed — defaults apply" />}
                        {st === 'probing' && <Loader2 className="h-3 w-3 shrink-0 animate-spin text-primary" />}
                        <span className={clsx('truncate', st === 'probing' ? 'text-secondary' : 'text-faint')}>
                          {pluginName(pluginId)} — {devs.length} device{devs.length === 1 ? '' : 's'}
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
                  {preflightQuery.isPending ? 'Resolving…' : `Review per-device state (${totalTargets})`}
                </button>
              </div>
            )}
          </div>
        </form>
      )}

      {/* ================= STEP 2 — review + submit ================= */}
      {step === 2 && (
        <div className="space-y-4">
          {!preflightQuery.isPending && preflightQuery.data && (
            <>
              {[...groups.entries()].map(([pluginId, devs]) => {
                const results = preflightQuery.data?.get(pluginId) ?? [];
                return (
                  <section key={pluginId} className="rounded-md border border-border bg-background p-3">
                    <h3 className="mb-2 text-sm font-semibold text-secondary">{pluginName(pluginId)} — {devs.length} device{devs.length === 1 ? '' : 's'}</h3>
                    <div className="space-y-1.5">
                      {devs.map((d) => {
                        const r = results.find((x) => x.deviceId === d.id);
                        const state: DnsDeployState = deployState.get(d.id) ?? 'new';
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
                              {(overrides[d.id] ?? '').trim() !== '' && (
                                <span title={`IP override for this device: ${overrides[d.id].trim()} (shared address is ${ip.trim()})`} className="rounded-full bg-info/15 px-2 py-0.5 text-xs text-info-fg">override → {overrides[d.id].trim()}</span>
                              )}
                              {state === 'deployed' && (
                                <span title="The live inventory already shows this exact entry on the device — the step will be a no-op there." className="rounded-full bg-success/15 px-2 py-0.5 text-xs text-success">already deployed</span>
                              )}
                              {state === 'replace' && (
                                <span title="The name exists on this device with a different address — it will be replaced in place." className="rounded-full bg-warning/15 px-2 py-0.5 text-xs text-warning-fg">will replace existing</span>
                              )}
                              {r?.degraded && (
                                <span title={r.error} className="rounded-full bg-danger/15 px-2 py-0.5 text-xs text-danger-fg">probe failed — defaults apply</span>
                              )}
                            </div>

                            {/* Expanded area — per-device IP override + probe notes. */}
                            {expanded && (
                              <div className="space-y-2 border-t border-border px-3 py-2">
                                <p className="text-xs text-faint">{name.trim().toLowerCase()} → {effIpFor(d.id)}</p>
                                <label className="block text-xs">
                                  <span className="mb-1 block font-medium text-secondary">IP override for this device (optional)</span>
                                  <input
                                    type="text"
                                    value={overrides[d.id] ?? ''}
                                    onChange={(e) => setOverrides((prev) => ({ ...prev, [d.id]: e.target.value }))}
                                    placeholder={`default: ${ip.trim()}`}
                                    className="w-full rounded-md border border-border px-2 py-1 font-mono text-xs"
                                  />
                                </label>
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
              {(() => {
                const plannedIds = new Set<string>();
                for (const devs of groups.values()) for (const d of devs) plannedIds.add(d.id);
                const deployed = [...plannedIds].filter((id) => deployState.get(id) === 'deployed');
                const replace = [...plannedIds].filter((id) => deployState.get(id) === 'replace');
                const fresh = [...plannedIds].filter((id) => !deployState.has(id));
                const devName = (id: string) => devicesQuery.data?.find((d) => d.id === id)?.name ?? id;
                return (
                  <section className="rounded-md border border-border bg-background p-3">
                    <h3 className="mb-2 text-sm font-semibold text-secondary">Rollout summary</h3>
                    {deployed.length > 0 && (
                      <p className="text-xs text-success">No-op (already deployed): {deployed.map(devName).join(', ')}</p>
                    )}
                    {replace.length > 0 && (
                      <p className="mt-1 text-xs text-warning-fg">Will replace existing address: {replace.map(devName).join(', ')}</p>
                    )}
                    <p className={clsx('mt-1 text-xs', fresh.length > 0 ? 'text-secondary' : 'text-faint')}>
                      Will create: {fresh.length > 0 ? fresh.map(devName).join(', ') : '— (nothing new)'}
                    </p>
                  </section>
                );
              })()}

              <div className="flex items-center gap-3">
                <button type="button" onClick={handleBack} className="rounded-md border border-border px-4 py-2 text-sm font-medium text-secondary hover:bg-muted">← Back</button>
                <button
                  type="button"
                  disabled={createPlans.isPending || isReadOnly}
                  onClick={() => {
                    // Validate any per-device overrides before creating plans.
                    const bad = Object.entries(overrides).find(([, v]) => v.trim() !== '' && !IP_PATTERN.test(v.trim()));
                    if (bad) {
                      setFormError(`Invalid IP override "${bad[1].trim()}" for ${devicesQuery.data?.find((d) => d.id === bad[0])?.name ?? bad[0]} — fix it in the review list.`);
                      return;
                    }
                    createPlans.mutate();
                  }}
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
