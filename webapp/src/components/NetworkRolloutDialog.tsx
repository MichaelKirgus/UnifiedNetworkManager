import { useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useMutation, useQuery } from '@tanstack/react-query';
import { Globe, X } from 'lucide-react';
import clsx from 'clsx';
import { api, CatalogEntry, Device, Site } from '../api/client';
import { useExecutionMode } from '../executionMode';

/**
 * NetworkRolloutDialog — the fleet abstraction for "create Network XY with VLAN
 * ID on all devices at site/tag". One canonical intent (`network.create`) is
 * fanned out per vendor plugin: every target device whose assigned router
 * plugin implements `network.create` gets a plan step; plugins that don't are
 * listed as skipped. Plans are created via the standard POST /plans fan-out, so
 * 2FA + configs:apply + audit trail apply exactly like single actions.
 */

interface NetworkRolloutDialogProps {
  onClose: () => void;
}

const INTENT_ID = 'network.create';

export function NetworkRolloutDialog({ onClose }: NetworkRolloutDialogProps) {
  const navigate = useNavigate();
  const { mode } = useExecutionMode();
  const isReadOnly = mode === 'readonly';

  // --- Scope -----------------------------------------------------------------
  const [siteId, setSiteId] = useState('');
  const [tagInput, setTagInput] = useState('');
  const tags = useMemo(() => tagInput.split(',').map((t) => t.trim()).filter(Boolean), [tagInput]);

  // --- Intent inputs (canonical network.create schema) -------------------------
  const [name, setName] = useState('');
  const [vlanId, setVlanId] = useState('');
  const [cidr, setCidr] = useState('');
  const [iface, setIface] = useState('');
  const [poolStart, setPoolStart] = useState('');
  const [poolEnd, setPoolEnd] = useState('');
  const [ssidName, setSsidName] = useState('');
  const [passphrase, setPassphrase] = useState('');

  const devicesQuery = useQuery({ queryKey: ['devices'], queryFn: api.devices });
  const sitesQuery = useQuery({ queryKey: ['sites'], queryFn: api.sites });
  const pluginsQuery = useQuery({ queryKey: ['plugins'], queryFn: api.plugins });

  // Devices matching the scope (site AND/OR tags — a device matches when it hits
  // every non-empty dimension).
  const scopedDevices: Device[] = useMemo(() => {
    const all = devicesQuery.data ?? [];
    return all.filter((d) => {
      if (siteId && d.siteId !== siteId) return false;
      if (tags.length > 0 && !tags.some((t) => d.tags.includes(t))) return false;
      return true;
    });
  }, [devicesQuery.data, siteId, tags]);

  // Candidate plugins: every plugin assigned to a scoped device.
  const candidatePluginIds = useMemo(() => {
    const s = new Set<string>();
    for (const d of scopedDevices) for (const p of d.plugins ?? []) s.add(p.pluginId);
    return [...s];
  }, [scopedDevices]);

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
    for (const d of scopedDevices) {
      for (const p of d.plugins ?? []) {
        if (!supporting.has(p.pluginId)) continue;
        let list = g.get(p.pluginId);
        if (!list) { list = []; g.set(p.pluginId, list); }
        list.push(d);
      }
    }
    return g;
  }, [scopedDevices, supporting]);

  const skippedDevices = useMemo(
    () => scopedDevices.filter((d) => !d.plugins?.some((p) => supporting.has(p.pluginId))),
    [scopedDevices, supporting]
  );

  // --- Submit ------------------------------------------------------------------
  const createPlans = useMutation({
    mutationFn: async () => {
      const inputs: Record<string, unknown> = { name: name.trim(), vlanId: Number(vlanId) };
      if (cidr.trim()) inputs.cidr = cidr.trim();
      if (iface.trim()) inputs.interface = iface.trim();
      if (poolStart.trim() && poolEnd.trim()) inputs.dhcpPool = { start: poolStart.trim(), end: poolEnd.trim() };
      if (ssidName.trim()) inputs.ssid = { name: ssidName.trim(), ...(passphrase ? { passphrase } : {}) };

      const created: Array<{ pluginId: string; planId: string; deviceCount: number }> = [];
      for (const [pluginId, devs] of groups.entries()) {
        const plan = await api.createPlan({
          pluginId,
          intentActionId: INTENT_ID,
          inputs,
          devices: devs.map((d) => ({ deviceId: d.id })),
        });
        created.push({ pluginId, planId: plan.id, deviceCount: devs.length });
      }
      if (mode === 'execute') {
        for (const c of created) await api.executePlan(c.planId);
      }
      return created;
    },
  });

  const [formError, setFormError] = useState<string | null>(null);

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!name.trim()) { setFormError('Network name is required.'); return; }
    const v = Number(vlanId);
    if (!Number.isInteger(v) || v < 1 || v > 4094) { setFormError('VLAN ID must be an integer 1..4094.'); return; }
    if (groups.size === 0) { setFormError('No target device has a plugin that implements network.create.'); return; }
    createPlans.mutate();
  }

  const totalTargets = [...groups.values()].reduce((n, l) => n + l.length, 0);
  const sites: Site[] = sitesQuery.data ?? [];
  const pluginName = (id: string) => pluginsQuery.data?.find((p) => p.id === id)?.name ?? id;

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto bg-black/40 p-4">
      <div className="mt-8 w-full max-w-2xl rounded-lg border border-border bg-card p-5 shadow-xl">
        <div className="mb-4 flex items-center justify-between">
          <h2 className="flex items-center gap-2 text-base font-semibold text-foreground">
            <Globe className="h-4 w-4" /> Roll out network across the fleet
          </h2>
          <button type="button" onClick={onClose} className="rounded p-1 text-secondary hover:bg-muted"><X className="h-4 w-4" /></button>
        </div>

        {formError && (
          <div className="mb-3 rounded-md border border-danger-border bg-danger px-3 py-2 text-sm text-danger-fg">{formError}</div>
        )}
        {createPlans.isError && (
          <div className="mb-3 rounded-md border border-danger-border bg-danger px-3 py-2 text-sm text-danger-fg">
            {(createPlans.error as Error).message}
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-4">
          {/* Scope */}
          <section className="rounded-md border border-border bg-background p-3">
            <h3 className="mb-2 text-sm font-semibold text-secondary">Target scope</h3>
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
              <label className="block text-sm">
                <span className="mb-1 block font-medium text-secondary">Site</span>
                <select value={siteId} onChange={(e) => setSiteId(e.target.value)} className="w-full rounded-md border border-border px-3 py-2 text-sm">
                  <option value="">All sites</option>
                  {sites.map((s) => (<option key={s.id} value={s.id}>{s.name}</option>))}
                </select>
              </label>
              <label className="block text-sm">
                <span className="mb-1 block font-medium text-secondary">Tags (comma-separated, OR)</span>
                <input type="text" value={tagInput} onChange={(e) => setTagInput(e.target.value)} placeholder="router, site-hq" className="w-full rounded-md border border-border px-3 py-2 text-sm" />
              </label>
            </div>
            <p className="mt-2 text-xs text-faint">
              {scopedDevices.length} device{scopedDevices.length === 1 ? '' : 's'} in scope — {totalTargets} target{totalTargets === 1 ? '' : 's'} on supporting plugin(s)
              {skippedDevices.length > 0 && `, ${skippedDevices.length} skipped (no network.create support)`}.
            </p>
          </section>

          {/* Intent inputs */}
          <section className="rounded-md border border-border bg-background p-3">
            <h3 className="mb-2 text-sm font-semibold text-secondary">Network</h3>
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
              <label className="block text-sm">
                <span className="mb-1 block font-medium text-secondary">Name *</span>
                <input type="text" value={name} onChange={(e) => setName(e.target.value)} placeholder="NET_XY" className="w-full rounded-md border border-border px-3 py-2 text-sm" />
              </label>
              <label className="block text-sm">
                <span className="mb-1 block font-medium text-secondary">VLAN ID *</span>
                <input type="number" min={1} max={4094} value={vlanId} onChange={(e) => setVlanId(e.target.value)} placeholder="42" className="w-full rounded-md border border-border px-3 py-2 text-sm" />
              </label>
              <label className="block text-sm">
                <span className="mb-1 block font-medium text-secondary">L3 address (CIDR, optional)</span>
                <input type="text" value={cidr} onChange={(e) => setCidr(e.target.value)} placeholder="10.42.0.1/24" className="w-full rounded-md border border-border px-3 py-2 text-sm" />
              </label>
              <label className="block text-sm">
                <span className="mb-1 block font-medium text-secondary">Interface (vendor default when empty)</span>
                <input type="text" value={iface} onChange={(e) => setIface(e.target.value)} placeholder="LAN-1" className="w-full rounded-md border border-border px-3 py-2 text-sm" />
              </label>
              <label className="block text-sm">
                <span className="mb-1 block font-medium text-secondary">DHCP pool start (optional)</span>
                <input type="text" value={poolStart} onChange={(e) => setPoolStart(e.target.value)} placeholder="10.42.0.10" className="w-full rounded-md border border-border px-3 py-2 text-sm" />
              </label>
              <label className="block text-sm">
                <span className="mb-1 block font-medium text-secondary">DHCP pool end</span>
                <input type="text" value={poolEnd} onChange={(e) => setPoolEnd(e.target.value)} placeholder="10.42.0.250" className="w-full rounded-md border border-border px-3 py-2 text-sm" />
              </label>
              <label className="block text-sm">
                <span className="mb-1 block font-medium text-secondary">WLAN SSID name (optional)</span>
                <input type="text" value={ssidName} onChange={(e) => setSsidName(e.target.value)} placeholder="XY-WIFI" className="w-full rounded-md border border-border px-3 py-2 text-sm" />
              </label>
              <label className="block text-sm">
                <span className="mb-1 block font-medium text-secondary">WPA2 passphrase (optional)</span>
                <input type="text" value={passphrase} onChange={(e) => setPassphrase(e.target.value)} placeholder="min. 8 chars" className="w-full rounded-md border border-border px-3 py-2 text-sm" />
              </label>
            </div>
          </section>

          {/* Target preview */}
          {groups.size > 0 && (
            <section className="rounded-md border border-border bg-background p-3">
              <h3 className="mb-2 text-sm font-semibold text-secondary">Will create one plan per plugin</h3>
              <ul className="space-y-1.5">
                {[...groups.entries()].map(([pid, devs]) => (
                  <li key={pid} className="text-sm text-secondary">
                    <span className="font-medium text-foreground">{pluginName(pid)}</span>{' '}
                    — {devs.length} device{devs.length === 1 ? '' : 's'}: {devs.map((d) => d.name).join(', ')}
                  </li>
                ))}
              </ul>
            </section>
          )}

          <div className="flex items-center gap-3">
            <button
              type="submit"
              disabled={createPlans.isPending || isReadOnly || groups.size === 0}
              className={clsx(
                'rounded-md px-4 py-2 text-sm font-semibold text-white',
                isReadOnly ? 'bg-muted opacity-50' : 'bg-primary hover:bg-primary-hover disabled:opacity-50'
              )}
            >
              {createPlans.isPending ? 'Creating…' : mode === 'execute' ? `Create + execute (${totalTargets})` : `Save as plan(s) (${totalTargets})`}
            </button>
            <span className="text-xs text-faint">Each step is validated by the plugin against its own input schema.</span>
          </div>
        </form>

        {createPlans.isSuccess && (
          <div className="mt-4 rounded-md border border-border bg-background p-3 text-sm">
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
    </div>
  );
}
