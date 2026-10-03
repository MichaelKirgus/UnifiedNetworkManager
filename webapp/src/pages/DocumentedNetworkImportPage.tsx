import { useEffect, useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { DatabaseZap, Loader2 } from 'lucide-react';
import clsx from 'clsx';
import { api, DocumentedNetworkInventoryImportResult } from '../api/client';
import { WizardLayout } from '../components/Wizard';

/**
 * DocumentedNetworkImportPage — "Import from live inventory" as a full-page
 * wizard (replaces the old modal). Copies every logical network currently
 * observed in the live inventory into the documented networks via an ADDITIVE
 * merge: existing entries are never overwritten, only missing subnets / VLAN ids
 * are added; nothing is deleted.
 *
 * Three steps on the shared <WizardLayout> shell:
 *   1. OPTIONS — pick filters (family, public-IP policy, range filter, age…).
 *   2. PREVIEW — a dry-run plan table with live busy feedback while the API
 *      scans the inventory; filters stay adjustable and re-run automatically.
 *   3. DONE — applied summary (created / merged / skipped).
 */

/** Splits the ranges textarea into entries (one per line or comma). */
function parseRangesText(text: string): string[] {
  return text.split(/[\n,]+/).map((s) => s.trim()).filter((s) => s.length > 0);
}

/** One subnet chip — mono, IPv6 purple-tinted (same convention as the live pages). */
function SubnetChip({ cidr }: { cidr: string }) {
  return <span className={`font-mono text-xs ${cidr.includes(':') ? 'text-accent-purple-fg' : ''}`}>{cidr}</span>;
}

type RangeMode = 'keep-all' | 'include-only' | 'exclude';
type PublicIpPolicy = 'keep' | 'strip' | 'skip-network';

export default function DocumentedNetworkImportPage() {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [searchParams] = useSearchParams();
  // Where "Cancel" returns to (set by the entry point).
  const from = searchParams.get('from') ?? '/documented-networks';

  // --- Filters (same defaults as the previous modal) ---------------------------
  const [skipWithoutSubnet, setSkipWithoutSubnet] = useState(true);
  const [skipWithoutVlan, setSkipWithoutVlan] = useState(false);
  const [version, setVersion] = useState<'all' | 'v4' | 'v6'>('all');
  const [publicIpv4Policy, setPublicIpv4Policy] = useState<PublicIpPolicy>('keep');
  const [publicIpv6Policy, setPublicIpv6Policy] = useState<PublicIpPolicy>('keep');
  const [rangeMode, setRangeMode] = useState<RangeMode>('keep-all');
  const [rangesText, setRangesText] = useState('');
  const [maxAgeHours, setMaxAgeHours] = useState(24);

  // --- Wizard state -------------------------------------------------------------
  const [step, setStep] = useState<1 | 2 | 3>(1);
  const [plan, setPlan] = useState<DocumentedNetworkInventoryImportResult | null>(null);
  const [applied, setApplied] = useState<DocumentedNetworkInventoryImportResult | null>(null);

  /** The shared request body for both the dry-run and the real import. */
  function buildBody(dryRun: boolean) {
    return { skipWithoutSubnet, skipWithoutVlan, version, publicIpv4Policy, publicIpv6Policy, rangeMode, ranges: parseRangesText(rangesText), maxAgeHours, dryRun };
  }

  const previewMutation = useMutation({
    mutationFn: () => api.importDocumentedNetworksFromInventory(buildBody(true)),
    onSuccess: (res) => setPlan(res),
  });
  const applyMutation = useMutation({
    mutationFn: () => api.importDocumentedNetworksFromInventory(buildBody(false)),
    onSuccess: (res) => {
      setApplied(res);
      setStep(3);
      void queryClient.invalidateQueries({ queryKey: ['documentedNetworks'] });
    },
  });

  // Re-run the preview whenever a filter changes while on the PREVIEW step.
  useEffect(() => {
    if (step === 2) previewMutation.mutate();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [skipWithoutSubnet, skipWithoutVlan, version, publicIpv4Policy, publicIpv6Policy, rangeMode, rangesText, maxAgeHours]);

  const plannedCreates = plan?.planned.filter((p) => p.action === 'create').length ?? 0;
  const plannedUpdates = plan?.planned.filter((p) => p.action === 'update').length ?? 0;
  const plannedSkips = plan?.planned.filter((p) => p.action === 'skip').length ?? 0;

  function handlePreview() {
    setStep(2);
    previewMutation.mutate();
  }

  // The reusable filter controls — rendered full in step 1 and compact in step 2.
  const familySelect = (
    <select className="rounded-md border border-border bg-background px-2 py-1 text-xs" value={version} onChange={(e) => setVersion(e.target.value as 'all' | 'v4' | 'v6')}>
      <option value="all">All (v4 + v6)</option>
      <option value="v4">IPv4 only</option>
      <option value="v6">IPv6 only</option>
    </select>
  );
  const publicV4Select = (
    <select className="rounded-md border border-border bg-background px-2 py-1 text-xs" value={publicIpv4Policy} onChange={(e) => setPublicIpv4Policy(e.target.value as PublicIpPolicy)}>
      <option value="keep">Keep (import all)</option>
      <option value="strip">Strip public, keep internal</option>
      <option value="skip-network">Skip whole network</option>
    </select>
  );
  const publicV6Select = (
    <select className="rounded-md border border-border bg-background px-2 py-1 text-xs" value={publicIpv6Policy} onChange={(e) => setPublicIpv6Policy(e.target.value as PublicIpPolicy)}>
      <option value="keep">Keep (import all)</option>
      <option value="strip">Strip public, keep internal</option>
      <option value="skip-network">Skip whole network</option>
    </select>
  );
  const rangeSelect = (
    <select className="rounded-md border border-border bg-background px-2 py-1 text-xs" value={rangeMode} onChange={(e) => setRangeMode(e.target.value as RangeMode)}>
      <option value="keep-all">All networks (no filter)</option>
      <option value="include-only">Only selected ranges</option>
      <option value="exclude">Exclude selected ranges</option>
    </select>
  );
  const ageSelect = (
    <select className="rounded-md border border-border bg-background px-2 py-1 text-xs" value={maxAgeHours} onChange={(e) => setMaxAgeHours(Number(e.target.value))}>
      <option value={0}>all time (no age limit)</option>
      <option value={6}>last 6 hours</option>
      <option value={24}>last 24 hours</option>
    </select>
  );

  return (
    <WizardLayout
      title="Import from live inventory"
      icon={<DatabaseZap className="h-4 w-4 text-primary" />}
      steps={[{ label: 'Options' }, { label: 'Preview' }, { label: 'Done' }]}
      current={step - 1}
      onExit={() => navigate(from)}
    >
      {/* ================= STEP 1 — options ================= */}
      {step === 1 && (
        <div className="space-y-4">
          <p className="text-sm text-secondary">
            Copies every logical network currently observed in the inventory into the documented networks. Existing entries are
            MERGED, never overwritten: their name, subnets, gateways, DNS/NTP servers, description and placement stay untouched — only new
            subnets and VLAN ids from the observation are added. Nothing is deleted.
          </p>

          <div className="flex flex-col gap-2 text-sm">
            <label className="flex items-center justify-between gap-3 rounded-md border border-border px-3 py-2" title="Pure SSID/VLAN groups without any IP address are skipped by default — enable to document them under their name.">
              <span className="text-secondary">Skip networks without a subnet</span>
              <input type="checkbox" checked={skipWithoutSubnet} onChange={(e) => setSkipWithoutSubnet(e.target.checked)} />
            </label>
            <label className="flex items-center justify-between gap-3 rounded-md border border-border px-3 py-2" title="Only import networks with a discovered VLAN id — drops untagged or unknown-VLAN networks.">
              <span className="text-secondary">Skip networks without a discovered VLAN</span>
              <input type="checkbox" checked={skipWithoutVlan} onChange={(e) => setSkipWithoutVlan(e.target.checked)} />
            </label>
            <label className="flex items-center justify-between gap-3 rounded-md border border-border px-3 py-2" title="Only import networks carrying at least one subnet of the chosen address family.">
              <span className="text-secondary">Address family</span>
              {familySelect}
            </label>
            <label className="flex items-center justify-between gap-3 rounded-md border border-border px-3 py-2" title="How to treat publicly routable IPv4 subnets (RFC 1918 private ranges count as internal). Strip removes only the public v4 subnets — the network is still documented with its internal ones. Skip-network drops the whole network when it has any public v4 subnet.">
              <span className="text-secondary">Public IPv4 subnets</span>
              {publicV4Select}
            </label>
            <label className="flex items-center justify-between gap-3 rounded-md border border-border px-3 py-2" title="How to treat publicly routable IPv6 subnets (GUA 2000::/3; ULA fc00::/7 counts as internal). Strip removes only the public v6 subnets — the network is still documented with its internal ones. Skip-network drops the whole network when it has any public v6 subnet.">
              <span className="text-secondary">Public IPv6 subnets</span>
              {publicV6Select}
            </label>
            <div className="rounded-md border border-border px-3 py-2" title="Restrict the import to specific networks or IP ranges — applied BEFORE all other options. A network matches when ANY of its subnets falls into ANY entry.">
              <div className="flex items-center justify-between gap-3">
                <span className="text-secondary">Network / IP range filter</span>
                {rangeSelect}
              </div>
              {rangeMode !== 'keep-all' && (
                <textarea
                  className="mt-2 w-full rounded-md border border-border bg-background px-2 py-1 font-mono text-xs"
                  rows={3}
                  placeholder={'One CIDR or range per line, e.g.\n192.168.10.0/24\n10.0.5.10-10.0.5.50\nfd00:1::/64'}
                  value={rangesText}
                  onChange={(e) => setRangesText(e.target.value)}
                />
              )}
            </div>
            <label className="flex items-center justify-between gap-3 rounded-md border border-border px-3 py-2" title="Only consider networks observed within this window (the inventory is swept after 24 h).">
              <span className="text-secondary">Observed within</span>
              {ageSelect}
            </label>
          </div>

          {(previewMutation.isError || applyMutation.isError) && (
            <div className="rounded-md border border-danger-border bg-danger px-3 py-2 text-sm text-danger-fg">
              {((previewMutation.error ?? applyMutation.error) as Error).message}
            </div>
          )}

          <div className="flex justify-end gap-2 border-t border-border pt-3">
            <button type="button" onClick={() => navigate(from)} className="rounded-md px-3 py-1.5 text-sm text-secondary hover:bg-muted">
              Cancel
            </button>
            <button
              type="button"
              disabled={previewMutation.isPending}
              onClick={handlePreview}
              className="inline-flex items-center gap-2 rounded-md bg-primary px-4 py-1.5 text-sm font-medium text-white hover:bg-primary-hover disabled:opacity-50"
            >
              <DatabaseZap className="h-4 w-4" /> Preview what would change
            </button>
          </div>
        </div>
      )}

      {/* ================= STEP 2 — dry-run preview ================= */}
      {step === 2 && (
        <div className="space-y-4">
          {/* Busy state while the API scans the live inventory. */}
          {previewMutation.isPending && !plan ? (
            <div className="rounded-md border border-border bg-background p-6 text-center">
              <Loader2 className="mx-auto h-6 w-6 animate-spin text-primary" />
              <p className="mt-3 text-sm font-medium text-secondary">Scanning live inventory…</p>
              <p className="mt-1 text-xs text-faint">Computing the additive merge plan against every observed network. This is read-only — nothing is written yet.</p>
              {/* Indeterminate bar — a single server call, so no per-item percentage. */}
              <div className="mx-auto mt-4 h-2 w-full max-w-md overflow-hidden rounded-full bg-muted">
                <div className="h-full w-full animate-pulse rounded-full bg-primary/60" />
              </div>
            </div>
          ) : plan ? (
            <>
              <p className="text-sm text-secondary">
                {plan.totalLiveNetworks} live network(s) considered. The merge is additive — existing documented data is preserved, only missing information is added.
              </p>

              <div className="flex flex-wrap gap-2 text-sm">
                <span className="rounded bg-success px-2 py-1 font-medium text-success-fg">{plannedCreates} to create</span>
                <span className="rounded bg-info px-2 py-1 font-medium text-info-fg">{plannedUpdates} to update (merge)</span>
                {plannedSkips > 0 && <span className="rounded bg-muted px-2 py-1 font-medium text-secondary">{plannedSkips} skipped</span>}
              </div>

              {/* Filters stay adjustable — the preview re-runs automatically. */}
              <div className="flex flex-wrap items-center gap-x-5 gap-y-2 rounded-md border border-border bg-background p-3 text-sm">
                <label className="flex items-center gap-2">
                  <input type="checkbox" checked={skipWithoutSubnet} onChange={(e) => setSkipWithoutSubnet(e.target.checked)} />
                  Skip without subnet
                </label>
                <label className="flex items-center gap-2">
                  <input type="checkbox" checked={skipWithoutVlan} onChange={(e) => setSkipWithoutVlan(e.target.checked)} />
                  Skip without VLAN
                </label>
                <label className="flex items-center gap-2 text-xs"><span className="text-faint">Family</span>{familySelect}</label>
                <label className="flex items-center gap-2 text-xs"><span className="text-faint">Public IPv4</span>{publicV4Select}</label>
                <label className="flex items-center gap-2 text-xs"><span className="text-faint">Public IPv6</span>{publicV6Select}</label>
                <label className="flex items-center gap-2 text-xs"><span className="text-faint">Ranges</span>{rangeSelect}</label>
                {rangeMode !== 'keep-all' && (
                  <textarea
                    className="w-full rounded-md border border-border bg-background px-2 py-1 font-mono text-xs"
                    rows={2}
                    placeholder={'One CIDR or range per line'}
                    value={rangesText}
                    onChange={(e) => setRangesText(e.target.value)}
                  />
                )}
                <label className="flex items-center gap-2 text-xs"><span className="text-faint">Observed within</span>{ageSelect}</label>
              </div>

              {previewMutation.isPending && (
                <p className="flex items-center gap-2 text-sm text-faint">
                  <Loader2 className="h-3.5 w-3.5 animate-spin" /> Recomputing preview…
                </p>
              )}

              <div className={clsx('max-h-[28rem] overflow-y-auto rounded-md border border-border', previewMutation.isPending && 'opacity-60')}>
                <table className="w-full text-left text-xs">
                  <thead className="sticky top-0 bg-muted">
                    <tr>
                      <th className="px-2 py-1.5 font-medium">Name</th>
                      <th className="px-2 py-1.5 font-medium">Subnets</th>
                      <th className="px-2 py-1.5 font-medium">VLAN</th>
                      <th className="px-2 py-1.5 font-medium">Action</th>
                    </tr>
                  </thead>
                  <tbody>
                    {plan.planned.slice(0, 300).map((p, i) => (
                      <tr key={`${p.name}-${i}`} className="border-t border-border">
                        <td className="max-w-[220px] truncate px-2 py-1 font-medium" title={p.name}>{p.name}</td>
                        <td className="px-2 py-1">
                          {p.subnets.length > 0 ? (
                            <span className="flex flex-wrap gap-x-2">{p.subnets.map((s) => <SubnetChip key={s} cidr={s} />)}</span>
                          ) : (
                            <span className="text-faint">—</span>
                          )}
                          {p.stripped ? (
                            <span className="ml-1 text-faint" title={`${p.stripped} public subnet(s) removed by the strip policy`}> · {p.stripped} stripped</span>
                          ) : null}
                        </td>
                        <td className="px-2 py-1">{p.vlanId != null ? `V${p.vlanId}` : <span className="text-faint">—</span>}</td>
                        <td className="px-2 py-1">
                          {p.action === 'create' && <span className="rounded bg-success px-1.5 py-0.5 text-[10px] font-semibold text-success-fg">create</span>}
                          {p.action === 'update' && <span className="rounded bg-info px-1.5 py-0.5 text-[10px] font-semibold text-info-fg">merge</span>}
                          {p.action === 'skip' && (
                            <span title={p.reason} className="text-faint">skip{p.reason ? ` — ${p.reason}` : ''}</span>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              {plan.planned.length > 300 && <p className="text-xs text-faint">…and {plan.planned.length - 300} more rows</p>}

              {/* Apply — with its own busy state while the real import runs. */}
              {applyMutation.isPending ? (
                <div className="rounded-md border border-border bg-background p-4 text-center">
                  <Loader2 className="mx-auto h-5 w-5 animate-spin text-primary" />
                  <p className="mt-2 text-sm font-medium text-secondary">Importing {plannedCreates + plannedUpdates} network(s)…</p>
                  <div className="mx-auto mt-3 h-2 w-full max-w-md overflow-hidden rounded-full bg-muted">
                    <div className="h-full w-full animate-pulse rounded-full bg-primary/60" />
                  </div>
                </div>
              ) : (
                <div className="flex justify-end gap-2 border-t border-border pt-3">
                  <button type="button" onClick={() => setStep(1)} className="rounded-md px-3 py-1.5 text-sm text-secondary hover:bg-muted">
                    Back to options
                  </button>
                  <button
                    type="button"
                    disabled={plannedCreates + plannedUpdates === 0}
                    onClick={() => applyMutation.mutate()}
                    className="inline-flex items-center gap-2 rounded-md bg-primary px-4 py-1.5 text-sm font-medium text-white hover:bg-primary-hover disabled:opacity-50"
                  >
                    <DatabaseZap className="h-4 w-4" /> Import {plannedCreates + plannedUpdates} network(s)
                  </button>
                </div>
              )}
            </>
          ) : null}
        </div>
      )}

      {/* ================= STEP 3 — done ================= */}
      {step === 3 && applied && (
        <div className="space-y-4">
          <div className="flex flex-wrap gap-2 text-sm">
            <span className="rounded bg-success px-2 py-1 font-medium text-success-fg">{applied.created} created</span>
            <span className="rounded bg-info px-2 py-1 font-medium text-info-fg">{applied.updated} updated (merged)</span>
            {applied.skipped > 0 && <span className="rounded bg-muted px-2 py-1 font-medium text-secondary">{applied.skipped} skipped</span>}
          </div>
          <p className="text-sm text-secondary">
            Existing documented networks were merged additively — no user data was overwritten or deleted.
          </p>
          <div className="flex justify-end gap-2 border-t border-border pt-3">
            <button
              type="button"
              onClick={() => { setPlan(null); setApplied(null); setStep(1); }}
              className="rounded-md px-3 py-1.5 text-sm text-secondary hover:bg-muted"
            >
              Import more
            </button>
            <button
              type="button"
              onClick={() => navigate(from)}
              className="inline-flex items-center gap-2 rounded-md bg-primary px-4 py-1.5 text-sm font-medium text-white hover:bg-primary-hover"
            >
              Back to Documented Networks
            </button>
          </div>
        </div>
      )}
    </WizardLayout>
  );
}
