import { useEffect, useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { DatabaseZap, GitMerge, Loader2 } from 'lucide-react';
import clsx from 'clsx';
import { api, DocumentedHostInventoryImportResult } from '../api/client';
import { WizardLayout } from '../components/Wizard';

/**
 * DocumentedHostImportPage — "Import from live inventory" (documented hosts) as a
 * full-page wizard on the shared <WizardLayout> shell. Copies every host currently
 * observed in the live inventory into the documented hosts via an ADDITIVE merge:
 * existing entries are never overwritten, only missing addresses / MACs / network
 * references are added; nothing is deleted. A host that is ALSO a registered device
 * inherits its site/layer/tags when they are missing.
 *
 * Three steps:
 *   1. OPTIONS — pick filters (hostname/network/VLAN skips, public-IP policy,
 *      range filter, age window, MAC sync policy).
 *   2. PREVIEW — a dry-run plan table with live busy feedback while the API scans
 *      the inventory; filters stay adjustable and re-run automatically.
 *   3. DONE — applied summary (created / merged / skipped + MAC sync totals).
 */

/** Splits the ranges textarea into entries (one per line or comma). */
function parseRangesText(text: string): string[] {
  return text.split(/[\n,]+/).map((s) => s.trim()).filter((s) => s.length > 0);
}

type RangeMode = 'keep-all' | 'include-only' | 'exclude';
type PublicIpPolicy = 'keep' | 'strip' | 'skip-host';
type MacSyncPolicy = 'keep' | 'replace' | 'add';

export default function DocumentedHostImportPage() {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [searchParams] = useSearchParams();
  // Where "Cancel" returns to (set by the entry point).
  const from = searchParams.get('from') ?? '/documented-hosts';

  // --- Filters (same defaults as the previous modal) ---------------------------
  const [skipWithoutHostname, setSkipWithoutHostname] = useState(true);
  const [skipUnknownNetworks, setSkipUnknownNetworks] = useState(false);
  const [publicIpv4Policy, setPublicIpv4Policy] = useState<PublicIpPolicy>('keep');
  const [publicIpv6Policy, setPublicIpv6Policy] = useState<PublicIpPolicy>('keep');
  const [rangeMode, setRangeMode] = useState<RangeMode>('keep-all');
  const [rangesText, setRangesText] = useState('');
  const [skipWithoutVlan, setSkipWithoutVlan] = useState(false);
  const [maxAgeHours, setMaxAgeHours] = useState(24);
  const [macSyncPolicy, setMacSyncPolicy] = useState<MacSyncPolicy>('keep');

  // --- Wizard state -------------------------------------------------------------
  const [step, setStep] = useState<1 | 2 | 3>(1);
  const [plan, setPlan] = useState<DocumentedHostInventoryImportResult | null>(null);
  const [applied, setApplied] = useState<DocumentedHostInventoryImportResult | null>(null);

  /** The shared request body for both the dry-run and the real import. */
  function buildBody(dryRun: boolean) {
    return { skipWithoutHostname, skipUnknownNetworks, publicIpv4Policy, publicIpv6Policy, rangeMode, ranges: parseRangesText(rangesText), skipWithoutVlan, maxAgeHours, macSyncPolicy, dryRun };
  }

  const previewMutation = useMutation({
    mutationFn: () => api.importDocumentedHostsFromInventory(buildBody(true)),
    onSuccess: (res) => setPlan(res),
  });
  const applyMutation = useMutation({
    mutationFn: () => api.importDocumentedHostsFromInventory(buildBody(false)),
    onSuccess: (res) => {
      setApplied(res);
      setStep(3);
      void queryClient.invalidateQueries({ queryKey: ['documentedHosts'] });
    },
  });

  // Re-run the preview whenever a filter changes while on the PREVIEW step.
  useEffect(() => {
    if (step === 2) previewMutation.mutate();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [skipWithoutHostname, skipUnknownNetworks, publicIpv4Policy, publicIpv6Policy, rangeMode, rangesText, skipWithoutVlan, maxAgeHours, macSyncPolicy]);

  const plannedCreates = plan?.planned.filter((p) => p.action === 'create').length ?? 0;
  const plannedUpdates = plan?.planned.filter((p) => p.action === 'update').length ?? 0;
  const plannedSkips = plan?.planned.filter((p) => p.action === 'skip').length ?? 0;
  // Smart hostname merge — live rows of one multi-NIC machine folded into a single entry.
  const mergedGroupCount = plan?.mergedGroups ?? 0;

  function handlePreview() {
    setStep(2);
    previewMutation.mutate();
  }

  // The reusable filter controls — rendered full in step 1 and compact in step 2.
  const publicV4Select = (
    <select className="rounded-md border border-border bg-background px-2 py-1 text-xs" value={publicIpv4Policy} onChange={(e) => setPublicIpv4Policy(e.target.value as PublicIpPolicy)}>
      <option value="keep">Keep (import all)</option>
      <option value="strip">Strip public, keep internal</option>
      <option value="skip-host">Skip whole host</option>
    </select>
  );
  const publicV6Select = (
    <select className="rounded-md border border-border bg-background px-2 py-1 text-xs" value={publicIpv6Policy} onChange={(e) => setPublicIpv6Policy(e.target.value as PublicIpPolicy)}>
      <option value="keep">Keep (import all)</option>
      <option value="strip">Strip public, keep internal</option>
      <option value="skip-host">Skip whole host</option>
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
  const macSyncSelect = (
    <select className="rounded-md border border-border bg-background px-2 py-1 text-xs" value={macSyncPolicy} onChange={(e) => setMacSyncPolicy(e.target.value as MacSyncPolicy)}>
      <option value="keep">No sync (flag mismatches only)</option>
      <option value="replace">Replace with inventory</option>
      <option value="add">Add new MAC to host</option>
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
            Copies every host currently observed in the inventory into the documented hosts. Existing entries are MERGED, never
            overwritten: their DNS names, friendly name, description and placement stay untouched — only new addresses, MACs and
            network references from the observation are added. A host that is ALSO a registered device inherits its site/layer/tags
            when they are missing. Nothing is deleted.
          </p>

          <div className="flex flex-col gap-2 text-sm">
            <label className="flex items-center justify-between gap-3 rounded-md border border-border px-3 py-2" title="Hosts without an observed hostname get no DNS name — skip them, or document them under their MAC address.">
              <span className="text-secondary">Skip hosts without a hostname</span>
              <input type="checkbox" checked={skipWithoutHostname} onChange={(e) => setSkipWithoutHostname(e.target.checked)} />
            </label>
            <label className="flex items-center justify-between gap-3 rounded-md border border-border px-3 py-2" title="Only import hosts whose addresses fall into a known logical network (from the Networks inventory).">
              <span className="text-secondary">Skip hosts without a known network</span>
              <input type="checkbox" checked={skipUnknownNetworks} onChange={(e) => setSkipUnknownNetworks(e.target.checked)} />
            </label>
            <label className="flex items-center justify-between gap-3 rounded-md border border-border px-3 py-2" title="Only import hosts whose addresses resolve to a known logical network with a discovered VLAN id — drops hosts on untagged or unknown networks.">
              <span className="text-secondary">Skip hosts without a discovered VLAN</span>
              <input type="checkbox" checked={skipWithoutVlan} onChange={(e) => setSkipWithoutVlan(e.target.checked)} />
            </label>
            <label className="flex items-center justify-between gap-3 rounded-md border border-border px-3 py-2" title="How to treat publicly routable IPv4 addresses (RFC 1918 private ranges count as internal). Strip removes only the public v4 addresses — the host is still imported with its internal ones. Skip-host drops the whole host when it has any public v4 address.">
              <span className="text-secondary">Public IPv4 addresses</span>
              {publicV4Select}
            </label>
            <label className="flex items-center justify-between gap-3 rounded-md border border-border px-3 py-2" title="How to treat publicly routable IPv6 addresses (GUA 2000::/3; ULA fc00::/7 counts as internal). Strip removes only the public v6 addresses — the host is still imported with its internal ones. Skip-host drops the whole host when it has any public v6 address.">
              <span className="text-secondary">Public IPv6 addresses</span>
              {publicV6Select}
            </label>
            <div className="rounded-md border border-border px-3 py-2" title="Restrict the import to specific networks or IP ranges — applied BEFORE all other options. A host matches when ANY of its addresses falls into ANY entry.">
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
            <label className="flex items-center justify-between gap-3 rounded-md border border-border px-3 py-2" title="Only consider hosts observed within this window (the inventory is swept after 24 h).">
              <span className="text-secondary">Observed within</span>
              {ageSelect}
            </label>
            <label className="flex items-center justify-between gap-3 rounded-md border border-border px-3 py-2" title="What to do when a documented MAC differs from what is currently observed for the same address — e.g. after a docker container re-creation or on clients with randomized MACs.">
              <span className="text-secondary">MAC sync</span>
              {macSyncSelect}
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
              <p className="mt-1 text-xs text-faint">Computing the additive merge plan against every observed host. This is read-only — nothing is written yet.</p>
              {/* Indeterminate bar — a single server call, so no per-item percentage. */}
              <div className="mx-auto mt-4 h-2 w-full max-w-md overflow-hidden rounded-full bg-muted">
                <div className="h-full w-full animate-pulse rounded-full bg-primary/60" />
              </div>
            </div>
          ) : plan ? (
            <>
              <p className="text-sm text-secondary">
                {plan.totalLiveHosts} live host(s) considered. The merge is additive — existing documented data is preserved, only missing information is added.
              </p>

              <div className="flex flex-wrap gap-2 text-sm">
                <span className="rounded bg-success px-2 py-1 font-medium text-success-fg">{plannedCreates} to create</span>
                <span className="rounded bg-info px-2 py-1 font-medium text-info-fg">{plannedUpdates} to update (merge)</span>
                {mergedGroupCount > 0 && (
                  <span title="Live rows sharing one hostname were folded into a single documented host — multi-NIC machines no longer create duplicate rows." className="rounded bg-warning px-2 py-1 font-medium text-warning-fg">
                    {mergedGroupCount} multi-NIC host(s) merged by hostname
                  </span>
                )}
                {(plan.macReplaced ?? 0) > 0 && (
                  <span title="Documented MACs that differ from the live observation would be REPLACED with the observed MAC." className="rounded bg-warning px-2 py-1 font-medium text-warning-fg">
                    {plan.macReplaced} MAC(s) to replace
                  </span>
                )}
                {(plan.macAdded ?? 0) > 0 && (
                  <span title="Observed MACs that would be ADDED as additional identities of their host (the documented MAC is kept)." className="rounded bg-info px-2 py-1 font-medium text-info-fg">
                    {plan.macAdded} MAC(s) to add
                  </span>
                )}
                {plannedSkips > 0 && <span className="rounded bg-muted px-2 py-1 font-medium text-secondary">{plannedSkips} skipped</span>}
              </div>

              {/* Filters stay adjustable — the preview re-runs automatically. */}
              <div className="flex flex-wrap items-center gap-x-5 gap-y-2 rounded-md border border-border bg-background p-3 text-sm">
                <label className="flex items-center gap-2">
                  <input type="checkbox" checked={skipWithoutHostname} onChange={(e) => setSkipWithoutHostname(e.target.checked)} />
                  Skip without hostname
                </label>
                <label className="flex items-center gap-2">
                  <input type="checkbox" checked={skipUnknownNetworks} onChange={(e) => setSkipUnknownNetworks(e.target.checked)} />
                  Skip unknown networks
                </label>
                <label className="flex items-center gap-2">
                  <input type="checkbox" checked={skipWithoutVlan} onChange={(e) => setSkipWithoutVlan(e.target.checked)} />
                  Skip without VLAN
                </label>
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
                <label className="flex items-center gap-2 text-xs" title="What to do when a documented MAC differs from what is currently observed for the same address.">
                  <span className="text-faint">MAC sync</span>
                  {macSyncSelect}
                </label>
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
                      <th className="px-2 py-1.5 font-medium">MAC</th>
                      <th className="px-2 py-1.5 font-medium">Hostname</th>
                      <th className="px-2 py-1.5 font-medium">IPs</th>
                      <th className="px-2 py-1.5 font-medium" title="Planned MAC sync changes (only shown when a MAC sync policy is active)">MAC sync</th>
                      <th className="px-2 py-1.5 font-medium">Action</th>
                    </tr>
                  </thead>
                  <tbody>
                    {plan.planned.slice(0, 300).map((p, i) => (
                      <tr key={`${p.mac}-${i}`} className="border-t border-border">
                        <td className="px-2 py-1 font-mono">
                          {p.mac}
                          {(p.mergedFrom ?? []).length > 0 && (
                            <span
                              title={`Folded into one host by hostname — also covers MAC ${p.mergedFrom!.join(', ')}`}
                              className="ml-1 inline-flex items-center gap-0.5 rounded bg-warning px-1 py-0.5 text-[10px] font-semibold text-warning-fg"
                            >
                              <GitMerge className="h-3 w-3" /> +{p.mergedFrom!.length}
                            </span>
                          )}
                        </td>
                        <td className="max-w-[220px] truncate px-2 py-1 font-mono" title={p.hostname ?? undefined}>
                          {p.hostname ?? <span className="text-faint">—</span>}
                        </td>
                        <td className="px-2 py-1">
                          {p.ips}
                          {p.stripped ? (
                            <span className="text-faint" title={`${p.stripped} public address(es) removed by the strip policy`}> · {p.stripped} stripped</span>
                          ) : null}
                        </td>
                        <td className="px-2 py-1">
                          {(p.macReplaced ?? 0) > 0 && (
                            <span title={`${p.macReplaced} documented MAC(s) would be replaced with the observed one`} className="mr-1 rounded bg-warning px-1.5 py-0.5 text-[10px] font-semibold text-warning-fg">
                              {p.macReplaced} mac → replace
                            </span>
                          )}
                          {(p.macAdded ?? 0) > 0 && (
                            <span title={`${p.macAdded} observed MAC(s) would be added as additional identities of this host`} className="rounded bg-info px-1.5 py-0.5 text-[10px] font-semibold text-info-fg">
                              {p.macAdded} mac → add
                            </span>
                          )}
                        </td>
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
                  <p className="mt-2 text-sm font-medium text-secondary">Importing {plannedCreates + plannedUpdates} host(s)…</p>
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
                    <DatabaseZap className="h-4 w-4" /> Import {plannedCreates + plannedUpdates} host(s)
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
            {(applied.macReplaced ?? 0) > 0 && (
              <span title="Documented MACs replaced with the observed one." className="rounded bg-warning px-2 py-1 font-medium text-warning-fg">
                {applied.macReplaced} MAC(s) replaced
              </span>
            )}
            {(applied.macAdded ?? 0) > 0 && (
              <span title="Observed MACs added as additional identities of their host." className="rounded bg-info px-2 py-1 font-medium text-info-fg">
                {applied.macAdded} MAC(s) added
              </span>
            )}
            {applied.skipped > 0 && <span className="rounded bg-muted px-2 py-1 font-medium text-secondary">{applied.skipped} skipped</span>}
          </div>
          <p className="text-sm text-secondary">
            Existing documented hosts were merged additively — no user data was overwritten or deleted.
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
              Back to Documented Hosts
            </button>
          </div>
        </div>
      )}
    </WizardLayout>
  );
}
