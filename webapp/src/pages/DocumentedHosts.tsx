import { Fragment, useEffect, useMemo, useState } from 'react';
import { useQuery, useQueryClient, useMutation } from '@tanstack/react-query';
import { CircleCheck, CircleX, DatabaseZap, Dices, NotebookPen, Pencil, Plus, Trash2, TriangleAlert, Upload, X } from 'lucide-react';
import { Layout } from '../components/Layout';
import { DataTable, DataTableColumn } from '../components/DataTable';
import { IpCidrInput } from '../components/IpCidrInput';
import { api, DocumentedHost, DocumentedHostRequest, NetworkLayer, Site } from '../api/client';
import { can } from '../auth/permissions';
import { useTimeFormat } from '../utils/time';
import { isIpLiteral } from '../utils/address';
import {
  DnsSuggestion,
  LiveHost,
  LiveIndex,
  NetworkOption,
  buildLiveIndex,
  ipFamily,
  labelContainsAddress,
  matchNetwork,
  matchingSubnets,
  resolveNetworkCidr,
  suggestDnsNames,
  suggestFreeIp,
} from '../utils/hostAutofill';
import { CsvImportField, CSV_IMPORT_FIELDS, parseCsv, splitCellValues, suggestHeaderMapping } from '../utils/csv';

/**
 * Documented hosts — the user-maintained host documentation page. Permanent
 * records of what SHOULD exist on the network (DNS names, friendly name +
 * description, site/layer placement, per-address documented MAC + network),
 * cross-referenced against the live ARP/NDP/DHCP inventory to mark each entry
 * "discovered" and flag documented MACs that no longer match reality.
 */

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

/** One draft IP row in the create/edit form. */
interface IpDraft {
  address: string;
  vlanId: string;
  mac: string;
  networkLabel: string;
}

/** Form state for one documented host (all fields as editable strings). */
interface HostFormState {
  dnsNames: string[];
  friendlyName: string;
  description: string;
  siteId: string;
  layerId: string;
  ips: IpDraft[];
}

const EMPTY_FORM: HostFormState = {
  dnsNames: [],
  friendlyName: '',
  description: '',
  siteId: '',
  layerId: '',
  ips: [{ address: '', vlanId: '', mac: '', networkLabel: '' }],
};

function formFromHost(h: DocumentedHost): HostFormState {
  return {
    dnsNames: [...h.dnsNames],
    friendlyName: h.friendlyName ?? '',
    description: h.description ?? '',
    siteId: h.siteId ?? '',
    layerId: h.layerId ?? '',
    ips: h.ips.map((ip) => ({ address: ip.address, vlanId: ip.vlanId != null ? String(ip.vlanId) : '', mac: ip.mac ?? '', networkLabel: ip.networkLabel ?? '' })),
  };
}

// ---------------------------------------------------------------------------
// Table cell renderers
// ---------------------------------------------------------------------------

/** Discovery status badge + MAC-mismatch warning for one documented host. */
function StatusCell({ row }: { row: DocumentedHost }) {
  return (
    <div className="flex items-center gap-1.5">
      {row.discovered ? (
        <span className="inline-flex items-center gap-1 rounded bg-success px-1.5 py-0.5 text-xs font-medium text-success-fg">
          <CircleCheck className="h-3 w-3" /> Discovered
        </span>
      ) : (
        <span className="inline-flex items-center gap-1 rounded bg-muted px-1.5 py-0.5 text-xs font-medium text-secondary">
          <CircleX className="h-3 w-3" /> Not seen
        </span>
      )}
      {row.macMismatch && (
        <span title="A documented MAC differs from what is currently observed for its address" className="text-warning-fg">
          <TriangleAlert className="h-4 w-4" />
        </span>
      )}
    </div>
  );
}

/** One IP block: address on top (VLAN chip when known), documented MAC below. */
function IpBlock({ row }: { row: DocumentedHost }) {
  return (
    <div className="flex flex-wrap gap-x-3 gap-y-1">
      {row.ips.map((ip) => (
        <span key={ip.id} className="inline-flex flex-col leading-tight">
          <span className={`font-mono text-xs ${ip.version === 'v6' ? 'text-accent-purple-fg' : ''}`}>
            {ip.address}
            {ip.vlanId != null && (
              <span title={`VLAN ${ip.vlanId}`} className="ml-1 rounded bg-muted px-1 py-0.5 text-[9px] font-semibold text-secondary">
                V{ip.vlanId}
              </span>
            )}
          </span>
          {ip.macMismatch && ip.observedMac ? (
            <span title={`Documented MAC differs — currently observed: ${ip.observedMac}`} className="font-mono text-[10px] font-semibold text-warning-fg">
              ⚠ {ip.mac}
            </span>
          ) : (
            <span className="font-mono text-[10px] text-faint">{ip.mac ?? 'no MAC'}</span>
          )}
        </span>
      ))}
    </div>
  );
}

/** Network references of a host — known networks in normal tone, free-form labels dimmed. */
function NetworkCell({ row }: { row: DocumentedHost }) {
  const labels = Array.from(new Set(row.ips.map((ip) => ip.networkName ?? ip.networkLabel).filter((l): l is string => !!l)));
  if (labels.length === 0) return <span className="text-faint">—</span>;
  return (
    <div className="flex flex-wrap gap-1">
      {row.ips
        .map((ip) => ({ name: ip.networkName ?? ip.networkLabel, known: ip.networkKnown }))
        .filter((n): n is { name: string; known: boolean } => !!n.name)
        .map((n, i) => (
          <span key={`${n.name}-${i}`} className={`rounded px-1.5 py-0.5 text-xs ${n.known ? 'bg-info text-info-fg' : 'bg-muted text-secondary'}`}>
            {n.name}
          </span>
        ))}
    </div>
  );
}

/** One VLAN line per IP — the column is multi-line, one entry per address. */
function VlanCell({ row }: { row: DocumentedHost }) {
  const lines = row.ips.map((ip) => ({ addr: ip.address, vlanId: ip.vlanId }));
  if (lines.every((l) => l.vlanId == null)) return <span className="text-faint">—</span>;
  return (
    <div className="flex flex-col gap-0.5 leading-tight">
      {lines.map((l, i) => (
        <span key={i} className="font-mono text-xs" title={`${l.addr}${l.vlanId != null ? ` — VLAN ${l.vlanId}` : ''}`}>
          <span className="text-faint">{l.addr}</span>{' '}
          {l.vlanId != null ? (
            <span className="rounded bg-muted px-1 py-0.5 text-[10px] font-semibold text-secondary">V{l.vlanId}</span>
          ) : (
            <span className="text-faint">—</span>
          )}
        </span>
      ))}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Inline create / edit form — with live-inventory auto-fill
// ---------------------------------------------------------------------------

interface HostFormCardProps {
  /** The host being edited; null = create. */
  initial: DocumentedHost | null;
  sites: Site[];
  layers: NetworkLayer[];
  /** All known network labels (merged logical networks + their subnets). */
  networkOptions: string[];
  /** Lookup index over the live host inventory (MAC / address → host). */
  liveIndex: LiveIndex;
  /** Known networks with their subnet CIDRs — for IP→network matching. */
  networksForMatch: NetworkOption[];
  /** Lowercased device name → resolved topology layer id (for layer pre-fill). */
  deviceLayers: Map<string, string>;
  /** Every address already in use or documented (lowercase) — free-IP suggestions skip these. */
  takenIps: Set<string>;
  onClose: () => void;
  onSaved: () => void;
}

function HostFormCard({ initial, sites, layers, networkOptions, liveIndex, networksForMatch, deviceLayers, takenIps, onClose, onSaved }: HostFormCardProps) {
  const [form, setForm] = useState<HostFormState>(() => (initial ? formFromHost(initial) : EMPTY_FORM));
  const [newName, setNewName] = useState('');
  const [error, setError] = useState<string | null>(null);

  // --- live-inventory lookups -------------------------------------------------

  /** Live host observed at this address (only for valid IP literals). */
  function liveForAddress(address: string): LiveHost | undefined {
    const a = address.trim().toLowerCase();
    if (!a || !isIpLiteral(a)) return undefined;
    return liveIndex.byIp.get(a)?.[0];
  }

  /**
   * Best-matching known network for an address — with the containing subnet
   * OF THE ADDRESS'S FAMILY (an IPv4 address never matches a v6 subnet and
   * vice versa). Null when no known network contains it.
   */
  function netMatchFor(address: string): { option: NetworkOption; cidr: string } | null {
    const a = address.trim();
    if (!a || !isIpLiteral(a)) return null;
    return matchNetwork(a, networksForMatch);
  }

  // --- IP row edits (auto-fill MAC + VLAN + network from reliable live data) --

  function setIp(index: number, patch: Partial<IpDraft>) {
    setForm((f) => {
      const prev = f.ips[index]; // the row BEFORE this change (auto-fill bookkeeping)
      let next = { ...prev, ...patch };
      if (patch.address !== undefined && patch.address.trim() !== prev.address.trim()) {
        const a = patch.address.trim();
        // Drop values that were AUTO-FILLED for the previous address — manual
        // overrides survive address edits.
        const prevHit = liveForAddress(prev.address);
        if (prevHit && next.mac === prevHit.mac) next = { ...next, mac: '' };
        const prevMatch = netMatchFor(prev.address);
        if (prevMatch?.cidr && next.networkLabel.trim() === prevMatch.cidr) next = { ...next, networkLabel: '' };
        if (prevMatch?.option.vlanId != null && next.vlanId.trim() === String(prevMatch.option.vlanId)) next = { ...next, vlanId: '' };
        // Then auto-fill from the live inventory for the NEW address.
        if (a && isIpLiteral(a)) {
          const hit = liveForAddress(a);
          if (hit) next = { ...next, mac: hit.mac };
          const match = netMatchFor(a);
          // Store the CONTAINING SUBNET of the address's family — never a
          // dual-stack network name that is only an IPv6 CIDR.
          if (match?.cidr && !next.networkLabel.trim()) next = { ...next, networkLabel: match.cidr };
          if (match?.option.vlanId != null && !next.vlanId.trim()) next = { ...next, vlanId: String(match.option.vlanId) };
        }
      }
      return { ...f, ips: f.ips.map((ip, i) => (i === index ? next : ip)) };
    });
  }

  /**
   * Picks the first free IP inside the row's SELECTED network — for documenting
   * a new VM/container/physical host. The family follows the network: an IPv4
   * subnet yields an IPv4 address, an IPv6-only one an IPv6 address.
   */
  function pickFreeIp(index: number) {
    const row = form.ips[index];
    const cidr = resolveNetworkCidr(row.networkLabel, networksForMatch);
    if (!cidr) {
      setError('Pick a known network for this row first — the free IP is chosen inside it.');
      return;
    }
    const pick = suggestFreeIp(cidr, networksForMatch, takenIps);
    if (!pick) {
      setError(`No free address found in ${cidr} — the subnet may be exhausted.`);
      return;
    }
    // setIp() runs the usual auto-fill bookkeeping for the new address.
    setIp(index, { address: pick.address });
  }

  /** Adds an IP row (optionally pre-filled from a known address). */
  function addIpRow(address?: string) {
    const a = (address ?? '').trim();
    let mac = '';
    let label = '';
    let vlan = '';
    if (a && isIpLiteral(a)) {
      const hit = liveForAddress(a);
      if (hit) mac = hit.mac;
      const match = netMatchFor(a);
      if (match?.cidr) label = match.cidr;
      if (match?.option.vlanId != null) vlan = String(match.option.vlanId);
    }
    setForm((f) => ({ ...f, ips: [...f.ips, { address: a, vlanId: vlan, mac, networkLabel: label }] }));
  }

  // --- DNS name suggestions (known hostnames from the live inventory) ---------

  const dnsSuggestions = useMemo(
    () => suggestDnsNames(newName, liveIndex).filter((s) => !form.dnsNames.includes(s.name)),
    [newName, liveIndex, form.dnsNames]
  );

  function addDnsName(name?: string) {
    const v = (name ?? newName).trim().toLowerCase();
    if (!v || form.dnsNames.includes(v)) return;
    setForm((f) => ({ ...f, dnsNames: [...f.dnsNames, v] }));
    setNewName('');
  }

  /** Pick a known host → pre-fill every field we have reliable data for. */
  function applySuggestion(s: DnsSuggestion) {
    const h = s.host;
    // Every address observed for this MAC becomes an IP row (MAC + network).
    // Zone-suffixed link-locals ("fe80::…%vlan20") are skipped — they are not
    // documentable addresses and the API rejects them.
    const observedIps: IpDraft[] = (h.ips ?? [])
      .filter((a) => !a.includes('%') && isIpLiteral(a.trim()))
      .map((a) => {
        const match = netMatchFor(a);
        return { address: a, vlanId: match?.option.vlanId != null ? String(match.option.vlanId) : '', mac: h.mac, networkLabel: match?.cidr ?? '' };
      });
    setForm((f) => {
      const dnsNames = f.dnsNames.includes(s.name) ? f.dnsNames : [...f.dnsNames, s.name];
      // Merge the observed addresses into the draft (user rows are kept).
      const ips = f.ips.filter((x) => x.address.trim() !== '');
      for (const ip of observedIps) {
        if (!ips.some((x) => x.address.trim().toLowerCase() === ip.address.toLowerCase())) ips.push(ip);
      }
      if (ips.length === 0) ips.push({ address: '', vlanId: '', mac: '', networkLabel: '' });
      const siteName = h.devices?.[0]?.siteName;
      // Layer pre-fill: a device whose NAME matches the picked host, when its
      // topology layer is known.
      const devLayer = deviceLayers.get(s.name.toLowerCase()) ?? (h.hostname ? deviceLayers.get(h.hostname.trim().toLowerCase()) : undefined);
      return {
        ...f,
        dnsNames,
        friendlyName: f.friendlyName || s.name.split('.')[0],
        siteId: f.siteId || (siteName ? sites.find((x) => x.name.toLowerCase() === siteName.toLowerCase())?.id ?? '' : ''),
        layerId: f.layerId || devLayer || '',
        ips,
      };
    });
    setNewName('');
  }

  function submit() {
    const names = form.dnsNames.map((n) => n.trim()).filter(Boolean);
    if (names.length === 0) {
      setError('Add at least one DNS name.');
      return;
    }
    const ips = form.ips.filter((ip) => ip.address.trim() !== '');
    if (ips.length === 0) {
      setError('Add at least one IP address.');
      return;
    }
    for (const ip of ips) {
      const a = ip.address.trim();
      if (!isIpLiteral(a)) {
        setError(`"${a}" is not a valid IPv4/IPv6 address.`);
        return;
      }
      // A typed "/prefix" must be in range for the family (v4 ≤ 32, v6 ≤ 128).
      const slash = a.indexOf('/');
      if (slash > 0) {
        const fam = ipFamily(a.slice(0, slash))!;
        const pfx = Number(a.slice(slash + 1));
        const max = fam === 'v4' ? 32 : 128;
        if (!Number.isInteger(pfx) || pfx < 0 || pfx > max) {
          setError(`"${a}" — prefix must be between 0 and ${max}.`);
          return;
        }
      }
      // A KNOWN network that cannot contain this address (e.g. an IPv4
      // address in an IPv6-only network) is invalid data.
      const lbl = ip.networkLabel.trim();
      if (lbl !== '' && labelContainsAddress(lbl, a, networksForMatch) === false) {
        setError(`${a} cannot live in “${lbl}” — pick a compatible network or clear the field.`);
        return;
      }
    }
    const body: DocumentedHostRequest = {
      dnsNames: names,
      friendlyName: form.friendlyName.trim() || null,
      description: form.description.trim() || null,
      siteId: form.siteId || null,
      layerId: form.layerId || null,
      ips: ips.map((ip) => ({
        address: ip.address.trim(),
        vlanId: ip.vlanId.trim() === '' ? null : Number(ip.vlanId),
        mac: ip.mac.trim() || null,
        networkLabel: ip.networkLabel.trim() || null,
      })),
    };
    if (initial) updateHost.mutate(body);
    else createHost.mutate(body);
  }

  const createHost = useMutation({
    mutationFn: (body: DocumentedHostRequest) => api.createDocumentedHost(body),
    onSuccess: onSaved,
    onError: (err: unknown) => setError((err as Error).message),
  });
  const updateHost = useMutation({
    mutationFn: (body: Partial<DocumentedHostRequest>) => api.updateDocumentedHost(initial!.id, body),
    onSuccess: onSaved,
    onError: (err: unknown) => setError((err as Error).message),
  });

  return (
    <div className="mb-4 rounded-md border border-border bg-card p-4">
      <div className="mb-3 flex items-center justify-between">
        <h2 className="text-sm font-semibold text-foreground">{initial ? `Edit documented host — ${initial.dnsNames[0]}` : 'New documented host'}</h2>
          <button type="button" aria-label="Close form" onClick={onClose} className="rounded p-1 text-faint hover:bg-muted">
            <X className="h-4 w-4" />
          </button>
        </div>

        {error && (
          <div className="mb-3 rounded-md border border-danger-border bg-danger px-3 py-2 text-sm text-danger-fg">{error}</div>
        )}

        <form
          onSubmit={(e) => {
            e.preventDefault();
            submit();
          }}
          className="flex flex-col gap-4"
        >
          {/* DNS names */}
          <div>
            <label className="mb-1 block text-sm font-medium text-secondary">DNS name(s) *</label>
            {form.dnsNames.length > 0 && (
              <div className="mb-2 flex flex-wrap gap-1.5">
                {form.dnsNames.map((n, i) => (
                  <span key={n} className="inline-flex items-center gap-1 rounded bg-muted px-2 py-0.5 font-mono text-xs">
                    {i === 0 && <span className="font-sans font-semibold text-faint">primary</span>}
                    {n}
                    <button
                      type="button"
                      aria-label={`Remove ${n}`}
                      onClick={() => setForm((f) => ({ ...f, dnsNames: f.dnsNames.filter((x) => x !== n) }))}
                      className="text-faint hover:text-danger-fg"
                    >
                      <X className="h-3 w-3" />
                    </button>
                  </span>
                ))}
              </div>
            )}
            <div className="flex gap-2">
              <div className="relative flex-1">
                <input
                  className="w-full rounded-md border border-border px-3 py-1.5 font-mono text-sm"
                  placeholder={form.dnsNames.length === 0 ? 'e.g. mail.example.com — known hosts are suggested' : 'Add another name…'}
                  value={newName}
                  onChange={(e) => setNewName(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter') {
                      e.preventDefault();
                      addDnsName();
                    }
                  }}
                />
                {dnsSuggestions.length > 0 && (
                  <div className="absolute z-10 mt-1 w-full overflow-hidden rounded-md border border-border bg-card shadow-lg">
                    {dnsSuggestions.map((s) => (
                      <button
                        key={s.name}
                        type="button"
                        onClick={() => applySuggestion(s)}
                        title={`Pre-fill from known host ${s.name}`}
                        className="flex w-full items-center justify-between gap-2 px-3 py-1.5 text-left text-sm hover:bg-muted"
                      >
                        <span className="font-mono">{s.name}</span>
                        <span className="shrink-0 font-mono text-[10px] text-faint">known host · {s.host.mac}</span>
                      </button>
                    ))}
                  </div>
                )}
              </div>
              <button type="button" onClick={() => addDnsName()} className="shrink-0 rounded-md border border-border px-3 py-1.5 text-sm hover:bg-muted">
                Add
              </button>
            </div>
          </div>

          {/* Friendly name + description */}
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
            <div>
              <label className="mb-1 block text-sm font-medium text-secondary">Friendly name</label>
              <input
                className="w-full rounded-md border border-border px-3 py-1.5 text-sm"
                placeholder='e.g. "Mail server"'
                value={form.friendlyName}
                onChange={(e) => setForm((f) => ({ ...f, friendlyName: e.target.value }))}
              />
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="mb-1 block text-sm font-medium text-secondary">Site</label>
                <select className="w-full rounded-md border border-border px-2 py-1.5 text-sm" value={form.siteId} onChange={(e) => setForm((f) => ({ ...f, siteId: e.target.value }))}>
                  <option value="">— none —</option>
                  {sites.map((s) => (
                    <option key={s.id} value={s.id}>{s.name}</option>
                  ))}
                </select>
              </div>
              <div>
                <label className="mb-1 block text-sm font-medium text-secondary">Layer</label>
                <select className="w-full rounded-md border border-border px-2 py-1.5 text-sm" value={form.layerId} onChange={(e) => setForm((f) => ({ ...f, layerId: e.target.value }))}>
                  <option value="">— none —</option>
                  {layers.map((l) => (
                    <option key={l.id} value={l.id}>{l.name}</option>
                  ))}
                </select>
              </div>
            </div>
          </div>
          <div>
            <label className="mb-1 block text-sm font-medium text-secondary">Description</label>
            <textarea
              className="w-full rounded-md border border-border px-3 py-1.5 text-sm"
              rows={2}
              placeholder="Documentation — purpose, owner, notes…"
              value={form.description}
              onChange={(e) => setForm((f) => ({ ...f, description: e.target.value }))}
            />
          </div>

          {/* IP addresses — a little table so every filled field keeps its legend */}
          <div>
            <label className="mb-1 block text-sm font-medium text-secondary">IP address(es) *</label>
            <table className="w-full border-separate border-spacing-x-2">
              <thead>
                <tr>
                  <th className="pb-1.5 text-left align-bottom text-xs font-medium text-faint">IP address</th>
                  <th className="w-[70px] pb-1.5 text-left align-bottom text-xs font-medium text-faint" title="VLAN id the address lives in — auto-filled from the inventory when known; override freely">
                    VLAN
                  </th>
                  <th className="w-[205px] pb-1.5 text-left align-bottom text-xs font-medium text-faint" title="Documented MAC — auto-filled from live observations when the host is known; override freely">
                    MAC
                  </th>
                  <th className="pb-1.5 text-left align-bottom text-xs font-medium text-faint">Network</th>
                  <th className="w-[32px] pb-1.5" title="Pick the first free IP in the selected network (family follows the network)" />
                  <th className="w-[32px] pb-1.5" />
                </tr>
              </thead>
              <tbody>
                {form.ips.map((ip, i) => {
                  const live = liveForAddress(ip.address);
                  const addr = ip.address.trim();
                  const isAddr = addr !== '' && isIpLiteral(addr);
                  // Only offer subnets (of the address's family) that can actually
                  // contain this address — all known networks while still typing.
                  const netChoices = isAddr ? matchingSubnets(addr, networksForMatch) : networkOptions;
                  const label = ip.networkLabel.trim();
                  // KNOWN network that cannot contain this address (e.g. an IPv4
                  // address in an IPv6-only network) — invalid data.
                  const labelBad = isAddr && label !== '' && labelContainsAddress(label, addr, networksForMatch) === false;
                  const showHint = live || labelBad || (isAddr && netChoices.length > 0 && !netChoices.includes(label));
                  return (
                    <Fragment key={i}>
                      <datalist id={`dh-net-${i}`}>
                        {netChoices.map((n) => (
                          <option key={n} value={n} />
                        ))}
                      </datalist>
                      <tr>
                        <td className="align-top">
                          <IpCidrInput
                            addressOnly
                            listId={`dh-net-${i}`}
                            placeholder="IPv4 or IPv6"
                            title={isAddr ? 'Pick a compatible subnet from the suggestions' : undefined}
                            value={ip.address}
                            onChange={(v) => setIp(i, { address: v })}
                          />
                        </td>
                        <td className="align-top">
                          <input
                            className="w-full rounded-md border border-border px-2 py-1.5 font-mono text-sm"
                            placeholder="auto"
                            title="VLAN id the address lives in — auto-filled from the inventory when known; override freely"
                            value={ip.vlanId}
                            onChange={(e) => setIp(i, { vlanId: e.target.value })}
                          />
                        </td>
                        <td className="align-top">
                          <input
                            className="w-full rounded-md border border-border px-3 py-1.5 font-mono text-sm"
                            placeholder="auto"
                            title="Documented MAC — auto-filled from live observations when the host is known; override freely"
                            value={ip.mac}
                            onChange={(e) => setIp(i, { mac: e.target.value })}
                          />
                        </td>
                        <td className="align-top">
                          <input
                            className={`w-full rounded-md border px-3 py-1.5 font-mono text-sm ${labelBad ? 'border-danger' : 'border-border'}`}
                            placeholder="known or new"
                            list={`dh-net-${i}`}
                            title={
                              labelBad
                                ? `"${label}" cannot contain ${addr} — pick a compatible network or clear the field`
                                : 'Pick a known subnet from the suggestions, or type a label for an unknown one'
                            }
                            value={ip.networkLabel}
                            onChange={(e) => setIp(i, { networkLabel: e.target.value })}
                          />
                        </td>
                        <td className="align-top">
                          <button
                            type="button"
                            aria-label="Pick first free IP in the selected network"
                            title={`First free ${resolveNetworkCidr(ip.networkLabel, networksForMatch)?.includes(':') ? 'IPv6' : 'IPv4'} address in the selected network — skips every live and documented address`}
                            disabled={!resolveNetworkCidr(ip.networkLabel, networksForMatch)}
                            onClick={() => pickFreeIp(i)}
                            className="rounded-md p-1.5 text-secondary hover:bg-muted hover:text-primary disabled:opacity-30"
                          >
                            <Dices className="h-4 w-4" />
                          </button>
                        </td>
                        <td className="align-top">
                          <button
                            type="button"
                            aria-label="Remove address"
                            disabled={form.ips.length === 1}
                            onClick={() => setForm((f) => ({ ...f, ips: f.ips.filter((_, j) => j !== i) }))}
                            className="rounded-md p-1.5 text-secondary hover:bg-muted hover:text-danger-fg disabled:opacity-30"
                          >
                            <Trash2 className="h-4 w-4" />
                          </button>
                        </td>
                      </tr>
                      {showHint && (
                        <tr>
                          <td colSpan={6} className="pb-1.5 pt-0.5">
                            <p className={`text-[11px] ${labelBad ? 'text-danger-fg' : 'text-faint'}`}>
                              {live && <>Known host — observed as {live.hostname ?? 'unknown'} with MAC {live.mac}. </>}
                              {labelBad && (
                                <>{addr} cannot live in “{label}” — pick one of the possible networks or clear the field.</>
                              )}
                              {!labelBad && isAddr && netChoices.length > 0 && !netChoices.includes(label) && (
                                <> Possible networks: {netChoices.slice(0, 4).join(', ')}</>
                              )}
                            </p>
                          </td>
                        </tr>
                      )}
                    </Fragment>
                  );
                })}
              </tbody>
            </table>
            <button
              type="button"
              onClick={() => addIpRow()}
              className="mt-2 inline-flex items-center gap-1 rounded-md border border-border px-3 py-1.5 text-sm hover:bg-muted"
            >
              <Plus className="h-4 w-4" /> Add IP address
            </button>
          </div>

          {/* Footer */}
          <div className="flex justify-end gap-2 border-t border-border pt-3">
            <button type="button" onClick={onClose} className="rounded-md px-3 py-1.5 text-sm text-secondary hover:bg-muted">
              Cancel
            </button>
            <button
              type="submit"
              disabled={createHost.isPending || updateHost.isPending}
              className="inline-flex items-center gap-2 rounded-md bg-primary px-4 py-1.5 text-sm font-medium text-white hover:bg-primary-hover disabled:opacity-50"
            >
              {initial ? 'Save changes' : 'Create host'}
            </button>
          </div>
        </form>
    </div>
  );
}

// ---------------------------------------------------------------------------
// CSV import modal (flexible header mapping)
// ---------------------------------------------------------------------------

interface ImportModalProps {
  sites: Site[];
  layers: NetworkLayer[];
  onClose: () => void;
  onDone: () => void;
}

function ImportModal({ sites, layers, onClose, onDone }: ImportModalProps) {
  const [headers, setHeaders] = useState<string[]>([]);
  const [rows, setRows] = useState<string[][]>([]);
  const [fileName, setFileName] = useState('');
  const [mapping, setMapping] = useState<Partial<Record<CsvImportField, number>>>({});
  const [matchBy, setMatchBy] = useState<'dns' | 'mac'>('dns');
  const [updateExisting, setUpdateExisting] = useState(true);
  // Client-side mapping errors (bad site/layer names, missing values) — shown
  // alongside the server's per-row validation errors after an import run.
  const [localErrors, setLocalErrors] = useState<{ index: number; error: string }[]>([]);
  const [result, setResult] = useState<{ created: number; updated: number; skipped: number; errors: { index: number; error: string }[] } | null>(null);

  function handleFile(file: File) {
    file.text().then((text) => {
      const matrix = parseCsv(text);
      if (matrix.length < 2) return;
      const head = matrix[0].map((h, i) => h.trim() || `Column ${i + 1}`);
      setHeaders(head);
      setRows(matrix.slice(1));
      setMapping(suggestHeaderMapping(head));
      setFileName(file.name);
      setResult(null);
    });
  }

  /** Builds the structured import rows from the current mapping. */
  function buildPayload(): { hosts: DocumentedHostRequest[]; localErrors: { index: number; error: string }[] } {
    const siteByName = new Map(sites.map((s) => [s.name.toLowerCase(), s.id] as const));
    const layerByName = new Map(layers.map((l) => [l.name.toLowerCase(), l.id] as const));
    const hosts: DocumentedHostRequest[] = [];
    const localErrors: { index: number; error: string }[] = [];

    rows.forEach((r, i) => {
      // Line number in the file (header is line 1).
      const line = i + 2;
      const get = (f: CsvImportField): string => {
        const col = mapping[f];
        return col !== undefined && col >= 0 ? (r[col] ?? '').trim() : '';
      };

      const dnsNames = splitCellValues(get('dnsNames'));
      const addresses = splitCellValues(get('address')).filter(isIpLiteral);
      if (dnsNames.length === 0) {
        localErrors.push({ index: line, error: 'no DNS name mapped/found' });
        return;
      }
      if (addresses.length === 0) {
        localErrors.push({ index: line, error: 'no valid IP address found in the mapped column' });
        return;
      }

      let siteId: string | null = null;
      const siteText = get('siteId');
      if (siteText) {
        siteId = siteByName.get(siteText.toLowerCase()) ?? null;
        if (!siteId) {
          localErrors.push({ index: line, error: `unknown site "${siteText}"` });
          return;
        }
      }
      let layerId: string | null = null;
      const layerText = get('layerId');
      if (layerText) {
        layerId = layerByName.get(layerText.toLowerCase()) ?? null;
        if (!layerId) {
          localErrors.push({ index: line, error: `unknown layer "${layerText}"` });
          return;
        }
      }

      const mac = get('mac');
      const networkLabel = get('networkLabel');
      hosts.push({
        dnsNames,
        friendlyName: get('friendlyName') || null,
        description: get('description') || null,
        siteId,
        layerId,
        ips: addresses.map((a) => ({ address: a, mac: mac || null, networkLabel: networkLabel || null })),
      });
    });

    return { hosts, localErrors };
  }

  const importMutation = useMutation({
    mutationFn: (body: { hosts: DocumentedHostRequest[]; matchBy: 'dns' | 'mac'; updateExisting: boolean }) =>
      api.importDocumentedHosts(body),
    onSuccess: (res) => {
      setResult(res);
      onDone();
    },
  });

  function runImport() {
    const { hosts, localErrors } = buildPayload();
    setLocalErrors(localErrors);
    if (hosts.length === 0) return;
    importMutation.mutate({ hosts, matchBy, updateExisting });
  }

  /** True when a column index is claimed by any mapped field. */
  const usedColumns = useMemo(() => new Set(Object.values(mapping).filter((c): c is number => typeof c === 'number' && c >= 0)), [mapping]);

  const previewRows = rows.slice(0, 5);

  return (
    <div className="fixed inset-0 z-40 flex items-start justify-center overflow-y-auto bg-primary/40 p-4 sm:items-center" onClick={onClose}>
      <div className="w-full max-w-3xl rounded-md border border-border bg-card p-5 shadow-lg" onClick={(e) => e.stopPropagation()}>
        <div className="mb-4 flex items-center justify-between">
          <h2 className="text-base font-semibold text-foreground">Import documented hosts from CSV</h2>
          <button type="button" aria-label="Close import dialog" onClick={onClose} className="rounded p-1 text-faint hover:bg-muted">
            <X className="h-4 w-4" />
          </button>
        </div>

        {/* Step 1 — pick the file */}
        {headers.length === 0 && (
          <label className="flex cursor-pointer flex-col items-center gap-2 rounded-md border-2 border-dashed border-border p-8 text-sm text-secondary hover:bg-muted">
            <Upload className="h-6 w-6" />
            Choose a CSV file (exported from your spreadsheet)
            <input type="file" accept=".csv,text/csv,text/plain" className="hidden" onChange={(e) => { const f = e.target.files?.[0]; if (f) handleFile(f); }} />
          </label>
        )}

        {/* Step 2 — header mapping */}
        {headers.length > 0 && !result && (
          <>
            <p className="mb-3 text-sm text-secondary">
              <span className="font-mono">{fileName}</span> — {rows.length} data row(s), {headers.length} column(s). Map each field to a
              column; unmapped fields are left empty.
            </p>

            {/* Preview */}
            <div className="mb-4 overflow-x-auto rounded-md border border-border">
              <table className="w-full text-left text-xs">
                <thead className="bg-muted">
                  <tr>
                    {headers.map((h, i) => (
                      <th key={i} className={`whitespace-nowrap px-2 py-1.5 font-medium ${usedColumns.has(i) ? 'text-primary' : ''}`}>
                        {h}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {previewRows.map((r, i) => (
                    <tr key={i} className="border-t border-border">
                      {headers.map((_, j) => (
                        <td key={j} className="max-w-[180px] truncate whitespace-nowrap px-2 py-1 font-mono">{r[j] ?? ''}</td>
                      ))}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {/* Mapping grid */}
            <div className="mb-4 grid grid-cols-1 gap-2 sm:grid-cols-2">
              {CSV_IMPORT_FIELDS.map(({ field, label, hint }) => (
                <label key={field} className="flex items-center justify-between gap-3 rounded-md border border-border px-3 py-2 text-sm" title={hint}>
                  <span className="text-secondary">{label}</span>
                  <select
                    className="max-w-[180px] rounded-md border border-border bg-background px-2 py-1 text-xs"
                    value={mapping[field] ?? -1}
                    onChange={(e) => setMapping((m) => ({ ...m, [field]: Number(e.target.value) }))}
                  >
                    <option value={-1}>— skip —</option>
                    {headers.map((h, i) => (
                      <option key={i} value={i}>{h}</option>
                    ))}
                  </select>
                </label>
              ))}
            </div>

            {/* Options */}
            <div className="mb-4 flex flex-wrap items-center gap-5 text-sm">
              <label className="flex items-center gap-2">
                Match existing hosts by
                <select className="rounded-md border border-border bg-background px-2 py-1 text-xs" value={matchBy} onChange={(e) => setMatchBy(e.target.value as 'dns' | 'mac')}>
                  <option value="dns">DNS name</option>
                  <option value="mac">documented MAC</option>
                </select>
              </label>
              <label className="flex items-center gap-2">
                <input type="checkbox" checked={updateExisting} onChange={(e) => setUpdateExisting(e.target.checked)} />
                Update matched hosts (otherwise skip them)
              </label>
            </div>

            <div className="flex justify-end gap-2 border-t border-border pt-3">
              <button type="button" onClick={() => { setHeaders([]); setRows([]); setFileName(''); setResult(null); setLocalErrors([]); }} className="rounded-md px-3 py-1.5 text-sm text-secondary hover:bg-muted">
                Choose another file
              </button>
              <button
                type="button"
                disabled={importMutation.isPending}
                onClick={runImport}
                className="inline-flex items-center gap-2 rounded-md bg-primary px-4 py-1.5 text-sm font-medium text-white hover:bg-primary-hover disabled:opacity-50"
              >
                <Upload className="h-4 w-4" /> Import {rows.length} row(s)
              </button>
            </div>
          </>
        )}

        {/* Step 3 — result */}
        {result && (
          <>
            <div className="mb-4 flex flex-wrap gap-2 text-sm">
              <span className="rounded bg-success px-2 py-1 font-medium text-success-fg">{result.created} created</span>
              <span className="rounded bg-info px-2 py-1 font-medium text-info-fg">{result.updated} updated</span>
              {result.skipped > 0 && <span className="rounded bg-muted px-2 py-1 font-medium text-secondary">{result.skipped} skipped</span>}
            </div>
{[...localErrors, ...result.errors].length > 0 && (
              <div className="mb-4 max-h-48 overflow-y-auto rounded-md border border-warning-border bg-warning px-3 py-2 text-xs text-warning-fg">
                {[...localErrors, ...result.errors].slice(0, 50).map((e, i) => (
                  <p key={i}>Line {e.index}: {e.error}</p>
                ))}
                {[...localErrors, ...result.errors].length > 50 && <p>…and {[...localErrors, ...result.errors].length - 50} more</p>}
              </div>
            )}
            <div className="flex justify-end gap-2 border-t border-border pt-3">
              <button type="button" onClick={onClose} className="rounded-md px-3 py-1.5 text-sm text-secondary hover:bg-muted">
                Close
              </button>
              <button
                type="button"
                onClick={() => { setHeaders([]); setRows([]); setFileName(''); setResult(null); setLocalErrors([]); }}
                className="rounded-md border border-border px-3 py-1.5 text-sm hover:bg-muted"
              >
                Import another file
              </button>
            </div>
          </>
        )}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Import-from-inventory modal — copies the LIVE host inventory into the
// documented hosts (additive merge, dry-run preview first)
// ---------------------------------------------------------------------------

interface InventoryImportModalProps {
  onClose: () => void;
  onDone: () => void;
}

function InventoryImportModal({ onClose, onDone }: InventoryImportModalProps) {
  const [skipWithoutHostname, setSkipWithoutHostname] = useState(true);
  const [skipUnknownNetworks, setSkipUnknownNetworks] = useState(false);
  const [skipPublicIpv4, setSkipPublicIpv4] = useState(false);
  const [skipPublicIpv6, setSkipPublicIpv6] = useState(false);
  const [skipWithoutVlan, setSkipWithoutVlan] = useState(false);
  const [maxAgeHours, setMaxAgeHours] = useState(24);
  // Phase: 'options' → pick filters; 'plan' → dry-run preview; 'done' → applied.
  const [phase, setPhase] = useState<'options' | 'plan' | 'done'>('options');
  const [plan, setPlan] = useState<import('../api/client').DocumentedHostInventoryImportResult | null>(null);
  const [applied, setApplied] = useState<import('../api/client').DocumentedHostInventoryImportResult | null>(null);

  const previewMutation = useMutation({
    mutationFn: () => api.importDocumentedHostsFromInventory({ skipWithoutHostname, skipUnknownNetworks, skipPublicIpv4, skipPublicIpv6, skipWithoutVlan, maxAgeHours, dryRun: true }),
    onSuccess: (res) => {
      setPlan(res);
      setPhase('plan');
    },
  });
  const applyMutation = useMutation({
    mutationFn: () => api.importDocumentedHostsFromInventory({ skipWithoutHostname, skipUnknownNetworks, skipPublicIpv4, skipPublicIpv6, skipWithoutVlan, maxAgeHours, dryRun: false }),
    onSuccess: (res) => {
      setApplied(res);
      setPhase('done');
      onDone();
    },
  });

  // Re-run the preview whenever the filters change while in plan phase.
  useEffect(() => {
    if (phase === 'plan') previewMutation.mutate();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [skipWithoutHostname, skipUnknownNetworks, skipPublicIpv4, skipPublicIpv6, skipWithoutVlan, maxAgeHours]);

  const plannedCreates = plan?.planned.filter((p) => p.action === 'create').length ?? 0;
  const plannedUpdates = plan?.planned.filter((p) => p.action === 'update').length ?? 0;
  const plannedSkips = plan?.planned.filter((p) => p.action === 'skip').length ?? 0;

  return (
    <div className="fixed inset-0 z-40 flex items-start justify-center overflow-y-auto bg-primary/40 p-4 sm:items-center" onClick={onClose}>
      <div className="w-full max-w-3xl rounded-md border border-border bg-card p-5 shadow-lg" onClick={(e) => e.stopPropagation()}>
        <div className="mb-4 flex items-center justify-between">
          <h2 className="text-base font-semibold text-foreground">Import from live inventory</h2>
          <button type="button" aria-label="Close import dialog" onClick={onClose} className="rounded p-1 text-faint hover:bg-muted">
            <X className="h-4 w-4" />
          </button>
        </div>

        {/* Phase 1 — options */}
        {phase === 'options' && (
          <>
            <p className="mb-3 text-sm text-secondary">
              Copies every host currently observed in the inventory into the documented hosts. Existing entries are
              MERGED, never overwritten: their DNS names, friendly name, description and placement stay untouched —
              only new addresses, MACs and network references from the observation are added. Nothing is deleted.
            </p>

            <div className="mb-4 flex flex-col gap-2 text-sm">
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
              <label className="flex items-center justify-between gap-3 rounded-md border border-border px-3 py-2" title="Drop hosts that carry a publicly routable IPv4 address (RFC 1918 private ranges count as internal).">
                <span className="text-secondary">Skip hosts with public IPv4 addresses</span>
                <input type="checkbox" checked={skipPublicIpv4} onChange={(e) => setSkipPublicIpv4(e.target.checked)} />
              </label>
              <label className="flex items-center justify-between gap-3 rounded-md border border-border px-3 py-2" title="Drop hosts that carry a publicly routable IPv6 address (ULA fc00::/7 counts as internal).">
                <span className="text-secondary">Skip hosts with public IPv6 addresses</span>
                <input type="checkbox" checked={skipPublicIpv6} onChange={(e) => setSkipPublicIpv6(e.target.checked)} />
              </label>
              <label className="flex items-center justify-between gap-3 rounded-md border border-border px-3 py-2" title="Only consider hosts observed within this window (the inventory is swept after 24 h).">
                <span className="text-secondary">Observed within</span>
                <select className="rounded-md border border-border bg-background px-2 py-1 text-xs" value={maxAgeHours} onChange={(e) => setMaxAgeHours(Number(e.target.value))}>
                  <option value={0}>all time (no age limit)</option>
                  <option value={6}>last 6 hours</option>
                  <option value={24}>last 24 hours</option>
                </select>
              </label>
            </div>

            <div className="flex justify-end gap-2 border-t border-border pt-3">
              <button type="button" onClick={onClose} className="rounded-md px-3 py-1.5 text-sm text-secondary hover:bg-muted">
                Cancel
              </button>
              <button
                type="button"
                disabled={previewMutation.isPending}
                onClick={() => previewMutation.mutate()}
                className="inline-flex items-center gap-2 rounded-md bg-primary px-4 py-1.5 text-sm font-medium text-white hover:bg-primary-hover disabled:opacity-50"
              >
                <DatabaseZap className="h-4 w-4" /> Preview what would change
              </button>
            </div>
          </>
        )}

        {/* Phase 2 — dry-run plan */}
        {phase === 'plan' && plan && (
          <>
            <p className="mb-3 text-sm text-secondary">
              {plan.totalLiveHosts} live host(s) considered. The merge is additive — existing documented data is preserved, only missing information is added.
            </p>

            <div className="mb-4 flex flex-wrap gap-2 text-sm">
              <span className="rounded bg-success px-2 py-1 font-medium text-success-fg">{plannedCreates} to create</span>
              <span className="rounded bg-info px-2 py-1 font-medium text-info-fg">{plannedUpdates} to update (merge)</span>
              {plannedSkips > 0 && <span className="rounded bg-muted px-2 py-1 font-medium text-secondary">{plannedSkips} skipped</span>}
            </div>

            {/* Filters stay adjustable — the preview re-runs automatically */}
            <div className="mb-4 flex flex-wrap items-center gap-5 text-sm">
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
              <label className="flex items-center gap-2">
                <input type="checkbox" checked={skipPublicIpv4} onChange={(e) => setSkipPublicIpv4(e.target.checked)} />
                Skip public IPv4
              </label>
              <label className="flex items-center gap-2">
                <input type="checkbox" checked={skipPublicIpv6} onChange={(e) => setSkipPublicIpv6(e.target.checked)} />
                Skip public IPv6
              </label>
              <label className="flex items-center gap-2">
                Observed within
                <select className="rounded-md border border-border bg-background px-2 py-1 text-xs" value={maxAgeHours} onChange={(e) => setMaxAgeHours(Number(e.target.value))}>
                  <option value={0}>all time</option>
                  <option value={6}>last 6 hours</option>
                  <option value={24}>last 24 hours</option>
                </select>
              </label>
            </div>

            {previewMutation.isPending && <p className="mb-3 text-sm text-faint">Recomputing preview…</p>}

            <div className="mb-4 max-h-72 overflow-y-auto rounded-md border border-border">
              <table className="w-full text-left text-xs">
                <thead className="sticky top-0 bg-muted">
                  <tr>
                    <th className="px-2 py-1.5 font-medium">MAC</th>
                    <th className="px-2 py-1.5 font-medium">Hostname</th>
                    <th className="px-2 py-1.5 font-medium">IPs</th>
                    <th className="px-2 py-1.5 font-medium">Action</th>
                  </tr>
                </thead>
                <tbody>
                  {plan.planned.slice(0, 300).map((p) => (
                    <tr key={p.mac} className="border-t border-border">
                      <td className="px-2 py-1 font-mono">{p.mac}</td>
                      <td className="max-w-[220px] truncate px-2 py-1 font-mono" title={p.hostname ?? undefined}>
                        {p.hostname ?? <span className="text-faint">—</span>}
                      </td>
                      <td className="px-2 py-1">{p.ips}</td>
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
            {plan.planned.length > 300 && <p className="mb-2 text-xs text-faint">…and {plan.planned.length - 300} more rows</p>}

            <div className="flex justify-end gap-2 border-t border-border pt-3">
              <button type="button" onClick={() => setPhase('options')} className="rounded-md px-3 py-1.5 text-sm text-secondary hover:bg-muted">
                Back to options
              </button>
              <button
                type="button"
                disabled={applyMutation.isPending || plannedCreates + plannedUpdates === 0}
                onClick={() => applyMutation.mutate()}
                className="inline-flex items-center gap-2 rounded-md bg-primary px-4 py-1.5 text-sm font-medium text-white hover:bg-primary-hover disabled:opacity-50"
              >
                <DatabaseZap className="h-4 w-4" /> Import {plannedCreates + plannedUpdates} host(s)
              </button>
            </div>
          </>
        )}

        {/* Phase 3 — applied */}
        {phase === 'done' && applied && (
          <>
            <div className="mb-4 flex flex-wrap gap-2 text-sm">
              <span className="rounded bg-success px-2 py-1 font-medium text-success-fg">{applied.created} created</span>
              <span className="rounded bg-info px-2 py-1 font-medium text-info-fg">{applied.updated} updated (merged)</span>
              {applied.skipped > 0 && <span className="rounded bg-muted px-2 py-1 font-medium text-secondary">{applied.skipped} skipped</span>}
            </div>
            <p className="mb-4 text-sm text-secondary">
              Existing documented hosts were merged additively — no user data was overwritten or deleted.
            </p>
            <div className="flex justify-end gap-2 border-t border-border pt-3">
              <button type="button" onClick={onClose} className="rounded-md px-3 py-1.5 text-sm text-secondary hover:bg-muted">
                Close
              </button>
            </div>
          </>
        )}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

export default function DocumentedHosts() {
  const queryClient = useQueryClient();
  const canWrite = can('documented-hosts:write');
  const { formatDateTime } = useTimeFormat();

  const [formOpen, setFormOpen] = useState(false);
  const [editing, setEditing] = useState<DocumentedHost | null>(null);
  const [importOpen, setImportOpen] = useState(false);
  const [inventoryImportOpen, setInventoryImportOpen] = useState(false);

  // Documented hosts + the reference data the form needs. The live host rows
  // power MAC auto-fill in the form and keep "discovered" fresh (30 s cadence).
  const hostsQuery = useQuery({ queryKey: ['documentedHosts'], queryFn: () => api.documentedHosts(), refetchInterval: 30_000 });
  const sitesQuery = useQuery({ queryKey: ['sites'], queryFn: api.sites });
  const layersQuery = useQuery({ queryKey: ['layers'], queryFn: api.layers });
  const networksQuery = useQuery({ queryKey: ['networks'], queryFn: () => api.networks() });
  const liveHostsQuery = useQuery({ queryKey: ['hosts'], queryFn: () => api.hosts(), refetchInterval: 30_000 });
  // Topology graph — device nodes carry the RESOLVED layer (override > plugin
  // suggestion > heuristic), which powers the form's layer pre-fill.
  const topologyQuery = useQuery({ queryKey: ['topology'], queryFn: () => api.topology() });

  // Known network labels for the form's datalist — merged logical networks by
  // display name plus every real subnet CIDR they carry.
  const networkOptions = useMemo(() => {
    const set = new Set<string>();
    for (const n of networksQuery.data ?? []) {
      set.add(n.name);
      for (const s of n.subnets ?? []) set.add(s);
    }
    return Array.from(set).sort();
  }, [networksQuery.data]);

  // Auto-fill data: live host index (MAC/address → host) + known networks with
  // their subnet CIDRs + VLAN ids (for IP→network/VLAN matching in the form).
  const liveIndex = useMemo(() => buildLiveIndex(liveHostsQuery.data ?? []), [liveHostsQuery.data]);
  const networksForMatch = useMemo(
    () => (networksQuery.data ?? []).map((n) => ({ label: n.name, cidrs: n.subnets ?? [], vlanId: n.vlanId ?? null })),
    [networksQuery.data]
  );

  // Lowercased device name → resolved topology layer id (for the form's layer pre-fill).
  const deviceLayers = useMemo(() => {
    const m = new Map<string, string>();
    for (const n of topologyQuery.data?.nodes ?? []) {
      if (n.kind === 'device' && n.layer) m.set(n.name.toLowerCase(), n.layer);
    }
    return m;
  }, [topologyQuery.data]);

  // Every address already in use or documented — free-IP suggestions must skip
  // all of them so a new host never collides with reality.
  const takenIps = useMemo(() => {
    const s = new Set<string>();
    for (const h of liveHostsQuery.data ?? []) {
      for (const ip of h.ips ?? []) {
        const a = ip.trim().toLowerCase();
        if (a) s.add(a);
      }
    }
    for (const h of hostsQuery.data ?? []) {
      for (const ip of h.ips) s.add(ip.address.toLowerCase());
    }
    return s;
  }, [liveHostsQuery.data, hostsQuery.data]);

  function openCreate() {
    setEditing(null);
    setFormOpen(true);
    window.scrollTo({ top: 0 });
  }
  function openEdit(row: DocumentedHost) {
    setEditing(row);
    setFormOpen(true);
    window.scrollTo({ top: 0 });
  }
  function closeForm() {
    setFormOpen(false);
    setEditing(null);
  }
  function handleSaved() {
    queryClient.invalidateQueries({ queryKey: ['documentedHosts'] });
    closeForm();
  }
  function handleDelete(row: DocumentedHost) {
    const label = row.dnsNames[0] ?? row.id;
    if (!window.confirm(`Delete documented host "${label}"?`)) return;
    deleteMutation.mutate(row.id);
  }
  const deleteMutation = useMutation({
    mutationFn: (id: string) => api.deleteDocumentedHost(id),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['documentedHosts'] }),
  });

  const columns: DataTableColumn<DocumentedHost>[] = [
    {
      header: 'Name',
      key: 'dnsNames',
      width: 240,
      exportValue: (row) => row.dnsNames.join(', '),
      searchText: (row) => [row.dnsNames.join(' '), row.friendlyName ?? '', row.description ?? ''].join(' '),
      render: (row) => (
        <div className="leading-tight">
          <span className="font-medium text-foreground">{row.dnsNames[0]}</span>
          {row.dnsNames.length > 1 && (
            <span title={row.dnsNames.slice(1).join(', ')} className="ml-1 rounded bg-muted px-1 py-0.5 text-[10px] font-semibold text-secondary">
              +{row.dnsNames.length - 1}
            </span>
          )}
          {row.friendlyName && <p className="text-xs text-faint">{row.friendlyName}</p>}
        </div>
      ),
    },
    {
      header: 'IPs / MAC',
      key: 'ips',
      width: 230,
      exportValue: (row) => row.ips.map((ip) => `${ip.address} ${ip.mac ?? ''}`).join(' '),
      render: (row) => <IpBlock row={row} />,
    },
    {
      header: 'Network',
      key: 'networks',
      width: 170,
      exportValue: (row) => Array.from(new Set(row.ips.map((ip) => ip.networkName ?? ip.networkLabel).filter(Boolean))).join(', '),
      render: (row) => <NetworkCell row={row} />,
    },
    {
      header: 'VLAN',
      key: 'vlans',
      width: 150,
      exportValue: (row) => row.ips.map((ip) => `${ip.address}: ${ip.vlanId ?? ''}`).join(', '),
      render: (row) => <VlanCell row={row} />,
    },
    {
      header: 'Site',
      key: 'siteName',
      width: 120,
      render: (row) => row.siteName ?? <span className="text-faint">—</span>,
    },
    {
      header: 'Layer',
      key: 'layerName',
      width: 110,
      render: (row) => row.layerName ?? <span className="text-faint">—</span>,
    },
    {
      header: 'Status',
      key: 'discovered',
      width: 150,
      exportValue: (row) => (row.discovered ? 'discovered' : 'not seen'),
      render: (row) => <StatusCell row={row} />,
    },
    {
      header: 'Observed hostname',
      key: 'observedHostname',
      width: 160,
      render: (row) => row.observedHostname ?? <span className="text-faint">—</span>,
    },
    {
      header: 'Last seen',
      key: 'lastSeenAt',
      width: 170,
      sortAccessor: (row) => (row.lastSeenAt ? new Date(row.lastSeenAt).getTime() : null),
      render: (row) => row.lastSeenAt ? formatDateTime(row.lastSeenAt) : <span className="text-faint">—</span>,
    },
    {
      header: 'Description',
      key: 'description',
      hiddenByDefault: true,
      render: (row) => row.description ?? <span className="text-faint">—</span>,
    },
    {
      header: 'Date added',
      key: 'createdAt',
      width: 170,
      hiddenByDefault: true,
      sortAccessor: (row) => new Date(row.createdAt).getTime(),
      render: (row) => formatDateTime(row.createdAt),
    },
    {
      header: 'Date modified',
      key: 'updatedAt',
      width: 170,
      hiddenByDefault: true,
      sortAccessor: (row) => new Date(row.updatedAt).getTime(),
      render: (row) => formatDateTime(row.updatedAt),
    },
    ...(canWrite
      ? [
          {
            header: 'Actions',
            key: 'actions',
            width: 100,
            sortable: false as const,
            excludeFromExport: true,
            render: (row: DocumentedHost) => (
              <div className="flex gap-1">
                <button type="button" aria-label={`Edit ${row.dnsNames[0]}`} title="Edit host" className="rounded-md p-1.5 text-secondary hover:bg-muted hover:text-foreground" onClick={() => openEdit(row)}>
                  <Pencil className="h-4 w-4" />
                </button>
                <button type="button" aria-label={`Delete ${row.dnsNames[0]}`} title="Delete host" className="rounded-md p-1.5 text-secondary hover:bg-danger hover:text-danger-fg" onClick={() => handleDelete(row)}>
                  <Trash2 className="h-4 w-4" />
                </button>
              </div>
            ),
          },
        ]
      : []),
  ];

  return (
    <Layout
      title={
        <span className="inline-flex items-center gap-2">
          Documented Hosts
          <NotebookPen className="h-4 w-4 text-faint" />
        </span>
      }
      actions={
        canWrite && (
          <>
            <button type="button" onClick={() => setInventoryImportOpen(true)} title="Copy the live host inventory into the documented hosts (additive merge)" className="inline-flex items-center gap-2 rounded-md border border-border px-3 py-1.5 text-sm font-medium hover:bg-muted">
              <DatabaseZap className="h-4 w-4" /> Import from Inventory
            </button>
            <button type="button" onClick={() => setImportOpen(true)} className="inline-flex items-center gap-2 rounded-md border border-border px-3 py-1.5 text-sm font-medium hover:bg-muted">
              <Upload className="h-4 w-4" /> Import CSV
            </button>
            <button type="button" onClick={openCreate} className="inline-flex items-center gap-2 rounded-md bg-primary px-3 py-1.5 text-sm font-medium text-white hover:bg-primary-hover">
              <Plus className="h-4 w-4" /> New host
            </button>
          </>
        )
      }
    >
      {formOpen && canWrite && (
        <HostFormCard
          initial={editing}
          sites={sitesQuery.data ?? []}
          layers={layersQuery.data ?? []}
          networkOptions={networkOptions}
          liveIndex={liveIndex}
          networksForMatch={networksForMatch}
          deviceLayers={deviceLayers}
          takenIps={takenIps}
          onClose={closeForm}
          onSaved={handleSaved}
        />
      )}
      {hostsQuery.isLoading && <p className="text-sm text-muted-foreground">Loading documented hosts…</p>}
      {hostsQuery.isError && (
        <p className="text-sm text-danger-fg">Failed to load documented hosts: {(hostsQuery.error as Error).message}</p>
      )}
      {hostsQuery.data && (
        <DataTable
          columns={columns}
          rows={hostsQuery.data}
          rowKey={(row) => row.id}
          storageKey="documented-hosts"
          autoRefresh={{ intervalMs: 30_000, queries: [hostsQuery, liveHostsQuery] }}
          searchPlaceholder="Search documented hosts…"
          emptyMessage="No documented hosts yet — create one with “New host” or import your spreadsheet as CSV."
          selectable={canWrite}
          bulkActions={
            canWrite
              ? [
                  {
                    label: 'Delete selected',
                    confirm: (count) => `Delete ${count} documented host${count === 1 ? '' : 's'}? This cannot be undone.`,
                    onClick: async (selected: DocumentedHost[]) => {
                      const errors: string[] = [];
                      for (const h of selected) {
                        try {
                          await api.deleteDocumentedHost(h.id);
                        } catch (err) {
                          errors.push(`${h.dnsNames[0]}: ${(err as Error).message}`);
                        }
                      }
                      queryClient.invalidateQueries({ queryKey: ['documentedHosts'] });
                      if (errors.length > 0) alert(`Deleted ${selected.length - errors.length} of ${selected.length}. ${errors.join(' | ')}`);
                    },
                  },
                ]
              : undefined
          }
        />
      )}

      {importOpen && (
        <ImportModal
          sites={sitesQuery.data ?? []}
          layers={layersQuery.data ?? []}
          onClose={() => setImportOpen(false)}
          onDone={() => queryClient.invalidateQueries({ queryKey: ['documentedHosts'] })}
        />
      )}

      {inventoryImportOpen && (
        <InventoryImportModal
          onClose={() => setInventoryImportOpen(false)}
          onDone={() => queryClient.invalidateQueries({ queryKey: ['documentedHosts'] })}
        />
      )}
    </Layout>
  );
}
