import { Fragment, useEffect, useMemo, useRef, useState } from 'react';
import { useQuery, useQueryClient, useMutation } from '@tanstack/react-query';
import { Archive, CircleCheck, CircleX, DatabaseZap, GitMerge, Globe, NotebookPen, Pencil, Plus, Tag, Trash2, Upload, X } from 'lucide-react';
import { Layout } from '../components/Layout';
import { DataTable, DataTableColumn } from '../components/DataTable';
import { ChipInput } from '../components/ChipInput';
import { api, DocumentedNetwork, DocumentedNetworkRequest, NetworkLayer, Site } from '../api/client';
import { can } from '../auth/permissions';
import { useTimeFormat } from '../utils/time';
import { isIpLiteral } from '../utils/address';
import { NETWORK_CSV_IMPORT_FIELDS, NetworkCsvImportField, parseCsv, splitCellValues, suggestNetworkHeaderMapping } from '../utils/csv';

/**
 * Documented networks — the user-maintained network documentation page. The
 * documented-network counterpart of Documented Hosts: permanent records of what
 * SHOULD exist on the network (name, subnets, VLAN, gateways, DNS/NTP
 * servers, site/layer placement), cross-referenced against the live
 * logical-network
 * inventory to mark each entry "discovered".
 */

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

/** Form state for one documented network (all fields as editable strings). */
interface NetworkFormState {
  name: string;
  subnets: string[]; // dynamic CIDR rows ('' = empty row)
  vlanId: string;
  gateways: string[]; // dynamic IP rows
  dnsServers: string[]; // dynamic IP rows
  ntpServers: string[]; // dynamic IP rows
  friendlyName: string;
  description: string;
  siteId: string;
  layerId: string;
  tags: string[];
  isActive: boolean;
}

const EMPTY_FORM: NetworkFormState = {
  name: '',
  subnets: [''],
  vlanId: '',
  gateways: [],
  dnsServers: [],
  ntpServers: [],
  friendlyName: '',
  description: '',
  siteId: '',
  layerId: '',
  tags: [],
  isActive: true,
};

function formFromNetwork(n: DocumentedNetwork): NetworkFormState {
  return {
    name: n.name,
    subnets: n.subnets.length > 0 ? [...n.subnets] : [''],
    vlanId: n.vlanId != null ? String(n.vlanId) : '',
    gateways: [...n.gateways],
    dnsServers: [...n.dnsServers],
    ntpServers: [...(n.ntpServers ?? [])],
    friendlyName: n.friendlyName ?? '',
    description: n.description ?? '',
    siteId: n.siteId ?? '',
    layerId: n.layerId ?? '',
    tags: [...(n.tags ?? [])],
    isActive: n.isActive !== false,
  };
}

/** True for a structurally valid CIDR ("a.b.c.d/p" or "fd00::/p", prefix in range). */
function isCidrLiteral(value: string): boolean {
  const v = value.trim();
  const i = v.indexOf('/');
  if (i <= 0) return false;
  const net = v.slice(0, i);
  const pfx = Number(v.slice(i + 1));
  if (!isIpLiteral(net)) return false;
  const max = net.includes(':') ? 128 : 32;
  return Number.isInteger(pfx) && pfx >= 0 && pfx <= max;
}

/** IPv4 literal → unsigned 32-bit int (null when not a v4 literal). */
function ipv4ToInt(value: string): number | null {
  const o = value.split('.').map(Number);
  if (o.length !== 4 || o.some((x) => !Number.isInteger(x) || x < 0 || x > 255)) return null;
  return ((o[0] << 24) | (o[1] << 16) | (o[2] << 8) | o[3]) >>> 0;
}

/** IPv6 literal → BigInt (null when not a v6 literal). */
function ipv6ToBigInt(value: string): bigint | null {
  const v = value.replace(/%[a-zA-Z0-9._-]+$/, '');
  if (!v.includes(':')) return null;
  // Expand "::" compression into full 8 groups.
  let halves = v.split('::');
  if (halves.length > 2) return null;
  const left = halves[0] === '' ? [] : halves[0].split(':');
  const right = halves.length === 2 && halves[1] !== '' ? halves[1].split(':') : [];
  let groups: string[];
  if (halves.length === 2) {
    if (left.length + right.length > 7) return null;
    groups = [...left, ...Array(8 - left.length - right.length).fill('0'), ...right];
  } else {
    if (left.length !== 8) return null;
    groups = left;
  }
  let out = 0n;
  for (const g of groups) {
    if (!/^[0-9a-fA-F]{1,4}$/.test(g)) return null;
    out = (out << 16n) | BigInt(parseInt(g, 16));
  }
  return out;
}

/** True when the two CIDR blocks overlap (containment in either direction). */
function cidrsOverlap(a: string, b: string): boolean {
  const sa = a.trim().split('/');
  const sb = b.trim().split('/');
  if (sa.length !== 2 || sb.length !== 2) return false;
  const [na, pa] = sa;
  const [nb, pb] = sb;
  const pfxA = Number(pa);
  const pfxB = Number(pb);
  // Families must match.
  if (na.includes(':') !== nb.includes(':')) return false;
  if (!na.includes(':')) {
    const ia = ipv4ToInt(na);
    const ib = ipv4ToInt(nb);
    if (ia === null || ib === null) return false;
    const pfx = Math.min(pfxA, pfxB);
    const mask = pfx === 0 ? 0 : (~0 << (32 - pfx)) >>> 0;
    return (ia & mask) === (ib & mask);
  }
  const ia = ipv6ToBigInt(na);
  const ib = ipv6ToBigInt(nb);
  if (ia === null || ib === null) return false;
  const pfx = Math.min(pfxA, pfxB);
  const mask = pfx === 0 ? 0n : ((1n << 128n) - 1n) ^ ((1n << BigInt(128 - pfx)) - 1n);
  return (ia & mask) === (ib & mask);
}

// ---------------------------------------------------------------------------
// Table cell renderers
// ---------------------------------------------------------------------------

/** Discovery status badge + stale marker. */
function StatusCell({ row }: { row: DocumentedNetwork }) {
  return (
    <div className="flex items-center gap-1.5">
      {!row.isActive && (
        <span
          title="Marked as not in active use — the entry stays documented but is treated as a stale item"
          className="inline-flex items-center gap-1 rounded bg-warning px-1.5 py-0.5 text-xs font-medium text-warning-fg"
        >
          <Archive className="h-3 w-3" /> Stale
        </span>
      )}
      {row.discovered ? (
        <span className="inline-flex items-center gap-1 rounded bg-success px-1.5 py-0.5 text-xs font-medium text-success-fg">
          <CircleCheck className="h-3 w-3" /> Discovered
        </span>
      ) : (
        <span className="inline-flex items-center gap-1 rounded bg-muted px-1.5 py-0.5 text-xs font-medium text-secondary">
          <CircleX className="h-3 w-3" /> Not seen
        </span>
      )}
    </div>
  );
}

/** One subnet chip — mono, IPv6 purple-tinted (same convention as the live pages). */
function SubnetChip({ cidr }: { cidr: string }) {
  return (
    <span className={`font-mono text-xs ${cidr.includes(':') ? 'text-accent-purple-fg' : ''}`}>{cidr}</span>
  );
}

/** One IP list cell (gateways / DNS servers) — mono, IPv6 purple-tinted. */
function IpListCell({ ips }: { ips: string[] }) {
  if (ips.length === 0) return <span className="text-faint">—</span>;
  return (
    <div className="flex flex-col gap-0.5 leading-tight">
      {ips.map((ip) => (
        <span key={ip} className={`font-mono text-xs ${ip.includes(':') ? 'text-accent-purple-fg' : ''}`}>{ip}</span>
      ))}
    </div>
  );
}

/** Observed subnets of the matching live group(s) — dimmed when not discovered. */
function ObservedCell({ row }: { row: DocumentedNetwork }) {
  if (!row.discovered || row.observedSubnets.length === 0) return <span className="text-faint">—</span>;
  const missing = row.subnets.filter((s) => !row.observedSubnets.includes(s));
  return (
    <div className="flex flex-col gap-0.5 leading-tight" title={missing.length > 0 ? `Documented but not currently observed: ${missing.join(', ')}` : undefined}>
      {row.observedSubnets.map((s) => (
        <span key={s} className={`font-mono text-xs ${s.includes(':') ? 'text-accent-purple-fg' : ''}`}>{s}</span>
      ))}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Inline create / edit form — with live-inventory auto-fill
// ---------------------------------------------------------------------------

interface NetworkFormCardProps {
  /** The network being edited; null = create. */
  initial: DocumentedNetwork | null;
  sites: Site[];
  layers: NetworkLayer[];
  /** All known network names + subnet CIDRs (merged logical networks) — datalist for the name field. */
  liveNameOptions: string[];
  onClose: () => void;
  onSaved: () => void;
}

function NetworkFormCard({ initial, sites, layers, liveNameOptions, onClose, onSaved }: NetworkFormCardProps) {
  const [form, setForm] = useState<NetworkFormState>(() => (initial ? formFromNetwork(initial) : EMPTY_FORM));
  const [error, setError] = useState<string | null>(null);
  // Live logical networks — power the name datalist + subnet auto-fill below.
  const liveQuery = useQuery({ queryKey: ['networks'], queryFn: () => api.networks(), refetchInterval: 30_000 });

  function patch(p: Partial<NetworkFormState>) {
    setForm((f) => ({ ...f, ...p }));
  }

  /** Auto-fill from the live inventory when a subnet row matches a known logical network. */
  function applyLiveMatch(cidr: string) {
    if (!isCidrLiteral(cidr)) return;
    // Find the live group whose subnets contain (or are contained in) this CIDR.
    const match = (liveQuery.data ?? []).find((n) =>
      (n.subnets ?? []).some((s) => cidrsOverlap(s, cidr.trim()))
    );
    if (!match) return;
    setForm((f) => ({
      ...f,
      // Name suggestion — only when the user hasn't typed one yet.
      name: f.name.trim() ? f.name : match.name,
      // VLAN — fill gaps only, manual values always win.
      vlanId: f.vlanId.trim() !== '' || match.vlanId == null ? f.vlanId : String(match.vlanId),
    }));
  }

  function setSubnet(index: number, value: string) {
    const prev = form.subnets[index];
    setForm((f) => ({ ...f, subnets: f.subnets.map((s, i) => (i === index ? value : s)) }));
    if (value.trim() !== prev.trim()) applyLiveMatch(value);
  }

  function addSubnetRow() {
    setForm((f) => ({ ...f, subnets: [...f.subnets.filter((s) => s.trim() !== ''), ''] }));
  }
  function removeSubnetRow(index: number) {
    setForm((f) => {
      const next = f.subnets.filter((_, i) => i !== index);
      return { ...f, subnets: next.length > 0 ? next : [''] };
    });
  }

  function addIpRow(kind: 'gateways' | 'dnsServers' | 'ntpServers') {
    setForm((f) => ({ ...f, [kind]: [...f[kind], ''] }));
  }
  function setIpRow(kind: 'gateways' | 'dnsServers' | 'ntpServers', index: number, value: string) {
    setForm((f) => ({ ...f, [kind]: f[kind].map((v, i) => (i === index ? value : v)) }));
  }
  function removeIpRow(kind: 'gateways' | 'dnsServers' | 'ntpServers', index: number) {
    setForm((f) => ({ ...f, [kind]: f[kind].filter((_, i) => i !== index) }));
  }

  function submit() {
    const name = form.name.trim();
    if (!name) {
      setError('A name is required — the identity of the documented network.');
      return;
    }
    const subnets = form.subnets.map((s) => s.trim()).filter(Boolean);
    for (const s of subnets) {
      if (!isCidrLiteral(s)) {
        setError(`"${s}" is not a valid CIDR block — expected e.g. 192.168.1.0/24 or fd00::/64.`);
        return;
      }
    }
    const vlanNum = form.vlanId.trim() === '' ? null : Number(form.vlanId);
    if (vlanNum !== null && (!Number.isInteger(vlanNum) || vlanNum < 0 || vlanNum > 4095)) {
      setError(`VLAN id must be an integer between 0 and 4095.`);
      return;
    }
    const parseIps = (list: string[], label: string): string[] | null => {
      const out: string[] = [];
      for (const v of list) {
        const t = v.trim();
        if (!t) continue;
        if (!isIpLiteral(t)) {
          setError(`"${t}" is not a valid ${label} address.`);
          return null;
        }
        if (!out.includes(t)) out.push(t);
      }
      return out;
    };
    const gateways = parseIps(form.gateways, 'gateway');
    if (gateways === null) return;
    const dnsServers = parseIps(form.dnsServers, 'DNS server');
    if (dnsServers === null) return;
    const ntpServers = parseIps(form.ntpServers, 'NTP server');
    if (ntpServers === null) return;

    const body: DocumentedNetworkRequest = {
      name,
      subnets,
      vlanId: vlanNum,
      gateways,
      dnsServers,
      ntpServers,
      friendlyName: form.friendlyName.trim() || null,
      description: form.description.trim() || null,
      siteId: form.siteId || null,
      layerId: form.layerId || null,
      tags: form.tags,
      isActive: form.isActive,
    };
    if (initial) updateNetwork.mutate(body);
    else createNetwork.mutate(body);
  }

  const createNetwork = useMutation({
    mutationFn: (body: DocumentedNetworkRequest) => api.createDocumentedNetwork(body),
    onSuccess: onSaved,
    onError: (err: unknown) => setError((err as Error).message),
  });
  const updateNetwork = useMutation({
    mutationFn: (body: Partial<DocumentedNetworkRequest>) => api.updateDocumentedNetwork(initial!.id, body),
    onSuccess: onSaved,
    onError: (err: unknown) => setError((err as Error).message),
  });

  return (
    <div className="mb-4 rounded-md border border-border bg-card p-4">
      <div className="mb-3 flex items-center justify-between">
        <h2 className="text-sm font-semibold text-foreground">{initial ? `Edit documented network — ${initial.name}` : 'New documented network'}</h2>
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
        {/* Name + friendly name */}
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
          <label className="text-sm">
            <span className="mb-1 block text-secondary">Name (required)</span>
            <input
              list="documented-network-name-options"
              value={form.name}
              onChange={(e) => patch({ name: e.target.value })}
              placeholder={'VLAN 30, 10.40.0.0/16, Mgmt LAN…'}
              className="w-full rounded-md border border-border bg-background px-2 py-1.5 text-sm"
            />
            <datalist id="documented-network-name-options">
              {liveNameOptions.map((o) => (
                <option key={o} value={o} />
              ))}
            </datalist>
          </label>
          <label className="text-sm">
            <span className="mb-1 block text-secondary">Friendly name</span>
            <input
              value={form.friendlyName}
              onChange={(e) => patch({ friendlyName: e.target.value })}
              placeholder={'Optional human-friendly label'}
              className="w-full rounded-md border border-border bg-background px-2 py-1.5 text-sm"
            />
          </label>
        </div>

        {/* Subnets + VLAN */}
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
          <div className="sm:col-span-2">
            <span className="mb-1 block text-sm text-secondary">Subnets (CIDR blocks)</span>
            <div className="flex flex-col gap-1.5">
              {form.subnets.map((s, i) => (
                <Fragment key={i}>
                  <div className="flex items-center gap-2">
                    <input
                      value={s}
                      onChange={(e) => setSubnet(i, e.target.value)}
                      placeholder={'10.40.0.0/16 or fd00::/64'}
                      className="w-full rounded-md border border-border bg-background px-2 py-1.5 font-mono text-sm"
                    />
                    {form.subnets.length > 1 && (
                      <button type="button" aria-label={`Remove subnet ${s || i + 1}`} onClick={() => removeSubnetRow(i)} className="rounded p-1 text-faint hover:bg-muted">
                        <X className="h-4 w-4" />
                      </button>
                    )}
                  </div>
                </Fragment>
              ))}
              <button type="button" onClick={addSubnetRow} className="self-start rounded-md border border-border px-2 py-1 text-xs text-secondary hover:bg-muted">
                + Add subnet
              </button>
            </div>
          </div>
          <label className="text-sm">
            <span className="mb-1 block text-secondary">VLAN id</span>
            <input
              type="number"
              min={0}
              max={4095}
              value={form.vlanId}
              onChange={(e) => patch({ vlanId: e.target.value })}
              placeholder={'30'}
              className="w-full rounded-md border border-border bg-background px-2 py-1.5 font-mono text-sm"
            />
          </label>
        </div>

        {/* Gateways + DNS servers + NTP servers */}
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
          {(['gateways', 'dnsServers', 'ntpServers'] as const).map((kind) => (
            <div key={kind}>
              <span className="mb-1 block text-sm text-secondary">{kind === 'gateways' ? 'Gateways' : kind === 'dnsServers' ? 'DNS servers' : 'NTP servers'}</span>
              <div className="flex flex-col gap-1.5">
                {form[kind].map((v, i) => (
                  <Fragment key={i}>
                    <div className="flex items-center gap-2">
                      <input
                        value={v}
                        onChange={(e) => setIpRow(kind, i, e.target.value)}
                        placeholder={'10.40.0.1'}
                        className="w-full rounded-md border border-border bg-background px-2 py-1.5 font-mono text-sm"
                      />
                      <button type="button" aria-label={`Remove ${kind === 'gateways' ? 'gateway' : kind === 'dnsServers' ? 'DNS server' : 'NTP server'} ${v || i + 1}`} onClick={() => removeIpRow(kind, i)} className="rounded p-1 text-faint hover:bg-muted">
                        <X className="h-4 w-4" />
                      </button>
                    </div>
                  </Fragment>
                ))}
                {form[kind].length === 0 && (
                  <p className="text-xs text-faint">None documented.</p>
                )}
                <button type="button" onClick={() => addIpRow(kind)} className="self-start rounded-md border border-border px-2 py-1 text-xs text-secondary hover:bg-muted">
                  + Add {kind === 'gateways' ? 'gateway' : kind === 'dnsServers' ? 'DNS server' : 'NTP server'}
                </button>
              </div>
            </div>
          ))}
        </div>

        {/* Site / layer / tags */}
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
          <label className="text-sm">
            <span className="mb-1 block text-secondary">Site</span>
            <select value={form.siteId} onChange={(e) => patch({ siteId: e.target.value })} className="w-full rounded-md border border-border bg-background px-2 py-1.5 text-sm">
              <option value="">— unassigned —</option>
              {sites.map((s) => (
                <option key={s.id} value={s.id}>{s.name}</option>
              ))}
            </select>
          </label>
          <label className="text-sm">
            <span className="mb-1 block text-secondary">Layer</span>
            <select value={form.layerId} onChange={(e) => patch({ layerId: e.target.value })} className="w-full rounded-md border border-border bg-background px-2 py-1.5 text-sm">
              <option value="">— unassigned —</option>
              {layers.map((l) => (
                <option key={l.id} value={l.id}>{l.name}</option>
              ))}
            </select>
          </label>
        </div>

        {/* Tags + description */}
        <ChipInput values={form.tags} onChange={(tags) => patch({ tags })} ariaLabel="Tags" />
        <label className="text-sm">
          <span className="mb-1 block text-secondary">Description</span>
          <textarea
            value={form.description}
            onChange={(e) => patch({ description: e.target.value })}
            rows={2}
            placeholder={'Optional documentation text'}
            className="w-full rounded-md border border-border bg-background px-2 py-1.5 text-sm"
          />
        </label>

        {/* Lifecycle */}
        <label className="flex items-center gap-2 text-sm">
          <input type="checkbox" checked={form.isActive} onChange={(e) => patch({ isActive: e.target.checked })} />
          In active use (uncheck to mark as a stale item — the row stays documented but is dimmed)
        </label>

        {/* Actions */}
        <div className="flex justify-end gap-2 border-t border-border pt-3">
          <button type="button" onClick={onClose} className="rounded-md px-3 py-1.5 text-sm text-secondary hover:bg-muted">
            Cancel
          </button>
          <button
            type="submit"
            disabled={createNetwork.isPending || updateNetwork.isPending}
            className="inline-flex items-center gap-2 rounded-md bg-primary px-4 py-1.5 text-sm font-medium text-white hover:bg-primary-hover disabled:opacity-50"
          >
            {initial ? 'Save changes' : 'Create network'}
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
  const [mapping, setMapping] = useState<Partial<Record<NetworkCsvImportField, number>>>({});
  const [matchBy, setMatchBy] = useState<'name' | 'subnet'>('name');
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
      setMapping(suggestNetworkHeaderMapping(head));
      setFileName(file.name);
      setResult(null);
    });
  }

  /** Builds the structured import rows from the current mapping. */
  function buildPayload(): { networks: DocumentedNetworkRequest[]; localErrors: { index: number; error: string }[] } {
    const siteByName = new Map(sites.map((s) => [s.name.toLowerCase(), s.id] as const));
    const layerByName = new Map(layers.map((l) => [l.name.toLowerCase(), l.id] as const));
    const networks: DocumentedNetworkRequest[] = [];
    const localErrors: { index: number; error: string }[] = [];

    rows.forEach((r, i) => {
      // Line number in the file (header is line 1).
      const line = i + 2;
      const get = (f: NetworkCsvImportField): string => {
        const col = mapping[f];
        return col !== undefined && col >= 0 ? (r[col] ?? '').trim() : '';
      };

      const name = get('name');
      if (!name) {
        localErrors.push({ index: line, error: 'no name mapped/found' });
        return;
      }

      // Subnets — every cell value must be a valid CIDR.
      const subnets = splitCellValues(get('subnets'));
      for (const s of subnets) {
        if (!isCidrLiteral(s)) {
          localErrors.push({ index: line, error: `invalid subnet "${s}" — expected a CIDR block like 192.168.1.0/24` });
          return;
        }
      }

      // VLAN id.
      let vlanId: number | null = null;
      const vlanText = get('vlanId');
      if (vlanText) {
        const n = Number(vlanText);
        if (!Number.isInteger(n) || n < 0 || n > 4095) {
          localErrors.push({ index: line, error: `invalid VLAN id "${vlanText}"` });
          return;
        }
        vlanId = n;
      }

      // Gateways + DNS servers + NTP servers — every cell value must be a bare IP literal.
      const parseIps = (text: string, label: string): string[] | null => {
        const out: string[] = [];
        for (const v of splitCellValues(text)) {
          if (!isIpLiteral(v)) return null;
          if (!out.includes(v)) out.push(v);
        }
        return out;
      };
      const gwText = get('gateways');
      if (gwText) {
        const gws = parseIps(gwText, 'gateway');
        if (gws === null) {
          localErrors.push({ index: line, error: `invalid gateway address in "${gwText}"` });
          return;
        }
      }
      const dnsText = get('dnsServers');
      let dnsIps: string[] | null = [];
      if (dnsText) {
        dnsIps = parseIps(dnsText, 'DNS server');
        if (dnsIps === null) {
          localErrors.push({ index: line, error: `invalid DNS server address in "${dnsText}"` });
          return;
        }
      }
      const ntpText = get('ntpServers');
      let ntpIps: string[] | null = [];
      if (ntpText) {
        ntpIps = parseIps(ntpText, 'NTP server');
        if (ntpIps === null) {
          localErrors.push({ index: line, error: `invalid NTP server address in "${ntpText}"` });
          return;
        }
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

      networks.push({
        name,
        subnets,
        vlanId,
        gateways: gwText ? parseIps(gwText, 'gateway')! : [],
        dnsServers: dnsIps ?? [],
        ntpServers: ntpIps ?? [],
        friendlyName: get('friendlyName') || null,
        description: get('description') || null,
        siteId,
        layerId,
        tags: splitCellValues(get('tags')),
      });
    });

    return { networks, localErrors };
  }

  const importMutation = useMutation({
    mutationFn: (body: { networks: DocumentedNetworkRequest[]; matchBy: 'name' | 'subnet'; updateExisting: boolean }) =>
      api.importDocumentedNetworks(body),
    onSuccess: (res) => {
      setResult(res);
      onDone();
    },
  });

  function runImport() {
    const { networks, localErrors } = buildPayload();
    setLocalErrors(localErrors);
    if (networks.length === 0) return;
    importMutation.mutate({ networks, matchBy, updateExisting });
  }

  /** True when a column index is claimed by any mapped field. */
  const usedColumns = useMemo(() => new Set(Object.values(mapping).filter((c): c is number => typeof c === 'number' && c >= 0)), [mapping]);

  const previewRows = rows.slice(0, 5);

  return (
    <div className="fixed inset-0 z-40 flex items-start justify-center overflow-y-auto bg-primary/40 p-4 sm:items-center" onClick={onClose}>
      <div className="w-full max-w-3xl rounded-md border border-border bg-card p-5 shadow-lg" onClick={(e) => e.stopPropagation()}>
        <div className="mb-4 flex items-center justify-between">
          <h2 className="text-base font-semibold text-foreground">Import documented networks from CSV</h2>
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
              {NETWORK_CSV_IMPORT_FIELDS.map(({ field, label, hint }) => (
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
                Match existing networks by
                <select className="rounded-md border border-border bg-background px-2 py-1 text-xs" value={matchBy} onChange={(e) => setMatchBy(e.target.value as 'name' | 'subnet')}>
                  <option value="name">name (then subnet overlap)</option>
                  <option value="subnet">subnet overlap</option>
                </select>
              </label>
              <label className="flex items-center gap-2">
                <input type="checkbox" checked={updateExisting} onChange={(e) => setUpdateExisting(e.target.checked)} />
                Update matched networks (otherwise skip them)
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
// Import-from-inventory modal — copies the LIVE network inventory into the
// documented networks (additive merge, dry-run preview first)
// ---------------------------------------------------------------------------

/** Splits the ranges textarea into entries (one per line or comma). */
function parseRangesText(text: string): string[] {
  return text
    .split(/[\n,]+/)
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
}

interface InventoryImportModalProps {
  onClose: () => void;
  onDone: () => void;
}

function InventoryImportModal({ onClose, onDone }: InventoryImportModalProps) {
  type RangeMode = 'keep-all' | 'include-only' | 'exclude';
  type PublicIpPolicy = 'keep' | 'strip' | 'skip-network';
  const [skipWithoutSubnet, setSkipWithoutSubnet] = useState(true);
  const [skipWithoutVlan, setSkipWithoutVlan] = useState(false);
  const [version, setVersion] = useState<'all' | 'v4' | 'v6'>('all');
  const [publicIpv4Policy, setPublicIpv4Policy] = useState<PublicIpPolicy>('keep');
  const [publicIpv6Policy, setPublicIpv6Policy] = useState<PublicIpPolicy>('keep');
  const [rangeMode, setRangeMode] = useState<RangeMode>('keep-all');
  const [rangesText, setRangesText] = useState('');
  const [maxAgeHours, setMaxAgeHours] = useState(24);
  // Phase: 'options' → pick filters; 'plan' → dry-run preview; 'done' → applied.
  const [phase, setPhase] = useState<'options' | 'plan' | 'done'>('options');
  const [plan, setPlan] = useState<import('../api/client').DocumentedNetworkInventoryImportResult | null>(null);
  const [applied, setApplied] = useState<import('../api/client').DocumentedNetworkInventoryImportResult | null>(null);

  const previewMutation = useMutation({
    mutationFn: () => api.importDocumentedNetworksFromInventory({ skipWithoutSubnet, skipWithoutVlan, version, publicIpv4Policy, publicIpv6Policy, rangeMode, ranges: parseRangesText(rangesText), maxAgeHours, dryRun: true }),
    onSuccess: (res) => {
      setPlan(res);
      setPhase('plan');
    },
  });
  const applyMutation = useMutation({
    mutationFn: () => api.importDocumentedNetworksFromInventory({ skipWithoutSubnet, skipWithoutVlan, version, publicIpv4Policy, publicIpv6Policy, rangeMode, ranges: parseRangesText(rangesText), maxAgeHours, dryRun: false }),
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
  }, [skipWithoutSubnet, skipWithoutVlan, version, publicIpv4Policy, publicIpv6Policy, rangeMode, rangesText, maxAgeHours]);

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
              Copies every logical network currently observed in the inventory into the documented networks. Existing entries are
              MERGED, never overwritten: their name, subnets, gateways, DNS/NTP servers, description and placement stay untouched — only new
              subnets and VLAN ids from the observation are added. Nothing is deleted.
            </p>

            <div className="mb-4 flex flex-col gap-2 text-sm">
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
                <select className="rounded-md border border-border bg-background px-2 py-1 text-xs" value={version} onChange={(e) => setVersion(e.target.value as 'all' | 'v4' | 'v6')}>
                  <option value="all">All (v4 + v6)</option>
                  <option value="v4">IPv4 only</option>
                  <option value="v6">IPv6 only</option>
                </select>
              </label>
              <label className="flex items-center justify-between gap-3 rounded-md border border-border px-3 py-2" title="How to treat publicly routable IPv4 subnets (RFC 1918 private ranges count as internal). Strip removes only the public v4 subnets — the network is still documented with its internal ones. Skip-network drops the whole network when it has any public v4 subnet.">
                <span className="text-secondary">Public IPv4 subnets</span>
                <select className="rounded-md border border-border bg-background px-2 py-1 text-xs" value={publicIpv4Policy} onChange={(e) => setPublicIpv4Policy(e.target.value as PublicIpPolicy)}>
                  <option value="keep">Keep (import all)</option>
                  <option value="strip">Strip public, keep internal</option>
                  <option value="skip-network">Skip whole network</option>
                </select>
              </label>
              <label className="flex items-center justify-between gap-3 rounded-md border border-border px-3 py-2" title="How to treat publicly routable IPv6 subnets (GUA 2000::/3; ULA fc00::/7 counts as internal). Strip removes only the public v6 subnets — the network is still documented with its internal ones. Skip-network drops the whole network when it has any public v6 subnet.">
                <span className="text-secondary">Public IPv6 subnets</span>
                <select className="rounded-md border border-border bg-background px-2 py-1 text-xs" value={publicIpv6Policy} onChange={(e) => setPublicIpv6Policy(e.target.value as PublicIpPolicy)}>
                  <option value="keep">Keep (import all)</option>
                  <option value="strip">Strip public, keep internal</option>
                  <option value="skip-network">Skip whole network</option>
                </select>
              </label>
              <div className="rounded-md border border-border px-3 py-2" title="Restrict the import to specific networks or IP ranges — applied BEFORE all other options. A network matches when ANY of its subnets falls into ANY entry.">
                <div className="flex items-center justify-between gap-3">
                  <span className="text-secondary">Network / IP range filter</span>
                  <select className="rounded-md border border-border bg-background px-2 py-1 text-xs" value={rangeMode} onChange={(e) => setRangeMode(e.target.value as RangeMode)}>
                    <option value="keep-all">All networks (no filter)</option>
                    <option value="include-only">Only selected ranges</option>
                    <option value="exclude">Exclude selected ranges</option>
                  </select>
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
              {plan.totalLiveNetworks} live network(s) considered. The merge is additive — existing documented data is preserved, only missing information is added.
            </p>

            <div className="mb-4 flex flex-wrap gap-2 text-sm">
              <span className="rounded bg-success px-2 py-1 font-medium text-success-fg">{plannedCreates} to create</span>
              <span className="rounded bg-info px-2 py-1 font-medium text-info-fg">{plannedUpdates} to update (merge)</span>
              {plannedSkips > 0 && <span className="rounded bg-muted px-2 py-1 font-medium text-secondary">{plannedSkips} skipped</span>}
            </div>

            {/* Filters stay adjustable — the preview re-runs automatically */}
            <div className="mb-4 flex flex-wrap items-center gap-5 text-sm">
              <label className="flex items-center gap-2">
                <input type="checkbox" checked={skipWithoutSubnet} onChange={(e) => setSkipWithoutSubnet(e.target.checked)} />
                Skip without subnet
              </label>
              <label className="flex items-center gap-2">
                <input type="checkbox" checked={skipWithoutVlan} onChange={(e) => setSkipWithoutVlan(e.target.checked)} />
                Skip without VLAN
              </label>
              <label className="flex items-center gap-2">
                Family
                <select className="rounded-md border border-border bg-background px-2 py-1 text-xs" value={version} onChange={(e) => setVersion(e.target.value as 'all' | 'v4' | 'v6')}>
                  <option value="all">all</option>
                  <option value="v4">IPv4</option>
                  <option value="v6">IPv6</option>
                </select>
              </label>
              <label className="flex items-center gap-2">
                Public IPv4
                <select className="rounded-md border border-border bg-background px-2 py-1 text-xs" value={publicIpv4Policy} onChange={(e) => setPublicIpv4Policy(e.target.value as PublicIpPolicy)}>
                  <option value="keep">keep</option>
                  <option value="strip">strip public</option>
                  <option value="skip-network">skip network</option>
                </select>
              </label>
              <label className="flex items-center gap-2">
                Public IPv6
                <select className="rounded-md border border-border bg-background px-2 py-1 text-xs" value={publicIpv6Policy} onChange={(e) => setPublicIpv6Policy(e.target.value as PublicIpPolicy)}>
                  <option value="keep">keep</option>
                  <option value="strip">strip public</option>
                  <option value="skip-network">skip network</option>
                </select>
              </label>
              <label className="flex items-center gap-2">
                Ranges
                <select className="rounded-md border border-border bg-background px-2 py-1 text-xs" value={rangeMode} onChange={(e) => setRangeMode(e.target.value as RangeMode)}>
                  <option value="keep-all">all</option>
                  <option value="include-only">only selected</option>
                  <option value="exclude">exclude</option>
                </select>
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
                    <th className="px-2 py-1.5 font-medium">Name</th>
                    <th className="px-2 py-1.5 font-medium">Subnets</th>
                    <th className="px-2 py-1.5 font-medium">VLAN</th>
                    <th className="px-2 py-1.5 font-medium">Action</th>
                  </tr>
                </thead>
                <tbody>
                  {plan.planned.slice(0, 300).map((p, i) => (
                    <tr key={`${p.name}-${i}`} className="border-t border-border">
                      <td className="max-w-[220px] truncate px-2 py-1 font-medium" title={p.name}>
                        {p.name}
                      </td>
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
                <DatabaseZap className="h-4 w-4" /> Import {plannedCreates + plannedUpdates} network(s)
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
              Existing documented networks were merged additively — no user data was overwritten or deleted.
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
// Bulk placement picker — sets a site or layer on every selected row in one
// bulk call (the registries are the SAME ones devices use).
// ---------------------------------------------------------------------------

interface PlacementPickerProps {
  kind: 'site' | 'layer';
  /** Ids of the selected rows to update. */
  ids: string[];
  sites: Site[];
  layers: NetworkLayer[];
  onClose: () => void;
}

function PlacementPickerModal({ kind, ids, sites, layers, onClose }: PlacementPickerProps) {
  const queryClient = useQueryClient();
  const [value, setValue] = useState(''); // '' = not chosen yet; 'clear' = unassign
  const options = kind === 'site' ? sites : layers;
  const label = kind === 'site' ? 'Site' : 'Layer';

  function apply() {
    if (!value) return;
    const targetId = value === 'clear' ? null : value;
    api.bulkSetDocumentedNetworkPlacement(ids, kind === 'site' ? { siteId: targetId } : { layerId: targetId })
      .then((res) => {
        queryClient.invalidateQueries({ queryKey: ['documentedNetworks'] });
        if (res.missing.length > 0) alert(`${res.updated} updated, ${res.missing.length} id(s) no longer exist.`);
      })
      .catch((err) => alert(`Failed to set ${label.toLowerCase()}: ${(err as Error).message}`));
    onClose();
  }

  return (
    <div className="fixed inset-0 z-40 flex items-center justify-center bg-primary/40 p-4" onClick={onClose}>
      <div className="w-full max-w-sm rounded-md border border-border bg-card p-5 shadow-lg" onClick={(e) => e.stopPropagation()}>
        <h2 className="mb-3 text-base font-semibold text-foreground">Set {label.toLowerCase()} for {ids.length} selected network{ids.length === 1 ? '' : 's'}</h2>
        <p className="mb-3 text-sm text-secondary">
          Assigns the chosen {label.toLowerCase()} to every selected row in one call — no per-row editing needed.
        </p>
        <select className="w-full rounded-md border border-border px-2 py-1.5 text-sm" value={value} onChange={(e) => setValue(e.target.value)}>
          <option value="">— choose {label.toLowerCase()} —</option>
          {options.map((o) => (
            <option key={o.id} value={o.id}>{o.name}</option>
          ))}
          <option value="clear">— unassign (clear) —</option>
        </select>
        <div className="mt-4 flex justify-end gap-2 border-t border-border pt-3">
          <button type="button" onClick={onClose} className="rounded-md px-3 py-1.5 text-sm text-secondary hover:bg-muted">
            Cancel
          </button>
          <button
            type="button"
            disabled={!value}
            onClick={apply}
            className="inline-flex items-center gap-2 rounded-md bg-primary px-4 py-1.5 text-sm font-medium text-white hover:bg-primary-hover disabled:opacity-50"
          >
            Apply to {ids.length} network{ids.length === 1 ? '' : 's'}
          </button>
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

export default function DocumentedNetworks() {
  const queryClient = useQueryClient();
  const canWrite = can('documented-networks:write');
  const { formatDateTime } = useTimeFormat();

  const [formOpen, setFormOpen] = useState(false);
  const [editing, setEditing] = useState<DocumentedNetwork | null>(null);
  const [importOpen, setImportOpen] = useState(false);
  const [inventoryImportOpen, setInventoryImportOpen] = useState(false);
  // Imperative handle into the table's selection (one-click duplicate select).
  const tableSelection = useRef<((keys: string[]) => void) | null>(null);

  // Documented networks + the reference data the form needs. The live network
  // rows power name auto-fill in the form and keep "discovered" fresh (30 s cadence).
  const networksQuery = useQuery({ queryKey: ['documentedNetworks'], queryFn: () => api.documentedNetworks(), refetchInterval: 30_000 });
  const sitesQuery = useQuery({ queryKey: ['sites'], queryFn: api.sites });
  const layersQuery = useQuery({ queryKey: ['layers'], queryFn: api.layers });
  // Live logical networks — name datalist + subnet auto-fill in the form.
  const liveNetworksQuery = useQuery({ queryKey: ['networks'], queryFn: () => api.networks(), refetchInterval: 30_000 });

  // Known network names for the form's datalist — merged logical networks by
  // display name plus every real subnet CIDR they carry.
  const liveNameOptions = useMemo(() => {
    const set = new Set<string>();
    for (const n of liveNetworksQuery.data ?? []) {
      set.add(n.name);
      for (const s of n.subnets ?? []) set.add(s);
    }
    return Array.from(set).sort();
  }, [liveNetworksQuery.data]);

  // Duplicate detection: rows whose subnets OVERLAP belong to one group
  // (union-find over CIDR containment either direction). A network documented
  // twice under different names ends up as several overlapping rows — these
  // are merge candidates.
  const duplicateGroups = useMemo(() => {
    const nets = networksQuery.data ?? [];
    const parent = new Map<string, string>();
    const find = (x: string): string => {
      let r = x;
      while (parent.get(r) !== r) r = parent.get(r)!;
      return r;
    };
    for (const n of nets) parent.set(n.id, n.id);

    // Canonicalize every row's subnets once.
    const canonical: { id: string; cidrs: string[] }[] = nets.map((n) => ({
      id: n.id,
      cidrs: n.subnets.filter((s) => s.includes('/')),
    }));

    // Union rows that share ANY CIDR containment in either direction.
    for (let i = 0; i < canonical.length; i++) {
      for (let j = i + 1; j < canonical.length; j++) {
        let overlap = false;
        outer: for (const a of canonical[i].cidrs) {
          for (const b of canonical[j].cidrs) {
            if (cidrsOverlap(a, b)) { overlap = true; break outer; }
          }
        }
        if (overlap) parent.set(find(canonical[i].id), find(canonical[j].id));
      }
    }

    const byRoot = new Map<string, DocumentedNetwork[]>();
    for (const n of nets) {
      const root = find(n.id);
      const list = byRoot.get(root);
      if (list) list.push(n);
      else byRoot.set(root, [n]);
    }
    // row id -> its full duplicate group (only groups with 2+ members).
    const out = new Map<string, DocumentedNetwork[]>();
    for (const members of byRoot.values()) {
      if (members.length > 1) for (const m of members) out.set(m.id, members);
    }
    return out;
  }, [networksQuery.data]);

  function openCreate() {
    setEditing(null);
    setFormOpen(true);
    window.scrollTo({ top: 0 });
  }
  function openEdit(row: DocumentedNetwork) {
    setEditing(row);
    setFormOpen(true);
    window.scrollTo({ top: 0 });
  }
  function closeForm() {
    setFormOpen(false);
    setEditing(null);
  }
  function handleSaved() {
    queryClient.invalidateQueries({ queryKey: ['documentedNetworks'] });
    closeForm();
  }
  function handleDelete(row: DocumentedNetwork) {
    if (!window.confirm(`Delete documented network "${row.name}"?`)) return;
    deleteMutation.mutate(row.id);
  }
  const deleteMutation = useMutation({
    mutationFn: (id: string) => api.deleteDocumentedNetwork(id),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['documentedNetworks'] }),
  });

  // Active/stale lifecycle — optimistic flip, rolled back on failure.
  function handleToggleActive(row: DocumentedNetwork) {
    const next = !row.isActive;
    const prevData = networksQuery.data;
    queryClient.setQueryData<DocumentedNetwork[]>(['documentedNetworks'], (old) =>
      old?.map((n) => (n.id === row.id ? { ...n, isActive: next } : n)) ?? old
    );
    toggleActiveMutation.mutate({ id: row.id, isActive: next }, {
      onSettled: () => queryClient.invalidateQueries({ queryKey: ['documentedNetworks'] }),
      onError: () => {
        if (prevData) queryClient.setQueryData(['documentedNetworks'], prevData);
      },
    });
  }
  const toggleActiveMutation = useMutation({
    mutationFn: ({ id, isActive }: { id: string; isActive: boolean }) => api.bulkUpdateDocumentedNetworks([id], isActive),
  });

  // Merge duplicate rows into one — the oldest row survives (its id + createdAt
  // are kept); subnets/gateways/DNS servers are unioned.
  const mergeMutation = useMutation({
    mutationFn: (ids: string[]) => api.mergeDocumentedNetworks(ids),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['documentedNetworks'] }),
  });

  // Bulk site/layer placement — a picker modal collects the target value, then
  // one bulk call sets it on every selected row (null = clear).
  const [placementPicker, setPlacementPicker] = useState<{ kind: 'site' | 'layer'; ids: string[] } | null>(null);

  const columns: DataTableColumn<DocumentedNetwork>[] = [
    {
      header: 'Name',
      key: 'name',
      width: 240,
      exportValue: (row) => row.name,
      searchText: (row) => [row.name, row.friendlyName ?? '', row.description ?? '', ...row.subnets].join(' '),
      render: (row) => {
        const dups = duplicateGroups.get(row.id);
        return (
          <div className="leading-tight">
            <span className="font-medium text-foreground">{row.name}</span>
            {dups && (
              <button
                type="button"
                title={`${dups.length} documented networks share overlapping subnets — click to select them all, then use “Merge selected”`}
                onClick={() => tableSelection.current?.(dups.map((n) => n.id))}
                className="ml-1 inline-flex items-center gap-0.5 rounded bg-warning px-1 py-0.5 text-[10px] font-semibold text-warning-fg hover:opacity-80"
              >
                <GitMerge className="h-3 w-3" /> {dups.length}
              </button>
            )}
            {row.friendlyName && <p className="text-xs text-faint">{row.friendlyName}</p>}
          </div>
        );
      },
    },
    {
      header: 'Subnets',
      key: 'subnets',
      width: 230,
      exportValue: (row) => row.subnets.join(', '),
      render: (row) =>
        row.subnets.length > 0 ? (
          <div className="flex flex-wrap gap-x-2 gap-y-0.5">
            {row.subnets.map((s) => (
              <SubnetChip key={s} cidr={s} />
            ))}
          </div>
        ) : (
          <span className="text-faint">—</span>
        ),
    },
    {
      header: 'VLAN',
      key: 'vlanId',
      width: 90,
      exportValue: (row) => String(row.vlanId ?? ''),
      render: (row) =>
        row.vlanId != null ? (
          <span className="inline-flex rounded bg-muted px-1.5 py-0.5 text-xs font-medium text-secondary">V{row.vlanId}</span>
        ) : (
          <span className="text-faint">—</span>
        ),
    },
    {
      header: 'Gateways',
      key: 'gateways',
      width: 150,
      exportValue: (row) => row.gateways.join(', '),
      render: (row) => <IpListCell ips={row.gateways} />,
    },
    {
      header: 'DNS servers',
      key: 'dnsServers',
      width: 150,
      hiddenByDefault: true,
      exportValue: (row) => row.dnsServers.join(', '),
      render: (row) => <IpListCell ips={row.dnsServers} />,
    },
    {
      header: 'NTP servers',
      key: 'ntpServers',
      width: 150,
      hiddenByDefault: true,
      exportValue: (row) => row.ntpServers.join(', '),
      render: (row) => <IpListCell ips={row.ntpServers} />,
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
      // Free-form user tags — same data basis as devices.
      header: 'Tags',
      key: 'tags',
      width: 160,
      exportValue: (row) => (row.tags ?? []).join(', '),
      render: (row) => {
        const tags = row.tags ?? [];
        if (tags.length === 0) return <span className="text-faint">—</span>;
        return (
          <div className="flex flex-wrap gap-1">
            {tags.map((t) => (
              <span key={t} className="inline-flex items-center gap-1 rounded-full bg-accent-indigo/60 px-2 py-0.5 text-xs font-medium text-accent-indigo-fg">
                <Tag className="h-3 w-3" />
                {t}
              </span>
            ))}
          </div>
        );
      },
    },
    {
      header: 'Status',
      key: 'discovered',
      width: 150,
      exportValue: (row) => (row.discovered ? 'discovered' : 'not seen'),
      render: (row) => <StatusCell row={row} />,
    },
    {
      header: 'Observed subnets',
      key: 'observedSubnets',
      width: 180,
      hiddenByDefault: true,
      exportValue: (row) => row.observedSubnets.join(', '),
      render: (row) => <ObservedCell row={row} />,
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
            width: 130,
            sortable: false as const,
            excludeFromExport: true,
            render: (row: DocumentedNetwork) => (
              <div className="flex gap-1">
                <button
                  type="button"
                  aria-label={row.isActive ? `Mark ${row.name} stale` : `Mark ${row.name} active`}
                  title={row.isActive ? 'Mark as a stale item (not in active use)' : 'Mark as active again'}
                  className={`rounded-md p-1.5 hover:bg-muted ${row.isActive ? 'text-secondary hover:text-warning-fg' : 'text-warning-fg hover:text-foreground'}`}
                  onClick={() => handleToggleActive(row)}
                >
                  <Archive className="h-4 w-4" />
                </button>
                <button type="button" aria-label={`Edit ${row.name}`} title="Edit network" className="rounded-md p-1.5 text-secondary hover:bg-muted hover:text-foreground" onClick={() => openEdit(row)}>
                  <Pencil className="h-4 w-4" />
                </button>
                <button type="button" aria-label={`Delete ${row.name}`} title="Delete network" className="rounded-md p-1.5 text-secondary hover:bg-danger hover:text-danger-fg" onClick={() => handleDelete(row)}>
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
          Documented Networks
          <Globe className="h-4 w-4 text-faint" />
        </span>
      }
      actions={
        canWrite && (
          <>
            <button type="button" onClick={() => setInventoryImportOpen(true)} title="Copy the live network inventory into the documented networks (additive merge)" className="inline-flex items-center gap-2 rounded-md border border-border px-3 py-1.5 text-sm font-medium hover:bg-muted">
              <DatabaseZap className="h-4 w-4" /> Import from Inventory
            </button>
            <button type="button" onClick={() => setImportOpen(true)} className="inline-flex items-center gap-2 rounded-md border border-border px-3 py-1.5 text-sm font-medium hover:bg-muted">
              <Upload className="h-4 w-4" /> Import CSV
            </button>
            <button type="button" onClick={openCreate} className="inline-flex items-center gap-2 rounded-md bg-primary px-3 py-1.5 text-sm font-medium text-white hover:bg-primary-hover">
              <Plus className="h-4 w-4" /> New network
            </button>
          </>
        )
      }
    >
      {formOpen && canWrite && (
        <NetworkFormCard
          initial={editing}
          sites={sitesQuery.data ?? []}
          layers={layersQuery.data ?? []}
          liveNameOptions={liveNameOptions}
          onClose={closeForm}
          onSaved={handleSaved}
        />
      )}
      {networksQuery.isLoading && <p className="text-sm text-muted-foreground">Loading documented networks…</p>}
      {networksQuery.isError && (
        <p className="text-sm text-danger-fg">Failed to load documented networks: {(networksQuery.error as Error).message}</p>
      )}
      {networksQuery.data && (
        <DataTable
          columns={columns}
          rows={networksQuery.data}
          rowKey={(row) => row.id}
          storageKey="documented-networks"
          autoRefresh={{ intervalMs: 30_000, queries: [networksQuery] }}
          searchPlaceholder="Search documented networks…"
          emptyMessage="No documented networks yet — create one with “New network” or import your spreadsheet as CSV."
          selectable={canWrite}
          rowClassName={(row) => (row.isActive ? undefined : 'opacity-50')}
          selectionRef={tableSelection}
          bulkActions={
            canWrite
              ? [
                  {
                    label: 'Merge selected',
                    enabled: (rows) => rows.length >= 2,
                    confirm: (count) => `Merge ${count} documented network${count === 1 ? '' : 's'} into ONE row?\nThe oldest row survives; subnets, gateways, DNS and NTP servers are combined and the other rows are deleted. This cannot be undone.`,
                    onClick: async (selected) => {
                      try {
                        const res = await mergeMutation.mutateAsync(selected.map((n) => n.id));
                        alert(`Merged ${res.count} row(s) into “${res.merged.name}”.`);
                      } catch (err) {
                        alert(`Merge failed: ${(err as Error).message}`);
                      }
                    },
                  },
                  {
                    label: 'Set site…',
                    onClick: async (selected: DocumentedNetwork[]) => setPlacementPicker({ kind: 'site', ids: selected.map((n) => n.id) }),
                  },
                  {
                    label: 'Set layer…',
                    onClick: async (selected: DocumentedNetwork[]) => setPlacementPicker({ kind: 'layer', ids: selected.map((n) => n.id) }),
                  },
                  {
                    label: 'Mark active',
                    onClick: async (selected: DocumentedNetwork[]) => {
                      const res = await api.bulkUpdateDocumentedNetworks(selected.map((n) => n.id), true);
                      queryClient.invalidateQueries({ queryKey: ['documentedNetworks'] });
                      if (res.missing.length > 0) alert(`${res.updated} marked active, ${res.missing.length} id(s) no longer exist.`);
                    },
                  },
                  {
                    label: 'Mark stale',
                    confirm: (count) => `Mark ${count} documented network${count === 1 ? '' : 's'} as a stale item? They stay documented but are dimmed in the list.`,
                    onClick: async (selected: DocumentedNetwork[]) => {
                      const res = await api.bulkUpdateDocumentedNetworks(selected.map((n) => n.id), false);
                      queryClient.invalidateQueries({ queryKey: ['documentedNetworks'] });
                      if (res.missing.length > 0) alert(`${res.updated} marked stale, ${res.missing.length} id(s) no longer exist.`);
                    },
                  },
                  {
                    label: 'Delete selected',
                    confirm: (count) => `Delete ${count} documented network${count === 1 ? '' : 's'}? This cannot be undone.`,
                    onClick: async (selected: DocumentedNetwork[]) => {
                      const errors: string[] = [];
                      for (const n of selected) {
                        try {
                          await api.deleteDocumentedNetwork(n.id);
                        } catch (err) {
                          errors.push(`${n.name}: ${(err as Error).message}`);
                        }
                      }
                      queryClient.invalidateQueries({ queryKey: ['documentedNetworks'] });
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
          onDone={() => queryClient.invalidateQueries({ queryKey: ['documentedNetworks'] })}
        />
      )}

      {inventoryImportOpen && (
        <InventoryImportModal
          onClose={() => setInventoryImportOpen(false)}
          onDone={() => queryClient.invalidateQueries({ queryKey: ['documentedNetworks'] })}
        />
      )}

      {placementPicker && canWrite && (
        <PlacementPickerModal
          kind={placementPicker.kind}
          ids={placementPicker.ids}
          sites={sitesQuery.data ?? []}
          layers={layersQuery.data ?? []}
          onClose={() => setPlacementPicker(null)}
        />
      )}
    </Layout>
  );
}
