import { useEffect, useMemo, useRef, useState } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import clsx from 'clsx';
import { Loader2, Network, Pencil, Plus, Trash2, Wifi } from 'lucide-react';
import { Layout } from '../components/Layout';
import { DataTable, DataTableColumn } from '../components/DataTable';
import { DeviceChip } from '../components/DeviceChip';
import { DialogShell } from '../components/DialogShell';
import { ReauthDialog } from '../components/ReauthDialog';
import { READONLY_MESSAGE, runAction, useExecutionMode, type ExecutionMode } from '../executionMode';
import { api, ApiError, CatalogEntry, DhcpNetworkRow, DhcpReservationRow, HostRow } from '../api/client';

// ---------------------------------------------------------------------------
// Validation patterns (mirror the plugins' action input schemas)
// ---------------------------------------------------------------------------

const MAC_PATTERN = /^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$/;
const IPV4_PATTERN = /^\d{1,3}(\.\d{1,3}){3}$/;
const CIDR_PATTERN = /^\d{1,3}(\.\d{1,3}){3}\/\d{1,2}$/;

/** Lease time in seconds → compact human form ("30m", "2h", "1d"). */
function formatLease(seconds: number | null | undefined): string {
  if (seconds == null || !Number.isFinite(seconds) || seconds <= 0) return '—';
  const m = Math.round(seconds / 60);
  if (m < 60) return `${m}m`;
  const h = m / 60;
  if (h < 48) return Number.isInteger(h) ? `${h}h` : `${Math.floor(h)}h ${Math.round(m % 60)}m`;
  const d = Math.round(seconds / 86_400);
  return `${d}d`;
}

// ---------------------------------------------------------------------------
// Catalog-driven action resolution.
//
// The DHCP page is vendor-agnostic: every dialog inspects the plugin's
// advertised input schemas and builds plan steps accordingly — no vendor
// sniffing. The three supported shapes today:
//   - RouterOS  dhcp.staticMapping.add {macAddress, address}        (immediate)
//   - OpenWrt   dhcp.staticMapping.add {mac, ip[, hostname]}        (self-applying)
//   - OPNsense  dhcp.staticMapping.add {interface, mac, ip}         (staged → reconfigure)
// A `required: interface` field on the add schema is what marks a staged vendor.
// ---------------------------------------------------------------------------

type PlanStep = { deviceId: string; actionId: string; input: Record<string, unknown> };

function schemaHas(schema: CatalogEntry['inputSchema'], field: string): boolean {
  return !!schema && typeof schema === 'object' && Object.prototype.hasOwnProperty.call(schema, field);
}

/** Staged vendors (OPNsense) key their delete handle on a uuid and need an
 * explicit reconfigure step to activate changes; immediate vendors (RouterOS,
 * OpenWrt) apply on add/delete. The uuid-keyed delete is the reliable marker —
 * RouterOS/OpenWrt also advertise dhcp.reconfigure but don't need it here. */
function isStagedDhcpVendor(actions: CatalogEntry[]): boolean {
  const del = actions.find((a) => a.id === 'dhcp.staticMapping.delete');
  return !!del && schemaHas(del.inputSchema, 'uuid') && actions.some((a) => a.id === 'dhcp.reconfigure');
}

/** How to add a reservation on this plugin (null = unsupported). */
export function resolveReservationAdd(actions: CatalogEntry[] | undefined): {
  actionId: string;
  /** Input fields the dialog must collect. */
  fields: Array<'mac' | 'ip' | 'hostname' | 'interface'>;
  /** True when a trailing dhcp.reconfigure step is required to activate (staged vendors). */
  needsReconfigure: boolean;
} | null {
  if (!actions) return null;
  const add = actions.find((a) => a.id === 'dhcp.staticMapping.add');
  if (!add) return null;
  const s = add.inputSchema ?? {};
  const fields: Array<'mac' | 'ip' | 'hostname' | 'interface'> = [];
  // RouterOS uses macAddress/address; OpenWrt + OPNsense use mac/ip.
  if (schemaHas(s, 'macAddress') || schemaHas(s, 'mac')) fields.push('mac');
  if (schemaHas(s, 'address') || schemaHas(s, 'ip')) fields.push('ip');
  if (schemaHas(s, 'hostname')) fields.push('hostname');
  // OPNsense declares an OPTIONAL interface field (required only for its dnsmasq
  // backend; Kea resolves the subnet from the IP) — offer it as a dropdown.
  const ifaceEntry = s['interface'] as { required?: boolean } | undefined;
  if (ifaceEntry?.required || !schemaHas(s, 'macAddress')) fields.push('interface');
  return { actionId: add.id, fields, needsReconfigure: isStagedDhcpVendor(actions) };
}

/** How to EDIT an existing reservation on this plugin (null = unsupported).
 * Prefers the vendor's in-place set action; otherwise falls back to a
 * delete-then-add two-step plan (OpenWrt has no update path — its add always
 * creates a new uci host section, so re-adding alone would duplicate). */
export function resolveReservationEdit(actions: CatalogEntry[] | undefined): {
  /** 'set' = single dhcp.staticMapping.set step; 'deleteAdd' = delete + add steps. */
  mode: 'set' | 'deleteAdd';
  actionId: string;
  needsReconfigure: boolean;
} | null {
  if (!actions) return null;
  const staged = isStagedDhcpVendor(actions);
  const set = actions.find((a) => a.id === 'dhcp.staticMapping.set');
  if (set && schemaHas(set.inputSchema, 'uuid')) {
    return { mode: 'set', actionId: set.id, needsReconfigure: staged };
  }
  const add = actions.find((a) => a.id === 'dhcp.staticMapping.add');
  const del = actions.find((a) => a.id === 'dhcp.staticMapping.delete');
  if (add && del) {
    return { mode: 'deleteAdd', actionId: add.id, needsReconfigure: staged };
  }
  return null;
}

/** How to delete a reservation on this plugin (null = unsupported). */
export function resolveReservationDelete(actions: CatalogEntry[] | undefined): {
  actionId: string;
  /** Which row field carries the delete handle ('mac' or 'refId'). */
  byField: 'mac' | 'refId';
  needsReconfigure: boolean;
} | null {
  if (!actions) return null;
  const del = actions.find((a) => a.id === 'dhcp.staticMapping.delete');
  if (!del) return null;
  const s = del.inputSchema ?? {};
  let byField: 'mac' | 'refId';
  if (schemaHas(s, 'uuid')) byField = 'refId'; // OPNsense — staged, needs reconfigure
  else if (schemaHas(s, 'macAddress') || schemaHas(s, 'mac')) byField = 'mac';
  else return null;
  const needsReconfigure = byField === 'refId' && actions.some((a) => a.id === 'dhcp.reconfigure');
  return { actionId: del.id, byField, needsReconfigure };
}

/** How to create a DHCP network on this plugin (null = unsupported). */
export function resolveNetworkCreate(actions: CatalogEntry[] | undefined): {
  /** First step's action id — 'dhcp.network.create' (OPNsense) or 'dhcp.reconfigure' (RouterOS full-stack provisioner). */
  actionId: string;
  fields: Array<'interface' | 'cidr' | 'rangeStart' | 'rangeEnd' | 'leaseTime' | 'dnsServers'>;
  needsReconfigure: boolean;
} | null {
  if (!actions) return null;
  const explicit = actions.find((a) => a.id === 'dhcp.network.create');
  if (explicit) {
    const s = explicit.inputSchema ?? {};
    const fields: Array<'interface' | 'cidr' | 'rangeStart' | 'rangeEnd'> = [];
    if (schemaHas(s, 'interface')) fields.push('interface');
    if (schemaHas(s, 'cidr')) fields.push('cidr');
    if (schemaHas(s, 'rangeStart')) fields.push('rangeStart');
    if (schemaHas(s, 'rangeEnd')) fields.push('rangeEnd');
    return { actionId: explicit.id, fields, needsReconfigure: actions.some((a) => a.id === 'dhcp.reconfigure') };
  }
  // RouterOS: dhcp.reconfigure IS the network provisioner (pool + range + server).
  const reconf = actions.find((a) => a.id === 'dhcp.reconfigure');
  if (reconf && schemaHas(reconf.inputSchema, 'interface')) {
    const s = reconf.inputSchema ?? {};
    const fields: Array<'interface' | 'cidr' | 'rangeStart' | 'rangeEnd' | 'leaseTime' | 'dnsServers'> = ['interface'];
    if (schemaHas(s, 'cidr')) fields.push('cidr');
    if (schemaHas(s, 'rangeStart') && schemaHas(s, 'rangeEnd')) { fields.push('rangeStart'); fields.push('rangeEnd'); }
    if (schemaHas(s, 'leaseTime')) fields.push('leaseTime');
    if (schemaHas(s, 'dnsServers')) fields.push('dnsServers');
    return { actionId: reconf.id, fields, needsReconfigure: false };
  }
  return null;
}

/** How to delete a DHCP network on this plugin (null = unsupported). */
export function resolveNetworkDelete(actions: CatalogEntry[] | undefined): {
  actionId: string;
  byField: 'refId';
  needsReconfigure: boolean;
} | null {
  if (!actions) return null;
  const del = actions.find((a) => a.id === 'dhcp.network.delete');
  if (!del || !schemaHas(del.inputSchema, 'refId')) return null;
  return { actionId: del.id, byField: 'refId', needsReconfigure: !!actions.some((a) => a.id === 'dhcp.reconfigure') };
}

// ---------------------------------------------------------------------------
// Plan helpers (same contract as the DNS / Services pages)
// ---------------------------------------------------------------------------

/** Creates a plan for ONE plugin from explicit steps. In Execute mode it is also
 * executed in the background; in Plan mode it is saved WITHOUT executing and only
 * its id is returned — callers surface a "saved" notice instead of tracking execution. */
async function createAndExecutePlan(
  pluginId: string,
  firstStep: PlanStep,
  extraSteps: PlanStep[],
  mode: ExecutionMode,
): Promise<string> {
  const create = async () => {
    const plan = await api.createPlan({
      pluginId,
      intentActionId: firstStep.actionId,
      inputs: firstStep.input,
      devices: [{ deviceId: firstStep.deviceId }],
    });
    if (extraSteps.length > 0) {
      await api.addPlanStepsBulk(plan.id, extraSteps.map((s) => ({ deviceId: s.deviceId, actionId: s.actionId, input: s.input })));
    }
    return plan;
  };
  return runAction(create, (id) => api.executePlan(id), mode);
}

// ---------------------------------------------------------------------------
// Dialogs
// ---------------------------------------------------------------------------

/** Add a static reservation on one device. The dialog collects exactly the
 * fields the selected plugin's add schema declares (see resolveReservationAdd).
 * When the vendor offers an interface field, it is rendered as a dropdown of
 * that device's collected DHCP networks (with a free-text fallback) instead of
 * a bare text input. */
function AddReservationDialog({
  devices,
  prefill,
  networksByDevice,
  busy,
  onClose,
  onSubmit,
}: {
  /** Candidate devices with their resolved add shape + a display label. */
  devices: Array<{ deviceId: string; pluginId: string; label: string; resolution: NonNullable<ReturnType<typeof resolveReservationAdd>> }>;
  prefill?: Partial<{ mac: string; ip: string; hostname: string; interface: string }>;
  /** Collected DHCP networks per device — powers the network dropdown. */
  networksByDevice?: Record<string, DhcpNetworkRow[]>;
  busy: boolean;
  onClose: () => void;
  onSubmit: (deviceId: string, pluginId: string, input: Record<string, unknown>) => void;
}) {
  const [deviceId, setDeviceId] = useState(devices[0]?.deviceId ?? '');
  const target = devices.find((d) => d.deviceId === deviceId);
  const [mac, setMac] = useState(prefill?.mac ?? '');
  const [ip, setIp] = useState(prefill?.ip ?? '');
  const [hostname, setHostname] = useState(prefill?.hostname ?? '');
  // Network selection: '' = no network row chosen (free-text fallback below).
  const [networkKey, setNetworkKey] = useState(() => {
    if (!prefill?.interface) return '';
    const nets = networksByDevice?.[devices[0]?.deviceId ?? ''] ?? [];
    const match = nets.find((n) => n.iface === prefill.interface);
    return match ? `${match.name}|${match.rangeStart}` : '';
  });
  // Free-text interface — used when no network rows are collected for the
  // device, or when the user picks "Other…" in the dropdown.
  const [freeIface, setFreeIface] = useState(() => {
    if (!prefill?.interface) return '';
    const nets = networksByDevice?.[devices[0]?.deviceId ?? ''] ?? [];
    return nets.some((n) => n.iface === prefill.interface) ? '' : prefill.interface;
  });

  const fields = target?.resolution.fields ?? [];
  const deviceNetworks = (target && networksByDevice ? networksByDevice[target.deviceId] : undefined) ?? [];
  const selectedNetwork = networkKey === '' ? null : deviceNetworks.find((n) => `${n.name}|${n.rangeStart}` === networkKey) ?? null;
  // The interface field is OPTIONAL for every current vendor (OPNsense's Kea
  // backend resolves the subnet from the IP; dnsmasq enforces it server-side).
  const ifaceValue = selectedNetwork?.iface ?? freeIface.trim();

  const macOk = MAC_PATTERN.test(mac.trim());
  const ipOk = IPV4_PATTERN.test(ip.trim());
  const valid = (fields.includes('mac') ? macOk : true) && (fields.includes('ip') ? ipOk : true);

  function submit() {
    if (!target || !valid) return;
    // Canonical field set — the page maps it onto the vendor's exact schema names.
    const input: Record<string, unknown> = {};
    for (const f of target.resolution.fields) {
      if (f === 'mac') input['mac'] = mac.trim().toLowerCase();
      else if (f === 'ip') input['ip'] = ip.trim();
      else if (f === 'hostname') input['hostname'] = hostname.trim() || undefined;
      else if (f === 'interface' && ifaceValue) input['interface'] = ifaceValue;
    }
    onSubmit(target.deviceId, target.pluginId, input);
  }

  return (
    <DialogShell
      title="Add DHCP reservation"
      subtitle="Binds a MAC address to a fixed IP on the selected device"
      icon={<Plus className="h-4 w-4 text-primary" />}
      onClose={onClose}
      maxWidth="max-w-md"
      footer={
        <div className="flex items-center justify-end gap-2">
          <button type="button" onClick={onClose} disabled={busy} className="rounded-md border border-border px-3 py-1.5 text-sm hover:bg-muted">Cancel</button>
          <button
            type="button"
            onClick={submit}
            disabled={!valid || busy}
            className={clsx('rounded-md bg-primary px-3 py-1.5 text-sm font-medium text-white hover:bg-primary-hover', (!valid || busy) && 'cursor-not-allowed opacity-40')}
          >
            {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : 'Add reservation'}
          </button>
        </div>
      }
    >
      <p className="mb-3 text-xs text-muted-foreground">
        The change is applied through the plan workflow — in Plan mode it is saved without executing.
      </p>
      {devices.length > 1 && (
        <>
          <label className="mb-1 block text-xs font-medium text-muted-foreground">Device</label>
          <select value={deviceId} onChange={(e) => setDeviceId(e.target.value)} disabled={busy} className="mb-3 w-full rounded-md border border-border bg-background px-2 py-1.5 text-sm">
            {devices.map((d) => (
              <option key={d.deviceId} value={d.deviceId}>{d.label}</option>
            ))}
          </select>
        </>
      )}
      {fields.includes('mac') && (
        <>
          <label className="mb-1 block text-xs font-medium text-muted-foreground">MAC address</label>
          <input value={mac} onChange={(e) => setMac(e.target.value)} autoFocus placeholder="aa:bb:cc:dd:ee:ff" disabled={busy}
            className={clsx('mb-3 w-full rounded-md border bg-background px-2 py-1.5 font-mono text-sm', mac !== '' && !macOk ? 'border-danger-border' : 'border-border')} />
          {mac !== '' && !macOk && <p className="-mt-2 mb-3 text-xs text-danger-fg">Not a valid MAC address</p>}
        </>
      )}
      {fields.includes('ip') && (
        <>
          <label className="mb-1 block text-xs font-medium text-muted-foreground">Fixed IP</label>
          <input value={ip} onChange={(e) => setIp(e.target.value)} placeholder="10.0.0.50" disabled={busy}
            className={clsx('mb-3 w-full rounded-md border bg-background px-2 py-1.5 font-mono text-sm', ip !== '' && !ipOk ? 'border-danger-border' : 'border-border')} />
          {ip !== '' && !ipOk && <p className="-mt-2 mb-3 text-xs text-danger-fg">Not a valid IPv4 address</p>}
        </>
      )}
      {fields.includes('interface') && (
        <>
          <label className="mb-1 block text-xs font-medium text-muted-foreground">Network{deviceNetworks.length === 0 ? ' / interface' : ''}</label>
          {deviceNetworks.length > 0 ? (
            <>
              <select value={networkKey} onChange={(e) => setNetworkKey(e.target.value)} disabled={busy} className="mb-2 w-full rounded-md border border-border bg-background px-2 py-1.5 text-sm">
                <option value="">Other… (type the interface)</option>
                {deviceNetworks.map((n) => (
                  <option key={`${n.name}|${n.rangeStart}`} value={`${n.name}|${n.rangeStart}`}>
                    {n.name} ({n.rangeStart}–{n.rangeEnd}){n.iface ? ` · ${n.iface}` : ''}
                  </option>
                ))}
              </select>
              {networkKey === '' && (
                <input value={freeIface} onChange={(e) => setFreeIface(e.target.value)} placeholder="lan" disabled={busy}
                  className="mb-3 w-full rounded-md border border-border bg-background px-2 py-1.5 font-mono text-sm" />
              )}
            </>
          ) : (
            <input value={freeIface} onChange={(e) => setFreeIface(e.target.value)} placeholder="lan" disabled={busy}
              className="mb-3 w-full rounded-md border border-border bg-background px-2 py-1.5 font-mono text-sm" />
          )}
        </>
      )}
      {fields.includes('hostname') && (
        <>
          <label className="mb-1 block text-xs font-medium text-muted-foreground">Hostname (optional)</label>
          <input value={hostname} onChange={(e) => setHostname(e.target.value)} placeholder="printer" disabled={busy}
            className="w-full rounded-md border border-border bg-background px-2 py-1.5 text-sm" />
        </>
      )}
    </DialogShell>
  );
}

/** Edit an existing static reservation in place. Uses the vendor's set action
 * when advertised; otherwise a delete-then-add two-step plan (see
 * resolveReservationEdit). The MAC is editable — changing it rebinds the fixed
 * IP to a different client. */
function EditReservationDialog({
  row,
  resolution,
  busy,
  onClose,
  onSubmit,
}: {
  row: DhcpReservationRow;
  resolution: NonNullable<ReturnType<typeof resolveReservationEdit>>;
  busy: boolean;
  onClose: () => void;
  /** Called with the canonical edit input (mac/ip/hostname). */
  onSubmit: (input: Record<string, unknown>) => void;
}) {
  const [mac, setMac] = useState(row.mac);
  const [ip, setIp] = useState(row.ip ?? '');
  const [hostname, setHostname] = useState(row.hostname ?? '');

  const macOk = MAC_PATTERN.test(mac.trim());
  const ipOk = IPV4_PATTERN.test(ip.trim());
  const valid = macOk && ipOk;

  function submit() {
    if (!valid) return;
    onSubmit({ mac: mac.trim().toLowerCase(), ip: ip.trim(), hostname: hostname.trim() || undefined });
  }

  return (
    <DialogShell
      title="Edit DHCP reservation"
      subtitle={`Static binding on ${row.deviceName ?? 'this device'}${resolution.mode === 'deleteAdd' ? ' — applied as delete + re-add (no in-place update on this vendor)' : ''}`}
      icon={<Pencil className="h-4 w-4 text-primary" />}
      onClose={onClose}
      maxWidth="max-w-md"
      footer={
        <div className="flex items-center justify-end gap-2">
          <button type="button" onClick={onClose} disabled={busy} className="rounded-md border border-border px-3 py-1.5 text-sm hover:bg-muted">Cancel</button>
          <button
            type="button"
            onClick={submit}
            disabled={!valid || busy}
            className={clsx('rounded-md bg-primary px-3 py-1.5 text-sm font-medium text-white hover:bg-primary-hover', (!valid || busy) && 'cursor-not-allowed opacity-40')}
          >
            {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : 'Save changes'}
          </button>
        </div>
      }
    >
      <p className="mb-3 text-xs text-muted-foreground">
        The change is applied through the plan workflow — in Plan mode it is saved without executing.
      </p>
      <label className="mb-1 block text-xs font-medium text-muted-foreground">MAC address</label>
      <input value={mac} onChange={(e) => setMac(e.target.value)} autoFocus placeholder="aa:bb:cc:dd:ee:ff" disabled={busy}
        className={clsx('mb-3 w-full rounded-md border bg-background px-2 py-1.5 font-mono text-sm', mac !== '' && !macOk ? 'border-danger-border' : 'border-border')} />
      {mac !== '' && !macOk && <p className="-mt-2 mb-3 text-xs text-danger-fg">Not a valid MAC address</p>}
      <label className="mb-1 block text-xs font-medium text-muted-foreground">Fixed IP</label>
      <input value={ip} onChange={(e) => setIp(e.target.value)} placeholder="10.0.0.50" disabled={busy}
        className={clsx('mb-3 w-full rounded-md border bg-background px-2 py-1.5 font-mono text-sm', ip !== '' && !ipOk ? 'border-danger-border' : 'border-border')} />
      {ip !== '' && !ipOk && <p className="-mt-2 mb-3 text-xs text-danger-fg">Not a valid IPv4 address</p>}
      <label className="mb-1 block text-xs font-medium text-muted-foreground">Hostname (optional)</label>
      <input value={hostname} onChange={(e) => setHostname(e.target.value)} placeholder="printer" disabled={busy}
        className="w-full rounded-md border border-border bg-background px-2 py-1.5 text-sm" />
    </DialogShell>
  );
}

/** Add a DHCP network/range on one device. Fields follow the plugin's create
 * schema (see resolveNetworkCreate) — RouterOS accepts cidr OR explicit range,
 * OPNsense requires an explicit range (+ optional cidr for Kea). */
function AddNetworkDialog({
  devices,
  prefillIface,
  busy,
  onClose,
  onSubmit,
}: {
  devices: Array<{ deviceId: string; pluginId: string; label: string; resolution: NonNullable<ReturnType<typeof resolveNetworkCreate>> }>;
  /** Serving interface to pre-fill (from the device's existing network rows). */
  prefillIface?: string | null;
  busy: boolean;
  onClose: () => void;
  onSubmit: (deviceId: string, pluginId: string, input: Record<string, unknown>) => void;
}) {
  const [deviceId, setDeviceId] = useState(devices[0]?.deviceId ?? '');
  const target = devices.find((d) => d.deviceId === deviceId);
  const fields = target?.resolution.fields ?? [];
  const [iface, setIface] = useState(prefillIface ?? '');
  const [cidr, setCidr] = useState('');
  const [rangeStart, setRangeStart] = useState('');
  const [rangeEnd, setRangeEnd] = useState('');
  const [leaseTime, setLeaseTime] = useState('30m');
  const [dnsServers, setDnsServers] = useState('');

  const cidrOk = cidr.trim() === '' || CIDR_PATTERN.test(cidr.trim());
  const startOk = rangeStart.trim() === '' || IPV4_PATTERN.test(rangeStart.trim());
  const endOk = rangeEnd.trim() === '' || IPV4_PATTERN.test(rangeEnd.trim());
  const hasCidr = fields.includes('cidr') && cidr.trim() !== '';
  const hasRange = fields.includes('rangeStart') && rangeStart.trim() !== '' && rangeEnd.trim() !== '';
  // OPNsense (explicit create) requires the range; RouterOS accepts either.
  const rangeRequired = target?.resolution.actionId === 'dhcp.network.create';
  const valid = cidrOk && startOk && endOk && (rangeRequired ? hasRange : hasCidr || hasRange);

  function submit() {
    if (!target || !valid) return;
    const input: Record<string, unknown> = {};
    for (const f of target.resolution.fields) {
      if (f === 'interface') input['interface'] = iface.trim();
      else if (f === 'cidr' && cidr.trim() !== '') input['cidr'] = cidr.trim();
      else if (f === 'rangeStart' && rangeStart.trim() !== '') input['rangeStart'] = rangeStart.trim();
      else if (f === 'rangeEnd' && rangeEnd.trim() !== '') input['rangeEnd'] = rangeEnd.trim();
      else if (f === 'leaseTime' && leaseTime.trim() !== '') input['leaseTime'] = leaseTime.trim();
      else if (f === 'dnsServers') {
        const list = dnsServers.split(',').map((s) => s.trim()).filter(Boolean);
        if (list.length > 0) input['dnsServers'] = list;
      }
    }
    onSubmit(target.deviceId, target.pluginId, input);
  }

  return (
    <DialogShell
      title="Add DHCP network"
      subtitle="Provisions a lease range on the selected device"
      icon={<Network className="h-4 w-4 text-primary" />}
      onClose={onClose}
      maxWidth="max-w-md"
      footer={
        <div className="flex items-center justify-end gap-2">
          <button type="button" onClick={onClose} disabled={busy} className="rounded-md border border-border px-3 py-1.5 text-sm hover:bg-muted">Cancel</button>
          <button
            type="button"
            onClick={submit}
            disabled={!valid || busy}
            className={clsx('rounded-md bg-primary px-3 py-1.5 text-sm font-medium text-white hover:bg-primary-hover', (!valid || busy) && 'cursor-not-allowed opacity-40')}
          >
            {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : 'Add network'}
          </button>
        </div>
      }
    >
      <p className="mb-3 text-xs text-muted-foreground">
        The change is applied through the plan workflow — in Plan mode it is saved without executing.
      </p>
      {devices.length > 1 && (
        <>
          <label className="mb-1 block text-xs font-medium text-muted-foreground">Device</label>
          <select value={deviceId} onChange={(e) => setDeviceId(e.target.value)} disabled={busy} className="mb-3 w-full rounded-md border border-border bg-background px-2 py-1.5 text-sm">
            {devices.map((d) => (
              <option key={d.deviceId} value={d.deviceId}>{d.label}</option>
            ))}
          </select>
        </>
      )}
      {fields.includes('interface') && (
        <>
          <label className="mb-1 block text-xs font-medium text-muted-foreground">Interface</label>
          <input value={iface} onChange={(e) => setIface(e.target.value)} placeholder="bridge1 / lan" disabled={busy}
            className="mb-3 w-full rounded-md border border-border bg-background px-2 py-1.5 font-mono text-sm" />
        </>
      )}
      {fields.includes('cidr') && (
        <>
          <label className="mb-1 block text-xs font-medium text-muted-foreground">Subnet CIDR (optional — the range is derived from it)</label>
          <input value={cidr} onChange={(e) => setCidr(e.target.value)} placeholder="10.0.0.0/24" disabled={busy}
            className={clsx('mb-3 w-full rounded-md border bg-background px-2 py-1.5 font-mono text-sm', !cidrOk ? 'border-danger-border' : 'border-border')} />
          {!cidrOk && <p className="-mt-2 mb-3 text-xs text-danger-fg">Not a valid CIDR</p>}
        </>
      )}
      {fields.includes('rangeStart') && (
        <>
          <label className="mb-1 block text-xs font-medium text-muted-foreground">Range start{rangeRequired ? '' : ' (optional when a CIDR is set)'}</label>
          <input value={rangeStart} onChange={(e) => setRangeStart(e.target.value)} placeholder="10.0.0.2" disabled={busy}
            className={clsx('mb-3 w-full rounded-md border bg-background px-2 py-1.5 font-mono text-sm', !startOk ? 'border-danger-border' : 'border-border')} />
          {!startOk && <p className="-mt-2 mb-3 text-xs text-danger-fg">Not a valid IPv4 address</p>}
        </>
      )}
      {fields.includes('rangeEnd') && (
        <>
          <label className="mb-1 block text-xs font-medium text-muted-foreground">Range end{rangeRequired ? '' : ' (optional when a CIDR is set)'}</label>
          <input value={rangeEnd} onChange={(e) => setRangeEnd(e.target.value)} placeholder="10.0.0.254" disabled={busy}
            className={clsx('mb-3 w-full rounded-md border bg-background px-2 py-1.5 font-mono text-sm', !endOk ? 'border-danger-border' : 'border-border')} />
          {!endOk && <p className="-mt-2 mb-3 text-xs text-danger-fg">Not a valid IPv4 address</p>}
        </>
      )}
      {fields.includes('leaseTime') && (
        <>
          <label className="mb-1 block text-xs font-medium text-muted-foreground">Lease time (optional)</label>
          <input value={leaseTime} onChange={(e) => setLeaseTime(e.target.value)} placeholder="30m / 2h" disabled={busy}
            className="mb-3 w-full rounded-md border border-border bg-background px-2 py-1.5 font-mono text-sm" />
        </>
      )}
      {fields.includes('dnsServers') && (
        <>
          <label className="mb-1 block text-xs font-medium text-muted-foreground">DNS servers (optional, comma-separated)</label>
          <input value={dnsServers} onChange={(e) => setDnsServers(e.target.value)} placeholder="1.1.1.1, 9.9.9.9" disabled={busy}
            className="w-full rounded-md border border-border bg-background px-2 py-1.5 font-mono text-sm" />
        </>
      )}
    </DialogShell>
  );
}

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

export default function Dhcp() {
  const queryClient = useQueryClient();
  const { mode } = useExecutionMode();
  const isPlanMode = mode === 'plan';
  const isReadOnly = mode === 'readonly';

  // Rows are upserted by the API's telemetry worker (30s poll) — refresh at the
  // same cadence so the view tracks live DHCP configuration.
  const dhcpQuery = useQuery({
    queryKey: ['dhcp'],
    queryFn: () => api.dhcp(),
    refetchInterval: 30_000,
  });

  // Live leases (hosts table, source 'dhcp') — joined by MAC to badge which
  // reservations are currently handed out and show lease expiry.
  const hostsQuery = useQuery({
    queryKey: ['hosts', 'dhcp-source'],
    queryFn: () => api.hosts({ source: 'dhcp' }),
    refetchInterval: 60_000,
  });
  const liveByMac = useMemo(() => {
    const m = new Map<string, HostRow>();
    for (const h of hostsQuery.data ?? []) m.set(h.mac.toLowerCase(), h);
    return m;
  }, [hostsQuery.data]);

  // --- Action catalogs ------------------------------------------------------
  // Drives dialog availability GENERICALLY: a button only renders when the
  // device's plugin advertises the matching action (see resolve* helpers).
  const devicesQuery = useQuery({ queryKey: ['dhcp', 'devices'], queryFn: () => api.devices() });
  const catalogPluginIds = useMemo(() => {
    const ids = new Set<string>();
    for (const r of dhcpQuery.data?.networks ?? []) ids.add(r.pluginId);
    for (const r of dhcpQuery.data?.reservations ?? []) ids.add(r.pluginId);
    for (const d of devicesQuery.data ?? []) for (const p of d.plugins ?? []) ids.add(p.pluginId);
    return [...ids];
  }, [dhcpQuery.data, devicesQuery.data]);
  const catalogsQuery = useQuery({
    queryKey: ['pluginActionCatalogs', 'dhcp', catalogPluginIds.join('|')],
    queryFn: async () => {
      const entries = await Promise.all(
        catalogPluginIds.map(async (pluginId) => [pluginId, (await api.pluginActions(pluginId)).actions] as const),
      );
      return Object.fromEntries(entries);
    },
    enabled: catalogPluginIds.length > 0,
  });

  function actionsOf(pluginId: string): CatalogEntry[] | undefined {
    return catalogsQuery.data?.[pluginId];
  }

  // --- Action feedback + plan tracking ---------------------------------------
  const [notice, setNotice] = useState<{ kind: 'ok' | 'info' | 'error'; text: string } | null>(null);
  const [reauth, setReauth] = useState<{ label: string; retry: () => void | Promise<void> } | null>(null);
  // Add-reservation dialog state — either the header button (all devices) or a
  // per-network-row button (device fixed + interface prefilled from that row).
  const [addingReservation, setAddingReservation] = useState<{ prefill?: Partial<{ mac: string; ip: string; hostname: string; interface: string }>; fixedDevice?: { deviceId: string; pluginId: string } } | null>(null);
  const [editingReservation, setEditingReservation] = useState<DhcpReservationRow | null>(null);
  const [addingNetwork, setAddingNetwork] = useState(false);

  /** Collected DHCP networks grouped by device — powers the network dropdown. */
  const networksByDevice = useMemo(() => {
    const m: Record<string, DhcpNetworkRow[]> = {};
    for (const n of dhcpQuery.data?.networks ?? []) (m[n.deviceId] ??= []).push(n);
    return m;
  }, [dhcpQuery.data]);

  /** MACs that already have a static reservation on ANY device. */
  const reservedMacs = useMemo(() => {
    const s = new Set<string>();
    for (const r of dhcpQuery.data?.reservations ?? []) s.add(r.mac.toLowerCase());
    return s;
  }, [dhcpQuery.data]);

  /** IPv4 dotted quad → uint32 (null when malformed). */
  function ipToUint32(ip: string): number | null {
    const parts = ip.split('.');
    if (parts.length !== 4) return null;
    let v = 0;
    for (const p of parts) {
      if (!/^\d{1,3}$/.test(p)) return null;
      const n = Number(p);
      if (n > 255) return null;
      v = v * 256 + n;
    }
    return v >>> 0;
  }

  /** True when `ip` falls inside a network row's range or CIDR. */
  function ipInNetwork(ip: string, net: DhcpNetworkRow): boolean {
    const addr = ipToUint32(ip);
    if (addr === null) return false;
    // Range containment (start–end inclusive).
    const start = ipToUint32(net.rangeStart);
    const end = ipToUint32(net.rangeEnd ?? net.rangeStart);
    if (start !== null && end !== null && addr >= start && addr <= end) return true;
    // CIDR containment.
    if (net.cidr) {
      const slash = net.cidr.lastIndexOf('/');
      const base = ipToUint32(net.cidr.slice(0, slash));
      const prefix = Number(net.cidr.slice(slash + 1));
      if (base !== null && Number.isInteger(prefix) && prefix >= 0 && prefix <= 32) {
        const mask = prefix === 0 ? 0 : (~0 << (32 - prefix)) >>> 0;
        if ((base & mask) === (addr & mask)) return true;
      }
    }
    return false;
  }

  /** Dynamic leases: hosts seen via DHCP that have NO static reservation on any
   * device, with the serving network/device attributed by IP containment. */
  const dynamicLeases = useMemo(() => {
    if (!hostsQuery.data) return [];
    const nets = dhcpQuery.data?.networks ?? [];
    const out: Array<{ host: HostRow; net?: DhcpNetworkRow }> = [];
    for (const h of hostsQuery.data) {
      if (!h.sources.includes('dhcp')) continue;
      if (reservedMacs.has(h.mac.toLowerCase())) continue;
      // Attribute the serving network by matching any known IP against ranges.
      let net: DhcpNetworkRow | undefined;
      for (const ip of h.ips) {
        const match = nets.find((n) => ipInNetwork(ip, n));
        if (match) { net = match; break; }
      }
      out.push({ host: h, net });
    }
    return out.sort((a, b) => (b.host.lastSeenAt ?? '').localeCompare(a.host.lastSeenAt ?? ''));
  }, [hostsQuery.data, dhcpQuery.data, reservedMacs]);
  // Plans kicked off in Execute mode — polled until they settle so the touched
  // devices force-refresh and the tables catch up.
  const [pendingPlans, setPendingPlans] = useState<Record<string, { deviceIds: string[]; names: string[] }>>({});
  const pendingRef = useRef(pendingPlans);
  useEffect(() => { pendingRef.current = pendingPlans; }, [pendingPlans]);

  function trackPlan(planId: string, deviceIds: string[], names: string[]) {
    setPendingPlans((prev) => ({ ...prev, [planId]: { deviceIds, names } }));
  }

  useEffect(() => {
    if (Object.keys(pendingPlans).length === 0) return;
    const timer = setInterval(async () => {
      for (const [planId, entry] of Object.entries(pendingRef.current)) {
        let p;
        try {
          p = await api.getPlan(planId);
        } catch { continue; } // transient API error — keep waiting
        if (!['succeeded', 'failed', 'cancelled'].includes(p.status)) continue;
        setPendingPlans((prev) => {
          const next = { ...prev };
          delete next[planId];
          return next;
        });
        try { await api.refreshDevices(entry.deviceIds); } catch { /* fall back to the 30s poll */ }
        void queryClient.invalidateQueries({ queryKey: ['dhcp'] });
        void queryClient.invalidateQueries({ queryKey: ['hosts', 'dhcp-source'] });
        if (p.status !== 'succeeded') {
          const what = entry.names[0] ?? entry.deviceIds.join(', ');
          setNotice({ kind: 'error', text: `A plan for ${what} finished with errors — check the Plans page.` });
        }
      }
    }, 3000);
    return () => clearInterval(timer);
  }, [pendingPlans, queryClient]);

  const busy = Object.keys(pendingPlans).length > 0;

  /** Builds + executes (or saves) a plan from explicit steps. */
  async function runSteps(pluginId: string, steps: PlanStep[], label: string): Promise<void> {
    if (steps.length === 0) return;
    const attempt = async () => {
      if (isReadOnly) { setNotice({ kind: 'info', text: READONLY_MESSAGE }); return; }
      const planId = await createAndExecutePlan(pluginId, steps[0], steps.slice(1), mode);
      if (isPlanMode) {
        setNotice({ kind: 'ok', text: `${label}: saved as a plan — not executed. Open the Plans center to run it later.` });
        return;
      }
      trackPlan(planId, [...new Set(steps.map((s) => s.deviceId))], [label]);
    };
    try {
      await attempt();
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) setReauth({ label, retry: attempt });
      else setNotice({ kind: 'error', text: `${label} failed: ${err instanceof Error ? err.message : String(err)}` });
    }
  }

  // --- Reservation actions ----------------------------------------------------

  /** Devices that can add a reservation (any assigned plugin advertises the action). */
  const reservationAddDevices = useMemo(() => {
    if (!devicesQuery.data || !catalogsQuery.data) return [];
    const out: Array<{ deviceId: string; pluginId: string; label: string; resolution: NonNullable<ReturnType<typeof resolveReservationAdd>> }> = [];
    for (const d of devicesQuery.data) {
      for (const p of d.plugins ?? []) {
        const res = resolveReservationAdd(catalogsQuery.data[p.pluginId]);
        if (!res) continue;
        out.push({ deviceId: d.id, pluginId: p.pluginId, label: `${d.name} (${p.pluginName ?? p.pluginId})`, resolution: res });
      }
    }
    return out;
  }, [devicesQuery.data, catalogsQuery.data]);

  /** Maps the dialogs' canonical {mac, ip, hostname[, interface]} onto the
   * plugin's exact add-schema field names (RouterOS uses macAddress/address). */
  function mapAddInput(pluginId: string, input: Record<string, unknown>): Record<string, unknown> {
    const s = actionsOf(pluginId)?.find((a) => a.id === 'dhcp.staticMapping.add')?.inputSchema ?? {};
    const mapped: Record<string, unknown> = { ...input };
    if (schemaHas(s, 'macAddress')) { mapped['macAddress'] = input['mac']; delete mapped['mac']; }
    if (schemaHas(s, 'address')) { mapped['address'] = input['ip']; delete mapped['ip']; }
    return mapped;
  }

  /** Builds the vendor-specific delete PlanStep for a reservation row. */
  function buildDeleteStep(row: DhcpReservationRow): PlanStep | null {
    const res = resolveReservationDelete(actionsOf(row.pluginId));
    if (!res) return null;
    let handle: string | null;
    if (res.byField === 'refId') {
      handle = row.refId ?? null;
      if (!handle) return null;
    } else {
      handle = row.mac;
    }
    const delSchema = actionsOf(row.pluginId)?.find((a) => a.id === 'dhcp.staticMapping.delete')?.inputSchema ?? {};
    const inputField = res.byField === 'refId' ? (schemaHas(delSchema, 'uuid') ? 'uuid' : 'refId') : schemaHas(delSchema, 'macAddress') ? 'macAddress' : 'mac';
    return { deviceId: row.deviceId, actionId: res.actionId, input: { [inputField]: handle } };
  }

  async function submitReservation(deviceId: string, pluginId: string, input: Record<string, unknown>) {
    const res = resolveReservationAdd(actionsOf(pluginId));
    if (!res) return;
    const steps: PlanStep[] = [{ deviceId, actionId: res.actionId, input: mapAddInput(pluginId, input) }];
    if (res.needsReconfigure) steps.push({ deviceId, actionId: 'dhcp.reconfigure', input: {} });
    setAddingReservation(null);
    await runSteps(pluginId, steps, `Add reservation ${String(input['mac'] ?? '')}`);
  }

  async function deleteReservation(row: DhcpReservationRow) {
    const step = buildDeleteStep(row);
    if (!step) { setNotice({ kind: 'info', text: `No stable delete handle for ${row.mac} on ${row.deviceName ?? 'this device'} — remove it in the appliance UI.` }); return; }
    const steps: PlanStep[] = [step];
    if (resolveReservationDelete(actionsOf(row.pluginId))?.needsReconfigure) steps.push({ deviceId: row.deviceId, actionId: 'dhcp.reconfigure', input: {} });
    await runSteps(row.pluginId, steps, `Delete reservation ${row.mac}`);
  }

  /** Edit a reservation in place (set action) or via delete + re-add. */
  async function submitEditReservation(row: DhcpReservationRow, input: Record<string, unknown>) {
    const res = resolveReservationEdit(actionsOf(row.pluginId));
    if (!res) return;
    setEditingReservation(null);
    const steps: PlanStep[] = [];
    if (res.mode === 'set') {
      const mapped = mapAddInput(row.pluginId, input);
      mapped['uuid'] = row.refId;
      steps.push({ deviceId: row.deviceId, actionId: res.actionId, input: mapped });
    } else {
      const delStep = buildDeleteStep(row);
      if (!delStep) { setNotice({ kind: 'info', text: `No stable delete handle for ${row.mac} — edit it in the appliance UI.` }); return; }
      steps.push(delStep, { deviceId: row.deviceId, actionId: res.actionId, input: mapAddInput(row.pluginId, input) });
    }
    if (res.needsReconfigure) steps.push({ deviceId: row.deviceId, actionId: 'dhcp.reconfigure', input: {} });
    await runSteps(row.pluginId, steps, `Edit reservation ${String(input['mac'] ?? '')}`);
  }

  /** Convert a dynamic lease into a static reservation — opens the add dialog
   * prefilled with the host's MAC/IP/hostname and (when attributable) pinned to
   * the device serving that network. */
  function convertLease(entry: { host: HostRow; net?: DhcpNetworkRow }) {
    const h = entry.host;
    let fixedDevice: { deviceId: string; pluginId: string } | undefined;
    if (entry.net) {
      const candidate = reservationAddDevices.find((d) => d.deviceId === entry.net!.deviceId && d.pluginId === entry.net!.pluginId);
      if (candidate) fixedDevice = { deviceId: candidate.deviceId, pluginId: candidate.pluginId };
    }
    setAddingReservation({
      prefill: { mac: h.mac.toLowerCase(), ip: h.ips.find((i) => IPV4_PATTERN.test(i)) ?? '', hostname: h.hostname ?? undefined },
      fixedDevice,
    });
  }

  // --- Network actions ----------------------------------------------------------

  /** Devices that can create a DHCP network. */
  const networkCreateDevices = useMemo(() => {
    if (!devicesQuery.data || !catalogsQuery.data) return [];
    const out: Array<{ deviceId: string; pluginId: string; label: string; resolution: NonNullable<ReturnType<typeof resolveNetworkCreate>> }> = [];
    for (const d of devicesQuery.data) {
      for (const p of d.plugins ?? []) {
        const res = resolveNetworkCreate(catalogsQuery.data[p.pluginId]);
        if (!res) continue;
        out.push({ deviceId: d.id, pluginId: p.pluginId, label: `${d.name} (${p.pluginName ?? p.pluginId})`, resolution: res });
      }
    }
    return out;
  }, [devicesQuery.data, catalogsQuery.data]);

  async function submitNetwork(deviceId: string, pluginId: string, input: Record<string, unknown>) {
    const res = resolveNetworkCreate(actionsOf(pluginId));
    if (!res) return;
    const steps: PlanStep[] = [{ deviceId, actionId: res.actionId, input }];
    if (res.needsReconfigure) steps.push({ deviceId, actionId: 'dhcp.reconfigure', input: {} });
    setAddingNetwork(false);
    await runSteps(pluginId, steps, `Add DHCP network ${String(input['interface'] ?? '')} on ${deviceId}`);
  }

  async function deleteNetwork(row: DhcpNetworkRow) {
    const res = resolveNetworkDelete(actionsOf(row.pluginId));
    if (!res || !row.refId) return;
    const steps: PlanStep[] = [{ deviceId: row.deviceId, actionId: res.actionId, input: { refId: row.refId } }];
    if (res.needsReconfigure) steps.push({ deviceId: row.deviceId, actionId: 'dhcp.reconfigure', input: {} });
    await runSteps(row.pluginId, steps, `Delete DHCP network ${row.name} (${row.rangeStart}–${row.rangeEnd})`);
  }

  // --- Tables -------------------------------------------------------------------

  const networkColumns: DataTableColumn<DhcpNetworkRow>[] = [
    {
      header: 'Device',
      key: 'device',
      width: 200,
      exportValue: (r) => r.deviceName ?? r.deviceId,
      render: (row) => (
        <DeviceChip
          deviceName={row.deviceName}
          managementAddress={row.managementAddress}
          pluginName={row.pluginName}
          siteName={row.siteName}
          interfaces={row.iface ? [row.iface] : []}
        />
      ),
    },
    { header: 'Name', key: 'name', width: 160, render: (r) => <span className="font-mono text-sm">{r.name}</span> },
    {
      header: 'Range',
      key: 'range',
      width: 200,
      exportValue: (r) => `${r.rangeStart}–${r.rangeEnd}`,
      render: (r) => <span className="font-mono text-sm">{r.rangeStart} – {r.rangeEnd}</span>,
    },
    { header: 'CIDR', key: 'cidr', width: 130, exportValue: (r) => r.cidr ?? '', render: (r) => (r.cidr ? <span className="font-mono text-sm">{r.cidr}</span> : <span className="text-faint">—</span>) },
    { header: 'Lease', key: 'leaseTimeSeconds', width: 80, exportValue: (r) => formatLease(r.leaseTimeSeconds), render: (r) => <span className="font-mono text-sm">{formatLease(r.leaseTimeSeconds)}</span> },
    { header: 'Gateway', key: 'gateway', width: 120, exportValue: (r) => r.gateway ?? '', render: (r) => (r.gateway ? <span className="font-mono text-sm">{r.gateway}</span> : <span className="text-faint">—</span>) },
    { header: 'DNS', key: 'dnsServers', width: 160, exportValue: (r) => r.dnsServers ?? '', render: (r) => (r.dnsServers ? <span className="font-mono text-xs">{r.dnsServers}</span> : <span className="text-faint">—</span>) },
    {
      header: 'Actions',
      key: 'actions',
      width: 90,
      render: (row) => {
        const canDelete = !!resolveNetworkDelete(actionsOf(row.pluginId)) && !!row.refId;
        const canAddResv = !!resolveReservationAdd(actionsOf(row.pluginId));
        if (!canDelete && !canAddResv) return <span className="text-faint">—</span>;
        return (
          <div className="flex items-center gap-1">
            {canAddResv && (
              <button
                type="button"
                aria-label={`Add reservation on ${row.name}`}
                title={isReadOnly ? READONLY_MESSAGE : `Add a static reservation in the ${row.rangeStart}–${row.rangeEnd} range`}
                disabled={isReadOnly || busy}
                onClick={() => setAddingReservation({ prefill: { interface: row.iface ?? undefined }, fixedDevice: { deviceId: row.deviceId, pluginId: row.pluginId } })}
                className={clsx('rounded-md p-1.5 text-primary hover:bg-muted', (isReadOnly || busy) && 'cursor-not-allowed opacity-30')}
              >
                <Plus size={14} />
              </button>
            )}
            {canDelete && (
              <button
                type="button"
                aria-label={`Delete DHCP network ${row.name}`}
                title={isReadOnly ? READONLY_MESSAGE : `Remove the ${row.rangeStart}–${row.rangeEnd} range from this device`}
                disabled={isReadOnly || busy}
                onClick={() => {
                  if (window.confirm(`Delete DHCP network "${row.name}" (${row.rangeStart}–${row.rangeEnd}) on ${row.deviceName ?? 'this device'}?\n\nClients in the range will stop receiving leases.`)) void deleteNetwork(row);
                }}
                className={clsx('rounded-md p-1.5 text-danger-fg hover:bg-muted', (isReadOnly || busy) && 'cursor-not-allowed opacity-30')}
              >
                <Trash2 size={14} />
              </button>
            )}
          </div>
        );
      },
    },
  ];

  const reservationColumns: DataTableColumn<DhcpReservationRow>[] = [
    {
      header: 'Device',
      key: 'device',
      width: 200,
      exportValue: (r) => r.deviceName ?? r.deviceId,
      render: (row) => (
        <DeviceChip
          deviceName={row.deviceName}
          managementAddress={row.managementAddress}
          pluginName={row.pluginName}
          siteName={row.siteName}
          interfaces={row.iface ? [row.iface] : []}
        />
      ),
    },
    { header: 'MAC', key: 'mac', width: 150, render: (r) => <span className="font-mono text-sm">{r.mac}</span> },
    { header: 'IP', key: 'ip', width: 130, exportValue: (r) => r.ip ?? '', render: (r) => (r.ip ? <span className="font-mono text-sm">{r.ip}</span> : <span className="text-faint">—</span>) },
    {
      header: 'Hostname',
      key: 'hostname',
      width: 160,
      exportValue: (r) => r.hostname ?? liveByMac.get(r.mac.toLowerCase())?.hostname ?? '',
      render: (row) => {
        const name = row.hostname ?? liveByMac.get(row.mac.toLowerCase())?.hostname;
        return name ? <span className="text-sm">{name}</span> : <span className="text-faint">—</span>;
      },
    },
    {
      // Live-lease join: a MAC present in the hosts table (source 'dhcp') is
      // currently holding a lease. RouterOS additionally exposes a per-row status.
      header: 'State',
      key: 'state',
      width: 130,
      exportValue: (r) => {
        const live = !!liveByMac.get(r.mac.toLowerCase());
        return [r.status ?? '', live ? 'leased' : ''].filter(Boolean).join(' ');
      },
      render: (row) => {
        const live = liveByMac.get(row.mac.toLowerCase());
        if (!row.status && !live) return <span className="text-faint">—</span>;
        return (
          <span className="flex flex-wrap items-center gap-1">
            {row.status && (
              <span className={clsx('rounded px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-wide', row.status === 'bound' ? 'bg-success/20 text-success-fg' : 'bg-muted text-secondary')}>{row.status}</span>
            )}
            {live && (
              <span className="rounded bg-info/20 px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-wide text-info-fg" title={live.expiry ? `Lease expires ${new Date(live.expiry).toLocaleString()}` : 'Active DHCP lease'}>
                leased{live.expiry ? ` · exp ${new Date(live.expiry).toLocaleDateString()}` : ''}
              </span>
            )}
          </span>
        );
      },
    },
    {
      header: 'Actions',
      key: 'actions',
      width: 90,
      render: (row) => {
        const res = resolveReservationDelete(actionsOf(row.pluginId));
        const canDelete = !!res && (res.byField === 'mac' || !!row.refId);
        // Editing needs a delete handle for the fallback path too — without one
        // neither operation can target the row.
        const editRes = resolveReservationEdit(actionsOf(row.pluginId));
        const canEdit = !!editRes && (res?.byField === 'mac' || !!row.refId);
        if (!canDelete && !canEdit) return <span className="text-faint">—</span>;
        return (
          <div className="flex items-center gap-1">
            {canEdit && (
              <button
                type="button"
                aria-label={`Edit reservation ${row.mac}`}
                title={isReadOnly ? READONLY_MESSAGE : `Change the fixed IP or hostname for ${row.mac}${row.ip ? ` (${row.ip})` : ''}`}
                disabled={isReadOnly || busy}
                onClick={() => setEditingReservation(row)}
                className={clsx('rounded-md p-1.5 text-secondary hover:bg-muted', (isReadOnly || busy) && 'cursor-not-allowed opacity-30')}
              >
                <Pencil size={14} />
              </button>
            )}
            {canDelete && (
              <button
                type="button"
                aria-label={`Delete reservation ${row.mac}`}
                title={isReadOnly ? READONLY_MESSAGE : `Remove the static binding for ${row.mac}${row.ip ? ` → ${row.ip}` : ''} on this device`}
                disabled={isReadOnly || busy}
                onClick={() => {
                  if (window.confirm(`Delete DHCP reservation for ${row.mac}${row.ip ? ` (${row.ip})` : ''} on ${row.deviceName ?? 'this device'}?\n\nThe client will receive a dynamic lease again.`)) void deleteReservation(row);
                }}
                className={clsx('rounded-md p-1.5 text-danger-fg hover:bg-muted', (isReadOnly || busy) && 'cursor-not-allowed opacity-30')}
              >
                <Trash2 size={14} />
              </button>
            )}
          </div>
        );
      },
    },
  ];

  const leaseColumns: DataTableColumn<{ host: HostRow; net?: DhcpNetworkRow }>[] = [
    {
      header: 'Hostname',
      key: 'hostname',
      width: 180,
      exportValue: (r) => r.host.hostname ?? '',
      render: (r) => (r.host.hostname ? <span className="text-sm">{r.host.hostname}</span> : <span className="text-faint">—</span>),
    },
    { header: 'MAC', key: 'mac', width: 150, exportValue: (r) => r.host.mac, render: (r) => <span className="font-mono text-sm">{r.host.mac}</span> },
    {
      header: 'IP',
      key: 'ip',
      width: 140,
      exportValue: (r) => r.host.ips.join(', '),
      render: (r) => <span className="font-mono text-sm">{r.host.ips[0] ?? '—'}</span>,
    },
    {
      header: 'Lease expiry',
      key: 'expiry',
      width: 160,
      exportValue: (r) => r.host.expiry ?? '',
      render: (r) => (r.host.expiry ? <span className="font-mono text-sm">{new Date(r.host.expiry).toLocaleString()}</span> : <span className="text-faint">—</span>),
    },
    {
      header: 'Serving network',
      key: 'network',
      width: 200,
      exportValue: (r) => r.net ? `${r.net.name} (${r.net.deviceName ?? r.net.deviceId})` : '',
      render: (r) => {
        if (!r.net) return <span className="text-faint" title="No collected DHCP network range contains this host's IP">—</span>;
        return (
          <DeviceChip
            deviceName={r.net.deviceName}
            managementAddress={r.net.managementAddress}
            pluginName={r.net.pluginName}
            siteName={r.net.siteName}
            interfaces={[r.net.name]}
          />
        );
      },
    },
    {
      header: 'Actions',
      key: 'actions',
      width: 160,
      excludeFromExport: true,
      render: (r) => {
        const convertible = !!r.net && reservationAddDevices.some((d) => d.deviceId === r.net!.deviceId && d.pluginId === r.net!.pluginId);
        return (
          <button
            type="button"
            title={isReadOnly ? READONLY_MESSAGE : convertible ? `Create a static reservation for ${r.host.mac} on ${r.net?.deviceName ?? 'this device'}` : 'No DHCP-capable plugin found for the serving network — use “Add reservation” instead'}
            disabled={isReadOnly || busy || !convertible}
            onClick={() => convertLease(r)}
            className={clsx('inline-flex items-center gap-1.5 rounded-md border border-border px-2 py-1 text-xs font-medium hover:bg-muted', (isReadOnly || busy || !convertible) && 'cursor-not-allowed opacity-30')}
          >
            <Plus size={12} /> Convert to static
          </button>
        );
      },
    },
  ];

  return (
    <Layout
      title="DHCP"
      actions={
        <>
          {reservationAddDevices.length > 0 && (
            <button
              type="button"
              onClick={() => setAddingReservation({})}
              disabled={isReadOnly || busy}
              className={clsx('inline-flex items-center gap-2 rounded-md bg-primary px-3 py-1.5 text-sm font-medium text-white hover:bg-primary-hover', (isReadOnly || busy) && 'cursor-not-allowed opacity-40')}
            >
              <Plus className="h-4 w-4" /> Add reservation
            </button>
          )}
          {networkCreateDevices.length > 0 && (
            <button
              type="button"
              onClick={() => setAddingNetwork(true)}
              disabled={isReadOnly || busy}
              className={clsx('inline-flex items-center gap-2 rounded-md border border-border px-3 py-1.5 text-sm font-medium hover:bg-muted', (isReadOnly || busy) && 'cursor-not-allowed opacity-40')}
            >
              <Network className="h-4 w-4" /> Add network
            </button>
          )}
        </>
      }
    >
      {dhcpQuery.isLoading && <p className="text-sm text-muted-foreground">Loading DHCP inventory...</p>}
      {dhcpQuery.isError && (
        <p className="text-sm text-danger-fg">Failed to load DHCP inventory: {(dhcpQuery.error as Error).message}</p>
      )}

      {notice && (
        <div
          className={clsx(
            'mb-3 rounded-md border px-3 py-2 text-sm',
            notice.kind === 'ok' && 'border-success-border bg-success text-success-fg',
            notice.kind === 'info' && 'border-info-border bg-info text-info-fg',
            notice.kind === 'error' && 'border-danger-border bg-danger text-danger-fg',
          )}
        >
          {notice.text}
        </div>
      )}

      {busy && (
        <div className="mb-3 flex items-center gap-2 rounded-md border border-info-border bg-info px-3 py-2 text-sm text-info-fg">
          <Loader2 className="h-4 w-4 animate-spin" />
          Waiting for plan execution to settle — the tables refresh automatically.
        </div>
      )}

      {dhcpQuery.data && (
        <>
          <h2 className="mb-2 flex items-center gap-2 text-sm font-semibold text-foreground">
            <Network className="h-4 w-4 text-primary" /> Networks ({dhcpQuery.data.networks.length})
          </h2>
          <div className="mb-6">
            <DataTable
              columns={networkColumns}
              rows={dhcpQuery.data.networks}
              rowKey={(row) => `${row.deviceId}|${row.pluginId}|${row.name}|${row.rangeStart}`}
              storageKey="dhcp-networks"
              autoRefresh={{ intervalMs: 30_000, queries: [dhcpQuery] }}
              searchPlaceholder="Search DHCP networks…"
              emptyMessage="No DHCP server networks collected yet — assign a dhcp-capable plugin (RouterOS, OPNsense or OpenWrt) to a device and wait for the next poll."
            />
          </div>

          <h2 className="mb-2 flex items-center gap-2 text-sm font-semibold text-foreground">
            <Wifi className="h-4 w-4 text-primary" /> Reservations ({dhcpQuery.data.reservations.length})
          </h2>
          <DataTable
            columns={reservationColumns}
            rows={dhcpQuery.data.reservations}
            rowKey={(row) => `${row.deviceId}|${row.pluginId}|${row.mac}`}
            storageKey="dhcp-reservations"
            autoRefresh={{ intervalMs: 30_000, queries: [dhcpQuery] }}
            searchPlaceholder="Search DHCP reservations…"
            emptyMessage="No static DHCP reservations collected yet — add one with “Add reservation”, or wait for the next poll after configuring them on a device."
          />

          <h2 className="mb-2 mt-6 flex items-center gap-2 text-sm font-semibold text-foreground">
            <Wifi className="h-4 w-4 text-primary" /> Dynamic leases without a static reservation ({dynamicLeases.length})
          </h2>
          <DataTable
            columns={leaseColumns}
            rows={dynamicLeases}
            rowKey={(entry) => entry.host.mac}
            storageKey="dhcp-dynamic-leases"
            autoRefresh={{ intervalMs: 60_000, queries: [hostsQuery] }}
            searchPlaceholder="Search dynamic leases…"
            emptyMessage="No DHCP clients without a static reservation right now — hosts seen via DHCP appear here until you convert one to a fixed binding."
          />
        </>
      )}

      {addingReservation && (
        <AddReservationDialog
          devices={addingReservation.fixedDevice ? reservationAddDevices.filter((d) => d.deviceId === addingReservation.fixedDevice!.deviceId && d.pluginId === addingReservation.fixedDevice!.pluginId) : reservationAddDevices}
          prefill={addingReservation.prefill}
          networksByDevice={networksByDevice}
          busy={busy}
          onClose={() => setAddingReservation(null)}
          onSubmit={(deviceId, pluginId, input) => void submitReservation(deviceId, pluginId, input)}
        />
      )}

      {editingReservation && (
        <EditReservationDialog
          row={editingReservation}
          resolution={resolveReservationEdit(actionsOf(editingReservation.pluginId))!}
          busy={busy}
          onClose={() => setEditingReservation(null)}
          onSubmit={(input) => void submitEditReservation(editingReservation, input)}
        />
      )}

      {addingNetwork && (
        <AddNetworkDialog
          devices={networkCreateDevices}
          prefillIface={dhcpQuery.data?.networks[0]?.iface ?? null}
          busy={busy}
          onClose={() => setAddingNetwork(false)}
          onSubmit={(deviceId, pluginId, input) => void submitNetwork(deviceId, pluginId, input)}
        />
      )}

      {/* In-session 2FA revalidation (plan create/execute returned 401). */}
      {reauth && (
        <ReauthDialog
          contextLabel={reauth.label}
          onClose={() => setReauth(null)}
          onSuccess={async () => {
            const retry = reauth.retry;
            setReauth(null);
            await retry();
          }}
        />
      )}
    </Layout>
  );
}
