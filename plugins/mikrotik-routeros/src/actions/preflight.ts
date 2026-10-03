/**
 * Preflight resolvers for the canonical fleet intents — the "smart" half of a
 * network rollout on RouterOS. Before plans are created, the webapp asks this
 * plugin to RESOLVE best-guess values per device against its LIVE state
 * (read-only):
 *   - which interface should carry the new VLAN / L3 address on THIS router,
 *   - whether a network with that name already exists (idempotency hint),
 *   - whether an existing VLAN with the requested tag can be reused.
 *
 * Transport contract: POST /preflight { intentActionId, inputs } — same body
 * shape as a single-device step dispatch. Resolvers NEVER write; they return
 * PreflightResult values that the UI renders and the user can override before
 * plan creation (overrides ride back in PlanRequest.deviceInputs).
 */

import type { L2Topology, PreflightCapabilities, PreflightPort, PreflightResult, PreflightValue } from '@unm/plugin-sdk';
import { suggestL2AttachPoint } from '@unm/plugin-sdk';
import { rosString } from '../routerosClient';
import type { ActionContext } from './types';
import { readRouterOsL2Topology, readSwitchVlanTable } from './l2Topology';

type Row = Record<string, unknown>;

/**
 * Preflight for `network.create` on one RouterOS router. Read-only: the L2
 * topology batch (interfaces + bridge ports + VLANs + bonding) plus a re-read
 * of /ip/address for dual-stack hints.
 */
export async function preflightNetworkCreate(ctx: ActionContext, inputs: Record<string, unknown>): Promise<PreflightResult> {
  const values: PreflightValue[] = [];

  const name = String(inputs.name ?? '').trim();
  const vlanId = typeof inputs.vlanId === 'number' ? Math.floor(inputs.vlanId as number) : null;
  // VLAN-only rollout — no L3 address requested for this device.
  const l2Only = vlanId !== null && !inputs.cidr && !inputs.ip && !inputs.cidrV6;

  let topo: L2Topology | null = null;
  let vlans: Row[] = [];
  // Switch-chip probe (null → no integrated switch → port selection N/A).
  const switchTable = await readSwitchVlanTable(ctx);
  try {
    [topo, vlans] = await Promise.all([readRouterOsL2Topology(ctx), ctx.client.get<Row[]>('/interface/vlan').catch(() => [] as Row[])]);
  } catch (e) {
    return { deviceId: ctx.deviceId ?? '', values, degraded: true, error: `state read failed: ${(e as Error).message}` };
  }

  // Port list + trunk flags for the dialog's quick selects (All / Trunk only /
  // Select ports) — rides along with the preflight, no extra round-trip.
  const ports: PreflightPort[] = topo.physicalPorts.map((p) => ({ name: p.name, trunk: p.trunk ?? false }));
  const capabilities: PreflightCapabilities = { vlanPorts: switchTable !== null };

  // Idempotency hint — a network with this name already exists (VLANs carry the name).
  if (name) {
    const needle = name.toUpperCase();
    const existing = vlans.find((v) => (rosString(v, ['name']) ?? '').toUpperCase() === needle);
    values.push(
      existing
        ? { key: 'name', value: name, confidence: 'high', note: `network "${name}" already exists as VLAN ${rosString(existing, ['name'])} (vlan-id ${rosString(existing, ['vlan-id'])}) — will be left untouched` }
        : { key: 'name', value: name, confidence: 'medium', note: l2Only ? `no network named "${name}" yet — a new VLAN (L2 only) will be created` : `no network named "${name}" yet — a new VLAN + L3 address will be created` },
    );
  }

  // Attach-point suggestion (the SDK's preference order over the live topology).
  const attach = suggestL2AttachPoint(topo!);
  if (attach) {
    values.push({ key: 'interface', value: attach.attach, confidence: /carries existing L3/i.test(attach.reason) ? 'high' : 'medium', note: `suggested attach point — ${attach.reason}` });
  } else if (l2Only && topo!.bridges.length > 0) {
    // VLAN-only rollout — no L3 address is bound, so any bridge works as the
    // parent domain. Prefer bridge1 (always present on RouterOS).
    const fallback = topo!.bridges.some((b) => b.name === 'bridge1') ? 'bridge1' : topo!.bridges[0].name;
    values.push({ key: 'interface', value: fallback, confidence: 'medium', note: `L2-only (no address requested) — VLAN will be created on a member of ${fallback}` });
  } else {
    values.push({ key: 'interface', value: null, confidence: 'low', note: 'no L3-carrying interface found — set the attach point explicitly' });
  }

  // VLAN hint — an existing VLAN with that tag is reused wherever it sits.
  if (vlanId !== null) {
    const byTag = vlans.find((v) => Number(rosString(v, ['vlan-id'])) === vlanId);
    values.push(
      byTag && rosString(byTag, ['name'])
        ? { key: 'vlanId', value: vlanId, confidence: 'high', note: `VLAN ${vlanId} already exists (${rosString(byTag, ['name'])}) — will be reused` }
        : { key: 'vlanId', value: vlanId, confidence: 'medium', note: `no VLAN ${vlanId} yet — one will be created on the attach point` },
    );
  }

  return { deviceId: ctx.deviceId ?? '', values, ports, capabilities };
}

/** Registry of preflight resolvers per canonical intent id. */
export const PREFLIGHT_RESOLVERS: Record<string, (ctx: ActionContext, inputs: Record<string, unknown>) => Promise<PreflightResult>> = {
  'network.create': preflightNetworkCreate,
};
