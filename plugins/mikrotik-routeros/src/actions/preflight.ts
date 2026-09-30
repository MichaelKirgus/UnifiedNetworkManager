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

import type { L2Topology, PreflightResult, PreflightValue } from '@unm/plugin-sdk';
import { suggestL2AttachPoint } from '@unm/plugin-sdk';
import { rosString } from '../routerosClient';
import type { ActionContext } from './types';
import { readRouterOsL2Topology } from './l2Topology';

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

  let topo: L2Topology | null = null;
  let vlans: Row[] = [];
  try {
    [topo, vlans] = await Promise.all([readRouterOsL2Topology(ctx), ctx.client.get<Row[]>('/interface/vlan').catch(() => [] as Row[])]);
  } catch (e) {
    return { deviceId: ctx.deviceId ?? '', values, degraded: true, error: `state read failed: ${(e as Error).message}` };
  }

  // Idempotency hint — a network with this name already exists (VLANs carry the name).
  if (name) {
    const needle = name.toUpperCase();
    const existing = vlans.find((v) => (rosString(v, ['name']) ?? '').toUpperCase() === needle);
    values.push(
      existing
        ? { key: 'name', value: name, confidence: 'high', note: `network "${name}" already exists as VLAN ${rosString(existing, ['name'])} (vlan-id ${rosString(existing, ['vlan-id'])}) — will be left untouched` }
        : { key: 'name', value: name, confidence: 'medium', note: `no network named "${name}" yet — a new VLAN + L3 address will be created` },
    );
  }

  // Attach-point suggestion (the SDK's preference order over the live topology).
  const attach = suggestL2AttachPoint(topo!);
  if (attach) {
    values.push({ key: 'interface', value: attach.attach, confidence: /carries existing L3/i.test(attach.reason) ? 'high' : 'medium', note: `suggested attach point — ${attach.reason}` });
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

  return { deviceId: ctx.deviceId ?? '', values };
}

/** Registry of preflight resolvers per canonical intent id. */
export const PREFLIGHT_RESOLVERS: Record<string, (ctx: ActionContext, inputs: Record<string, unknown>) => Promise<PreflightResult>> = {
  'network.create': preflightNetworkCreate,
};
