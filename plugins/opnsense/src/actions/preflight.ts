/**
 * Preflight resolvers for the canonical fleet intents — the "smart" half of a
 * network rollout on OPNsense. Before plans are created, the webapp asks this
 * plugin to RESOLVE best-guess values per device against its LIVE state
 * (read-only):
 *   - which interface should carry the new VLAN / L3 address on THIS appliance,
 *   - whether a network with that name already exists (idempotency hint),
 *   - whether an assignment write path is available at all (REST 26.7+ vs SSH).
 *
 * Transport contract: POST /preflight { intentActionId, inputs } — same body
 * shape as a single-device step dispatch. Resolvers NEVER write; they return
 * PreflightResult values that the UI renders and the user can override before
 * plan creation (overrides ride back in PlanRequest.deviceInputs).
 */

import type { L2Topology, PreflightInterfaceOption, PreflightResult, PreflightValue } from '@unm/plugin-sdk';
import { suggestL2AttachPoint } from '@unm/plugin-sdk';
import * as ifaces from '../client/interfaces';
import { probeAssignmentCapability, resolveAssignmentPath } from '../assignmentSsh';
import type { ActionContext } from './types';
import { readOpnsenseL2Topology } from './l2Topology';

interface IfcRowLite {
  device?: string;
  identifier?: string;
  description?: string;
  vlan?: { tag?: string; parent?: string };
  config?: { if?: string; descr?: string };
}

function rowsOf(data: unknown): IfcRowLite[] {
  const d = data as { rows?: IfcRowLite[] };
  return Array.isArray(d?.rows) ? d.rows : [];
}

/**
 * Resolves the attach point for a new network on this appliance, mirroring the
 * executor's logic: prefer an L3-carrying interface (suggestL2AttachPoint), and
 * walk UP from a VLAN device to its parent so the new VLAN is created as a
 * SIBLING of existing VLANs rather than stacked on top of one.
 */
function resolveAttach(topo: L2Topology, rows: IfcRowLite[]): { attach: string; reason: string } | null {
  const suggestion = suggestL2AttachPoint(topo);
  if (!suggestion) return null;
  let a = suggestion.attach;
  let reason = suggestion.reason;
  const vlanRow = rows.find((r) => r.device === a && r.vlan?.parent);
  if (vlanRow?.vlan?.parent) {
    // The suggested attach is a VLAN — the new network's VLAN is created as a
    // SIBLING on the parent, so report the parent as the attach point.
    reason = `new VLAN would be created on ${vlanRow.vlan.parent} (sibling of ${a}, which carries existing L3 networks)`;
    a = vlanRow.vlan.parent;
  }
  return { attach: a, reason };
}

/**
 * Preflight for `network.create` on one OPNsense appliance. Read-only:
 * interfaces_info + L2 topology + an assignment-path probe (a single GET that
 * 404s on ≤26.4 — no writes).
 */
export async function preflightNetworkCreate(ctx: ActionContext, inputs: Record<string, unknown>): Promise<PreflightResult> {
  const values: PreflightValue[] = [];

  const name = String(inputs.name ?? '').trim();
  const vlanId = typeof inputs.vlanId === 'number' ? Math.floor(inputs.vlanId as number) : null;

  let topo: L2Topology | null = null;
  let rows: IfcRowLite[] = [];
  try {
    const [infoRes, t] = await Promise.all([ifaces.getInterfacesInfo(ctx.client), readOpnsenseL2Topology(ctx)]);
    if (!infoRes.ok) throw new Error(`interfaces_info HTTP ${infoRes.status}`);
    rows = rowsOf(infoRes.data);
    topo = t;
  } catch (e) {
    return { deviceId: ctx.deviceId ?? '', values, degraded: true, error: `state read failed: ${(e as Error).message}` };
  }

  // Idempotency hint — a network with this name already exists.
  if (name) {
    const needle = name.toUpperCase();
    const existing = rows.find((r) => (r.description ?? '').toUpperCase() === needle || (r.config?.descr ?? '').toUpperCase() === needle);
    values.push(
      existing
        ? { key: 'name', value: name, confidence: 'high', note: `network "${name}" already exists on ${existing.device} (${existing.identifier}) — will be left untouched` }
        : { key: 'name', value: name, confidence: 'medium', note: `no network named "${name}" yet — a new interface assignment will be created` },
    );
  }

  // Attach-point suggestion (walked up from VLAN devices to their parent).
  const attach = resolveAttach(topo!, rows);
  if (attach) {
    values.push({ key: 'interface', value: attach.attach, confidence: /carries existing L3/i.test(attach.reason) ? 'high' : 'medium', note: `suggested attach point — ${attach.reason}` });
  } else {
    values.push({ key: 'interface', value: null, confidence: 'low', note: 'no L3-carrying interface found — set the attach point explicitly' });
  }

  // VLAN hint — an existing VLAN with that tag is reused wherever it sits.
  if (vlanId !== null) {
    try {
      const vlanRes = await ifaces.vlans.get(ctx.client);
      if (vlanRes.ok) {
        const vdata = vlanRes.data as { vlan?: { vlan?: Record<string, { tag?: string; vlanif?: string }> } };
        const existingVlan = Object.values(vdata?.vlan?.vlan ?? {}).find((v) => Number(v.tag) === vlanId);
        values.push(
          existingVlan?.vlanif
            ? { key: 'vlanId', value: vlanId, confidence: 'high', note: `VLAN ${vlanId} already exists (${existingVlan.vlanif}) — will be reused` }
            : { key: 'vlanId', value: vlanId, confidence: 'medium', note: `no VLAN ${vlanId} yet — one will be created on the attach point` },
        );
      }
    } catch { /* non-fatal */ }
  }

  // Write-path availability — resolveAssignmentPath folds in the 26.7.x case:
  // REST only when its model can hold an L3 address, otherwise SSH (bound slot),
  // otherwise null. The note distinguishes WHY ssh is used (no endpoint at all
  // vs. minimal 26.7.x model) so the plan author knows what to expect.
  try {
    const path = await resolveAssignmentPath(ctx.client, ctx.credentials as Record<string, unknown>);
    if (path === 'rest') {
      values.push({ key: '_writePath', value: 'rest', confidence: 'high', note: 'interface assignments are written via the REST model (full assignment model)' });
    } else if (path === 'ssh') {
      const cap = await probeAssignmentCapability(ctx.client);
      values.push(
        cap.restPresent
          ? { key: '_writePath', value: 'ssh', confidence: 'medium', note: "assignment REST API present, but this firmware's model has no IP fields — writes fall back to the bound SSH slot (config.xml edit + rc.configure_interface)" }
          : { key: '_writePath', value: 'ssh', confidence: 'medium', note: 'this appliance predates the assignment REST API — writes go through the bound SSH slot (config.xml edit + rc.configure_interface)' },
      );
    } else {
      values.push({ key: '_writePath', value: null, confidence: 'low', note: 'NO write path available: the assignment REST model cannot hold an L3 address and no `ssh` credential slot is bound — bind one before creating this plan' });
    }
  } catch { /* non-fatal */ }

  // Interface candidates for the dialog's dropdown — physical NICs, bridges,
  // LAG bundles (kernel device names; that is what `interface` expects).
  const interfaces: PreflightInterfaceOption[] = [
    ...topo!.physicalPorts.map((p): PreflightInterfaceOption => ({ name: p.name, kind: 'physical' as const })),
    ...topo!.bridges.map((b): PreflightInterfaceOption => ({ name: b.name, kind: 'bridge' as const })),
    ...topo!.bundles.map((bu): PreflightInterfaceOption => ({ name: bu.name, kind: 'bundle' as const })),
  ];

  return { deviceId: ctx.deviceId ?? '', values, interfaces };
}

/** Registry of preflight resolvers per canonical intent id. */
export const PREFLIGHT_RESOLVERS: Record<string, (ctx: ActionContext, inputs: Record<string, unknown>) => Promise<PreflightResult>> = {
  'network.create': preflightNetworkCreate,
};
