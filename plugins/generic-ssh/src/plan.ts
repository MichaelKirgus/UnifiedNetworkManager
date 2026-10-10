/**
 * The planner: turns a multi-device INTENT into an ordered, dependency-aware
 * execution PLAN (openwrt plan.ts pattern). Pure with respect to writes — it
 * never mutates devices and never generates key material; provisionRequests are
 * non-secret descriptors the API persists and the secrets provider fulfills.
 *
 * Intents:
 *  - wireguard.tunnel.create — 2 devices, one X25519 key pair per endpoint.
 * Single-device actions fan out (one step per device) for batch rollouts.
 */

import { appendSettleAndRefresh, finalizePlan, PlanningError, isCanonicalIntent } from '@unm/plugin-sdk';
import type { CatalogEntry, Plan, PlanDevice as SdkPlanDevice, PlanRequest as SdkPlanRequest, PlanStep, ProvisionRequest, InputSchema, RiskLevel } from '@unm/plugin-sdk';
import { getAction, listActions, listCatalog } from './actions/registry';

/** The SDK's generic PlanRequest (credentials = primary secret fields). */
export type PlanRequest = SdkPlanRequest<Record<string, unknown>>;
type PlanDevice = SdkPlanDevice<Record<string, unknown>>;

export type { Plan, PlanDevice };
export { PlanningError };

// --- Multi-device intents ---------------------------------------------------------

export interface IntentDescriptor {
  id: string;
  label: string;
  description?: string;
  module: string;
  riskLevel: RiskLevel;
  inputSchema: InputSchema;
  /** Number of devices required (exact). */
  deviceCount: number;
  provision: (inputs: Record<string, unknown>) => ProvisionRequest[];
  buildSteps: (inputs: Record<string, unknown>, devices: PlanDevice[]) => Omit<PlanStep, 'stepIndex'>[];
}

/** Reads an optional string input. */
function str(input: Record<string, unknown>, key: string): string | undefined {
  const v = input[key];
  return typeof v === 'string' && v.length > 0 ? v : undefined;
}

const WIREGUARD_TUNNEL: IntentDescriptor = {
  id: 'wireguard.tunnel.create',
  label: 'Create WireGuard tunnel between two devices',
  description:
    'Provisions one X25519 key pair per endpoint (via the secrets provider), creates a wg-quick interface on each side, adds the peer with the REMOTE public key + endpoint address on both sides, then activates both interfaces. Both endpoints must be reachable at their management addresses (or an explicit endpoint override).',
  module: 'WireGuard',
  riskLevel: 'write',
  deviceCount: 2,
  inputSchema: {
    name: { type: 'string', required: true, description: 'Tunnel/interface name (same on both sides)' },
    subnet: { type: 'string', required: true, description: 'Tunnel subnet, e.g. "10.255.0.0/24"' },
    listenPortA: { type: 'number', min: 1, max: 65535, default: 51820, description: 'UDP port on device A (default 51820)' },
    listenPortB: { type: 'number', min: 1, max: 65535, default: 51820, description: 'UDP port on device B (default 51820)' },
    endpointA: { type: 'string', description: "Public address of A as seen from B (default: A's management address)" },
    endpointB: { type: 'string', description: "Public address of B as seen from A (default: B's management address)" },
    allowedSubnetsA: { type: 'array', items: { type: 'string' }, description: 'CIDRs reachable THROUGH device A (advertised on B\'s peer entry)' },
    allowedSubnetsB: { type: 'array', items: { type: 'string' }, description: 'CIDRs reachable THROUGH device B (advertised on A\'s peer entry)' },
  },
  provision: () => [
    { ref: 'keyA', type: 'wireguardKeyPair', label: 'WireGuard key pair — endpoint A' },
    { ref: 'keyB', type: 'wireguardKeyPair', label: 'WireGuard key pair — endpoint B' },
  ],
  buildSteps: (inputs, devices) => {
    const [a, b] = devices;
    const name = str(inputs, 'name')!;
    const subnet = str(inputs, 'subnet')!;
    const portA = typeof inputs.listenPortA === 'number' ? inputs.listenPortA : 51820;
    const portB = typeof inputs.listenPortB === 'number' ? inputs.listenPortB : 51820;
    // Peer endpoint = the address the OTHER side dials. Default: management
    // address + listen port (works when WG rides the same interface).
    const epA = `${str(inputs, 'endpointA') ?? a.managementAddress}:${portA}`;
    const epB = `${str(inputs, 'endpointB') ?? b.managementAddress}:${portB}`;
    const throughA = Array.isArray(inputs.allowedSubnetsA) ? (inputs.allowedSubnetsA as string[]) : [];
    const throughB = Array.isArray(inputs.allowedSubnetsB) ? (inputs.allowedSubnetsB as string[]) : [];

    // Step layout: 0=A.server, 1=B.server, 2=A.peer(dep 0), 3=B.peer(dep 1),
    //              4=A.activate(dep 2), 5=B.activate(dep 3).
    return [
      { deviceId: a.deviceId, actionId: 'wireguard.server.set', input: { name, subnet, listenPort: portA, credentialRef: 'keyA' }, secretRefs: ['keyA'] },
      { deviceId: b.deviceId, actionId: 'wireguard.server.set', input: { name, subnet, listenPort: portB, credentialRef: 'keyB' }, secretRefs: ['keyB'] },
      {
        deviceId: a.deviceId,
        actionId: 'wireguard.peer.add',
        input: { name, endpoint: epB, allowedSubnets: throughB.length > 0 ? throughB : [subnet], credentialRef: 'keyB' },
        dependsOn: [0],
        secretRefs: ['keyB'],
      },
      {
        deviceId: b.deviceId,
        actionId: 'wireguard.peer.add',
        input: { name, endpoint: epA, allowedSubnets: throughA.length > 0 ? throughA : [subnet], credentialRef: 'keyA' },
        dependsOn: [1],
        secretRefs: ['keyA'],
      },
      { deviceId: a.deviceId, actionId: 'wireguard.service.reconfigure', input: { name }, dependsOn: [2] },
      { deviceId: b.deviceId, actionId: 'wireguard.service.reconfigure', input: { name }, dependsOn: [3] },
    ];
  },
};

export const MULTI_DEVICE_INTENTS: IntentDescriptor[] = [WIREGUARD_TUNNEL];

// --- Catalog (for /discover) --------------------------------------------------------

/** The full action catalog: single-device actions + multi-device intents. */
export function listCatalogWithIntents(): CatalogEntry[] {
  // Canonical fleet intents (network.create / network.delete) FAN OUT across
  // the batch — one step per device. 'N' tells the API to accept any device
  // count; a numeric 1 would reject legitimate multi-device rollouts.
  const fromActions: CatalogEntry[] = listCatalog().map((e) =>
    isCanonicalIntent(e.id) ? { ...e, deviceCount: 'N' as const } : e,
  );
  return [...fromActions, ...MULTI_DEVICE_INTENTS.map((i) => ({
    id: i.id,
    label: i.label,
    description: i.description,
    module: i.module,
    riskLevel: i.riskLevel,
    // Report the intent's TRUE device count so callers can enforce it.
    deviceCount: i.deviceCount as number | 'N',
    inputSchema: i.inputSchema,
  }))];
}

// --- Plan assembly ------------------------------------------------------------------

/** True for action ids that mutate device state (drives snapshot rollback). */
function isDirtyStep(actionId: string): boolean {
  const a = getAction(actionId);
  return !!a && a.riskLevel !== 'read';
}

// --- Settle + inventory-refresh tail ---------------------------------------------
// Applying one of these actions invalidates the updates inventory the API caches
// (device_updates). The plugin therefore appends reserved SYSTEM steps — executed
// by the UNM plan executor itself, never dispatched here: a visible settle wait,
// then a forced inventory re-poll so applied updates disappear from the Updates
// page instead of dangling. The PLUGIN owns both decisions (which intents need it
// and how long to wait); the API is a dumb runner.
const UPDATE_SETTLE_MS: Record<string, number> = {
  // A package install finishes inside the step; a short settle lets apt state +
  // any lock holders clear before the re-poll reads `apt list --upgradable`.
  'packages.update': 30_000,
  // Runs DETACHED (nohup) — may still be going when the step returns. The
  // refresh is best-effort: if the upgrade holds apt, the poll just sees the
  // in-flight state; if it finished, we get fresh data.
  'packages.dist-upgrade': 60_000,
  // apt-mark / version-lock changes are instant — only the held flags need a re-read.
  'packages.hold': 5_000,
  'packages.unhold': 5_000,
};

/** Appends the settle+refresh tail for update intents; passes other plans through. */
function withSettleTail(plan: Plan, intentId: string): Plan {
  const waitMs = UPDATE_SETTLE_MS[intentId];
  if (waitMs === undefined) return plan;
  return appendSettleAndRefresh(plan, Object.keys(UPDATE_SETTLE_MS), waitMs);
}

/** Builds the final plan for one intent + device set. */
export function buildPlan(req: PlanRequest): Plan {
  const intentId = req.intent?.actionId;
  if (!intentId) throw new PlanningError('Missing intent.actionId');

  // Multi-device intent?
  const intent = MULTI_DEVICE_INTENTS.find((i) => i.id === intentId);
  if (intent) {
    if (req.devices.length !== intent.deviceCount) {
      throw new PlanningError(`Intent ${intentId} requires exactly ${intent.deviceCount} devices, got ${req.devices.length}`);
    }
    const rawSteps = intent.buildSteps(req.intent.inputs ?? {}, req.devices as PlanDevice[]);
    return withSettleTail(
      finalizePlan(
        intentId,
        req.devices.map((d) => ({ deviceId: d.deviceId })),
        intent.provision(req.intent.inputs ?? {}),
        rawSteps,
        isDirtyStep,
        { rollbackStep: () => ({ actionId: 'snapshot.create', input: {} }) },
      ),
      intentId,
    );
  }

  // Single-device action → fan out one step per device.
  const action = getAction(intentId);
  if (!action) throw new PlanningError(`Unknown action or intent "${intentId}"`);
  if (req.devices.length === 0) throw new PlanningError('No devices supplied');

  // Per-device overrides (PlanRequest.deviceInputs — the rollout wizard's
  // confirmed preflight values, e.g. a different parent or L3 address per box)
  // merge on top of the shared inputs for that device only.
  const rawSteps: Omit<PlanStep, 'stepIndex'>[] = req.devices.map((d) => ({
    deviceId: d.deviceId,
    actionId: intentId,
    input: { ...(req.intent.inputs ?? {}), ...((req.deviceInputs ?? {})[d.deviceId] ?? {}) },
  }));
  return withSettleTail(
    finalizePlan(
      intentId,
      req.devices.map((d) => ({ deviceId: d.deviceId })),
      [],
      rawSteps,
      isDirtyStep,
      // Only prepend a rollback snapshot when the action actually writes.
      { rollbackStep: () => ({ actionId: 'snapshot.create', input: {} }) },
    ),
    intentId,
  );
}
