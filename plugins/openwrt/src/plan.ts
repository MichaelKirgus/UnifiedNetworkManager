/**
 * The planner: turns a multi-device INTENT into an ordered, dependency-aware
 * execution PLAN (opnsense plan.ts pattern). Pure with respect to writes — it
 * never mutates devices and never generates key material; provisionRequests are
 * non-secret descriptors the API persists and the secrets provider fulfills.
 *
 * Intents:
 *  - wireguard.tunnel.create   — 2 devices, one key pair per endpoint.
 *  - openvpn.sitesite.create   — 2 devices, one certificate bundle.
 *  - routes.backRoute.create   — SD-LAN/WAN forward + back-route pair.
 * Single-device actions fan out (one step per device) for batch rollouts.
 */

import { finalizePlan, PlanningError } from '@unm/plugin-sdk';
import type { CatalogEntry, Plan, PlanDevice as SdkPlanDevice, PlanRequest as SdkPlanRequest, PlanStep, ProvisionRequest, InputSchema, RiskLevel } from '@unm/plugin-sdk';
import { getAction, listActions } from './actions/registry';

export interface OpenWrtCredentials {
  username?: string;
  password?: string;
}

/** The SDK's generic PlanRequest (credentials = primary secret fields). */
export type PlanRequest = SdkPlanRequest<OpenWrtCredentials>;
type PlanDevice = SdkPlanDevice<OpenWrtCredentials>;

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
  label: 'Create WireGuard tunnel between two OpenWrt devices',
  description:
    'Provisions one key pair per endpoint (via the secrets provider), creates a wireguard server on each side, adds the peer with the REMOTE public key + endpoint address on both sides, then reloads networking. Both endpoints must be reachable at their management addresses.',
  module: 'WireGuard',
  riskLevel: 'write',
  deviceCount: 2,
  inputSchema: {
    name: { type: 'string', required: true, description: 'Tunnel/interface name (same on both sides)' },
    subnet: { type: 'string', required: true, description: 'Tunnel subnet, e.g. 10.255.0.0/24' },
    listenPort: { type: 'number', min: 1, max: 65535, default: 51820 },
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
    const listenPort = typeof inputs.listenPort === 'number' ? inputs.listenPort : 51820;
    const throughA = Array.isArray(inputs.allowedSubnetsA) ? (inputs.allowedSubnetsA as string[]) : [];
    const throughB = Array.isArray(inputs.allowedSubnetsB) ? (inputs.allowedSubnetsB as string[]) : [];

    // Step layout: 0=A.server, 1=B.server, 2=A.peer(dep 0), 3=B.peer(dep 1),
    //              4=A.reconf(dep 2), 5=B.reconf(dep 3)
    return [
      { deviceId: a.deviceId, actionId: 'wireguard.server.set', input: { name, subnet, listenPort, credentialRef: 'keyA' }, secretRefs: ['keyA'] },
      { deviceId: b.deviceId, actionId: 'wireguard.server.set', input: { name, subnet, listenPort, credentialRef: 'keyB' }, secretRefs: ['keyB'] },
      {
        deviceId: a.deviceId,
        actionId: 'wireguard.peer.add',
        input: { name, endpoint: b.managementAddress, allowedSubnets: throughB.length > 0 ? throughB : [subnet], credentialRef: 'keyB' },
        dependsOn: [0],
        secretRefs: ['keyB'],
      },
      {
        deviceId: b.deviceId,
        actionId: 'wireguard.peer.add',
        input: { name, endpoint: a.managementAddress, allowedSubnets: throughA.length > 0 ? throughA : [subnet], credentialRef: 'keyA' },
        dependsOn: [1],
        secretRefs: ['keyA'],
      },
      { deviceId: a.deviceId, actionId: 'wireguard.service.reconfigure', input: {}, dependsOn: [2] },
      { deviceId: b.deviceId, actionId: 'wireguard.service.reconfigure', input: {}, dependsOn: [3] },
    ];
  },
};

const OPENVPN_SITESITE: IntentDescriptor = {
  id: 'openvpn.sitesite.create',
  label: 'Create OpenVPN site-to-site link between two OpenWrt devices',
  description:
    'Provisions one certificate bundle (CA + cert + key, via the secrets provider), creates an openvpn instance on each side and reloads networking. Both devices must have the openvpn package installed.',
  module: 'OpenVPN',
  riskLevel: 'write',
  deviceCount: 2,
  inputSchema: {
    name: { type: 'string', required: true },
    modeA: { type: 'string', enum: ['server', 'client'], default: 'server' },
    modeB: { type: 'string', enum: ['server', 'client'], default: 'client' },
  },
  provision: () => [{ ref: 'profile', type: 'openvpnProfile', label: 'OpenVPN certificate bundle (CA + cert + key)' }],
  buildSteps: (inputs, devices) => {
    const [a, b] = devices;
    const name = str(inputs, 'name')!;
    return [
      { deviceId: a.deviceId, actionId: 'openvpn.instance.set', input: { name, mode: str(inputs, 'modeA') ?? 'server', credentialRef: 'profile' }, secretRefs: ['profile'] },
      { deviceId: b.deviceId, actionId: 'openvpn.instance.set', input: { name, mode: str(inputs, 'modeB') ?? 'client', credentialRef: 'profile' }, secretRefs: ['profile'] },
      { deviceId: a.deviceId, actionId: 'openvpn.service.reconfigure', input: {}, dependsOn: [0] },
      { deviceId: b.deviceId, actionId: 'openvpn.service.reconfigure', input: {}, dependsOn: [1] },
    ];
  },
};

const BACK_ROUTE: IntentDescriptor = {
  id: 'routes.backRoute.create',
  label: 'Create forward route + back-route between two OpenWrt devices (SD-LAN/WAN)',
  description:
    'The classic SD-WAN routing pair: on device A a static route toward the remote network; on device B a gateway + back-route toward the origin LAN so return traffic is routed correctly. Networking reloads per side.',
  module: 'Routing',
  riskLevel: 'write',
  deviceCount: 2,
  inputSchema: {
    interfaceA: { type: 'string', required: true, description: 'Interface on A that reaches B (e.g. wan)' },
    networkB: { type: 'string', required: true, description: "B's LAN CIDR to route from A" },
    gatewayB: { type: 'string', required: true, description: 'Gateway IP on the link toward B' },
    interfaceB: { type: 'string', required: true, description: 'Interface on B that reaches A (e.g. wan)' },
    networkA: { type: 'string', required: true, description: "A's LAN CIDR to route from B" },
  },
  provision: () => [],
  buildSteps: (inputs, devices) => {
    const [a, b] = devices;
    return [
      // A: static route toward B's network via the link gateway.
      { deviceId: a.deviceId, actionId: 'route.add', input: { name: str(inputs, 'interfaceA')!, network: str(inputs, 'networkB')! } },
      { deviceId: a.deviceId, actionId: 'routes.reconfigure', input: {}, dependsOn: [0] },
      // B: gateway toward A + back-route to A's LAN.
      { deviceId: b.deviceId, actionId: 'gateway.add', input: { name: str(inputs, 'interfaceB')!, gatewayIp: str(inputs, 'networkA')!.split('/')[0].replace(/\.\d+$/, '.1') } },
      { deviceId: b.deviceId, actionId: 'route.add', input: { name: str(inputs, 'interfaceB')!, network: str(inputs, 'networkA')! }, dependsOn: [2] },
      { deviceId: b.deviceId, actionId: 'routes.reconfigure', input: {}, dependsOn: [3] },
    ];
  },
};

export const MULTI_DEVICE_INTENTS: IntentDescriptor[] = [WIREGUARD_TUNNEL, OPENVPN_SITESITE, BACK_ROUTE];

// --- Catalog (for /discover) --------------------------------------------------------

/** The full action catalog: single-device actions + multi-device intents. */
export function listCatalog(): CatalogEntry[] {
  const fromActions: CatalogEntry[] = listActions().map((a) => ({
    id: a.id,
    label: a.label,
    description: a.description,
    module: a.module,
    riskLevel: a.riskLevel,
    deviceCount: 1 as const,
    timeoutMs: a.timeoutMs,
    retryOnDispatchFailure: a.retryOnDispatchFailure,
    inputSchema: a.inputSchema,
  }));
  const fromIntents: CatalogEntry[] = MULTI_DEVICE_INTENTS.map((i) => ({
    id: i.id,
    label: i.label,
    description: i.description,
    module: i.module,
    riskLevel: i.riskLevel,
    // Report the intent's TRUE device count (e.g. 2 for tunnels) so callers
    // can enforce it — 'N' would hide the requirement from API/webapp.
    deviceCount: i.deviceCount,
    inputSchema: i.inputSchema,
  }));
  return [...fromActions, ...fromIntents];
}

// --- Plan assembly ------------------------------------------------------------------

/** True for action ids that mutate device state (drives snapshot rollback). */
function isDirtyStep(actionId: string): boolean {
  const a = getAction(actionId);
  return !!a && a.riskLevel !== 'read';
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
    const rawSteps = intent.buildSteps(req.intent.inputs ?? {}, req.devices);
    return finalizePlan(
      intentId,
      req.devices.map((d) => ({ deviceId: d.deviceId })),
      intent.provision(req.intent.inputs ?? {}),
      rawSteps,
      isDirtyStep,
      { rollbackStep: () => ({ actionId: 'snapshot.create', input: {} }) }
    );
  }

  // Single-device action → fan out one step per device.
  const action = getAction(intentId);
  if (!action) throw new PlanningError(`Unknown action or intent "${intentId}"`);
  if (req.devices.length === 0) throw new PlanningError('No devices supplied');

  const rawSteps: Omit<PlanStep, 'stepIndex'>[] = req.devices.map((d) => ({
    deviceId: d.deviceId,
    actionId: intentId,
    input: { ...(req.intent.inputs ?? {}) },
  }));
  return finalizePlan(
    intentId,
    req.devices.map((d) => ({ deviceId: d.deviceId })),
    [],
    rawSteps,
    isDirtyStep,
    { rollbackStep: () => ({ actionId: 'snapshot.create', input: {} }) }
  );
}
