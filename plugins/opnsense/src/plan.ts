import { finalizePlan, PlanningError } from '@unm/plugin-sdk';
import type { Plan, PlanDevice as SdkPlanDevice, PlanRequest as SdkPlanRequest, PlanStep, ProvisionRequest, InputSchema, RiskLevel } from '@unm/plugin-sdk';
import * as dnsClient from './client/dns';
import * as dhcpClient from './client/dhcp';
import { createClient, OpnsenseCredentials, OpnsensePorts, OpnsenseTransport } from './client/http';
import { resolveEdition, SyncClass } from './client/editions';
import { getAction, listActions } from './actions/registry';
import { ActionDescriptor, validateInput } from './actions/types';

/**
 * The planner: turns a multi-device INTENT into an ordered, dependency-aware
 * execution PLAN. It is pure with respect to writes — it may issue READ-ONLY
 * probes against appliances (edition/backend detection) but never mutates them,
 * and it never generates key material (that belongs to the secrets provider;
 * the plan only REQUESTS credentials via provisionRequests).
 *
 * Two kinds of intents:
 *  - Single-device actions (registry, deviceCount 1): in a batch they FAN OUT —
 *    one independent step per device. This is the "roll out this change to N
 *    firewalls" case.
 *  - Multi-device intents (below, deviceCount 'N'): composite operations that
 *    span devices (wireguard/ipsec/openvpn tunnels, back-routes). Their steps
*    are built by dedicated builders because cross-device references (peer
 *    public keys, remote addresses) must be resolved at plan time — the plugin
 *    holds all devices' context.
 */

// The SDK's generic PlanRequest is extended with OPNsense transport/edition
// overrides (normally injected by the API via settings).
export interface PlanRequest extends SdkPlanRequest<OpnsenseCredentials> {
  transport?: OpnsenseTransport;
  /** Configured endpoint ports (normally injected by the API via settings). */
  ports?: OpnsensePorts;
  /** Plugin option overrides (normally injected by the API via settings). */
  editionOverride?: string;
  dnsBackend?: 'auto' | 'dnsmasq' | 'unbound';
  dhcpBackend?: 'auto' | 'dnsmasq' | 'kea';
}

// A plan device carrying OPNsense credentials (primary secret fields only).
type PlanDevice = SdkPlanDevice<OpnsenseCredentials>;

// Shared plan contract types + error (re-exported so index.ts keeps its imports).
export type { Plan, PlanDevice };
export { PlanningError };

// --- Per-device context (lazy, memoized probes) ---------------------------------

interface DeviceContext {
  edition: 'ce' | 'be';
  syncClasses: SyncClass[];
  dnsBackend: dnsClient.DnsBackend;
  dhcpBackend: dhcpClient.DhcpBackend;
}

/**
 * Resolves a device's runtime context (edition + DNS/DHCP backends). Probes are
 * issued LAZILY and memoized per host within one planning run, so the common
 * single-device case costs nothing extra. All probes are read-only and
 * best-effort — failures fall back to CE / dnsmasq defaults.
 */
async function resolveDeviceContext(
  device: PlanDevice,
  req: PlanRequest,
  memo: Map<string, DeviceContext>
): Promise<DeviceContext> {
  const key = `${device.managementAddress}:${device.deviceId}`;
  const hit = memo.get(key);
  if (hit) return hit;

  const client = createClient(device.managementAddress, device.credentials, req.transport, req.ports);
  const [editionInfo, dnsBackend, dhcpBackend] = await Promise.all([
    resolveEdition(client, device.managementAddress, req.editionOverride),
    req.dnsBackend && req.dnsBackend !== 'auto' ? Promise.resolve(req.dnsBackend) : dnsClient.detectDnsBackend(client),
    req.dhcpBackend && req.dhcpBackend !== 'auto' ? Promise.resolve(req.dhcpBackend) : dhcpClient.detectDhcpBackend(client),
  ]);

  const ctx: DeviceContext = {
    edition: editionInfo.edition,
    syncClasses: editionInfo.classes,
    dnsBackend,
    dhcpBackend,
  };
  memo.set(key, ctx);
  return ctx;
}

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
  label: 'Create WireGuard tunnel between two firewalls',
  description:
    'Provisions one key pair per endpoint (via the secrets provider), creates a server on each side, adds the peer with the REMOTE public key + endpoint address on both sides, then reloads the wireguard service. Both endpoints must be reachable at their management addresses.',
  module: 'WireGuard',
  riskLevel: 'write',
  deviceCount: 2,
  inputSchema: {
    name: { type: 'string', required: true, description: 'Tunnel/server name (same on both sides)' },
    subnet: { type: 'string', required: true, description: 'Tunnel subnet, e.g. 10.255.0.0/24' },
    listenPort: { type: 'number', min: 1, max: 65535, default: 51820 },
    interfaceA: { type: 'string', description: 'Bind interface on device A (default wan)' },
    interfaceB: { type: 'string', description: 'Bind interface on device B (default wan)' },
    allowedSubnets: { type: 'array', items: { type: 'string' }, description: 'CIDRs each side may reach through the tunnel (applied to both peers unless overridden)' },
    allowedSubnetsA: { type: 'array', items: { type: 'string' }, description: 'Override: subnets reachable THROUGH device A (advertised on B\'s peer entry)' },
    allowedSubnetsB: { type: 'array', items: { type: 'string' }, description: 'Override: subnets reachable THROUGH device B (advertised on A\'s peer entry)' },
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
    const defaultSubnets = Array.isArray(inputs.allowedSubnets) ? (inputs.allowedSubnets as string[]) : [];
    // Subnets advertised on the REMOTE side's peer entry: what you can reach THROUGH that remote.
    const throughA = Array.isArray(inputs.allowedSubnetsA) ? (inputs.allowedSubnetsA as string[]) : defaultSubnets;
    const throughB = Array.isArray(inputs.allowedSubnetsB) ? (inputs.allowedSubnetsB as string[]) : defaultSubnets;

    // Step layout: 0=A.server, 1=B.server, 2=A.peer(dep 0), 3=B.peer(dep 1), 4=A.reconf(dep 2), 5=B.reconf(dep 3)
    return [
      {
        deviceId: a.deviceId,
        actionId: 'wireguard.server.set',
        input: { name, subnet, listenPort, interface: str(inputs, 'interfaceA') ?? 'wan', credentialRef: 'keyA' },
        secretRefs: ['keyA'],
      },
      {
        deviceId: b.deviceId,
        actionId: 'wireguard.server.set',
        input: { name, subnet, listenPort, interface: str(inputs, 'interfaceB') ?? 'wan', credentialRef: 'keyB' },
        secretRefs: ['keyB'],
      },
      {
        deviceId: a.deviceId,
        actionId: 'wireguard.peer.add',
        input: { name: `${name}-to-${b.managementAddress}`, endpoint: b.managementAddress, allowedSubnets: throughB, credentialRef: 'keyB', serverUuid: '${steps[0].result.details.uuid}' },
        dependsOn: [0],
        secretRefs: ['keyB'],
      },
      {
        deviceId: b.deviceId,
        actionId: 'wireguard.peer.add',
        input: { name: `${name}-to-${a.managementAddress}`, endpoint: a.managementAddress, allowedSubnets: throughA, credentialRef: 'keyA', serverUuid: '${steps[1].result.details.uuid}' },
        dependsOn: [1],
        secretRefs: ['keyA'],
      },
      { deviceId: a.deviceId, actionId: 'wireguard.service.reconfigure', input: {}, dependsOn: [2] },
      { deviceId: b.deviceId, actionId: 'wireguard.service.reconfigure', input: {}, dependsOn: [3] },
    ];
  },
};

const IPSEC_TUNNEL: IntentDescriptor = {
  id: 'ipsec.tunnel.create',
  label: 'Create IPsec tunnel between two firewalls',
  description:
    'Provisions one shared PSK (via the secrets provider), adds a swanctl connection on each side pointing at the peer\'s public address with both networks, then reloads the ipsec service.',
  module: 'IPsec',
  riskLevel: 'write',
  deviceCount: 2,
  inputSchema: {
    name: { type: 'string', required: true },
    localNetworkA: { type: 'string', description: 'Own-side network on device A (CIDR)' },
    remoteNetworkA: { type: 'string', description: 'Peer-side network as seen from A (usually B\'s LAN, CIDR)' },
    localNetworkB: { type: 'string' },
    remoteNetworkB: { type: 'string' },
  },
  provision: () => [{ ref: 'psk', type: 'tunnelPsk', label: 'IPsec pre-shared key' }],
  buildSteps: (inputs, devices) => {
    const [a, b] = devices;
    const name = str(inputs, 'name')!;
    return [
      {
        deviceId: a.deviceId,
        actionId: 'ipsec.connection.add',
        input: {
          name,
          remoteAddress: b.managementAddress,
          localNetwork: str(inputs, 'localNetworkA') ?? '',
          remoteNetwork: str(inputs, 'remoteNetworkA') ?? '',
          credentialRef: 'psk',
        },
        secretRefs: ['psk'],
      },
      {
        deviceId: b.deviceId,
        actionId: 'ipsec.connection.add',
        input: {
          name,
          remoteAddress: a.managementAddress,
          localNetwork: str(inputs, 'localNetworkB') ?? '',
          remoteNetwork: str(inputs, 'remoteNetworkB') ?? '',
          credentialRef: 'psk',
        },
        secretRefs: ['psk'],
      },
      { deviceId: a.deviceId, actionId: 'ipsec.service.reconfigure', input: {}, dependsOn: [0] },
      { deviceId: b.deviceId, actionId: 'ipsec.service.reconfigure', input: {}, dependsOn: [1] },
    ];
  },
};

const OPENVPN_SITESITE: IntentDescriptor = {
  id: 'openvpn.sitesite.create',
  label: 'Create OpenVPN site-to-site link between two firewalls',
  description:
    'Provisions one certificate bundle (CA + cert + key, via the secrets provider), creates an instance on each side and reloads the openvpn service. The caller supplies a pre-built profile or lets the provider generate a self-signed CA.',
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
  label: 'Create forward route + back-route between two firewalls (SD-LAN/WAN)',
  description:
    'The classic SD-WAN routing pair: on device A a gateway + forward route toward the remote network; on device B a gateway + BACK-ROUTE toward the origin LAN so return traffic is routed correctly. Both modules are reconfigured per side.',
  module: 'Routing',
  riskLevel: 'write',
  deviceCount: 2,
  inputSchema: {
    /** Remote network to route from A (e.g. B\'s LAN). */
    remoteNetwork: { type: 'string', required: true },
    gatewayAName: { type: 'string', required: true },
    gatewayAInterface: { type: 'string', required: true, description: 'Interface on A facing the link to B' },
    gatewayAIp: { type: 'string', required: true, description: 'Next-hop IP for A\'s new gateway' },
    /** Origin LAN reachable from A (the back-route target on B). */
    originNetwork: { type: 'string', required: true },
    gatewayBName: { type: 'string', required: true },
    gatewayBInterface: { type: 'string', required: true, description: 'Interface on B facing the link to A' },
    gatewayBIp: { type: 'string', required: true, description: 'Next-hop IP for B\'s new gateway' },
  },
  provision: () => [],
  buildSteps: (inputs, devices) => {
    const [a, b] = devices;
    return [
      // Device A: forward path
      { deviceId: a.deviceId, actionId: 'gateway.add', input: { name: str(inputs, 'gatewayAName')!, interface: str(inputs, 'gatewayAInterface')!, gatewayIp: str(inputs, 'gatewayAIp')! } },
      { deviceId: a.deviceId, actionId: 'route.add', input: { network: str(inputs, 'remoteNetwork')!, gatewayName: str(inputs, 'gatewayAName')! }, dependsOn: [0] },
      { deviceId: a.deviceId, actionId: 'gateways.reconfigure', input: {}, dependsOn: [0] },
      { deviceId: a.deviceId, actionId: 'routes.reconfigure', input: {}, dependsOn: [1] },
      // Device B: back-route path
      { deviceId: b.deviceId, actionId: 'gateway.add', input: { name: str(inputs, 'gatewayBName')!, interface: str(inputs, 'gatewayBInterface')!, gatewayIp: str(inputs, 'gatewayBIp')! } },
      { deviceId: b.deviceId, actionId: 'route.add', input: { network: str(inputs, 'originNetwork')!, gatewayName: str(inputs, 'gatewayBName')! }, dependsOn: [4] },
      { deviceId: b.deviceId, actionId: 'gateways.reconfigure', input: {}, dependsOn: [4] },
      { deviceId: b.deviceId, actionId: 'routes.reconfigure', input: {}, dependsOn: [5] },
    ];
  },
};

export const MULTI_DEVICE_INTENTS: IntentDescriptor[] = [WIREGUARD_TUNNEL, IPSEC_TUNNEL, OPENVPN_SITESITE, BACK_ROUTE];

const intentById = new Map(MULTI_DEVICE_INTENTS.map((i) => [i.id, i]));

// --- Catalog (for /discover) --------------------------------------------------------

export interface CatalogEntry {
  id: string;
  label: string;
  description?: string;
  module: string;
  riskLevel: RiskLevel;
  /** Exact device count (1 = single-device action, 2 = tunnel intent...). */
  deviceCount: number | 'N';
  beOnly?: boolean;
  timeoutMs?: number;
  /** Flapping guard — false = the plan executor never re-dispatches this action. */
  retryOnDispatchFailure?: boolean;
  inputSchema: InputSchema;
}

/** The full action catalog: single-device actions + multi-device intents. */
export function listCatalog(): CatalogEntry[] {
  const fromActions: CatalogEntry[] = listActions().map((a) => ({
    id: a.id,
    label: a.label,
    description: a.description,
    module: a.module,
    riskLevel: a.riskLevel,
    deviceCount: 1 as const,
    beOnly: a.beOnly,
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

// --- Plan construction ------------------------------------------------------------------

/**
 * Builds an execution plan for the given intent + devices. Throws PlanningError
 * (→ HTTP 400) on invalid requests. May issue read-only probes per device
 * (edition/backend detection), memoized within the run.
 */
export async function buildPlan(req: PlanRequest): Promise<Plan> {
  const { actionId, inputs } = req.intent;
  const devices = req.devices ?? [];
  if (devices.length === 0) throw new PlanningError('At least one device is required');

  // --- Multi-device intent? -----------------------------------------------------
  const intent = intentById.get(actionId);
  if (intent) {
    if (devices.length !== intent.deviceCount) {
      throw new PlanningError(`Intent ${actionId} requires exactly ${intent.deviceCount} devices, got ${devices.length}`);
    }
    const issues = validateInput(intent.inputSchema, inputs ?? {});
    if (issues.length > 0) throw new PlanningError(`Invalid intent input: ${issues.map((i) => `${i.path}: ${i.message}`).join('; ')}`);

    const provisionRequests = intent.provision(inputs ?? {});
    const rawSteps = intent.buildSteps(inputs ?? {}, devices);
    return finalizePlan(actionId, devices, provisionRequests, rawSteps, isDirtyStep, { rollbackStep: () => ({ actionId: 'snapshot.create', input: {} }) });
  }

  // --- Single-device action (fan-out across the batch) -----------------------------
  const action: ActionDescriptor | undefined = getAction(actionId);
  if (!action) {
    throw new PlanningError(
      `Unknown action "${actionId}". Available: ${[...listActions().map((a) => a.id), ...MULTI_DEVICE_INTENTS.map((i) => i.id)].join(', ')}`
    );
  }

  const issues = validateInput(action.inputSchema, inputs ?? {});
  if (issues.length > 0) throw new PlanningError(`Invalid action input: ${issues.map((i) => `${i.path}: ${i.message}`).join('; ')}`);

  // BE-only actions need per-device edition resolution; CE devices get the fallback.
  const memo = new Map<string, DeviceContext>();
  const rawSteps: Omit<PlanStep, 'stepIndex'>[] = [];
  for (const device of devices) {
    let effectiveId = action.id;
    if (action.beOnly) {
      const ctx = await resolveDeviceContext(device, req, memo);
      if (ctx.edition === 'ce') {
        if (!action.ceFallback) throw new PlanningError(`Action ${actionId} requires Business Edition; device ${device.deviceId} is Community Edition and no fallback exists`);
        effectiveId = action.ceFallback;
      }
    }
    // Per-device overrides (PlanRequest.deviceInputs — the rollout wizard's
    // confirmed preflight values, e.g. a different attach point or L3 address
    // per appliance) merge on top of the shared inputs for that device only.
    rawSteps.push({ deviceId: device.deviceId, actionId: effectiveId, input: { ...(inputs ?? {}), ...(req.deviceInputs?.[device.deviceId] ?? {}) } });
  }

  return finalizePlan(actionId, devices, [], rawSteps, isDirtyStep, { rollbackStep: () => ({ actionId: 'snapshot.create', input: {} }) });
}

/** True when a step's action mutates the appliance (write/dangerous). */
function isDirtyStep(stepActionId: string): boolean {
  const a = getAction(stepActionId);
  return !!a && a.riskLevel !== 'read';
}
