const BASE = import.meta.env.VITE_API_URL ?? 'http://localhost:3000/v1';

/** API error that may carry per-field validation messages (e.g. plugin settings). */
export class ApiError extends Error {
  status: number;
  fieldErrors?: Record<string, string>;
  constructor(message: string, status: number, fieldErrors?: Record<string, string>) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.fieldErrors = fieldErrors;
  }
}

export interface Secret {
  id: string;
  label: string;
  type: string;
  providerId?: string | null;
  createdAt: string;
  expiresAt?: string;
  username: string;
}

export interface SecretField {
  name: string;
  label: string;
  input: 'text' | 'password' | 'select';
  secret?: boolean;
  required?: boolean;
  options?: string[];
}

export interface SecretType {
  type: string;
  label: string;
  fields: SecretField[];
}

export interface SecretProvider {
  id: string;
  name: string;
  version: string;
  endpoint: string;
  online: boolean;
  secretTypes: SecretType[];
}

export interface LoginResponse {
  challengeToken: string;
  twoFactorRequired: boolean;
}

export interface AuthFlow {
  flow: string;
}

export interface AuthRedirect {
  redirectUrl: string;
}

export interface VerifyResponse {
  accessToken: string;
  expiresIn: number;
  username: string;
  roles: string[];
  /** Effective permission set (explicit grants + role-derived). */
  permissions: string[];
}

/** One row of the device ↔ plugin join table (a device can have several). */
export interface DevicePluginAssignment {
  id: string;
  deviceId: string;
  pluginId: string;
  /** Credential source for this assignment (null = no credentials). */
  secretId?: string | null;
  isPrimary: boolean;
  createdAt: string;
  // Enriched fields returned by the list endpoints:
  pluginName?: string;
  pluginVersion?: string;
  pluginEndpoint?: string;
  pluginOnline?: boolean;
  secretLabel?: string | null;
}

export interface DevicePluginAssignmentInput {
  pluginId: string;
  secretId?: string | null;
  isPrimary?: boolean;
}

/** A device address as presented by the API (primary flag included). */
export interface DeviceAddress {
  /** IPv4, IPv6 literal, or DNS name (no scheme). */
  address: string;
  /** True for the device's managementAddress. */
  isPrimary: boolean;
  /** Row id of a secondary IP; null/undefined for the primary. */
  id?: string | null;
}

/** One row of the device_ips table (a secondary IP). */
export interface DeviceIpRow {
  id: string;
  deviceId: string;
  address: string;
  createdAt?: string;
}

/** A managed site (name + description + address/country/timezone/GPS). */
export interface Site {
  id: string;
  name: string;
  description?: string | null;
  address?: string | null;
  /** ISO-3166-1 alpha-2 country code, e.g. "DE". */
  country?: string | null;
  /** IANA timezone identifier, e.g. "Europe/Berlin". */
  timezone?: string | null;
  /** GPS location (WGS84 decimal degrees) — set together or both absent. */
  latitude?: number | null;
  longitude?: number | null;
  createdAt?: string;
}

export interface SiteCreateRequest {
  name: string;
  description?: string;
  address?: string;
  /** ISO-3166-1 alpha-2 country code, e.g. "DE". */
  country?: string;
  timezone?: string;
  /** GPS location — all-or-nothing (both set or both omitted/null). */
  latitude?: number | null;
  longitude?: number | null;
}

/** One configured network row from the cross-device inventory view. */
export interface NetworkRow {
  deviceId: string;
  deviceName?: string | null;
  managementAddress?: string | null;
  siteName?: string | null;
  pluginId: string;
  /** Display name of the plugin instance that collected this row (e.g. "OPNsense Plugin (site-a)"). */
  pluginName?: string | null;
  /** Interface name on the device (e.g. lan, vlan100). */
  name: string;
  /** IP address; null when the interface has no IP configured. */
  ip?: string | null;
  prefix?: number | null;
  version?: 'v4' | 'v6' | null;
  vlanId?: number | null;
  mac?: string | null;
  status?: string | null;
  collectedAt: string;
}

/** One discovered host from the cross-device inventory view.
 * Rows with the same MAC on one device+plugin are merged into a single row —
 * a dual-stack device appears once with both its IPv4 and IPv6 addresses. */
export interface HostRow {
  deviceId: string;
  deviceName?: string | null;
  managementAddress?: string | null;
  siteName?: string | null;
  pluginId: string;
  /** Display name of the plugin instance that observed this host. */
  pluginName?: string | null;
  mac: string;
  /** All known addresses of this host, IPv4 first. */
  ips: string[];
  /** Discovery sources that reported this MAC (e.g. arp + ndp for a dual-stack host). */
  sources: ('arp' | 'ndp' | 'dhcp')[];
  hostname?: string | null;
  manufacturer?: string | null;
  /** Interface(s) on the observing device where the host was seen (comma-joined when several). */
  intf?: string | null;
  /** Lease expiry (when a DHCP lease is known for this MAC). */
  expiry?: string | null;
  lastSeenAt: string;
}

/** A user account (never includes password hashes or TOTP secrets). */
export interface User {
  id: string;
  username: string;
  roles: string[];
  /** Explicit permission grants only (role-derived ones are added at login). */
  permissions: string[];
  twoFactorEnabled: boolean;
  createdAt?: string;
}

/** TOTP enrollment payload returned by user-create / totp-enroll. */
export interface TotpEnrollment {
  /** Base32 TOTP secret (shown as text + QR code). */
  secret: string;
  /** otpauth:// URI for authenticator-app setup. */
  otpauthUri: string;
}

/** A named bundle of permissions (roles are expanded at login time). */
export interface Role {
  name: string;
  description?: string | null;
  permissions: string[];
  createdAt?: string;
}

export interface PermissionCatalog {
  permissions: { id: string; description: string }[];
  roles: { name: string; description?: string | null; permissions: string[] }[];
}

export interface DeviceCreateRequest {
  name: string;
  vendor: string;
  deviceType: string;
  /** Primary address — IPv4, IPv6 literal, or DNS name (no scheme). */
  managementAddress: string;
  /** Optional assigned site. */
  siteId?: string | null;
  /** Optional secondary IPs registered at creation time. */
  ips?: string[];
  /** At least one plugin assignment; the first becomes primary. */
  plugins: DevicePluginAssignmentInput[];
}

export interface Device {
  id: string;
  name: string;
  vendor: string;
  deviceType: string;
  managementAddress: string;
  siteId?: string | null;
  /** Display name of the assigned site (null = unassigned). */
  siteName?: string | null;
  status: string;
  /** All addresses, primary first (list endpoints include this). */
  ips?: DeviceAddress[];
  /** Assigned plugins (list endpoints include this). */
  plugins?: DevicePluginAssignment[];
  /** Headline metrics (marked `summary` by the plugin) for inline table display. */
  summaryMetrics?: SummaryMetric[];
}

/** One plugin's monitoring snapshot for a device. */
export interface PluginTelemetrySnapshot {
  pluginId: string;
  collectedAt?: string | null;
  health: string;
  metrics: Record<string, unknown>;
  metricDescriptors?: MetricDescriptor[];
}

/** GET /devices/:id/monitoring — one snapshot per assigned plugin. */
export interface DeviceMonitoring {
  deviceId: string;
  /** Overall device health = worst-wins across all assignments. */
  health: string;
  snapshots: PluginTelemetrySnapshot[];
}

export interface Plugin {
  id: string;
  name: string;
  version: string;
  vendors: string[];
  capabilities: string[];
  endpoint: string;
  authType: string;
  lastSeenAt?: string | null;
}

export interface MetricDescriptor {
  key: string;
  label: string;
  unit?: string;
  format?: 'bytes' | 'bits' | 'duration' | 'number' | 'text';
  type: 'number' | 'string' | 'boolean' | 'enum';
  visualization: 'gauge' | 'plot' | 'text' | 'table';
  group?: string;
  min?: number;
  max?: number;
  color?: string;
  rows?: string[];
  /** Column field names for `table` visualizations (see MetricView). */
  columns?: string[];
  summary?: boolean;
  intervalMs?: number;
}

/** A headline metric shown inline in the device overview table. */
export interface SummaryMetric {
  key: string;
  label: string;
  value: unknown;
  unit?: string;
  format?: 'bytes' | 'bits' | 'duration' | 'number' | 'text';
  visualization: 'gauge' | 'plot' | 'text' | 'table';
  min?: number;
  max?: number;
  color?: string;
}

export interface PluginMetrics {
  pluginId: string;
  metrics: MetricDescriptor[];
}

/** A single option a plugin declares in its /discover response. */
export interface PluginOptionBase {
  key: string;
  label: string;
  type: 'string' | 'integer' | 'boolean';
  default?: unknown;
  description?: string;
  docsUrl?: string;
}

export interface StringOption extends PluginOptionBase {
  type: 'string';
  pattern?: string;
  minLength?: number;
  maxLength?: number;
}

export interface IntegerOption extends PluginOptionBase {
  type: 'integer';
  min?: number;
  max?: number;
}

export interface BooleanOption extends PluginOptionBase {
  type: 'boolean';
}

export type PluginOptionDescriptor = StringOption | IntegerOption | BooleanOption;

/** GET /plugins/:id/options response. */
export interface PluginOptionsResponse {
  pluginId: string;
  options: PluginOptionDescriptor[];
  /** Stored overrides only (key -> value). Empty when nothing was set. */
  values: Record<string, unknown>;
  /** Defaults merged with stored overrides — what the form should initialize to. */
  effectiveValues: Record<string, unknown>;
}

/** Per-field validation errors returned by PUT /plugins/:id/settings on failure. */
export interface PluginSettingsError {
  error: string;
  fieldErrors?: Record<string, string>;
}

export interface ConfigJob {
  id: string;
  deviceId: string;
  /** The assignment that executes this job. */
  pluginId?: string;
  action: string;
  status: string;
  result?: Record<string, unknown>;
  createdAt: string;
  finishedAt?: string;
}

// --- Execution plans ---------------------------------------------------------

/** One property of an action's input schema (JSON-Schema subset from the plugin). */
export interface InputSchemaProperty {
  type: 'string' | 'number' | 'boolean' | 'array' | 'object';
  label?: string;
  description?: string;
  required?: boolean;
  default?: unknown;
  pattern?: string;
  min?: number;
  max?: number;
  enum?: (string | number)[];
  items?: InputSchemaProperty;
  properties?: Record<string, InputSchemaProperty>;
}

/** A map of property name → schema (the catalog's `inputSchema`). */
export type InputSchema = Record<string, InputSchemaProperty>;

/** One entry of a plugin's action catalog (from /discover `actions`). */
export interface CatalogEntry {
  id: string;
  label: string;
  description?: string;
  module?: string;
  riskLevel?: 'read' | 'write' | 'dangerous';
  /** Exact device count for multi-device intents, or 'N' for fan-out. */
  deviceCount?: number | 'N';
  beOnly?: boolean;
  timeoutMs?: number;
  inputSchema?: InputSchema;
}

/** A provisioned secret attached to a plan (metadata only — never material). */
export interface PlanProvisionedSecret {
  ref: string;
  secretId: string;
  label?: string | null;
  type?: string;
}

/** One executable step of a plan. */
export interface PlanStep {
  id: string;
  planId: string;
  /** Final ordering; doubles as topological order. */
  stepIndex: number;
  deviceId: string;
  actionId: string;
  input: Record<string, unknown>;
  dependsOn?: number[];
  secretRefs?: string[];
  bestEffort?: boolean;
  status: 'pending' | 'running' | 'succeeded' | 'failed' | 'skipped';
  result?: Record<string, unknown> | null;
  startedAt?: string | null;
  finishedAt?: string | null;
}

/** A persisted execution plan (list shape; detail adds `steps`). */
export interface Plan {
  id: string;
  pluginId: string;
  intentActionId: string;
  status: 'draft' | 'ready' | 'executing' | 'succeeded' | 'failed' | 'cancelled';
  provisionedSecrets: PlanProvisionedSecret[];
  error?: string | null;
  createdBy: string;
  createdAt: string;
  updatedAt: string;
  finishedAt?: string | null;
  /** Present on list responses. */
  stepCount?: number;
  stepsDone?: number;
}

/** GET /plans/:id response — plan + ordered steps. */
export interface PlanDetail extends Plan {
  steps: PlanStep[];
}

function getToken(): string | null {
  return localStorage.getItem('accessToken');
}

async function apiFetch<T>(path: string, opts?: RequestInit): Promise<T> {
  const token = getToken();
  const res = await fetch(`${BASE}${path}`, {
    ...opts,
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { Authorization: 'Bearer ' + token } : {}),
      ...opts?.headers,
    },
  });
  if (!res.ok) {
    let message = `API error ${res.status}`;
    let fieldErrors: Record<string, string> | undefined;
    try {
      const body = await res.json();
      if (body?.error) message = body.error;
      if (body?.fieldErrors && typeof body.fieldErrors === 'object') fieldErrors = body.fieldErrors;
    } catch {
      // ignore body parse errors, fall back to generic message
    }
    throw new ApiError(message, res.status, fieldErrors);
  }
  if (res.status === 204) {
    return undefined as T;
  }
  return res.json();
}

export const api = {
  authFlow: () => apiFetch<AuthFlow>('/auth/flow'),
  authRedirect: () => apiFetch<AuthRedirect>('/auth/redirect'),
  login: (body: { username: string; password: string }) =>
    apiFetch<LoginResponse>('/auth/login', { method: 'POST', body: JSON.stringify(body) }),
  verify2fa: (body: { challengeToken: string; totpCode: string }) =>
    apiFetch<VerifyResponse>('/auth/2fa/verify', { method: 'POST', body: JSON.stringify(body) }),
  /** The caller's own profile (no users:read needed). */
  me: () => apiFetch<User & { effectivePermissions: string[] }>('/auth/me'),
  devices: () => apiFetch<Device[]>('/devices'),
  createDevice: (body: DeviceCreateRequest) =>
    apiFetch<Device & { plugins?: DevicePluginAssignment[] }>('/devices', {
      method: 'POST',
      body: JSON.stringify(body),
    }),
  /** Update identity fields of an existing device (plugins are managed separately). */
  updateDevice: (deviceId: string, body: Partial<Pick<Device, 'name' | 'vendor' | 'deviceType' | 'managementAddress'>> & { siteId?: string | null }) =>
    apiFetch<Device>(`/devices/${deviceId}`, { method: 'PATCH', body: JSON.stringify(body) }),
  // Device ↔ plugin assignments.
  devicePlugins: (deviceId: string) =>
    apiFetch<{ deviceId: string; plugins: DevicePluginAssignment[] }>(`/devices/${deviceId}/plugins`),
  addDevicePlugin: (deviceId: string, body: DevicePluginAssignmentInput) =>
    apiFetch<DevicePluginAssignment>(`/devices/${deviceId}/plugins`, {
      method: 'POST',
      body: JSON.stringify(body),
    }),
  removeDevicePlugin: (deviceId: string, pluginId: string) =>
    apiFetch<void>(`/devices/${deviceId}/plugins/${pluginId}`, { method: 'DELETE' }),
  /** Promote an assigned plugin to primary (demotes the current one). */
  setPrimaryPlugin: (deviceId: string, pluginId: string) =>
    apiFetch<DevicePluginAssignment>(`/devices/${deviceId}/plugins/${pluginId}`, { method: 'PATCH' }),
  /** Update an existing assignment's credentials and/or primary flag. */
  updateDevicePlugin: (deviceId: string, pluginId: string, body: { secretId?: string | null; isPrimary?: boolean }) =>
    apiFetch<DevicePluginAssignment>(`/devices/${deviceId}/plugins/${pluginId}`, { method: 'PATCH', body: JSON.stringify(body) }),
  // Device IP addresses (primary = managementAddress; secondaries managed here).
  deviceIps: (deviceId: string) =>
    apiFetch<{ deviceId: string; ips: DeviceAddress[] }>(`/devices/${deviceId}/ips`),
  addDeviceIp: (deviceId: string, address: string) =>
    apiFetch<DeviceIpRow>(`/devices/${deviceId}/ips`, { method: 'POST', body: JSON.stringify({ address }) }),
  removeDeviceIp: (deviceId: string, ipId: string) =>
    apiFetch<void>(`/devices/${deviceId}/ips/${ipId}`, { method: 'DELETE' }),
  /** Delete a device and everything that hangs off it. 409 while plans reference it. */
  deleteDevice: (deviceId: string) =>
    apiFetch<void>(`/devices/${deviceId}`, { method: 'DELETE' }),
  // Per-device settings overrides (inherit global → override per device).
  devicePluginOptions: (deviceId: string, pluginId: string) =>
    apiFetch<PluginOptionsResponse>(`/devices/${deviceId}/plugins/${pluginId}/options`),
  saveDevicePluginSettings: (deviceId: string, pluginId: string, settings: Record<string, unknown>) =>
    apiFetch<PluginOptionsResponse>(`/devices/${deviceId}/plugins/${pluginId}/settings`, {
      method: 'PUT',
      body: JSON.stringify({ settings }),
    }),
  resetDevicePluginSettings: (deviceId: string, pluginId: string) =>
    apiFetch<PluginOptionsResponse>(`/devices/${deviceId}/plugins/${pluginId}/settings`, { method: 'DELETE' }),
  monitoring: (deviceId: string) => apiFetch<DeviceMonitoring>(`/devices/${deviceId}/monitoring`),
  deviceTelemetry: (deviceId: string, limit = 30) =>
    apiFetch<{ deviceId: string; history: { collectedAt: string; health: string; pluginId?: string; metrics: Record<string, unknown> }[] }>(
      `/devices/${deviceId}/telemetry?limit=${limit}`
    ),
  plugins: () => apiFetch<Plugin[]>('/plugins'),
  configJobs: (deviceId: string, body: unknown) =>
    apiFetch<ConfigJob>(`/devices/${deviceId}/config-jobs`, { method: 'POST', body: JSON.stringify(body) }),
  allConfigJobs: () => apiFetch<ConfigJob[]>('/config-jobs'),
  getConfigJob: (jobId: string) => apiFetch<ConfigJob>(`/config-jobs/${jobId}`),
  secrets: () => apiFetch<Secret[]>('/secrets'),
  secretProviders: () => apiFetch<SecretProvider[]>('/secrets/providers'),
  createSecret: (body: {
    type: string;
    providerId?: string;
    fields: Record<string, string>;
    label: string;
    expiresAt?: string;
  }) => apiFetch<Secret>('/secrets', { method: 'POST', body: JSON.stringify(body) }),
  deleteSecret: (id: string) =>
    apiFetch<void>(`/secrets/${id}`, { method: 'DELETE' }),
  // Sites.
  sites: () => apiFetch<Site[]>('/sites'),
  createSite: (body: SiteCreateRequest) =>
    apiFetch<Site>('/sites', { method: 'POST', body: JSON.stringify(body) }),
  updateSite: (id: string, body: Partial<SiteCreateRequest>) =>
    apiFetch<Site>(`/sites/${id}`, { method: 'PATCH', body: JSON.stringify(body) }),
  deleteSite: (id: string) => apiFetch<void>(`/sites/${id}`, { method: 'DELETE' }),
  // Cross-device inventory views (Networks + Hosts pages).
  networks: (params?: { deviceId?: string; siteId?: string }) => {
    const qs = new URLSearchParams();
    if (params?.deviceId) qs.set('deviceId', params.deviceId);
    if (params?.siteId) qs.set('siteId', params.siteId);
    const suffix = qs.toString() ? `?${qs.toString()}` : '';
    return apiFetch<NetworkRow[]>(`/networks${suffix}`);
  },
  hosts: (params?: { deviceId?: string; siteId?: string; source?: 'arp' | 'ndp' | 'dhcp' }) => {
    const qs = new URLSearchParams();
    if (params?.deviceId) qs.set('deviceId', params.deviceId);
    if (params?.siteId) qs.set('siteId', params.siteId);
    if (params?.source) qs.set('source', params.source);
    const suffix = qs.toString() ? `?${qs.toString()}` : '';
    return apiFetch<HostRow[]>(`/hosts${suffix}`);
  },
  // Users + permission catalog.
  users: () => apiFetch<User[]>('/users'),
  createUser: (body: { username: string; password: string; roles?: string[]; permissions?: string[] }) =>
    apiFetch<{ user: User; enrollment: TotpEnrollment }>('/users', { method: 'POST', body: JSON.stringify(body) }),
  updateUser: (id: string, body: { roles?: string[]; permissions?: string[] }) =>
    apiFetch<User>(`/users/${id}`, { method: 'PATCH', body: JSON.stringify(body) }),
  deleteUser: (id: string) => apiFetch<void>(`/users/${id}`, { method: 'DELETE' }),
  // Credential management (self needs users:self-credentials, others need users:manage-credentials).
  resetUserPassword: (id: string, body: { newPassword: string; currentPassword?: string }) =>
    apiFetch<User>(`/users/${id}/password`, { method: 'POST', body: JSON.stringify(body) }),
  enrollTotp: (id: string) =>
    apiFetch<{ user: User; enrollment: TotpEnrollment }>(`/users/${id}/totp/enroll`, { method: 'POST' }),
  disableTotp: (id: string) => apiFetch<void>(`/users/${id}/totp`, { method: 'DELETE' }),
  permissionCatalog: () => apiFetch<PermissionCatalog>('/permissions'),
  // Roles.
  roles: () => apiFetch<Role[]>('/roles'),
  createRole: (body: { name: string; description?: string; permissions: string[] }) =>
    apiFetch<Role>('/roles', { method: 'POST', body: JSON.stringify(body) }),
  updateRole: (name: string, body: { description?: string | null; permissions?: string[] }) =>
    apiFetch<Role>(`/roles/${encodeURIComponent(name)}`, { method: 'PATCH', body: JSON.stringify(body) }),
  deleteRole: (name: string) => apiFetch<void>(`/roles/${encodeURIComponent(name)}`, { method: 'DELETE' }),
  requiredSecretType: (pluginId: string) =>
    apiFetch<{ requiredSecretType: string | null }>(`/plugins/${pluginId}/required-secret-type`),
  pluginMetrics: (pluginId: string) =>
    apiFetch<PluginMetrics>(`/plugins/${pluginId}/metrics`),
  // Plugin options & settings (descriptor-driven, API-validated).
  pluginOptions: (pluginId: string) =>
    apiFetch<PluginOptionsResponse>(`/plugins/${pluginId}/options`),
  savePluginSettings: (pluginId: string, settings: Record<string, unknown>) =>
    apiFetch<PluginOptionsResponse>(`/plugins/${pluginId}/settings`, {
      method: 'PUT',
      body: JSON.stringify({ settings }),
    }),
  resetPluginSettings: (pluginId: string) =>
    apiFetch<PluginOptionsResponse>(`/plugins/${pluginId}/settings`, { method: 'DELETE' }),
  // Action catalog (drives plan creation).
  pluginActions: (pluginId: string) =>
    apiFetch<{ pluginId: string; actions: CatalogEntry[] }>(`/plugins/${pluginId}/actions`),
  // Execution plans.
  plans: () => apiFetch<Plan[]>('/plans'),
  createPlan: (body: {
    pluginId: string;
    intentActionId: string;
    inputs?: Record<string, unknown>;
    devices: { deviceId: string }[];
  }) => apiFetch<PlanDetail>('/plans', { method: 'POST', body: JSON.stringify(body) }),
  getPlan: (id: string) => apiFetch<PlanDetail>(`/plans/${id}`),
  deletePlan: (id: string) => apiFetch<void>(`/plans/${id}`, { method: 'DELETE' }),
  executePlan: (id: string) => apiFetch<PlanDetail>(`/plans/${id}/execute`, { method: 'POST' }),
  cancelPlan: (id: string) => apiFetch<PlanDetail>(`/plans/${id}/cancel`, { method: 'POST' }),
  addPlanStep: (planId: string, body: {
    deviceId: string;
    actionId: string;
    input?: Record<string, unknown>;
    secretRefs?: string[];
    bestEffort?: boolean;
  }) => apiFetch<PlanDetail>(`/plans/${planId}/steps`, { method: 'POST', body: JSON.stringify(body) }),
  updatePlanStep: (planId: string, stepId: string, body: {
    actionId?: string;
    input?: Record<string, unknown>;
    secretRefs?: string[];
    dependsOn?: number[];
    bestEffort?: boolean;
  }) => apiFetch<PlanDetail>(`/plans/${planId}/steps/${stepId}`, { method: 'PATCH', body: JSON.stringify(body) }),
  removePlanStep: (planId: string, stepId: string) =>
    apiFetch<PlanDetail>(`/plans/${planId}/steps/${stepId}`, { method: 'DELETE' }),
  reorderPlanSteps: (planId: string, from: number, to: number) =>
    apiFetch<PlanDetail>(`/plans/${planId}/steps/reorder`, { method: 'PATCH', body: JSON.stringify({ from, to }) }),
  regeneratePlanSecret: (planId: string, ref: string) =>
    apiFetch<{ id: string; type?: string }>(`/plans/${planId}/secrets/${encodeURIComponent(ref)}/regenerate`, { method: 'POST' }),
};
