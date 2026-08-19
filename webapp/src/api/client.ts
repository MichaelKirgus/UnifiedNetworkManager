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
  roles: string[];
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

export interface DeviceCreateRequest {
  name: string;
  vendor: string;
  deviceType: string;
  managementAddress: string;
  site?: string;
  /** At least one plugin assignment; the first becomes primary. */
  plugins: DevicePluginAssignmentInput[];
}

export interface Device {
  id: string;
  name: string;
  vendor: string;
  deviceType: string;
  managementAddress: string;
  site?: string;
  status: string;
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
  devices: () => apiFetch<Device[]>('/devices'),
  createDevice: (body: DeviceCreateRequest) =>
    apiFetch<Device & { plugins?: DevicePluginAssignment[] }>('/devices', {
      method: 'POST',
      body: JSON.stringify(body),
    }),
  /** Update identity fields of an existing device (plugins are managed separately). */
  updateDevice: (deviceId: string, body: Partial<Pick<Device, 'name' | 'vendor' | 'deviceType' | 'managementAddress'>> & { site?: string | null }) =>
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
};
