const BASE = import.meta.env.VITE_API_URL ?? 'http://localhost:3000/v1';

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

export interface Device {
  id: string;
  name: string;
  vendor: string;
  deviceType: string;
  pluginId: string;
  managementAddress: string;
  site?: string;
  status: string;
  apiKey?: string;
  apiSecret?: string;
  /** Headline metrics (marked `summary` by the plugin) for inline table display. */
  summaryMetrics?: SummaryMetric[];
}

export interface TelemetrySnapshot {
  deviceId: string;
  collectedAt: string;
  health: string;
  metrics: Record<string, number>;  metricDescriptors?: MetricDescriptor[];}

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

export interface ConfigJob {
  id: string;
  deviceId: string;
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
    try {
      const body = await res.json();
      if (body?.error) message = body.error;
    } catch {
      // ignore body parse errors, fall back to generic message
    }
    throw new Error(message);
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
  createDevice: (body: unknown) =>
    apiFetch<Device>('/devices', { method: 'POST', body: JSON.stringify(body) }),
  monitoring: (deviceId: string) => apiFetch<TelemetrySnapshot>(`/devices/${deviceId}/monitoring`),
  deviceTelemetry: (deviceId: string, limit = 30) =>
    apiFetch<{ deviceId: string; history: { collectedAt: string; health: string; metrics: Record<string, unknown> }[] }>(
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
};
