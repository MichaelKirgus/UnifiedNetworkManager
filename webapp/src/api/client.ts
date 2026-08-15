const BASE = import.meta.env.VITE_API_URL ?? 'http://localhost:3000/v1';

export interface LoginResponse {
  challengeToken: string;
  twoFactorRequired: boolean;
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
}

export interface TelemetrySnapshot {
  deviceId: string;
  collectedAt: string;
  health: string;
  metrics: Record<string, number>;
}

export interface Plugin {
  id: string;
  name: string;
  version: string;
  vendors: string[];
  capabilities: string[];
  endpoint: string;
  authType: string;
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
  login: (body: { username: string; password: string }) =>
    apiFetch<LoginResponse>('/auth/login', { method: 'POST', body: JSON.stringify(body) }),
  verify2fa: (body: { challengeToken: string; totpCode: string }) =>
    apiFetch<VerifyResponse>('/auth/2fa/verify', { method: 'POST', body: JSON.stringify(body) }),
  devices: () => apiFetch<Device[]>('/devices'),
  createDevice: (body: unknown) =>
    apiFetch<Device>('/devices', { method: 'POST', body: JSON.stringify(body) }),
  monitoring: (deviceId: string) => apiFetch<TelemetrySnapshot>(`/devices/${deviceId}/monitoring`),
  plugins: () => apiFetch<Plugin[]>('/plugins'),
  createPlugin: (body: unknown) =>
    apiFetch<Plugin>('/plugins', { method: 'POST', body: JSON.stringify(body) }),
  configJobs: (deviceId: string, body: unknown) =>
    apiFetch<ConfigJob>(`/devices/${deviceId}/config-jobs`, { method: 'POST', body: JSON.stringify(body) }),
  allConfigJobs: () => apiFetch<ConfigJob[]>('/config-jobs'),
  getConfigJob: (jobId: string) => apiFetch<ConfigJob>(`/config-jobs/${jobId}`),
};
