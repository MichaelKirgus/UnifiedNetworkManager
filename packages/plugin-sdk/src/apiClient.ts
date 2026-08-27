/**
 * createApiClient — the axios bootstrap for plugins that talk BACK to the UNM
 * API's internal plugin routes (basic-auth, secrets-provider). Previously
 * near-verbatim in both.
 */

import axios, { AxiosInstance } from 'axios';

export interface ApiClientOptions {
  /** Base URL of the API (default http://localhost:3000/v1; set to http://api:3000/v1 inside Docker). */
  baseUrl?: string;
  /** Shared plugin API key (default: PLUGIN_API_KEY env). */
  apiKey?: string;
  timeoutMs?: number;
}

export function createApiClient(opts: ApiClientOptions = {}): AxiosInstance {
  const baseURL = (opts.baseUrl ?? process.env.UNM_API_URL ?? 'http://localhost:3000/v1').replace(/\/+$/, '');
  const apiKey = opts.apiKey ?? process.env.PLUGIN_API_KEY;
  return axios.create({
    baseURL,
    timeout: opts.timeoutMs ?? 5000,
    headers: apiKey ? { 'x-plugin-api-key': apiKey } : undefined,
  });
}

/** True when the error is an axios 404 response (i.e. "not found"). */
export function isNotFound(err: unknown): boolean {
  return axios.isAxiosError(err) && err.response?.status === 404;
}
