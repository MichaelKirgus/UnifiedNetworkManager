import { AxiosInstance } from 'axios';
import { get, post, OpnsenseApiResult } from './http';

/**
 * NTP (ntpd) module: service status + settings. Docs: development/api/core/ntpd.html.
 */

/** GET /api/ntpd/service/status — ntpd sync status. */
export function getServiceStatus(client: AxiosInstance): Promise<OpnsenseApiResult> {
  return get(client, '/api/ntpd/service/status');
}

/** GET /api/ntpd/settings/get — NTP settings (servers, etc.). */
export function getSettings(client: AxiosInstance): Promise<OpnsenseApiResult> {
  return get(client, '/api/ntpd/settings/get');
}

/** POST /api/ntpd/settings/set — update NTP settings (staged). Body: the settings object. */
export function setSettings(client: AxiosInstance, settings: Record<string, unknown>): Promise<OpnsenseApiResult> {
  return post(client, '/api/ntpd/settings/set', settings);
}

/** POST /api/core/service/restart/ntpd — restart ntpd to activate changes. */
export function restartService(client: AxiosInstance): Promise<OpnsenseApiResult> {
  return post(client, '/api/core/service/restart/ntpd', {});
}
