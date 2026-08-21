import { AxiosInstance } from 'axios';
import { get, post, OpnsenseApiResult } from './http';

/**
 * Trafficshaper module: pipes (bandwidth limits), queues and rules.
 * Docs: development/api/core/trafficshaper.html. Writes are staged;
 * `service.reconfigure` activates them.
 */

// --- Pipes -----------------------------------------------------------------------

/** GET /api/trafficshaper/settings/search_pipes — search pipes (rows[]). */
export function searchPipes(client: AxiosInstance, query?: Record<string, unknown>): Promise<OpnsenseApiResult> {
  return get(client, '/api/trafficshaper/settings/search_pipes', query);
}

/** GET /api/trafficshaper/settings/get_pipe/$uuid — one pipe. */
export function getPipe(client: AxiosInstance, uuid?: string): Promise<OpnsenseApiResult> {
  return get(client, `/api/trafficshaper/settings/get_pipe${uuid ? `/${encodeURIComponent(uuid)}` : ''}`);
}

/** POST /api/trafficshaper/settings/add_pipe — add a pipe (staged). Body: the pipe object. */
export function addPipe(client: AxiosInstance, pipe: Record<string, unknown>): Promise<OpnsenseApiResult> {
  return post(client, '/api/trafficshaper/settings/add_pipe', pipe);
}

/** POST /api/trafficshaper/settings/set_pipe/$uuid — update a pipe (staged). Body: the pipe object. */
export function setPipe(client: AxiosInstance, uuid: string, pipe: Record<string, unknown>): Promise<OpnsenseApiResult> {
  return post(client, `/api/trafficshaper/settings/set_pipe/${encodeURIComponent(uuid)}`, pipe);
}

/** POST /api/trafficshaper/settings/toggle_pipe/$uuid/$enabled — enable/disable a pipe (staged). */
export function togglePipe(client: AxiosInstance, uuid: string, enabled: boolean): Promise<OpnsenseApiResult> {
  return post(client, `/api/trafficshaper/settings/toggle_pipe/${encodeURIComponent(uuid)}/${enabled ? '1' : '0'}`, {});
}

/** POST /api/trafficshaper/settings/del_pipe/$uuid — delete a pipe (staged). */
export function deletePipe(client: AxiosInstance, uuid: string): Promise<OpnsenseApiResult> {
  return post(client, `/api/trafficshaper/settings/del_pipe/${encodeURIComponent(uuid)}`, {});
}

// --- Rules ---------------------------------------------------------------------------

/** GET /api/trafficshaper/settings/search_rules — search rules (rows[]). */
export function searchRules(client: AxiosInstance, query?: Record<string, unknown>): Promise<OpnsenseApiResult> {
  return get(client, '/api/trafficshaper/settings/search_rules', query);
}

/** POST /api/trafficshaper/settings/add_rule — add a rule (staged). Body: the rule object. */
export function addRule(client: AxiosInstance, rule: Record<string, unknown>): Promise<OpnsenseApiResult> {
  return post(client, '/api/trafficshaper/settings/add_rule', rule);
}

/** POST /api/trafficshaper/settings/set_rule/$uuid — update a rule (staged). Body: the rule object. */
export function setRule(client: AxiosInstance, uuid: string, rule: Record<string, unknown>): Promise<OpnsenseApiResult> {
  return post(client, `/api/trafficshaper/settings/set_rule/${encodeURIComponent(uuid)}`, rule);
}

/** POST /api/trafficshaper/settings/toggle_rule/$uuid/$enabled — enable/disable a rule (staged). */
export function toggleRule(client: AxiosInstance, uuid: string, enabled: boolean): Promise<OpnsenseApiResult> {
  return post(client, `/api/trafficshaper/settings/toggle_rule/${encodeURIComponent(uuid)}/${enabled ? '1' : '0'}`, {});
}

/** POST /api/trafficshaper/settings/del_rule/$uuid — delete a rule (staged). */
export function deleteRule(client: AxiosInstance, uuid: string): Promise<OpnsenseApiResult> {
  return post(client, `/api/trafficshaper/settings/del_rule/${encodeURIComponent(uuid)}`, {});
}

// --- Service ------------------------------------------------------------------------------

/** GET /api/trafficshaper/service/statistics — live shaper statistics. */
export function getStatistics(client: AxiosInstance): Promise<OpnsenseApiResult> {
  return get(client, '/api/trafficshaper/service/statistics');
}

/** POST /api/trafficshaper/service/reconfigure — ACTIVATE staged trafficshaper changes. */
export function reconfigureService(client: AxiosInstance): Promise<OpnsenseApiResult> {
  return post(client, '/api/trafficshaper/service/reconfigure', {});
}
