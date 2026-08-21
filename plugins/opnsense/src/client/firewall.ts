import { AxiosInstance } from 'axios';
import { get, post, OpnsenseApiResult } from './http';

/**
 * Firewall module: filter rules, aliases, groups/categories and the four NAT
 * rule sets (destination/source/one-to-one/NPT). Docs: development/api/core/firewall.html.
 *
 * OPNsense stages changes in the configuration; `apply()` reloads pf so staged
 * rule changes become active. Every write action here is therefore followed by
 * an explicit apply step at the action-registry level (two-phase model).
 */

// --- Filter rules -----------------------------------------------------------

/** GET /api/firewall/filter/search_rule — search filter rules (rows[] with uuid, description, ...). */
export function searchFilterRules(client: AxiosInstance, query?: Record<string, unknown>): Promise<OpnsenseApiResult> {
  return get(client, '/api/firewall/filter/search_rule', query);
}

/** GET /api/firewall/filter/get_rule/$uuid — one filter rule. */
export function getFilterRule(client: AxiosInstance, uuid: string): Promise<OpnsenseApiResult> {
  return get(client, `/api/firewall/filter/get_rule/${encodeURIComponent(uuid)}`);
}

/** POST /api/firewall/filter/add_rule — add a filter rule (staged). Body: { rule: {...} }. */
export function addFilterRule(client: AxiosInstance, rule: Record<string, unknown>): Promise<OpnsenseApiResult<{ uuid?: string }>> {
  return post(client, '/api/firewall/filter/add_rule', { rule });
}

/** POST /api/firewall/filter/set_rule/$uuid — update a filter rule (staged). Body: { rule: {...} }. */
export function setFilterRule(client: AxiosInstance, uuid: string, rule: Record<string, unknown>): Promise<OpnsenseApiResult> {
  return post(client, `/api/firewall/filter/set_rule/${encodeURIComponent(uuid)}`, { rule });
}

/** POST /api/firewall/filter/toggle_rule/$uuid/$enabled — enable/disable a rule (staged). */
export function toggleFilterRule(client: AxiosInstance, uuid: string, enabled: boolean): Promise<OpnsenseApiResult> {
  return post(client, `/api/firewall/filter/toggle_rule/${encodeURIComponent(uuid)}/${enabled ? '1' : '0'}`, {});
}

/** POST /api/firewall/filter/del_rule/$uuid — delete a rule (staged). */
export function deleteFilterRule(client: AxiosInstance, uuid: string): Promise<OpnsenseApiResult> {
  return post(client, `/api/firewall/filter/del_rule/${encodeURIComponent(uuid)}`, {});
}

/** GET /api/firewall/filter/move_rule_before/$selected/$target — reorder a rule (staged). */
export function moveFilterRuleBefore(client: AxiosInstance, selectedUuid: string, targetUuid: string): Promise<OpnsenseApiResult> {
  return get(
    client,
    `/api/firewall/filter/move_rule_before/${encodeURIComponent(selectedUuid)}/${encodeURIComponent(targetUuid)}`
  );
}

/** POST /api/firewall/filter/apply — ACTIVATE staged filter changes (reload pf). */
export function applyFilter(client: AxiosInstance): Promise<OpnsenseApiResult> {
  return post(client, '/api/firewall/filter/apply', {});
}

// --- Aliases ------------------------------------------------------------------

/** GET /api/firewall/alias/search_item — search aliases (rows[]). */
export function searchAliases(client: AxiosInstance, query?: Record<string, unknown>): Promise<OpnsenseApiResult> {
  return get(client, '/api/firewall/alias/search_item', query);
}

/** GET /api/firewall/alias/get_alias_u_u_i_d/$name — resolve an alias name to its uuid. */
export function getAliasUuidByName(client: AxiosInstance, name: string): Promise<OpnsenseApiResult> {
  return get(client, `/api/firewall/alias/get_alias_u_u_i_d/${encodeURIComponent(name)}`);
}

/** POST /api/firewall/alias/add_item — add an alias (staged). Body: { item: {...} }. */
export function addAlias(client: AxiosInstance, item: Record<string, unknown>): Promise<OpnsenseApiResult<{ uuid?: string }>> {
  return post(client, '/api/firewall/alias/add_item', { item });
}

/** POST /api/firewall/alias/set_item/$uuid — update an alias (staged). Body: { item: {...} }. */
export function setAlias(client: AxiosInstance, uuid: string, item: Record<string, unknown>): Promise<OpnsenseApiResult> {
  return post(client, `/api/firewall/alias/set_item/${encodeURIComponent(uuid)}`, { item });
}

/** POST /api/firewall/alias/del_item/$uuid — delete an alias (staged). */
export function deleteAlias(client: AxiosInstance, uuid: string): Promise<OpnsenseApiResult> {
  return post(client, `/api/firewall/alias/del_item/${encodeURIComponent(uuid)}`, {});
}

/** POST /api/firewall/alias/reconfigure — ACTIVATE staged alias changes. */
export function reconfigureAliases(client: AxiosInstance): Promise<OpnsenseApiResult> {
  return post(client, '/api/firewall/alias/reconfigure', {});
}

// --- NAT rule sets --------------------------------------------------------------
// All four share the same CRUD shape; a small generic keeps this DRY.

interface NatOps {
  search: (client: AxiosInstance, query?: Record<string, unknown>) => Promise<OpnsenseApiResult>;
  get: (client: AxiosInstance, uuid: string) => Promise<OpnsenseApiResult>;
  add: (client: AxiosInstance, rule: Record<string, unknown>) => Promise<OpnsenseApiResult<{ uuid?: string }>>;
  set: (client: AxiosInstance, uuid: string, rule: Record<string, unknown>) => Promise<OpnsenseApiResult>;
  toggle: (client: AxiosInstance, uuid: string, enabled: boolean) => Promise<OpnsenseApiResult>;
  del: (client: AxiosInstance, uuid: string) => Promise<OpnsenseApiResult>;
}

function natController(base: string): NatOps {
  return {
    search: (c, q) => get(c, `/api/firewall/${base}/search_rule`, q),
    get: (c, uuid) => get(c, `/api/firewall/${base}/get_rule/${encodeURIComponent(uuid)}`),
    add: (c, rule) => post(c, `/api/firewall/${base}/add_rule`, { rule }),
    set: (c, uuid, rule) => post(c, `/api/firewall/${base}/set_rule/${encodeURIComponent(uuid)}`, { rule }),
    toggle: (c, uuid, enabled) => post(c, `/api/firewall/${base}/toggle_rule/${encodeURIComponent(uuid)}/${enabled ? '1' : '0'}`, {}),
    del: (c, uuid) => post(c, `/api/firewall/${base}/del_rule/${encodeURIComponent(uuid)}`, {}),
  };
}

/** Destination NAT (port forwards). */
export const dNat = natController('d_nat');
/** Source NAT. */
export const sourceNat = natController('source_nat');
/** One-to-one NAT. */
export const oneToOne = natController('one_to_one');
/** NPT (IPv6 network prefix translation). */
export const npt = natController('npt');

// --- Groups / categories ----------------------------------------------------------

/** GET /api/firewall/group/search_item — firewall groups (rows[]). */
export function searchGroups(client: AxiosInstance, query?: Record<string, unknown>): Promise<OpnsenseApiResult> {
  return get(client, '/api/firewall/group/search_item', query);
}

/** POST /api/firewall/group/add_item — add a group (staged). Body: { item: {...} }. */
export function addGroup(client: AxiosInstance, item: Record<string, unknown>): Promise<OpnsenseApiResult<{ uuid?: string }>> {
  return post(client, '/api/firewall/group/add_item', { item });
}

/** POST /api/firewall/group/set_item/$uuid — update a group (staged). Body: { item: {...} }. */
export function setGroup(client: AxiosInstance, uuid: string, item: Record<string, unknown>): Promise<OpnsenseApiResult> {
  return post(client, `/api/firewall/group/set_item/${encodeURIComponent(uuid)}`, { item });
}

/** POST /api/firewall/group/del_item/$uuid — delete a group (staged). */
export function deleteGroup(client: AxiosInstance, uuid: string): Promise<OpnsenseApiResult> {
  return post(client, `/api/firewall/group/del_item/${encodeURIComponent(uuid)}`, {});
}

/** POST /api/firewall/group/reconfigure — ACTIVATE staged group changes. */
export function reconfigureGroups(client: AxiosInstance): Promise<OpnsenseApiResult> {
  return post(client, '/api/firewall/group/reconfigure', {});
}
