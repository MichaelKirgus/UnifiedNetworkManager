import { AxiosInstance } from 'axios';
import { get, post, OpnsenseApiResult } from './http';

/**
 * Interfaces module: physical/logical interface configuration plus the logical
 * interface types (VLAN, LAGG, bridge, loopback, VIP, GRE/GIF/VXLAN).
 * Docs: development/api/core/interfaces.html. All writes are staged; each
 * controller has its own reconfigure to activate.
 */

// --- Overview / settings ------------------------------------------------------

/** GET /api/interfaces/overview/interfaces_info — all interfaces with details (MACs, status, ...). */
export function getInterfacesInfo(client: AxiosInstance): Promise<OpnsenseApiResult> {
  return get(client, '/api/interfaces/overview/interfaces_info', { details: 'true' });
}

/** GET /api/interfaces/settings/get — interface settings (per-interface config incl. IPs). */
export function getInterfaceSettings(client: AxiosInstance): Promise<OpnsenseApiResult> {
  return get(client, '/api/interfaces/settings/get');
}

/** POST /api/interfaces/settings/set — update interface settings (staged). Body: the settings object. */
export function setInterfaceSettings(client: AxiosInstance, settings: Record<string, unknown>): Promise<OpnsenseApiResult> {
  return post(client, '/api/interfaces/settings/set', settings);
}

/** POST /api/interfaces/settings/reconfigure — ACTIVATE staged interface changes. */
export function reconfigureInterfaces(client: AxiosInstance): Promise<OpnsenseApiResult> {
  return post(client, '/api/interfaces/settings/reconfigure', {});
}

// --- Logical interfaces (shared CRUD shape) ------------------------------------

interface ItemOps {
  get: (client: AxiosInstance) => Promise<OpnsenseApiResult>;
  add: (client: AxiosInstance, item: Record<string, unknown>) => Promise<OpnsenseApiResult<{ uuid?: string }>>;
  set: (client: AxiosInstance, uuid: string, item: Record<string, unknown>) => Promise<OpnsenseApiResult>;
  del: (client: AxiosInstance, uuid: string) => Promise<OpnsenseApiResult>;
  reconfigure: (client: AxiosInstance) => Promise<OpnsenseApiResult>;
}

function itemController(base: string): ItemOps {
  return {
    get: (c) => get(c, `/api/interfaces/${base}/get`),
    add: (c, item) => post(c, `/api/interfaces/${base}/add_item`, { item }),
    set: (c, uuid, item) => post(c, `/api/interfaces/${base}/set_item/${encodeURIComponent(uuid)}`, { item }),
    del: (c, uuid) => post(c, `/api/interfaces/${base}/del_item/${encodeURIComponent(uuid)}`, {}),
    reconfigure: (c) => post(c, `/api/interfaces/${base}/reconfigure`, {}),
  };
}

/** VLANs. */
export const vlans = itemController('vlan_settings');
/** LAGG (link aggregation). */
export const laggs = itemController('lagg_settings');
/** Bridges. */
export const bridges = itemController('bridge_settings');
/** Loopback interfaces. */
export const loopbacks = itemController('loopback_settings');
/** Virtual IPs (VIPs / CARP/PPPoE). */
export const vips = itemController('vip_settings');
/** GRE tunnels (source → destination point-to-point links). */
export const gres = itemController('gre_settings');
