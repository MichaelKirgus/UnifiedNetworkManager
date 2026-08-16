import axios from 'axios';
import { Bonjour } from 'bonjour-service';
import { eq } from 'drizzle-orm';
import { db } from '../db';
import * as schema from '../db/schema';

/**
 * Self-describing identity that every plugin MUST expose, either via its
 * `/discover` endpoint (HTTP polling) or via mDNS TXT records (DNS-SD).
 * The `uuid` is the single source of truth that identifies a plugin and is
 * used as the primary key in the `plugins` table.
 */
export interface PluginIdentity {
  uuid: string;
  name: string;
  version: string;
  vendors: string[];
  capabilities: string[];
  endpoint: string;
  authType: string;
}

export interface DiscoveryOptions {
  /** Optional list of plugin HTTP endpoints to poll as a fallback when mDNS is not reachable (e.g. Docker bridge networks). */
  pollEndpoints?: string[];
  /** Poll interval in milliseconds. Defaults to 60_000. */
  pollIntervalMs?: number;
  /** How long a plugin stays "registered" after its last successful discovery, in ms. Defaults to 5 minutes. */
  staleAfterMs?: number;
}

const DISCOVERY_SERVICE_TYPE = 'unm-plugin';
const DISCOVERY_POLL_TIMEOUT_MS = 3000;

function parseTxt(txt: Record<string, string> | undefined): Partial<PluginIdentity> {
  const raw = txt ?? {};
  const list = (v: string | undefined): string[] =>
    v ? v.split(',').map((s) => s.trim()).filter(Boolean) : [];

  return {
    uuid: raw.uuid,
    name: raw.name,
    version: raw.version,
    vendors: list(raw.vendors),
    capabilities: list(raw.capabilities),
    endpoint: raw.endpoint,
    authType: raw.authType,
  };
}

async function fetchIdentity(endpoint: string): Promise<PluginIdentity | null> {
  try {
    const url = `${endpoint.replace(/\/+$/, '')}/discover`;
    const res = await axios.get<PluginIdentity>(url, { timeout: DISCOVERY_POLL_TIMEOUT_MS });
    const data = res.data;
    if (!data || typeof data.uuid !== 'string' || data.uuid.length === 0) {
      // eslint-disable-next-line no-console
      console.warn(`[discovery] plugin at ${endpoint} did not return a uuid`);
      return null;
    }
    return {
      uuid: data.uuid,
      name: data.name ?? data.uuid,
      version: data.version ?? 'unknown',
      vendors: Array.isArray(data.vendors) ? data.vendors : [],
      capabilities: Array.isArray(data.capabilities) ? data.capabilities : [],
      endpoint: data.endpoint ?? endpoint,
      authType: data.authType ?? 'none',
    };
  } catch (err) {
    // eslint-disable-next-line no-console
    console.warn(`[discovery] failed to fetch identity from ${endpoint}:`, (err as Error).message);
    return null;
  }
}

async function upsertPlugin(identity: PluginIdentity): Promise<void> {
  const now = new Date().toISOString();
  const existing = await db.query.plugins.findFirst({
    where: (plugins, { eq }) => eq(plugins.id, identity.uuid),
  });

  if (existing) {
    await db
      .update(schema.plugins)
      .set({
        name: identity.name,
        version: identity.version,
        vendors: JSON.stringify(identity.vendors),
        capabilities: JSON.stringify(identity.capabilities),
        endpoint: identity.endpoint,
        authType: identity.authType,
        lastSeenAt: now,
      })
      .where(eq(schema.plugins.id, identity.uuid));
  } else {
    await db.insert(schema.plugins).values({
      id: identity.uuid,
      name: identity.name,
      version: identity.version,
      vendors: JSON.stringify(identity.vendors),
      capabilities: JSON.stringify(identity.capabilities),
      endpoint: identity.endpoint,
      authType: identity.authType,
      createdAt: now,
      lastSeenAt: now,
    });
  }

  // eslint-disable-next-line no-console
  console.log(`[discovery] upserted plugin "${identity.name}" (${identity.uuid})`);
}

async function pollEndpoints(endpoints: string[]): Promise<void> {
  for (const endpoint of endpoints) {
    const identity = await fetchIdentity(endpoint);
    if (identity) {
      await upsertPlugin(identity);
    }
  }
}

/**
 * Starts plugin discovery. Two complementary mechanisms are used:
 *
 * 1. mDNS/DNS-SD browsing: plugins advertise themselves as `_unm-plugin._tcp`
 *    services. The API browses for them and upserts each one.
 * 2. HTTP polling fallback: mDNS multicast is often isolated on Docker bridge
 *    networks, so any plugin endpoints configured via `pollEndpoints` are
 *    also polled on an interval.
 *
 * Returns a cleanup function that stops both mechanisms.
 */
export function startPluginDiscovery(options: DiscoveryOptions = {}): () => void {
  const pollIntervalMs = options.pollIntervalMs ?? 60_000;
  const pollEndpointsList = options.pollEndpoints ?? [];

  let bonjour: Bonjour | null = null;
  let browser: ReturnType<Bonjour['find']> | null = null;
  let pollTimer: ReturnType<typeof setInterval> | null = null;

  // mDNS browsing
  try {
    bonjour = new Bonjour();
    browser = bonjour.find({ type: DISCOVERY_SERVICE_TYPE }, (service) => {
      const identity: PluginIdentity = {
        uuid: service.txt?.uuid ?? service.name,
        name: service.txt?.name ?? service.name,
        version: service.txt?.version ?? 'unknown',
        vendors: parseTxt(service.txt).vendors ?? [],
        capabilities: parseTxt(service.txt).capabilities ?? [],
        endpoint: service.txt?.endpoint ?? `http://${service.host}:${service.port}`,
        authType: service.txt?.authType ?? 'none',
      };
      void upsertPlugin(identity);
    });
    // eslint-disable-next-line no-console
    console.log('[discovery] browsing mDNS for plugins...');
  } catch (err) {
    // eslint-disable-next-line no-console
    console.warn('[discovery] mDNS browsing unavailable, using polling only:', (err as Error).message);
  }

  // HTTP polling fallback
  if (pollEndpointsList.length > 0) {
    void pollEndpoints(pollEndpointsList);
    pollTimer = setInterval(() => void pollEndpoints(pollEndpointsList), pollIntervalMs);
  }

  return () => {
    if (browser) browser.stop();
    if (bonjour) bonjour.destroy();
    if (pollTimer) clearInterval(pollTimer);
  };
}