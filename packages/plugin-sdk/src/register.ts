/**
 * register — push-based self-registration with the UNM API.
 *
 * Every plugin POSTs its full /discover payload to the API's internal
 * `POST /plugin/register` route (x-plugin-api-key gated) on boot, retries while
 * the API is unreachable, and re-registers on a slow heartbeat afterwards. The
 * API upserts the row into its plugins table and adds the endpoint to its
 * discovery poll set — so UNM needs NO pre-configured plugin catalog: ship one
 * container with ADVERTISED_ENDPOINT + UNM_API_URL + PLUGIN_API_KEY and the
 * plugin appears in the webapp automatically. This is what makes third-party
 * plugins (built by anyone, outside this repo) drop-in deployable.
 *
 * Self-registration is the primary discovery mechanism on Docker bridge
 * networks (where mDNS multicast is isolated). The API's legacy
 * PLUGIN_POLL_ENDPOINTS list still works as a fallback for topologies where
 * push registration isn't possible; mDNS remains a second path on networks
 * where multicast reaches.
 */

import axios from 'axios';
import { PluginIdentity } from './identity';

const DEFAULT_API_URL = 'http://api:3000/v1';
/** Retry backoff while the API is unreachable (the plugin may boot first). */
const INITIAL_RETRY_MS = 5_000;
const MAX_RETRY_MS = 30_000;
/** Re-register this often after success — keeps identity/descriptors fresh and
 *  self-heals a wiped or freshly-migrated plugins table with zero UNM config. */
const HEARTBEAT_MS = 5 * 60_000;

export interface RegisterOptions {
  /** Base URL of the API's internal endpoints (UNM_API_URL). Default http://api:3000/v1. */
  apiUrl?: string;
  /** Shared plugin key (PLUGIN_API_KEY). Registration is skipped when unset. */
  apiKey?: string;
}

/** POSTs one registration attempt. Resolves true on a 2xx response, false otherwise. Never throws. */
export async function registerWithApi(
  identity: PluginIdentity,
  discoverPayload: Record<string, unknown>,
  opts: RegisterOptions = {},
): Promise<boolean> {
  const apiKey = opts.apiKey ?? process.env.PLUGIN_API_KEY;
  if (!apiKey) return false; // standalone mode — no UNM API to register with
  const baseUrl = (opts.apiUrl ?? process.env.UNM_API_URL ?? DEFAULT_API_URL).replace(/\/+$/, '');
  try {
    const res = await axios.post(
      `${baseUrl}/plugin/register`,
      { ...discoverPayload, endpoint: identity.endpoint },
      { headers: { 'x-plugin-api-key': apiKey }, timeout: 10_000 },
    );
    return res.status >= 200 && res.status < 300;
  } catch (err) {
    const e = err as { message?: string };
    console.warn(`[register] self-registration failed (will retry): ${e.message ?? String(err)}`);
    return false;
  }
}

/**
 * Starts the registration loop: immediate attempt, capped exponential backoff
 * until it succeeds (the API may boot after the plugin), then a slow heartbeat.
 * Returns a stop function. Timers are unref'd — they never hold the process open.
 */
export function startRegistration(
  identity: PluginIdentity,
  buildPayload: () => Record<string, unknown>,
  opts: RegisterOptions = {},
): () => void {
  const apiKey = opts.apiKey ?? process.env.PLUGIN_API_KEY;
  if (!apiKey) {
    console.log('[register] PLUGIN_API_KEY not set — self-registration disabled (standalone mode)');
    return () => {};
  }

  let stopped = false;
  let timer: ReturnType<typeof setTimeout> | null = null;
  let failures = 0;
  let registeredOnce = false;

  const schedule = (delayMs: number): void => {
    if (stopped) return;
    timer = setTimeout(() => {
      void attempt();
    }, delayMs);
    (timer as unknown as { unref?: () => void }).unref?.();
  };

  const backoffMs = (): number => Math.min(MAX_RETRY_MS, INITIAL_RETRY_MS * 2 ** Math.min(failures, 3));

  const attempt = async (): Promise<void> => {
    let ok = false;
    try {
      ok = await registerWithApi(identity, buildPayload(), opts);
    } catch (err) {
      // registerWithApi never throws — defensive only.
      console.warn(`[register] unexpected error: ${(err as Error).message}`);
    }
    if (stopped) return;
    if (ok) {
      failures = 0;
      if (!registeredOnce) {
        registeredOnce = true;
        console.log(`[register] self-registered with UNM API at ${identity.endpoint}`);
      }
      schedule(HEARTBEAT_MS);
    } else {
      failures += 1;
      schedule(backoffMs());
    }
  };

  void attempt();

  return () => {
    stopped = true;
    if (timer) clearTimeout(timer);
  };
}
