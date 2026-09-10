import { randomBytes } from 'crypto';

/**
 * Console tickets — short-lived, single-use credentials for SSH consoles.
 *
 * A console is a LONG-LIVED bidirectional stream (WebSocket), so it cannot ride
 * the normal request/response credential pipeline: the browser must open the WS
 * with something that proves "this user may console THIS device", and the plugin
 * must be able to redeem that proof for FRESH credentials without ever seeing the
 * user's JWT. The flow:
 *
 *   1. Webapp → API  POST /devices/:id/console   (JWT, devices:write)
 *      → { ticket } — minted here, stored in memory with a 60 s TTL + single-use flag.
 *   2. Browser → API GET /devices/:id/console/ws?ticket=…
 *      → the WS proxy verifies the JWT again (upgrade headers), then redeems the
 *        ticket and connects to the plugin's /console endpoint, sending a hello
 *        frame with fresh credentials.
 *   3. Plugin → API POST /plugin/console/tickets/:id/redeem  (x-plugin-api-key)
 *      → { managementAddress, ipAddresses, credentials, context } — consumed ONCE.
 *
 * Tickets are in-memory by design: they live ≤60 s and only bridge the gap between
 * "user authorized" and "plugin has credentials". An API restart invalidates them
 * (the webapp simply re-mints). No DB table needed.
 */

interface TicketRecord {
  /** The device this ticket authorizes a console for. */
  deviceId: string;
  /** Which assignment to console (empty = primary) — resolved at mint time so the
   *  WS path reuses exactly the target that was capability-checked. */
  pluginId?: string;
  /** Plugin-owned context to forward verbatim (host shell / container exec, …). */
  context?: Record<string, unknown>;
  /** ISO expiry — tickets older than this are swept and rejected. */
  expiresAt: number;
  /** True once redeemed or expired-and-swept — a ticket is single-use. */
  consumed: boolean;
}

import { getCachedSettingValue } from './systemSettings';

/** Lifetime of a single-use console ticket (ms) — read live from Settings. */
function ticketTtlMs(): number {
  return Number(getCachedSettingValue('consoleTicketTtlMs')) || 60_000;
}
const tickets = new Map<string, TicketRecord>();

/** Lazy sweep of expired/consumed entries (cheap at console scale). */
function sweep(): void {
  const now = Date.now();
  for (const [id, t] of tickets) {
    if (t.consumed || now > t.expiresAt) tickets.delete(id);
  }
}

/** Mints a fresh single-use ticket for one device (+ optional assignment/context). */
export function mintConsoleTicket(deviceId: string, pluginId?: string, context?: Record<string, unknown>): string {
  sweep();
  const id = randomBytes(24).toString('base64url');
  tickets.set(id, {
    deviceId,
    ...(pluginId ? { pluginId } : {}),
    ...(context && Object.keys(context).length > 0 ? { context } : {}),
    expiresAt: Date.now() + ticketTtlMs(),
    consumed: false,
  });
  return id;
}

/** Looks up a live ticket WITHOUT consuming it (the WS proxy's pre-check). */
export function peekConsoleTicket(ticketId: string): TicketRecord | null {
  const t = tickets.get(ticketId);
  if (!t || t.consumed) return null;
  if (Date.now() > t.expiresAt) {
    tickets.delete(ticketId);
    return null;
  }
  return t;
}

/** Redeems a ticket — returns its payload exactly ONCE, then invalidates it. */
export function redeemConsoleTicket(ticketId: string): TicketRecord | null {
  const t = tickets.get(ticketId);
  if (!t || t.consumed) return null;
  if (Date.now() > t.expiresAt) {
    tickets.delete(ticketId);
    return null;
  }
  t.consumed = true;
  // Keep the record briefly so a racing double-redeem gets "consumed", not "unknown".
  setTimeout(() => tickets.delete(ticketId), ticketTtlMs()).unref?.();
  return t;
}
