/**
 * Client-IP resolution for deployments behind a reverse proxy.
 *
 * UNM is an admin appliance that is normally reached through a VPN or a
 * reverse proxy (TLS termination + auth). Behind such a proxy the TCP peer of
 * every request is the PROXY, so Express's default `req.ip` collapses all real
 * clients into one bucket and rate limiting stops protecting anything. This
 * module centralizes how the API recovers the real client address:
 *
 *   1. UNM_CLIENT_IP_HEADER — an explicit header carrying the client IP
 *      (e.g. Cloudflare's `CF-Connecting-IP`, or a custom `X-Real-Client`).
 *      When set, its value wins over everything else. The operator is telling
 *      the API "only my proxy sets this header" — so the API must only be
 *      reachable through that proxy (see docs/REVERSE-PROXY.md).
 *   2. X-Forwarded-For — handled by Express itself once trust proxy covers the
 *      request's peer (`app.set('trust proxy', …)`, driven by UNM_TRUST_PROXY).
 *      Express evaluates the trust policy PER PEER, so an untrusted direct
 *      connection cannot spoof its own bucket via a forged XFF header.
 *   3. req.ip / socket address as a last resort (direct connections).
 *
 * Both knobs are read from process.env at call time so `docker compose` env
 * changes apply on restart without code coupling (same pattern as CORS).
 */

import type { Request } from 'express';
import { ipKeyGenerator } from 'express-rate-limit';

/** Header name(s) to consult for the client IP, comma-separated. Empty = off. */
function configuredClientIpHeaders(): string[] {
  return (process.env.UNM_CLIENT_IP_HEADER ?? '')
    .split(',')
    .map((h) => h.trim())
    .filter(Boolean);
}

/** Strip an optional `:port` suffix from a client address (IPv4 or [IPv6]:port). */
function stripPort(addr: string): string {
  const inBrackets = addr.startsWith('[');
  const colon = inBrackets ? addr.lastIndexOf(':') : addr.indexOf(':');
  if (colon !== -1) {
    const candidate = addr.slice(colon + 1);
    // Only treat as a port when it is purely numeric.
    if (/^\d+$/.test(candidate)) return addr.slice(0, colon);
  }
  return addr;
}

/**
 * Resolve the real client IP for rate limiting / audit purposes.
 *
 * Precedence: UNM_CLIENT_IP_HEADER value → req.ip (which already reflects
 * X-Forwarded-For when trust proxy covers the peer) → socket address. The
 * result is always a non-empty string; ports are stripped so `10.1.2.3:54321`
 * and `10.1.2.3` resolve to the same client.
 */
export function resolveClientIp(req: Request): string {
  const headers = configuredClientIpHeaders();
  for (const name of headers) {
    const v = req.headers[name.toLowerCase()];
    if (Array.isArray(v)) {
      // Multiple values on one header — take the first non-empty entry.
      const first = v.map((s) => s.trim()).find(Boolean);
      if (first) return stripPort(first);
    } else if (typeof v === 'string' && v.trim()) {
      return stripPort(v.trim());
    }
  }

  // req.ip is the socket address for direct connections and the leftmost
  // X-Forwarded-For entry when trust proxy covers the peer — Express has
  // already done the per-peer trust evaluation, so no spoofing surface here.
  return stripPort(req.ip || req.socket.remoteAddress || 'unknown');
}

/**
 * A rate-limit keyGenerator that honors UNM_CLIENT_IP_HEADER, or undefined
 * when no such header is configured — in which case express-rate-limit's
 * default (req.ip) already does the right thing once trust proxy is set. The
 * resolved address goes through the library's ipKeyGenerator so IPv6 clients
 * are bucketed by /56 subnet (the same behavior as the built-in default).
 */
export function clientIpKeyGenerator(): ((req: Request) => string) | undefined {
  if (!configuredClientIpHeaders().length) return undefined;
  return (req: Request) => ipKeyGenerator(resolveClientIp(req));
}

/**
 * Parse UNM_TRUST_PROXY into the value Express's `app.set('trust proxy', …)`
 * accepts. Supported forms:
 *   - unset / empty            → false (no proxy — direct connections)
 *   - "1"                      → trust exactly one hop (the immediate peer),
 *                                i.e. a single reverse proxy in front of the API
 *   - "<n>"                    → trust n hops (e.g. "2" for LB + proxy)
 *   - "loopback"|"link-local"|…→ Express's named subnet policies
 *   - CIDR list                → trust peers within those networks, e.g.
 *                                "10.0.0.0/8, 172.16.0.0/12"
 */
export function parseTrustProxy(raw: string | undefined): boolean | number | string {
  const v = (raw ?? '').trim();
  if (!v) return false;
  if (/^\d+$/.test(v)) return Number(v);
  // Named policies + CIDR lists pass through to Express, which validates them.
  return v;
}
