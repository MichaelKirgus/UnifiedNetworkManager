/**
 * Fleet clock re-sync — `system.clock.sync` (canonical id shared across plugins).
 *
 * RouterOS specifics (verified live on 7.21 LTS):
 *  - mode='sync' : the NTP CLIENT config is a singleton table at
 *    `/rest/system/ntp/client` with fields {enabled, servers (comma-separated),
 *    mode, vrf}. There is NO separate server-list table — reconciliation means
 *    rewriting the `servers` string. Enabling + re-pointing makes RouterOS
 *    re-poll; there is no force-sync command, so convergence takes seconds to
 *    minutes depending on the server stratum.
 *  - mode='set'  : manual wall-clock via POST `/rest/system/clock/set {date,time}`
 *    and/or IANA timezone via `{time-zone-name}` (the REST parameter is
 *    `time-zone-name`, NOT `time-zone`). PATCH /system/clock rejects with 500,
 *    so the command-word POST form is used. When a zone is set while
 *    autodetect is on it is silently ignored — autodetect must be disabled in
 *    the same action first. Writes apply IMMEDIATELY (RouterOS has no staged
 *    model) and are verified by re-reading /system/clock.
 */

import type { ActionContext, ActionDescriptor } from './types';
import { rosString } from '../routerosClient';

type Row = Record<string, unknown>;

/** Strict ISO-8601 instant shape (rejects anything that could carry injection). */
const ISO_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2})?(Z|[+-]\d{2}:?\d{2})?$/;

/** IANA identifiers are [A-Za-z0-9_+-/]; reject anything else before it hits the API. */
const TZ_RE = /^[A-Za-z][A-Za-z0-9_+-]*(\/[A-Za-z0-9_+-]+)*$/;

/** NTP server entries: hostnames, dotted IPv4, or bracketed IPv6. */
const SERVER_RE = /^(?:\[[0-9a-fA-F:.]+\]|[0-9a-zA-Z.-]+)$/;

/** Parses an ISO instant into epoch ms (null when unparseable). */
function isoToEpochMs(iso: string): number | null {
  const m = iso.match(/^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})(?::(\d{2}))?(Z|[+-]\d{2}:?\d{2})?$/);
  if (!m) return null;
  const [, y, mo, d] = m;
  // Normalize to a form Date.parse handles unambiguously (seconds + Z when no offset).
  const normalized = iso.endsWith('Z') || /[+-]\d{2}:?\d{2}$/.test(iso) ? iso : `${iso}Z`;
  const ms = Date.parse(normalized);
  if (!Number.isFinite(ms)) return null;
  // Sanity: the parsed components must match what we were given (guards against
  // out-of-range dates like month 13 that some parsers silently roll over).
  const dt = new Date(ms);
  if (dt.getUTCFullYear() !== Number(y) || dt.getUTCMonth() + 1 !== Number(mo) || dt.getUTCDate() !== Number(d)) return null;
  return ms;
}

/**
 * Formats an absolute instant as the WALL-CLOCK date/time a device in `zone`
 * would display — RouterOS `/system/clock set {date,time}` interprets its values
 * in the CURRENTLY configured zone, so we must send local components, not UTC.
 */
function epochMsToWallClock(ms: number, zone: string): { date: string; time: string } | null {
  try {
    const dtf = new Intl.DateTimeFormat('en-CA', {
      timeZone: zone,
      year: 'numeric', month: '2-digit', day: '2-digit',
      hour: '2-digit', minute: '2-digit', second: '2-digit',
      hour12: false,
    });
    const parts = Object.fromEntries(dtf.formatToParts(new Date(ms)).map((p) => [p.type, p.value]));
    if (!parts.year || !parts.month || !parts.day || !parts.hour || !parts.minute) return null;
    // en-CA yields YYYY-MM-DD directly. hour '24' is an ICU edge for midnight — normalize.
    const h = parts.hour === '24' ? '00' : parts.hour;
    return { date: `${parts.year}-${parts.month}-${parts.day}`, time: `${h}:${parts.minute}:${parts.second ?? '00'}` };
  } catch {
    return null; // unknown zone name — caller falls back to UTC
  }
}

/** Resolves the IANA zone a device will be in AFTER this action (target tz when set, else current). */
function resolveTargetZone(currentTz: string | undefined, targetTz: string | undefined): string {
  if (targetTz) return targetTz;
  // RouterOS reports e.g. "Europe/Berlin" or a numeric offset like "+02:00"; only IANA names work with Intl.
  if (currentTz && TZ_RE.test(currentTz)) return currentTz;
  return 'UTC';
}

/** Singleton tables may answer as a bare object OR a one-element array (version-dependent) — normalize to the row. */
function firstRow(raw: unknown): Row | null {
  if (Array.isArray(raw)) return raw[0] && typeof raw[0] === 'object' ? (raw[0] as Row) : null;
  return raw && typeof raw === 'object' ? (raw as Row) : null;
}

/** Reads the current /system/clock row (date/time/time-zone-name). */
async function readClock(ctx: ActionContext): Promise<Row | null> {
  try {
    const rows = await ctx.client.get<unknown>('/system/clock');
    return firstRow(rows);
  } catch {
    return null;
  }
}

/** Splits the comma-separated `servers` field of /system/ntp/client. */
function parseServerList(row: Row | null): string[] {
  const raw = row ? rosString(row, ['servers']) : undefined;
  if (!raw) return [];
  return raw.split(',').map((s) => s.trim()).filter(Boolean);
}

export const clockSyncAction: ActionDescriptor = {
  id: 'system.clock.sync',
  label: 'Sync or set device clock',
  description:
    "Re-syncs the router to its NTP source (mode='sync') and/or sets a specific wall-clock time and/or IANA timezone (mode='set'). Fleet-wide intent — fans out one step per device. 'sync' enables the /system/ntp/client and optionally re-points its server list; RouterOS has no force-sync command, so convergence happens on the next poll. 'set' writes /system/clock directly.",
  module: 'System',
  riskLevel: 'write',
  deviceCount: 'N',
  timeoutMs: 60_000,
  inputSchema: {
    mode: { type: 'string', required: true, enum: ['sync', 'set'], description: "'sync' = re-trigger native NTP; 'set' = manual wall-clock and/or timezone" },
    timeUtc: { type: 'string', description: "ISO-8601 UTC instant for mode='set' (e.g. 2026-10-02T14:30:00Z)" },
    timezone: { type: 'string', description: "IANA zone for mode='set' (e.g. Europe/Berlin); independent of timeUtc" },
    servers: { type: 'array', items: { type: 'string' }, description: "Optional NTP server list for mode='sync' — re-points /system/ntp/client to exactly these addresses" },
  },
  execute: async (ctx, input) => {
    const mode = String(input.mode ?? '').trim();
    if (!['sync', 'set'].includes(mode)) return { success: false, error: "mode must be 'sync' or 'set'." };

    // --- sync: enable NTP client (+ optional server re-pointing) --------------
    if (mode === 'sync') {
      const servers = Array.isArray(input.servers) ? input.servers.map((s) => String(s).trim()).filter(Boolean) : [];
      for (const s of servers) {
        if (!SERVER_RE.test(s)) return { success: false, error: `Invalid NTP server "${s}" — expected a hostname or IP address.` };
      }

      let before: Row | null;
      try {
        const rows = await ctx.client.get<unknown>('/system/ntp/client');
        before = firstRow(rows) ?? {};
      } catch (e) {
        return { success: false, error: `Could not read /system/ntp/client: ${e instanceof Error ? e.message : String(e)}` };
      }

      const enabled = rosString(before, ['enabled']) === 'true' || before['enabled'] === true;
      const currentServers = parseServerList(before);
      const serversChanged = servers.length > 0 && JSON.stringify(currentServers) !== JSON.stringify(servers);

      // Nothing to do — already enabled and (no list given or identical).
      if (enabled && !serversChanged) {
        return { success: true, applied: false, details: { mode: 'sync', note: `NTP client already enabled with ${currentServers.length} server(s) — no change made.`, ntpEnabled: true } };
      }

      // One command-word POST rewrites the singleton (enable + servers together).
      const body: Record<string, unknown> = { enabled: true };
      if (serversChanged) body['servers'] = servers.join(',');
      try {
        await ctx.client.post('/system/ntp/client/set', body);
      } catch (e) {
        return { success: false, error: `Updating /system/ntp/client failed: ${e instanceof Error ? e.message : String(e)}` };
      }

      // Verify by re-reading. RouterOS REST can serve stale singleton state for a
      // moment right after a set — allow two retries with a short settle delay.
      let after: Row | null = null;
      for (let attempt = 0; attempt < 3; attempt++) {
        if (attempt > 0) await new Promise((r) => setTimeout(r, 1_500));
        try {
          const rows = await ctx.client.get<unknown>('/system/ntp/client');
          after = firstRow(rows);
        } catch { /* verification read failed — retry */ }
        if (after && (rosString(after, ['enabled']) === 'true' || after['enabled'] === true)) break;
      }
      if (!after || (rosString(after, ['enabled']) !== 'true' && after['enabled'] !== true)) {
        return { success: false, error: 'NTP client could not be enabled — check the router.' };
      }
      const note = serversChanged
        ? `NTP client enabled with ${servers.length} server(s): ${servers.join(', ')}.`
        : 'NTP client ensured enabled — re-syncing to its configured servers.';
      return { success: true, applied: true, details: { mode: 'sync', note, ntpEnabled: true } };
    }

    // --- set: manual wall-clock and/or timezone -------------------------------
    const timeUtc = typeof input.timeUtc === 'string' && input.timeUtc.trim() ? input.timeUtc.trim() : undefined;
    const tz = typeof input.timezone === 'string' && input.timezone.trim() ? input.timezone.trim() : undefined;
    if (!timeUtc && !tz) return { success: false, error: "mode 'set' requires at least one of timeUtc or timezone." };
    if (tz && !TZ_RE.test(tz)) return { success: false, error: 'Invalid timezone identifier.' };

    // Read the current clock FIRST — RouterOS interprets /system/clock set {date,time}
    // in the zone that is active AT WRITE TIME, so we must express the target
    // instant in the zone the device will have when the time write lands.
    const before = await readClock(ctx);
    const currentTz = before ? rosString(before, ['time-zone-name', 'time-zone']) : undefined;

    // Build the /system/clock/set command-word POST bodies. Timezone FIRST (when
    // both are given) so the subsequent time write is interpreted under the new zone.
    const steps: Array<{ label: string; run: () => Promise<void> }> = [];
    if (tz) {
      steps.push({
        label: `timezone=${tz}`,
        run: async () => {
          // Autodetect ON silently ignores a manual zone — disable it first.
          const autodetectOn = before ? rosString(before, ['time-zone-autodetect']) === 'true' || before['time-zone-autodetect'] === true : false;
          if (autodetectOn) {
            await ctx.client.post('/system/clock/set', { 'time-zone-autodetect': 'no' });
          }
          // The REST parameter is `time-zone-name` (`time-zone` is rejected).
          await ctx.client.post('/system/clock/set', { 'time-zone-name': tz });
        },
      });
    }
    if (timeUtc) {
      if (!ISO_RE.test(timeUtc)) return { success: false, error: 'timeUtc must be an ISO-8601 instant (e.g. 2026-10-02T14:30:00Z).' };
      const ms = isoToEpochMs(timeUtc);
      if (ms === null) return { success: false, error: `Could not parse timeUtc "${timeUtc}".` };
      const zone = resolveTargetZone(currentTz, tz);
      const parts = epochMsToWallClock(ms, zone);
      if (!parts) return { success: false, error: `Could not convert ${timeUtc} to wall-clock components for zone ${zone}.` };
      steps.push({
        label: `clock=${parts.date} ${parts.time} (in ${zone})`,
        run: async () => { await ctx.client.post('/system/clock/set', { date: parts.date, time: parts.time }); },
      });
    }

    for (const step of steps) {
      try {
        await step.run();
      } catch (e) {
        return { success: false, error: `${step.label} failed: ${e instanceof Error ? e.message : String(e)}` };
      }
    }

    // Verify by re-reading /system/clock.
    const after = await readClock(ctx);
    const reportedTz = after ? rosString(after, ['time-zone-name', 'time-zone']) ?? null : null;
    return {
      success: true,
      applied: true,
      verified: tz === undefined || (reportedTz !== null && reportedTz.toLowerCase() === tz.toLowerCase()),
      details: { mode: 'set', timeUtc: timeUtc ?? undefined, timezone: tz ?? undefined, reportedTimezone: reportedTz },
    };
  },
};
