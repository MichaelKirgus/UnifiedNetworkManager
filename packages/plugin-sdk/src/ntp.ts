/**
 * NTP / SNTP client — shared helper for plugins that need to query a device's
 * time service (RFC 1305 wire format, RFC 4330 SNTP).
 *
 * Why this lives in the SDK: several plugin families will want "is there an
 * NTP/SNTP service on this host, and what time does it serve?" — the generic
 * (S)NTP plugin today, vendor plugins later. The protocol is tiny (one 48-byte
 * UDP datagram), so a single well-tested implementation beats per-plugin copies.
 *
 * Usage:
 *   const r = await queryNtp('192.168.0.1', 123, 5000);
 *   if (r.ok) { ... r.timeEpochMs is the absolute instant the server transmits }
 *
 * The function NEVER throws: every failure mode (DNS, timeout, malformed
 * response, unexpected mode) resolves to `{ ok: false, error }` so callers can
 * map it onto health/metrics without try/catch.
 */

import dgram from 'dgram';
import dns from 'dns';
import net from 'net';

/** Seconds between the NTP epoch (1900-01-01) and the Unix epoch (1970-01-01). */
const NTP_EPOCH_OFFSET_SECONDS = 2_208_988_800;

/** Result of one NTP/SNTP query. `ok` is true for any well-formed server reply. */
export interface NtpQueryResult {
  /** True when a well-formed NTP server response (mode 4–6, ≥ 48 bytes) arrived. */
  ok: boolean;
  /** Human-readable failure reason when !ok (DNS/timeout/malformed/…). */
  error?: string;
  /** Client-measured round-trip time of the query in ms (when a reply arrived). */
  rttMs?: number;
  /** Leap indicator from the header: 0 none, 1/2 last minute has 61/59 s, 3 alarm. */
  leapIndicator?: number;
  /** NTP version negotiated by the server (4 for modern stacks). */
  version?: number;
  /** Stratum of the source: 1 = reference clock, …, 15 = unsynchronized, 0 = unspecified/kiss-o'-death. */
  stratum?: number;
  /** Precision as a power-of-two exponent (e.g. -20 ≈ 954 ns). */
  precision?: number;
  /** Root delay in seconds (16.16 fixed-point, decoded). */
  rootDelaySeconds?: number;
  /** Root dispersion in seconds (16.16 fixed-point, decoded). */
  rootDispersionSeconds?: number;
  /** Reference ID: dotted IPv4 for stratum ≤ 1, else a 4-char ASCII identifier. */
  referenceId?: string;
  /** Absolute instant carried by the server's transmit timestamp, epoch ms (when decodable). */
  timeEpochMs?: number | null;
  /** UTC wall clock of `timeEpochMs` as ISO-8601 ("…Z") — for display/machine use. */
  timeIsoUtc?: string | null;
}

/**
 * Queries one NTP/SNTP endpoint and resolves with the parsed server reply.
 *
 * @param host    IPv4/IPv6 literal or DNS name of the time service.
 * @param port    UDP port (default 123).
 * @param timeoutMs how long to wait for a reply before giving up (default 5000).
 */
export async function queryNtp(
  host: string,
  port = 123,
  timeoutMs = 5_000
): Promise<NtpQueryResult> {
  const target = String(host ?? '').trim();
  if (!target) return { ok: false, error: 'no host to query' };

  // Resolve the address up front — works for literals AND DNS names, and picks
  // the socket family (v4/v6) so we never send v4 packets at a v6 literal.
  let addr: string;
  let family: 4 | 6;
  try {
    const ipVersion = net.isIP(target);
    if (ipVersion !== 0) {
      addr = target;
      family = ipVersion === 6 ? 6 : 4;
    } else {
      const r = await dns.promises.lookup(target, { verbatim: true });
      addr = r.address;
      // dns.lookup reports the family as a NUMBER (4 or 6), not "IPv4"/"IPv6".
      family = r.family === 6 ? 6 : 4;
    }
  } catch (err) {
    return { ok: false, error: `DNS lookup failed for ${target}: ${(err as Error).message}` };
  }

  // One client request: LI=0, VN=4, Mode=3 → header byte 0x1B; the rest zero.
  const packet = Buffer.alloc(48);
  packet[0] = 0x1b;

  return new Promise<NtpQueryResult>((resolve) => {
    let settled = false;
    let socket: dgram.Socket | null = null;
    const finish = (r: NtpQueryResult) => {
      if (!settled) {
        settled = true;
        try {
          socket?.close();
        } catch {
          // already closed.
        }
        resolve(r);
      }
    };

    try {
      // Explicit v4/v6 socket type — unambiguous across @types/node versions.
      socket = dgram.createSocket(family === 6 ? 'udp6' : 'udp4');
    } catch (err) {
      finish({ ok: false, error: `cannot open UDP socket: ${(err as Error).message}` });
      return;
    }

    const startedAt = Date.now();
    const timer = setTimeout(() => {
      finish({ ok: false, error: `no NTP response from ${target}:${port} within ${timeoutMs} ms` });
    }, timeoutMs);

    socket.once('error', (err) => {
      clearTimeout(timer);
      finish({ ok: false, error: err.message });
    });

    socket.once('message', (msg: Buffer) => {
      const rttMs = Date.now() - startedAt;
      clearTimeout(timer);
      const parsed = parseNtpResponse(msg);
      if (parsed.error) {
        finish({ ok: false, error: parsed.error, rttMs });
        return;
      }
      finish({ ok: true, rttMs, ...parsed });
    });

    socket.send(packet, 0, packet.length, port, addr, (err) => {
      if (err) {
        clearTimeout(timer);
        finish({ ok: false, error: `send failed: ${err.message}` });
      }
    });
  });
}

/** Parsed fields of a well-formed reply — or `{ error }` when the datagram is unusable. */
interface ParsedNtp {
  error?: string;
  leapIndicator?: number;
  version?: number;
  stratum?: number;
  precision?: number;
  rootDelaySeconds?: number;
  rootDispersionSeconds?: number;
  referenceId?: string;
  timeEpochMs?: number | null;
  timeIsoUtc?: string | null;
}

/** Decodes a ≥48-byte NTP server reply (never throws). */
function parseNtpResponse(buf: Buffer): ParsedNtp {
  if (!Buffer.isBuffer(buf) || buf.length < 48) {
    return { error: `malformed NTP response (${buf?.length ?? 0} bytes, need ≥ 48)` };
  }

  const header = buf[0];
  const leapIndicator = header >> 6;
  const version = (header >> 3) & 7;
  const mode = header & 7;
  // Modes: 1–3 client, 4 server, 5 broadcast, 6 NTS. Anything ≤ 3 means we got
  // our own request echoed back (or a non-server spoke to us) — not an answer.
  if (mode < 4 || mode > 6) {
    return { error: `unexpected NTP mode ${mode} in response (expected server reply)` };
  }

  const stratum = buf[1];
  const precision = buf.readInt8(2); // signed exponent, e.g. -20
  // Root delay / dispersion are 32-bit fields: high 16 bits integer seconds,
  // low 16 bits fraction (16.16 fixed-point).
  const rootDelaySeconds = buf.readUInt16BE(4) + buf.readUInt16BE(6) / 0x10000;
  const rootDispersionSeconds = buf.readUInt16BE(8) + buf.readUInt16BE(10) / 0x10000;

  // Reference ID: IPv4 address (dotted quad) for stratum ≤ 1, else a 4-char ASCII tag.
  let referenceId: string;
  if (stratum <= 1) {
    referenceId = `${buf[12]}.${buf[13]}.${buf[14]}.${buf[15]}`;
  } else {
    referenceId = buf.toString('ascii', 12, 16).replace(/\0+$/, '').trim();
  }

  // Transmit timestamp (offset 40): the time the server sent this reply — THE
  // value a client would set its clock to. NTP seconds + 32-bit fraction.
  const ntpSeconds = buf.readUInt32BE(40);
  const fraction = buf.readUInt32BE(44);
  if (ntpSeconds === 0) {
    return { error: 'server returned a zero transmit timestamp' };
  }

  const timeEpochMs = Math.round((ntpSeconds - NTP_EPOCH_OFFSET_SECONDS) * 1000 + (fraction / 0x1_0000_0000) * 1000);
  return {
    leapIndicator,
    version,
    stratum,
    precision,
    rootDelaySeconds,
    rootDispersionSeconds,
    referenceId,
    timeEpochMs,
    timeIsoUtc: new Date(timeEpochMs).toISOString(),
  };
}
