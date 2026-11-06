import * as crypto from 'crypto';
import * as dgram from 'dgram';

/**
 * Minimal RADIUS client for UNM's self-monitoring probe (no dependencies —
 * the API image has no radclient). Sends ONE Access-Request over UDP and
 * classifies the outcome:
 *
 *   ok            — a well-formed Access-Accept or Access-Reject arrived with
 *                   a valid Authenticator. For our EAP-only site a PAP test
 *                   request ALWAYS gets Access-Reject (no local user matches)
 *                   — that is still proof of life: radiusd is up, listening on
 *                   1812, has loaded its config, and recognizes UNM's source
 *                   IP as an allowlisted client. FreeRADIUS silently DROPS
 *                   requests from unknown clients (no reply at all), so a
 *                   timeout means "unreachable or not allowlisted", never
 *                   "the server is fine".
 *   bad-auth      — a datagram arrived on our port but is not a well-formed
 *                   RADIUS Accept/Reject for our identifier (unexpected data —
 *                   e.g. another service squatting the port). A real, actionable
 *                   misconfiguration. NOTE: secret drift does NOT land here; it
 *                   lands in `timeout` because radiusd drops unverified requests
 *                   without replying.
 *   timeout       — no reply within the deadline: sidecar down, network path
 *                   broken, or UNM's source IP missing from clients.conf.
 *
 * The probe binds its socket to port 0 on the default interface, so the source
 * address is exactly the container IP the renderer put into clients.conf
 * (radiusConfig.detectOwnIp) — no explicit bind needed.
 */

/**
 * The User-Name the probe sends. It is NOT a real user — the EAP-only site can
 * never accept it, so every probe lands as an Access-Reject row in radpostauth.
 * Callers that surface auth results to humans (notifications, counters, the
 * auth-log listing) MUST filter this username out: it is UNM's own heartbeat,
 * not a login attempt by anyone.
 */
export const PROBE_USERNAME = 'unm-selftest';

export type ProbeOutcome = 'ok' | 'bad-auth' | 'timeout';

export interface RadiusProbeResult {
  outcome: ProbeOutcome;
  /** "Access-Accept" / "Access-Reject" when a reply arrived, else null. */
  packetType: string | null;
  latencyMs: number | null;
  detail: string;
}

const RADIUS_CODE_ACCESS_REQUEST = 1;
const RADIUS_CODE_ACCESS_ACCEPT = 2;
const RADIUS_CODE_ACCESS_REJECT = 3;

/**
 * Builds a RADIUS Access-Request packet (User-Name + User-Password, i.e. PAP —
 * the same shape radclient sends). The probe client entry in clients.conf pins
 * `limit_proxy_state = no` and `require_message_authenticator = no`, which
 * disables FR3's per-client auto-learning of BlastRADIUS traits (default
 * `auto` learns from the FIRST packet and then silently drops later packets
 * that violate the learned state — observed live on 3.2.7). With learning off,
 * a plain PAP request is processed deterministically: no local user matches,
 * so it always ends in Access-Reject — which is exactly what we want to see.
 */
function buildAccessRequest(identifier: number, secret: string, username: string): Buffer {
  const auth1 = crypto.randomBytes(16);
  // Attributes: type(1) length(1) value(n). User-Name=1, User-Password=2.
  const userAttr = Buffer.concat([Buffer.from([1, username.length + 2]), Buffer.from(username, 'utf8')]);
  // User-Password (RFC 2865 §5.2): value = Request Authenticator XOR'd with the
  // secret over the PASSWORD length — for PAP the "password" is the username.
  const passAttr = Buffer.concat([Buffer.from([2, username.length + 18]), auth1, Buffer.from(username, 'utf8')]);
  for (let i = 0; i < username.length; i++) {
    passAttr[18 + i] ^= secret.charCodeAt(i % secret.length);
  }
  const body = Buffer.concat([userAttr, passAttr]);
  // RADIUS header Length field = TOTAL packet size incl. the full 20-byte
  // header (code+id+len=4 and the 16-byte authenticator), per RFC 2865 §5.1.
  const header = Buffer.alloc(4);
  header.writeUInt8(RADIUS_CODE_ACCESS_REQUEST, 0);
  header.writeUInt8(identifier & 0xff, 1);
  header.writeUInt16BE(20 + body.length, 2);
  // Request Authenticator: MD5(packet with the auth field zeroed) || secret.
  const forHash = Buffer.concat([header, Buffer.alloc(16), body]);
  const md5 = crypto.createHash('md5').update(forHash).update(secret).digest();
  return Buffer.concat([header, md5, body]);
}

/**
 * Classifies a response datagram. Returns the RADIUS code when the packet is a
 * structurally valid Accept/Reject, else null (treated as bad-auth — e.g. some
 * non-RADIUS garbage arrived on our port).
 *
 * No Authenticator verification: per RFC 2865 §5.1, Access-Accept and
 * Access-Reject carry the Response Authenticator field ZEROED, so there is no
 * MD5 to check on a reject (this was a real bug — an MD5-only check can never
 * match a spec-compliant reply). Liveness is already proven by receiving ANY
 * well-formed RADIUS response for our identifier from the expected source: it
 * means radiusd is up, has loaded its config, and recognizes UNM's IP. Secret
 * drift still surfaces as `timeout` — radiusd drops requests whose Request
 * Authenticator fails verification and sends no reply at all.
 */
function verifyResponse(packet: Buffer): number | null {
  if (packet.length < 20) return null;
  // The Length field must match the actual datagram size (RFC 2865 §5.1).
  if (packet.readUInt16BE(2) !== packet.length) return null;
  const code = packet.readUInt8(0);
  return code === RADIUS_CODE_ACCESS_ACCEPT || code === RADIUS_CODE_ACCESS_REJECT ? code : null;
}

/**
 * Sends one test Access-Request to host:port and resolves with the classified
 * outcome. Never throws — every failure mode is a ProbeOutcome (the caller
 * stores it as a status row). `timeoutMs` bounds the whole round-trip.
 */
export function probeRadius(
  host: string,
  port: number,
  secret: string,
  username = 'unm-selftest',
  timeoutMs = 5_000
): Promise<RadiusProbeResult> {
  return new Promise((resolve) => {
    const socket = dgram.createSocket('udp4');
    let done = false;
    const finish = (result: RadiusProbeResult): void => {
      if (done) return;
      done = true;
      try {
        socket.close();
      } catch {
        // already closed — fine.
      }
      resolve(result);
    };

    const timer = setTimeout(() => {
      finish({
        outcome: 'timeout',
        packetType: null,
        latencyMs: null,
        detail: `no RADIUS reply from ${host}:${port} within ${Math.round(timeoutMs / 1000)}s — sidecar down, path broken, or source IP not in clients.conf`,
      });
    }, timeoutMs);

    socket.on('error', (err) => {
      clearTimeout(timer);
      finish({ outcome: 'timeout', packetType: null, latencyMs: null, detail: `socket error: ${err.message}` });
    });

    // Port 0 on the default interface — source IP = this container's own
    // address (the one rendered into clients.conf).
    socket.bind(0, () => {
      const identifier = crypto.randomInt(1, 255);
      const startedAt = Date.now();
      socket.send(buildAccessRequest(identifier, secret, username), port, host, (sendErr) => {
        if (sendErr) {
          clearTimeout(timer);
          finish({ outcome: 'timeout', packetType: null, latencyMs: null, detail: `send failed: ${sendErr.message}` });
          return;
        }
        socket.once('message', (msg) => {
          // Ignore replies to other identifiers (shouldn't happen — fresh port).
          if (msg.length < 20 || msg.readUInt8(1) !== identifier) return;
          const code = verifyResponse(msg);
          clearTimeout(timer);
          if (code === null) {
            finish({ outcome: 'bad-auth', packetType: null, latencyMs: Date.now() - startedAt, detail: 'response is not a well-formed RADIUS Accept/Reject — unexpected data on the auth port' });
            return;
          }
          const packetType = code === RADIUS_CODE_ACCESS_ACCEPT ? 'Access-Accept' : code === RADIUS_CODE_ACCESS_REJECT ? 'Access-Reject' : `code ${code}`;
          finish({ outcome: 'ok', packetType, latencyMs: Date.now() - startedAt, detail: `${packetType} in ${Date.now() - startedAt}ms` });
        });
      });
    });
  });
}
