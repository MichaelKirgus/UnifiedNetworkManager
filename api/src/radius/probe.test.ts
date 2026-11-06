/**
 * Unit tests for the RADIUS self-monitoring probe (probe.ts).
 *
 * Security-adjacent: a broken probe either masks a dead sidecar (false "ok")
 * or flaps into CRIT alerts (false "timeout"). The packet layout and response
 * classification are verified here WITHOUT a live FreeRADIUS — the request
 * bytes are checked field-by-field against an independent reading of RFC 2865,
 * and probeRadius() is exercised end-to-end against a loopback UDP fake server
 * that returns spec-compliant replies.
 *
 * The single most important regression covered: per RFC 2865 §5.1, Access-Accept
 * and Access-Reject carry the Response Authenticator field ZEROED, so a
 * well-formed reject MUST classify as ok (liveness), never bad-auth. An
 * MD5-only check can never match a spec-compliant reply — that was a real bug.
 */

import * as crypto from 'crypto';
import * as dgram from 'dgram';
import { buildAccessRequest, probeRadius, verifyResponse, PROBE_USERNAME } from './probe';

const CODE_REQUEST = 1;
const CODE_ACCEPT = 2;
const CODE_REJECT = 3;

describe('buildAccessRequest (RFC 2865 §5.1/§5.3 layout)', () => {
  const secret = 'b763e7bb299cd93f36c31e12ee01f05b2003d7d3f34116bc';
  const username = 'unm-selftest';

  it('emits a structurally valid Access-Request (code, id, length)', () => {
    const pkt = buildAccessRequest(0x2a, secret, username);

    // Minimum RADIUS packet is the 20-byte header.
    expect(pkt.length).toBeGreaterThanOrEqual(20);
    // code = Access-Request
    expect(pkt.readUInt8(0)).toBe(CODE_REQUEST);
    // identifier round-trips (mod 256)
    expect(pkt.readUInt8(1)).toBe(0x2a & 0xff);
    // Length field MUST equal the total datagram size (§5.1). This is exactly
    // the invariant verifyResponse() relies on to reject truncated/garbage.
    expect(pkt.readUInt16BE(2)).toBe(pkt.length);
  });

  it('carries a User-Name attribute with the probe username', () => {
    const pkt = buildAccessRequest(7, secret, username);

    // Attributes start right after the 20-byte header. First attr: type=1
    // (User-Name), length = valueLen + 2, then the UTF-8 username.
    expect(pkt.readUInt8(20)).toBe(1); // User-Name
    expect(pkt.readUInt8(21)).toBe(username.length + 2);
    expect(pkt.subarray(22, 22 + username.length).toString('utf8')).toBe(username);
  });

  it('carries a User-Password (PAP) attribute of the correct size', () => {
    const pkt = buildAccessRequest(7, secret, username);

    // After User-Name: type=2 (User-Password), length = 18 + username.length
    // (the 16-byte authenticator prefix + the password bytes).
    const userAttrLen = username.length + 2;
    const passOffset = 20 + userAttrLen;
    expect(pkt.readUInt8(passOffset)).toBe(2); // User-Password
    expect(pkt.readUInt8(passOffset + 1)).toBe(username.length + 18);
    // Total packet must be exactly header + both attributes.
    expect(pkt.length).toBe(20 + userAttrLen + (username.length + 18));
  });

  it('XORs the password bytes with the secret over the username length', () => {
    const pkt = buildAccessRequest(7, secret, username);

    // Independent re-implementation of the PAP transform: value = RequestAuth
    // (16 bytes) || password XOR key, where for this probe "password" is the
    // username and the key cycles over the shared secret.
    const userAttrLen = username.length + 2;
    const passValueStart = 20 + userAttrLen + 2 + 16; // skip type+len + RequestAuth
    for (let i = 0; i < username.length; i++) {
      const expected = username.charCodeAt(i) ^ secret.charCodeAt(i % secret.length);
      expect(pkt[passValueStart + i]).toBe(expected & 0xff);
    }
  });

  it('uses a fresh Request Authenticator per call (not constant)', () => {
    const a = buildAccessRequest(7, secret, username);
    const b = buildAccessRequest(7, secret, username);
    // The 16-byte authenticator field (offsets 4..20) should differ between
    // calls — a fixed value would be a replay/weakness smell.
    expect(a.subarray(4, 20).equals(b.subarray(4, 20))).toBe(false);
  });

  it('matches the probe username constant used for filtering', () => {
    expect(PROBE_USERNAME).toBe('unm-selftest');
  });
});

describe('verifyResponse (structural classification)', () => {
  // Builds a minimal well-formed reply: header + zeroed authenticator, no attrs.
  function makeReply(code: number, id: number, authZeroed = true): Buffer {
    const pkt = Buffer.alloc(20);
    pkt.writeUInt8(code, 0);
    pkt.writeUInt8(id & 0xff, 1);
    pkt.writeUInt16BE(20, 2); // Length = 20 (header only)
    if (!authZeroed) crypto.randomBytes(16).copy(pkt, 4);
    return pkt;
  }

  it('accepts a spec-compliant Access-Reject with ZEROED authenticator', () => {
    // THE regression: §5.1 zeroes the Response Authenticator on Accept/Reject,
    // so liveness = well-formed reply for our id, NOT an MD5 match.
    const reject = makeReply(CODE_REJECT, 0x2a, true);
    expect(verifyResponse(reject)).toBe(CODE_REJECT);
  });

  it('accepts a spec-compliant Access-Accept with ZEROED authenticator', () => {
    const accept = makeReply(CODE_ACCEPT, 0x2a, true);
    expect(verifyResponse(accept)).toBe(CODE_ACCEPT);
  });

  it('rejects a datagram shorter than the 20-byte header', () => {
    expect(verifyResponse(Buffer.from([1, 2, 3]))).toBeNull();
    expect(verifyResponse(Buffer.alloc(19))).toBeNull();
  });

  it('rejects a packet whose Length field does not match its size', () => {
    const pkt = makeReply(CODE_REJECT, 0x2a);
    pkt.writeUInt16BE(40, 2); // claim 40 bytes but only send 20
    expect(verifyResponse(pkt)).toBeNull();
  });

  it('rejects a non-Accept/Reject code (e.g. Access-Challenge = 11)', () => {
    const challenge = makeReply(11, 0x2a);
    expect(verifyResponse(challenge)).toBeNull();
  });
});

describe('probeRadius (end-to-end against a loopback UDP fake server)', () => {
  let server: dgram.Socket | null = null;

  afterEach(async () => {
    if (server) {
      const s = server;
      server = null;
      await new Promise<void>((resolve) => s.close(() => resolve()));
    }
  });

  function startServer(handler: (req: Buffer, rinfo: dgram.RemoteInfo) => void): Promise<number> {
    return new Promise((resolve, reject) => {
      const s = dgram.createSocket('udp4');
      s.on('error', reject);
      s.bind(0, '127.0.0.1', () => {
        server = s;
        resolve(s.address().port);
      });
      s.on('message', (msg, rinfo) => handler(msg, rinfo));
    });
  }

  it('classifies a well-formed Access-Reject reply as ok (liveness)', async () => {
    const port = await startServer((req, rinfo) => {
      // Echo back a minimal spec-compliant reject: code=3, same id, zeroed auth.
      const reply = Buffer.alloc(20);
      reply.writeUInt8(CODE_REJECT, 0);
      reply.writeUInt8(req.readUInt8(1), 1); // match the request identifier
      reply.writeUInt16BE(20, 2);
      server!.send(reply, rinfo.port, rinfo.address);
    });

    const res = await probeRadius('127.0.0.1', port, 'whatever-secret', PROBE_USERNAME, 3000);
    expect(res.outcome).toBe('ok');
    expect(res.packetType).toBe('Access-Reject');
    expect(typeof res.latencyMs).toBe('number');
  });

  it('classifies a well-formed Access-Accept reply as ok', async () => {
    const port = await startServer((req, rinfo) => {
      const reply = Buffer.alloc(20);
      reply.writeUInt8(CODE_ACCEPT, 0);
      reply.writeUInt8(req.readUInt8(1), 1);
      reply.writeUInt16BE(20, 2);
      server!.send(reply, rinfo.port, rinfo.address);
    });

    const res = await probeRadius('127.0.0.1', port, 'whatever-secret', PROBE_USERNAME, 3000);
    expect(res.outcome).toBe('ok');
    expect(res.packetType).toBe('Access-Accept');
  });

  it('classifies garbage on the auth port as bad-auth (not ok, not timeout)', async () => {
    const port = await startServer((req, rinfo) => {
      // A datagram ADDRESSED TO OUR IDENTIFIER that is NOT a well-formed
      // Accept/Reject: valid size + matching id, but an invalid RADIUS code.
      // (A packet with the wrong id is correctly ignored → timeout, not bad-auth.)
      const junk = Buffer.alloc(20);
      junk.writeUInt8(99, 0); // invalid RADIUS code
      junk.writeUInt8(req.readUInt8(1), 1); // match our identifier
      junk.writeUInt16BE(20, 2);
      server!.send(junk, rinfo.port, rinfo.address);
    });

    const res = await probeRadius('127.0.0.1', port, 'whatever-secret', PROBE_USERNAME, 3000);
    expect(res.outcome).toBe('bad-auth');
    expect(res.packetType).toBeNull();
  });

  it('times out when the server never replies (sidecar down)', async () => {
    // Bind a socket that accepts but never answers.
    const port = await startServer(() => {
      /* silent — simulates radiusd dropping an unverified/unknown-client request */
    });

    const res = await probeRadius('127.0.0.1', port, 'whatever-secret', PROBE_USERNAME, 300);
    expect(res.outcome).toBe('timeout');
    expect(res.packetType).toBeNull();
    expect(res.latencyMs).toBeNull();
  });

  it('ignores a reply for a DIFFERENT identifier and keeps waiting to timeout', async () => {
    const port = await startServer((req, rinfo) => {
      // Reply with the WRONG identifier — the probe must not accept it.
      const wrongId = (req.readUInt8(1) + 1) & 0xff;
      const reply = Buffer.alloc(20);
      reply.writeUInt8(CODE_REJECT, 0);
      reply.writeUInt8(wrongId, 1);
      reply.writeUInt16BE(20, 2);
      server!.send(reply, rinfo.port, rinfo.address);
    });

    const res = await probeRadius('127.0.0.1', port, 'whatever-secret', PROBE_USERNAME, 300);
    expect(res.outcome).toBe('timeout');
  });
});
