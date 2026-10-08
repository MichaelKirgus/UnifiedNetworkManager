/**
 * @unm/plugin-test-kit — SNTP mock appliance (RFC 1305 wire format).
 *
 * Answers ANY ≥48-byte UDP datagram with a well-formed stratum-2 server reply
 * carrying the current time in its transmit timestamp. Wire layout matches what
 * the SDK's queryNtp()/parseNtpResponse() expects: header byte LI=0 VN=4 mode=4
 * (0x23), stratum, precision, 16.16 root delay/dispersion, ASCII reference id
 * ("MOCK" for stratum > 1) and a non-zero transmit timestamp at offset 40.
 */

import dgram from 'node:dgram';

const NTP_EPOCH_OFFSET_SECONDS = 2_208_988_800;

/**
 * @param {{stratum?: number, precision?: number}} [opts]
 * @returns {Promise<{port:number, stop:()=>Promise<void>}>}
 */
export function startNtpMock({ stratum = 2, precision = -20 } = {}) {
  return new Promise((resolve, reject) => {
    const sock = dgram.createSocket('udp4');
    sock.on('error', (err) => {
      if (!sock.__started) reject(err);
    });
    sock.on('message', (msg, rinfo) => {
      if (msg.length < 48) return; // ignore malformed clients — a real server would too
      const reply = Buffer.alloc(48);
      reply[0] = 0x24; // LI=0, VN=4, mode=4 (server) — 0x23 would be mode 3 (client echo!)
      reply[1] = stratum;
      reply.writeInt8(precision, 2);
      // Root delay 0.5 s / dispersion 0.75 s as 16.16 fixed-point.
      reply.writeUInt16BE(0, 4);
      reply.writeUInt16BE(0x8000, 6);
      reply.writeUInt16BE(0, 8);
      reply.writeUInt16BE(0xc000, 10);
      if (stratum <= 1) {
        // Dotted-quad reference id for stratum ≤ 1.
        [127, 126, 125, 124].forEach((o, i) => reply[12 + i] = o);
      } else {
        reply.write('MOCK', 12, 'ascii');
      }
      const nowSec = Math.floor(Date.now() / 1000);
      reply.writeUInt32BE(nowSec + NTP_EPOCH_OFFSET_SECONDS >>> 0, 40);
      // Fraction: (ms * 2^32) / 1000 — keep it in uint32 range.
      const frac = Math.round(((Date.now() % 1000) * 0x1_0000_0000) / 1000) >>> 0;
      reply.writeUInt32BE(frac, 44);
      sock.send(reply, rinfo.port, rinfo.address);
    });
    sock.bind(0, '127.0.0.1', () => {
      sock.__started = true;
      const port = sock.address().port;
      resolve({
        port,
        stop: () => new Promise((res) => sock.close(() => res())),
      });
    });
  });
}
