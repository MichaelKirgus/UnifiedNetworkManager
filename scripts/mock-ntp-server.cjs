#!/usr/bin/env node
/**
 * Minimal mock NTP/SNTP server for UNM plugin testing (RFC 1305 wire format).
 *
 * Answers every well-formed mode-3 client request with a mode-4 reply carrying
 * the CURRENT time — so the generic-ntp plugin sees "a running NTP service" and
 * can be exercised end-to-end WITHOUT outbound internet access (this host blocks
 * UDP/123). Served values: stratum 2, precision -20 (~954 ns), reference ID
 * "MOCK", root delay/dispersion 0. The transmit timestamp is the real current
 * time, so a correct client measures ~0 drift against its own clock.
 *
 * Run standalone:   node scripts/mock-ntp-server.cjs [port]     (default 123)
 * Or as the compose `mock-ntp` service (see docker-compose.yml).
 */

const dgram = require('dgram');

const PORT = Number(process.argv[2]) || 123;
// Seconds between the NTP epoch (1900-01-01) and the Unix epoch (1970-01-01).
const NTP_EPOCH_OFFSET_SECONDS = 2_208_988_800;

const socket = dgram.createSocket('udp4');

socket.on('message', (msg, rinfo) => {
  // Only answer genuine client requests (mode 3); ignore everything else.
  if (!Buffer.isBuffer(msg) || msg.length < 48 || (msg[0] & 7) !== 3) return;

  const reply = Buffer.alloc(48);
  reply[0] = 0x24; // LI=0, VN=4, Mode=4 (server)
  reply[1] = 2; // stratum 2
  reply.writeInt8(-20, 2); // precision ≈ 954 ns
  reply.writeUInt32BE(0, 4); // root delay 0 s
  reply.writeUInt32BE(0, 8); // root dispersion 0 s
  reply.write('MOCK', 12, 'ascii'); // reference ID (stratum > 1 → ASCII tag)

  const nowMs = Date.now();
  const nowSec = Math.floor(nowMs / 1000) + NTP_EPOCH_OFFSET_SECONDS;
  reply.writeUInt32BE(nowSec, 40); // transmit timestamp — seconds
  // Fraction: the sub-second part as a 32-bit fixed-point value (ms/1000 · 2^32).
  // A hardcoded fraction would make every client measure a constant offset.
  reply.writeUInt32BE(Math.round(((nowMs % 1000) / 1000) * 0x1_0000_0000), 44);

  socket.send(reply, 0, 48, rinfo.port, rinfo.address, (err) => {
    if (!err) console.log(`[mock-ntp] answered ${rinfo.address}:${rinfo.port} with stratum-2 current time`);
  });
});

socket.on('error', (err) => {
  console.error('[mock-ntp] socket error:', err.message);
  process.exit(1);
});

socket.bind(PORT, '0.0.0.0', () => {
  console.log(`[mock-ntp] listening on udp://0.0.0.0:${PORT} (stratum 2, ref MOCK)`);
});
