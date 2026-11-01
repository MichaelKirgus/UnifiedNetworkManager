/**
 * Test config for plugins/generic-ipmi — see packages/plugin-test-kit README.
 * T4 target: an in-process mock BMC speaking IPMI 2.0 / RMCP+ (cipher suite 3)
 * over UDP — Open Session + RAKP1-4 with real HMAC-SHA1/AES-CBC crypto, then the
 * command set the monitoring poll uses (chassis status, SDR walk + sensor
 * readings, FRU read, SEL tail, LAN config params). The mock verifies the
 * console's RAKP3 authcode and integrity trailers, so a broken client fails T4.
 */

import dgram from 'node:dgram';
import crypto from 'node:crypto';

// --- Crypto helpers (mirror the plugin's implementation — must match spec) -------

function hmacSha1(key, ...parts) {
  const h = crypto.createHmac('sha1', key);
  for (const p of parts) h.update(p);
  return h.digest();
}

// K2 is a full 20-byte SHA-1 digest; AES-128 uses only its first 16 bytes (openipmi/OpenSSL).
const aesKey = (k2) => k2.subarray(0, 16);

/** IPMI confidentiality framing: random IV + ciphertext; pad bytes 1..n then a pad-length byte. */
function aesEncrypt(k2, pt) {
  const mod = (pt.length + 1) % 16;
  const padLen = mod ? 16 - mod : 0;
  const padded = Buffer.alloc(pt.length + padLen + 1);
  pt.copy(padded, 0);
  for (let i = 0; i < padLen; ++i) padded[pt.length + i] = i + 1;
  padded[pt.length + padLen] = padLen;
  const iv = crypto.randomBytes(16);
  const c = crypto.createCipheriv('aes-128-cbc', aesKey(k2), iv);
  c.setAutoPadding(false);
  return Buffer.concat([iv, c.update(padded), c.final()]);
}

function aesDecrypt(k2, framed) {
  const iv = framed.subarray(0, 16);
  const ct = framed.subarray(16);
  const d = crypto.createDecipheriv('aes-128-cbc', aesKey(k2), iv);
  d.setAutoPadding(false);
  let plain;
  try {
    plain = Buffer.concat([d.update(ct), d.final()]);
  } catch (e) {
    throw new Error(`mock: AES decrypt failed: ${e.message}`);
  }
  const padLen = plain[plain.length - 1];
  return plain.subarray(0, plain.length - 1 - padLen);
}

function le32(v) {
  const b = Buffer.alloc(4);
  b.writeUInt32LE(v >>> 0);
  return b;
}
const readLe32 = (buf, o) => buf.readUInt32LE(o);
const readLe16 = (buf, o) => buf.readUInt16LE(o);

/** Copies src into dst at offset with the byte order reversed (RMCP+ wire form). */
function reverseCopy(src, dst, offset) {
  for (let i = 0; i < src.length; ++i) dst[offset + i] = src[src.length - 1 - i];
}

// --- FRU image --------------------------------------------------------------------

function buildFruImage() {
  const area = (fields) => {
    // fields: [type, ascii-string] pairs; the area is terminated by type 0x00.
    // Layout per IPMI spec: length byte (area size excl. itself), then
    // [type(1), len(1), value(len)]* fields, ending with a 0x00 terminator.
    const fieldBytes = Buffer.concat(fields.map(([t, s]) => Buffer.concat([Buffer.from([t, s.length]), Buffer.from(s, 'ascii')])));
    const content = Buffer.concat([fieldBytes, Buffer.from([0x00])]);
    // length byte counts every byte after itself (fields + terminator).
    return Buffer.concat([Buffer.from([content.length]), content]);
  };

  const chassis = area([[1, 'MockCorp'], [2, 'MockServer'], [5, 'SN000001']]);
  const board = area([[2, 'MockCorp'], [3, 'MockServer'], [4, 'BSN00001']]);
  const product = area([[1, 'MockCorp'], [2, 'MockServer'], [5, 'PSN00001']]);

  const header = Buffer.alloc(8);
  header[0] = 0x01; // version
  header[1] = 0x00; // internal offset
  header[2] = 8; // chassis area start
  header[3] = 8 + chassis.length; // board area start
  header[4] = 8 + chassis.length + board.length; // product area start
  return Buffer.concat([header, chassis, board, product]);
}

// --- SDR records --------------------------------------------------------------------

/** Builds one full-sensor SDR record (type 0x01) content buffer (59 bytes). */
function buildSensorRecord({ sensorNum, typeCode, baseUnit, m, b, k1, k2, upperCritRaw, upperNonCritRaw, id }) {
  const c = Buffer.alloc(59, 0);
  // keys: owner_id=0, channel/lun/resv=0, sensor_num.
  c[2] = sensorNum;
  // entity id/instance (3,1 = processor), init/capabilities/type.
  c[7] = typeCode;
  c[8] = 0x01; // threshold reading type
  // mask bytes [9..14] zero.
  // unit byte [15]: analog format in bits [7:6] — two's complement (2).
  c[15] = 0x40;
  c[16] = baseUnit & 0xff; // base unit type code
  c[17] = 0x00; // modifier unit
  c[18] = 0x00; // linearization: linear
  // mtol u16 LE @19..20 — openipmi __TO_M layout (wraparound, NOT contiguous):
  //   M[7:0] in bits [15:8], M[9:8] in bits [7:6]. Round-trips through the macro.
  const mtolField = ((m & 0xff) << 8) | (((m >> 8) & 3) << 6);
  c[19] = mtolField & 0xff;
  c[20] = (mtolField >> 8) & 0xff;
  // bacc u32 LE @21..24 — openipmi __TO_B/__TO_R_EXP/__TO_B_EXP layout:
  //   B[7:0] in bits [31:24], B[9:8] in bits [25:24]; k2(Rexp) signed-4 in bits [7:4]; k1(Bexp) signed-4 in bits [3:0].
  const bacc = ((b & 0xff) << 24) | (((b >> 8) & 3) << 22) | ((k2 & 0xf) << 4) | (k1 & 0xf); // k-nibbles are signed two's-complement (openipmi tos32(...,4))
  c[21] = bacc & 0xff;
  c[22] = (bacc >> 8) & 0xff;
  c[23] = (bacc >> 16) & 0xff;
  c[24] = (bacc >> 24) & 0xff;
  // analog_flag, nominal/normal/sensor raw values.
  c[25] = 0x07; // nominal+max+min present
  c[26] = 0x00; // nominal read (raw)
  c[27] = upperCritRaw & 0xff; // normal max (raw) — informational only
  c[28] = 0x00; // normal min
  c[29] = 0xff; // sensor max
  c[30] = 0x00; // sensor min
  // thresholds: upper{non_recover, critical, non_critical} @31..33, lower @34..36.
  c[31] = 0xff; // upper non-recoverable — absent (invalid)
  c[32] = upperCritRaw & 0xff;
  c[33] = upperNonCritRaw & 0xff;
  c[34] = 0x00; // lower thresholds absent
  c[35] = 0x00;
  c[36] = 0x00;
  // hysteresis @37..38, reserved @39..40, oem @41.
  // id_code @42 + id_string @43..58 (ASCII).
  const idBytes = Buffer.from(id.slice(0, 16), 'ascii');
  c[42] = idBytes.length; // ASCII: length in low 6 bits
  idBytes.copy(c, 43);
  return c;
}

// --- Mock BMC -----------------------------------------------------------------------

export async function startIpmiMock() {
  const events = [];
  const fruImage = buildFruImage();

  // SDR repository: three full sensor records.
  const sdrRecords = new Map([
    [0x0001, buildSensorRecord({ sensorNum: 0x01, typeCode: 0x01, baseUnit: 0x01 /* °C */, m: 1, b: 0, k1: 0, k2: 0, upperCritRaw: 85, upperNonCritRaw: 75, id: 'CPU1 Temp' })],
    [0x0002, buildSensorRecord({ sensorNum: 0x02, typeCode: 0x02, baseUnit: 0x03 /* Volts */, m: 1, b: 0, k1: 0, k2: 0, upperCritRaw: 15, upperNonCritRaw: 14, id: 'PSU1 Voltage' })],
    [0x0003, buildSensorRecord({ sensorNum: 0x03, typeCode: 0x04, baseUnit: 0x07 /* RPM */, m: 10, b: 0, k1: 0, k2: 0, upperCritRaw: 80, upperNonCritRaw: 60, id: 'Fan1' })],
  ]);
  const sdrOrder = [0x0001, 0x0002, 0x0003];

  // Live sensor readings (raw bytes).
  const sensorReadings = new Map([[0x01, 45], [0x02, 12], [0x03, 45]]); // Fan1: 45*10=450 RPM < 600 non-crit → ok

  // Per-sensor threshold settings (raw bytes) — mutable state for Set Sensor Thresholds.
  const thresholds = new Map([
    [0x01, { lowerNonCrit: 0x00, lowerCrit: 0x00, lowerNonRecov: 0xff, upperNonCrit: 75, upperCrit: 85, upperNonRecov: 0xff }], // CPU1 Temp °C
    [0x02, { lowerNonCrit: 14, lowerCrit: 13, lowerNonRecov: 0xff, upperNonCrit: 14, upperCrit: 15, upperNonRecov: 0xff }], // PSU1 Voltage V
    [0x03, { lowerNonCrit: 60, lowerCrit: 50, lowerNonRecov: 0xff, upperNonCrit: 70, upperCrit: 80, upperNonRecov: 0xff }], // Fan1 RPM (m=10)
  ]);

  // SEL records (newest first in the backward walk).
  const nowSec = Math.floor(Date.now() / 1000);
  const selRecords = new Map([
    [0x0002, { ts: nowSec - 3600, sensorType: 0x01, sensorNum: 0x01, eventByte: 0x82 /* upper non-crit high, deasserted */ }],
    [0x0001, { ts: nowSec - 7200, sensorType: 0x04, sensorNum: 0x03, eventByte: 0x09 /* limit exceeded, asserted */ }],
  ]);

  // LAN config params.
  const lanParams = new Map([
    [1, Buffer.from([192, 168, 100, 10])],
    [2, Buffer.from([255, 255, 255, 0])],
    [3, Buffer.from([192, 168, 100, 1])],
    [4, Buffer.from([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])],
  ]);

  // Aspeed OEM fan state (netfn 0x3a) — AST2600 layout: mode bytes per channel
  // (0=disabled, 1=auto, 2=manual) + duty percent. All channels start in auto @40%.
  const aspeed = {
    variant: 'ast2600',
    modes: Array.from({ length: 16 }, () => 1), // all auto
    duties: Array.from({ length: 16 }, () => 40),
  };

  const BMC_ID = 0x12345678;
  const BMC_GUID = crypto.createHash('sha1').update('mock-bmc-guid').digest().subarray(0, 16);
  let session = null; // current RMCP+ session state (one at a time — the kit is sequential)

  const socket = dgram.createSocket({ type: 'udp4', reuseAddr: false });

  /** Builds an in-session response packet (encrypted + integrity trailer when active). */
  function buildSessionResponse(payloadType, plaintext, seqNum) {
    let wire;
    if (session.cryptAlg === 1) wire = aesEncrypt(session.k2, plaintext);
    else wire = plaintext;

    const payloadLen = wire.length;
    // Integrity pad: make (12 + payloadLen + 2 + s) a multiple of 4.
    let padSize = 0;
    if (session.integrityAlg === 1) {
      while ((12 + payloadLen + 2 + padSize) % 4 !== 0) ++padSize;
    }

    const total = 16 + wire.length + padSize + (session.integrityAlg === 1 ? 2 + 12 : 0);
    const pkt = Buffer.alloc(total, 0xff);
    pkt[0] = 0x06; // RMCP version
    pkt[3] = 0x07; // class IPMI
    pkt[4] = 0x06; // authtype RMCP+
    let pt = payloadType;
    if (session.cryptAlg === 1) pt |= 0x80;
    if (session.integrityAlg === 1) pt |= 0x40;
    pkt[5] = pt;
    pkt.writeUInt32LE(BMC_ID, 6); // session id
    pkt.writeUInt32LE(seqNum || 1, 10); // sequence number (client ignores it)
    pkt.writeUInt16LE(payloadLen, 14);
    wire.copy(pkt, 16);

    if (session.integrityAlg === 1) {
      const trailerStart = 16 + wire.length;
      pkt[trailerStart + padSize] = padSize; // padLength field
      pkt[trailerStart + padSize + 1] = 0x07; // next header
      const macInputSize = 12 + payloadLen + padSize + 2;
      hmacSha1(session.k1, pkt.subarray(4, 4 + macInputSize)).subarray(0, 12).copy(pkt, trailerStart + padSize + 2);
    }
    return pkt;
  }

  /** Builds a pre-session response packet (never encrypted/authenticated). */
  function buildPreSessionResponse(payloadType, payload) {
    const pkt = Buffer.alloc(16 + payload.length, 0);
    pkt[0] = 0x06;
    pkt[3] = 0x07;
    pkt[4] = 0x06;
    pkt[5] = payloadType;
    pkt.writeUInt16LE(payload.length, 14);
    payload.copy(pkt, 16);
    return pkt;
  }

  /** Dispatches one decrypted IPMI command message → response data (after comCode). */
  function handleCommand(netfn, cmd, data) {
    // Returns [comCode, dataBuffer].
    switch ((netfn << 8) | cmd) {
      case (0x06 << 8) | 0x42: // Set Session Privilege Level
        events.push('set-priv-level');
        return [0x00, Buffer.alloc(0)];

      case (0x00 << 8) | 0x01: // Get Chassis Status
        events.push('chassis-status');
        return [0x00, Buffer.from([0x01 /* powered on */, 0x00])];

      case (0x06 << 8) | 0x48: {
        // Activate Payload (SOL) — channel(1), payloadType(1).
        events.push('activate-sol');
        const channel = data[0] ?? 1;
        return [0x00, Buffer.from([channel, 260 /* max chars per packet */])];
      }

      case (0x0a << 8) | 0x20: {
        // Get SDR Info → version(1), count(u16 LE), freeSpace(u16), stamps(8), opSupport(1).
        events.push('sdr-info');
        const count = sdrOrder.length;
        return [0x00, Buffer.from([0x51, count & 0xff, (count >> 8) & 0xff, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0x0f])];
      }

      case (0x0a << 8) | 0x21: // Reserve SDR → reservation id u16 LE.
        events.push('reserve-sdr');
        return [0x00, Buffer.from([0x34, 0x12])];

      case (0x0a << 8) | 0x23: {
        // Get SDR → request [reserveId(2), id(2), offset(1), length(1)].
        events.push('get-sdr');
        const reqId = readLe16(data, 2);
        const idx = sdrOrder.indexOf(reqId === 0 ? sdrOrder[0] : reqId);
        if (idx < 0) return [0xda /* invalid record id */, Buffer.alloc(0)];
        const recId = sdrOrder[idx];
        const nextId = idx + 1 < sdrOrder.length ? sdrOrder[idx + 1] : 0xffff;
        const content = sdrRecords.get(recId);
        // Response data: next_id(2) + rec_id(2) + version(1)=0x51 + type(1) + length(1) + content.
        const rspData = Buffer.alloc(7 + content.length);
        rspData.writeUInt16LE(nextId, 0);
        rspData.writeUInt16LE(recId, 2);
        rspData[4] = 0x51; // version
        rspData[5] = 0x01; // record type: full sensor
        rspData[6] = content.length;
        content.copy(rspData, 7);
        return [0x00, rspData];
      }

      case (0x04 << 8) | 0x2d: {
        // Get Sensor Reading → request [sensorNum]. Response [status(1), reading(1)].
        events.push('get-sensor-reading');
        const sensorNum = data[0];
        const raw = sensorReadings.get(sensorNum);
        if (raw === undefined) return [0xd0 /* sensor not present */, Buffer.alloc(0)];
        return [0x00, Buffer.from([0x00, raw])];
      }

      case (0x04 << 8) | 0x27: {
        // Get Sensor Thresholds → request [sensorNum]. Response = 6 raw bytes in the
        // order lowerNC, lowerC, lowerNR, upperNC, upperC, upperNR.
        events.push('get-sensor-threshold');
        const sensorNum = data[0];
        if (!thresholds.has(sensorNum)) return [0xd0 /* sensor not present */, Buffer.alloc(0)];
        const t = thresholds.get(sensorNum);
        return [0x00, Buffer.from([t.lowerNonCrit, t.lowerCrit, t.lowerNonRecov, t.upperNonCrit, t.upperCrit, t.upperNonRecov])];
      }

      case (0x04 << 8) | 0x26: {
        // Set Sensor Thresholds → request [sensorNum(1), setMask(1), lNC, lC, lNR, uNC, uC, uNR].
        events.push('set-sensor-threshold');
        const sensorNum = data[0];
        const mask = data[1];
        if (!thresholds.has(sensorNum)) return [0xd0 /* sensor not present */, Buffer.alloc(0)];
        const t = thresholds.get(sensorNum);
        // Mask bits (openipmi *_SPECIFIED): 0x01 lNC, 0x02 lC, 0x04 lNR, 0x08 uNC, 0x10 uC, 0x20 uNR.
        if (mask & 0x01) t.lowerNonCrit = data[2];
        if (mask & 0x02) t.lowerCrit = data[3];
        if (mask & 0x04) t.lowerNonRecov = data[4];
        if (mask & 0x08) t.upperNonCrit = data[5];
        if (mask & 0x10) t.upperCrit = data[6];
        if (mask & 0x20) t.upperNonRecov = data[7];
        return [0x00, Buffer.alloc(0)];
      }

      case (0x0a << 8) | 0x18: {
        // Read FRU Data → request [fruId(1), offset(1), count(1)].
        events.push('read-fru');
        const offset = data[1] ?? 0;
        const count = data[2] ?? 32;
        if (offset >= fruImage.length) return [0x00, Buffer.alloc(0)]; // end of FRU
        const chunk = fruImage.subarray(offset, Math.min(offset + count, fruImage.length));
        return [0x00, Buffer.from(chunk)];
      }

      case (0x0a << 8) | 0x40: {
        // Get SEL Info → version(1), entryCount(u16 LE @1..2), freeSpace(u16), stamps(8), supportedCmds(1).
        events.push('sel-info');
        const count = selRecords.size;
        return [0x00, Buffer.from([0x51, count & 0xff, (count >> 8) & 0xff, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0x0f])];
      }

      case (0x0a << 8) | 0x42: // Reserve SEL → reservation id u16 LE.
        events.push('reserve-sel');
        return [0x00, Buffer.from([0x78, 0x56])];

      case (0x0a << 8) | 0x43: {
        // Get SEL Entry → request [reserveId(2), id(2), offset(1)=0, length(1)].
        // Backward walk: id=0 → newest first; each response's next_id points further back.
        events.push('get-sel-entry');
        const reqId = readLe16(data, 2);
        const order = [...selRecords.keys()].sort((a, b) => b - a); // newest (highest id) first
        let idx;
        if (reqId === 0) idx = 0;
        else {
          const pos = order.indexOf(reqId);
          idx = pos < 0 ? -1 : pos + 1;
        }
        if (idx >= order.length) return [0xda, Buffer.alloc(0)]; // past the oldest → end
        const recId = order[idx];
        const nextId = idx + 1 < order.length ? order[idx + 1] : 0xffff;
        const r = selRecords.get(recId);
        // Response data: next_id(2) + rec_id(2) + record_type(1)=0x02 (system event)
        //   + timestamp u32 LE @5..8 + gen_id u16 @9..10 + evm_rev @11 + sensor_type @12
        //   + sensor_num @13 + event_byte @14 + event_data[3] @15..17.
        const rspData = Buffer.alloc(18, 0);
        rspData.writeUInt16LE(nextId, 0);
        rspData.writeUInt16LE(recId, 2);
        rspData[4] = 0x02; // record type: system event
        rspData.writeUInt32LE(r.ts >>> 0, 5);
        rspData.writeUInt16LE(0x0005, 9); // gen id (system)
        rspData[11] = 0x04; // EVM rev
        rspData[12] = r.sensorType;
        rspData[13] = r.sensorNum;
        rspData[14] = r.eventByte;
        return [0x00, rspData];
      }

      case (0x0c << 8) | 0x52: {
        // Get LAN Config Params → request [channel(1), paramSelector(2 LE)].
        events.push('get-lan-param');
        const paramId = readLe16(data, 1);
        return [0x00, Buffer.from(lanParams.get(paramId) ?? [])];
      }

      case (0x0c << 8) | 0x51: {
        // Set LAN Config Params → request [channel(1), paramSelector(2 LE), inData...].
        events.push('set-lan-param');
        const paramId = readLe16(data, 1);
        lanParams.set(paramId, Buffer.from(data.subarray(3)));
        return [0x00, Buffer.alloc(0)];
      }

      case (0x3a << 8) | 0xd0: {
        // Aspeed AST2600 OEM fan commands — cmd byte is always 0xd0; the
        // subcommand rides in data[0].
        const sub = data[0];
        switch (sub) {
          case 0x12: // read mode → 16 channel bytes
            events.push('aspeed-read-mode');
            return [0x00, Buffer.from(aspeed.modes)];
          case 0x11: // set mode ← data[1..16] (0=disabled, 1=auto, 2=manual)
            events.push('aspeed-set-mode');
            for (let i = 0; i < 16 && i + 1 < data.length; ++i) aspeed.modes[i] = data[i + 1];
            return [0x00, Buffer.alloc(0)];
          case 0x0f: // read duty → 16 percent bytes
            events.push('aspeed-read-duty');
            return [0x00, Buffer.from(aspeed.duties)];
          case 0x0e: {
            // set duty ← data[1..16] — only effective while a channel is manual.
            events.push('aspeed-set-duty');
            for (let i = 0; i < 16 && i + 1 < data.length; ++i) if (aspeed.modes[i] === 2) aspeed.duties[i] = data[i + 1];
            return [0x00, Buffer.alloc(0)];
          }
          default:
            events.push(`aspeed-unknown-sub 0x${sub.toString(16)}`);
            return [0xff /* unknown command */, Buffer.alloc(0)];
        }
      }

      case (0x3a << 8) | 0xd7: // AST2500 read mode → per-channel bytes (0=auto, 1=manual)
        events.push('aspeed25-read-mode');
        return [0x00, Buffer.from(aspeed.modes.map((m) => (m === 2 ? 1 : 0)))];

      case (0x3a << 8) | 0xd8: {
        // AST2500 set mode ← data[0..15] (0=auto, 1=manual).
        events.push('aspeed25-set-mode');
        for (let i = 0; i < 16 && i < data.length; ++i) aspeed.modes[i] = data[i] === 1 ? 2 : 1;
        return [0x00, Buffer.alloc(0)];
      }

      case (0x3a << 8) | 0xda: // AST2500 read duty → per-channel percent bytes
        events.push('aspeed25-read-duty');
        return [0x00, Buffer.from(aspeed.duties)];

      case (0x3a << 8) | 0x01: {
        // AST2500 set duty ← data[0..7] — applies directly.
        events.push('aspeed25-set-duty');
        for (let i = 0; i < 8 && i < data.length; ++i) aspeed.duties[i] = data[i];
        return [0x00, Buffer.alloc(0)];
      }

      default:
        events.push(`unknown-cmd netfn=0x${netfn.toString(16)} cmd=0x${cmd.toString(16)}`);
        return [0xff /* unknown command */, Buffer.alloc(0)];
    }
  }

  /** Handles one RAKP1 payload → sends the RAKP2 response. */
  function handleRakp1(payload, rinfo) {
    const bmcId = readLe32(payload, 4);
    if (bmcId !== BMC_ID) throw new Error('mock: unexpected bmc_id in RAKP1');
    const consoleRandWire = payload.subarray(8, 24);
    const consoleRandStored = Buffer.from([...consoleRandWire].reverse()); // wire form is byte-reversed
    const roleByte = payload[24];
    const ulen = payload[27];
    const username = payload.subarray(28, 28 + ulen).toString('utf8');

    const bmcRandStored = crypto.randomBytes(16);
    session.bmcRandStored = bmcRandStored; // needed later for the SIK derivation in RAKP3
    const kuid = Buffer.alloc(20, 0);
    Buffer.from(session.password, 'utf8').copy(kuid, 0, 0, Math.min(20, session.password.length));

    // RAKP2 HMAC: SIDm + SIDc + Rm(stored) + Rc(stored) + GUIDc(stored) + ROLEm + ULENGTHm + username.
    const macInput = Buffer.concat([le32(session.consoleId), le32(BMC_ID), consoleRandStored, bmcRandStored, BMC_GUID, Buffer.from([roleByte]), Buffer.from([ulen]), Buffer.from(username, 'utf8')]);
    const authcode = hmacSha1(kuid, macInput); // full 20-byte SHA-1

    events.push(`rakp1 user=${username} role=0x${roleByte.toString(16)}`);

    const rsp = Buffer.alloc(60, 0);
    rsp[0] = 0; // tag
    rsp[1] = 0; // return code: no errors
    rsp.writeUInt32LE(session.consoleId, 4); // console id LE
    reverseCopy(bmcRandStored, rsp, 8); // bmc rand wire-reversed
    reverseCopy(BMC_GUID, rsp, 24); // guid wire-reversed
    authcode.copy(rsp, 40);

    socket.send(buildPreSessionResponse(0x13 /* RAKP_2 */, rsp), rinfo.port, rinfo.address);
  }

  /** Handles one RAKP3 payload → verifies the console's authcode, sends RAKP4. */
  function handleRakp3(payload, rinfo) {
    const rc = payload[1];
    if (rc !== 0x00) {
      // Console reported a RAKP2 error — acknowledge with an empty RAKP4.
      events.push('rakp3 console-error-ack');
      const rsp = Buffer.alloc(8, 0);
      rsp[1] = rc;
      rsp.writeUInt32LE(BMC_ID, 4);
      socket.send(buildPreSessionResponse(0x15 /* RAKP_4 */, rsp), rinfo.port, rinfo.address);
      return;
    }

    const bmcId = readLe32(payload, 4);
    if (bmcId !== BMC_ID) throw new Error('mock: unexpected bmc_id in RAKP3');
    const consoleAuthcode = payload.subarray(8, 28); // full 20-byte SHA-1

    // Expected: HMAC-SHA1(Kuid, Rc(stored) + SIDm + ROLEm + ULENGTHm + username).
    const expected = hmacSha1(session.kuid, Buffer.concat([session.bmcRandStored, le32(session.consoleId), Buffer.from([session.roleByte]), Buffer.from([session.ulength]), session.usernameBuf]));
    if (!expected.equals(consoleAuthcode)) {
      events.push('rakp3 AUTHCODE-MISMATCH');
      const rsp = Buffer.alloc(8, 0);
      rsp[1] = 0x03; // invalid integrity check value
      rsp.writeUInt32LE(BMC_ID, 4);
      socket.send(buildPreSessionResponse(0x15, rsp), rinfo.port, rinfo.address);
      return;
    }

    events.push('rakp3 authcode-ok');

    // SIK → K1 → K2 (same derivation the console must use).
    const sik = hmacSha1(session.kuid, Buffer.concat([session.consoleRandStored, session.bmcRandStored, Buffer.from([session.roleByte]), Buffer.from([session.ulength]), session.usernameBuf]));
    session.sik = sik;
    session.k1 = hmacSha1(sik, Buffer.alloc(20, 0x01));
    session.k2 = hmacSha1(sik, Buffer.alloc(20, 0x02));

    // RAKP4 ICV: HMAC-SHA1(SIK, Rm(stored) + SIDc + GUIDc), first 12 bytes.
    const icv = hmacSha1(sik, Buffer.concat([session.consoleRandStored, le32(BMC_ID), BMC_GUID])).subarray(0, 12);
    const rsp = Buffer.alloc(8 + 12, 0);
    rsp[0] = 0; // tag
    rsp[1] = 0; // return code: no errors
    rsp.writeUInt32LE(session.consoleId, 4); // console id LE
    icv.copy(rsp, 8);

    socket.send(buildPreSessionResponse(0x15 /* RAKP_4 */, rsp), rinfo.port, rinfo.address);
  }

  /** Handles one in-session packet (IPMI command or SOL). */
  function handleInSession(pkt, rinfo) {
    const payloadType = pkt[5] & 0x3f;
    const sessionId = readLe32(pkt, 6);
    if (sessionId !== BMC_ID) return; // not our session — ignore

    const payloadLen = readLe16(pkt, 14);
    const end = 16 + payloadLen;

    // Verify the integrity trailer when authenticated.
    if ((pkt[5] & 0x40) !== 0 && session.integrityAlg === 1) {
      let padSize = -1;
      for (let s = 0; s <= 3; ++s) {
        if ((12 + payloadLen + 2 + s) % 4 === 0 && end + s + 2 + 12 === pkt.length) padSize = s;
      }
      if (padSize < 0 || pkt[end + padSize] !== padSize || pkt[end + padSize + 1] !== 0x07) {
        events.push('integrity-trailer-malformed');
        return;
      }
      const macInputSize = 12 + payloadLen + padSize + 2;
      const expectedMac = hmacSha1(session.k1, pkt.subarray(4, 4 + macInputSize)).subarray(0, 12);
      if (!expectedMac.equals(pkt.subarray(end + padSize + 2, end + padSize + 2 + 12))) {
        events.push('integrity-trailer-MISMATCH');
        return;
      }
    }

    // Decrypt the payload when encrypted.
    let plaintext = pkt.subarray(16, end);
    if ((pkt[5] & 0x80) !== 0 && session.cryptAlg === 1) {
      try {
        plaintext = aesDecrypt(session.k2, plaintext);
      } catch (e) {
        events.push(`decrypt-failed: ${e.message}`);
        return;
      }
    }

    if (payloadType === 0x01 /* SOL */) {
      // SOL packet: header [seq(1), acked(1), acceptedChars(1), flags(1)] + data.
      const sentSeq = plaintext[0];
      const dataLen = Math.min(plaintext.length - 4, session.maxSolChars ?? 260);
      events.push(`sol-packet seq=${sentSeq} len=${dataLen}`);
      // Respond with an ACK (no terminal data in the mock).
      const ackHdr = Buffer.from([sentSeq + 1 & 0xff, sentSeq + 1 & 0xff, dataLen, 0x80 /* flags: SOL payload */]);
      socket.send(buildSessionResponse(0x01, ackHdr, 1), rinfo.port, rinfo.address);
      return;
    }

    if (payloadType !== 0x00 /* IPMI */) {
      events.push(`unexpected-payload-type 0x${payloadType.toString(16)}`);
      return;
    }

    // IPMI command message: rsAddr@0, netfn<<2|lun @1, csum@2, rqAddr@3, seq<<2 @4, cmd@5, data@6+.
    if (plaintext.length < 7) return;
    const netfn = (plaintext[1] >> 2) & 0x3f;
    const cmd = plaintext[5];
    const data = plaintext.subarray(6);

    let comCode;
    let rspData;
    try {
      [comCode, rspData] = handleCommand(netfn, cmd, data);
    } catch (e) {
      events.push(`command-crash: ${e.message}`);
      return;
    }

    // Response message: rsAddr, netfn<<2|lun|resp-bit, csum, rqAddr, seq<<2, cmd,
    // comCode @6, data @7+, trailing checksum (8 fixed bytes + data).
    const msg = Buffer.alloc(8 + rspData.length);
    msg[0] = 0x20; // rsAddr
    msg[1] = (netfn << 2) | 0x01; // response indicator bit set
    let sum = 0;
    for (const b of msg.subarray(0, 2)) sum += b;
    msg[2] = (256 - (sum & 0xff)) & 0xff;
    msg[3] = 0x81; // rqAddr
    msg[4] = plaintext[4]; // echo request seq byte
    msg[5] = cmd;
    msg[6] = comCode;
    rspData.copy(msg, 7);
    let sum2 = 0;
    for (const b of msg.subarray(3)) sum2 += b;
    msg[msg.length - 1] = (256 - (sum2 & 0xff)) & 0xff;

    socket.send(buildSessionResponse(0x00, msg, 1), rinfo.port, rinfo.address);
  }

  socket.on('message', (msg, rinfo) => {
    try {
      if (msg.length < 16 || msg[0] !== 0x06 || msg[3] !== 0x07 || msg[4] !== 0x06) return; // not RMCP+

      const payloadType = msg[5] & 0x3f;
      const payloadLen = readLe16(msg, 14);
      const payload = msg.subarray(16, 16 + payloadLen);

      switch (payloadType) {
        case 0x10: {
          // Open Session Request — start a fresh session. The console id is the
          // LE u32 at payload offset 4 (payload starts at msg[16]).
          events.push('open-session');
          session = {
            consoleId: readLe32(payload, 4),
            bmcRandStored: null,
            consoleRandStored: null,
            roleByte: 0,
            ulength: 0,
            usernameBuf: Buffer.alloc(0),
            kuid: null,
            sik: null,
            k1: null,
            k2: null,
            authAlg: 1,
            integrityAlg: 1,
            cryptAlg: 1,
            password: 'secret', // the test credential — known to the mock
          };
          const rsp = Buffer.alloc(40, 0);
          rsp[0] = 0; // tag
          rsp[1] = 0; // return code: no errors
          rsp[2] = 3; // max privilege level: admin
          rsp.writeUInt32LE(session.consoleId, 4); // console id LE
          rsp.writeUInt32LE(BMC_ID, 8); // bmc id LE
          rsp[16] = 1; // auth alg: RAKP-HMAC-SHA1
          rsp[24] = 1; // integrity alg: HMAC-SHA1-96
          rsp[32] = 1; // crypt alg: AES-CBC-128
          socket.send(buildPreSessionResponse(0x11 /* OPEN_RESPONSE */, rsp), rinfo.port, rinfo.address);
          return;
        }

        case 0x12: // RAKP_1
          if (!session) return;
          handleRakp1(payload, rinfo);
          session.consoleRandStored = Buffer.from([...payload.subarray(8, 24)].reverse());
          session.roleByte = payload[24];
          session.ulength = payload[27];
          session.usernameBuf = Buffer.from(payload.subarray(28, 28 + payload[27]), 'utf8');
          {
            const kuid = Buffer.alloc(20, 0);
            Buffer.from(session.password, 'utf8').copy(kuid, 0, 0, Math.min(20, session.password.length));
            session.kuid = kuid;
          }
          return;

        case 0x14: // RAKP_3
          if (!session) return;
          handleRakp3(payload, rinfo);
          return;

        default:
          // In-session (IPMI/SOL) — only meaningful after RAKP4.
          if (session?.k2 && session?.k1) handleInSession(msg, rinfo);
      }
    } catch (e) {
      events.push(`mock-error: ${e.message}`);
    }
  });

  await new Promise((resolve) => socket.bind(0, '127.0.0.1', resolve));
  const port = socket.address().port;

  return {
    name: 'ipmi-mock-bmc',
    port,
    events,
    aspeed, // exposed so extraChecks can assert on the mock's fan state
    stop: () => new Promise((resolve) => socket.close(() => resolve())),
  };
}

export default {
  async setup({ getDeadUdpPort }) {
    const bmc = await startIpmiMock();
    return {
      mocks: [bmc],
      config: {
        monitoringAddress: `127.0.0.1:${bmc.port}`,
        credentials: { username: 'admin', password: 'secret' },
        expectHealth: 'ok',
        deadAddress: `127.0.0.1:${await getDeadUdpPort()}`,
        expectDeadHealth: 'critical',
        extraChecks: async ({ url, rec }) => {
          const ev = bmc.events.join(' ');
          rec.check('X', 'mock saw the full RAKP handshake (open→rakp1→rakp3-ok)', /open-session/.test(ev) && /rakp1 user=admin/.test(ev) && /rakp3 authcode-ok/.test(ev), ev.slice(0, 400));
          rec.check('X', 'mock verified the console integrity trailers (no mismatches)', !ev.includes('integrity-trailer-MISMATCH') && !ev.includes('decrypt-failed'), ev.slice(0, 400));
          rec.check('X', 'monitoring read chassis status + SDR walk + sensor readings', /chassis-status/.test(ev) && (ev.match(/get-sdr/g) ?? []).length >= 3 && (ev.match(/get-sensor-reading/g) ?? []).length === 3, ev.slice(0, 400));
          rec.check('X', 'monitoring read FRU + SEL tail + LAN params', /read-fru/.test(ev) && /sel-info/.test(ev) && (ev.match(/get-sel-entry/g) ?? []).length >= 2 && (ev.match(/get-lan-param/g) ?? []).length >= 4, ev.slice(0, 400));

          // sensor.threshold.set — Fan1 (sensor 3, m=10): 650 RPM → raw 65, 750 RPM → raw 75.
          const setR = await fetch(`${url}/config`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ deviceId: 'x', managementAddress: `127.0.0.1:${bmc.port}`, credentials: { username: 'admin', password: 'secret' }, actionId: 'sensor.threshold.set', input: { sensorNum: 3, upperNonCrit: 650, upperCrit: 750 } }),
          });
          const setJ = await setR.json();
          rec.check('X', '/config sensor.threshold.set applied + verified (raw 65/75)', setR.status === 200 && setJ.success === true && setJ.result?.verified === true && setJ.result?.details?.rawApplied?.upperNonCrit === 65 && setJ.result?.details?.rawApplied?.upperCrit === 75, JSON.stringify(setJ).slice(0, 300));

          // sensor.threshold.get — re-read: raw must be the values we wrote; converted back to engineering units.
          const getR = await fetch(`${url}/config`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ deviceId: 'x', managementAddress: `127.0.0.1:${bmc.port}`, credentials: { username: 'admin', password: 'secret' }, actionId: 'sensor.threshold.get', input: { sensorNum: 3 } }),
          });
          const getJ = await getR.json();
          rec.check('X', '/config sensor.threshold.get round-trips (raw 65/75 → 650/750 RPM)', getR.status === 200 && getJ.success === true && getJ.result?.details?.raw?.upperNonCrit === 65 && getJ.result?.details?.converted?.upperNonCrit === 650 && getJ.result?.details?.converted?.upperCrit === 750, JSON.stringify(getJ).slice(0, 300));

          // fan.aspeed.get — auto-detect must resolve to ast2600; all channels start in auto @40%.
          const fanGetR = await fetch(`${url}/config`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ deviceId: 'x', managementAddress: `127.0.0.1:${bmc.port}`, credentials: { username: 'admin', password: 'secret' }, actionId: 'fan.aspeed.get', input: {} }),
          });
          const fanGetJ = await fanGetR.json();
          rec.check('X', '/config fan.aspeed.get auto-detects ast2600 + reads 16 channels (auto @40%)', fanGetR.status === 200 && fanGetJ.success === true && fanGetJ.result?.details?.variant === 'ast2600' && Array.isArray(fanGetJ.result?.details?.channels) && fanGetJ.result.details.channels.length === 16 && fanGetJ.result.details.channels.every((c) => c.mode === 'auto' && c.dutyPercent === 40), JSON.stringify(fanGetJ).slice(0, 300));

          // fan.aspeed.set — duty 60%: AST2600 must switch to manual first (mock enforces
          // "duty only applies in manual mode"), then write all 16 channels.
          const fanSetR = await fetch(`${url}/config`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ deviceId: 'x', managementAddress: `127.0.0.1:${bmc.port}`, credentials: { username: 'admin', password: 'secret' }, actionId: 'fan.aspeed.set', input: { dutyPercent: 60 } }),
          });
          const fanSetJ = await fanSetR.json();
          rec.check('X', '/config fan.aspeed.set applies + verifies 60% (manual mode first)', fanSetR.status === 200 && fanSetJ.success === true && fanSetJ.result?.verified === true && fanSetJ.result?.details?.dutyPercent === 60 && bmc.aspeed.modes.every((m) => m === 2) && bmc.aspeed.duties.every((d) => d === 60), JSON.stringify(fanSetJ).slice(0, 300));

          // fan.aspeed.auto-restore — back to auto; mock duties stay at 60 (BMC keeps last duty in auto too).
          const fanAutoR = await fetch(`${url}/config`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ deviceId: 'x', managementAddress: `127.0.0.1:${bmc.port}`, credentials: { username: 'admin', password: 'secret' }, actionId: 'fan.aspeed.auto-restore', input: {} }),
          });
          const fanAutoJ = await fanAutoR.json();
          rec.check('X', '/config fan.aspeed.auto-restore returns all channels to auto + verified', fanAutoR.status === 200 && fanAutoJ.success === true && fanAutoJ.result?.verified === true && bmc.aspeed.modes.every((m) => m === 1), JSON.stringify(fanAutoJ).slice(0, 300));

          // Monitoring with the aspeedFan option enabled → ipmi.fan table metric.
          const monR = await fetch(`${url}/monitoring`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'x-unm-settings': JSON.stringify({ aspeedFan: true }) },
            body: JSON.stringify({ deviceId: 'x', managementAddress: `127.0.0.1:${bmc.port}`, credentials: { username: 'admin', password: 'secret' } }),
          });
          const monJ = await monR.json();
          rec.check('X', '/monitoring with aspeedFan=true emits the ipmi.fan table (16 rows, auto mode)', monR.status === 200 && Array.isArray(monJ.metrics?.['ipmi.fan']) && monJ.metrics['ipmi.fan'].length === 16 && monJ.metrics['ipmi.fan'].every((c) => c.mode === 'auto'), JSON.stringify(monJ.metrics?.['ipmi.fan'] ?? null).slice(0, 300));
        },
      },
    };
  },
};
