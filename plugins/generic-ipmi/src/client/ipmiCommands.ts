/**
 * IPMI command layer — the spec-defined commands this plugin uses, on top of
 * the RMCP+ session client. All functions take a connected IpmiClient and
 * return plain data structures (no UNM types here).
 *
 * Wire layouts verified against openipmi source + IPMI v2.0 spec:
 *   - Get SDR response data = next_id(2) + rec_id(2) + version=0x51(1) + type(1)
 *     + length(1), then the record content. Full-sensor fields are parsed at
 *     fixed offsets relative to the CONTENT start (see parseFullSensorRecord).
 *   - Sensor value conversion: ((m·val) + (b·10^k1)) · 10^k2, with m/b/k1/k2
 *     extracted from the record's mtol/bacc fields exactly as openipmi does.
 *   - Get SEL Entry response data = next_id(2) + rec_id(2) + record_type(1);
 *     for standard-spec records (<0xc0): timestamp=u32 LE @[5..8] which is
 *     SECONDS SINCE UNIX EPOCH, sensor_type@[12], sensor_num@[13],
 *     event_type(7b)|event_dir(bit7)@[14].
 *   - FRU: the 8-byte header carries the area start offsets at bytes [2]
 *     (chassis), [3] (board), [4] (product); each area is length-prefixed and
 *     holds [type(1), len(1), value(len)] fields terminated by type 0x00.
 */

import { IpmiClient, IpmiError } from './ipmiClient';

// --- Netfn / command ids -------------------------------------------------------------
// NOTE: netfn assignments verified against openipmi (the reference ipmitool):
//   - ALL SEL commands (Get Info/Reserve/Entry/Clear) ride on NETFN_STORAGE (0xa),
//     NOT the SE netfn — that is what real BMCs answer.
//   - Get Sensor Reading rides on NETFN_SE (0x4) in openipmi's ipmi_sdr.c.

const NETFN_CHASSIS = 0x00;
const NETFN_SE = 0x04; // used for Get Sensor Reading (openipmi convention)
const NETFN_APP = 0x06;
const NETFN_STORAGE = 0x0a; // SDR + ALL SEL commands
const NETFN_TRANSPORT = 0x0c;

// Chassis commands.
const CHASSIS_GET_STATUS = 0x01;
const CHASSIS_SYSTEM_POWER_CTRL = 0x06;
const CHASSIS_SET_BOOT_OPTIONS = 0x08;
const CHASSIS_GET_SYS_BOOT_OPTIONS = 0x09;

// Sensor reading (openipmi: netfn SE, cmd 0x2d).
const CMD_GET_SENSOR_READING = 0x2d;

// Storage commands.
const STORAGE_GET_SDR_INFO = 0x20;
const STORAGE_RESERVE_SDR = 0x21;
const STORAGE_GET_SDR = 0x23;
const STORAGE_READ_FRU_DATA = 0x18;
const STORAGE_GET_FRU_LOCATOR = 0x14;

// SE (System Event Log) commands.
const SE_GET_SEL_INFO = 0x40;
const SE_RESERVE_SEL = 0x42;
const SE_GET_SEL_ENTRY = 0x43;
const SE_CLEAR_SEL = 0x47;

// Transport / channel commands.
const TRANSPORT_SET_LAN_CONFIG_PARAMS = 0x51;
const TRANSPORT_GET_LAN_CONFIG_PARAMS = 0x52;

/** Chassis power state (decoded from the status bytes). */
export interface ChassisStatus {
  poweredOn: boolean;
  powerControlLost: boolean;
  restorePolicy: 'always-on' | 'previous-state' | 'always-off';
  raw: number;
}

/** One SDR full sensor record with its live reading + threshold state. */
export interface SensorReading {
  recordId: number;
  /** The unique sensor number (from the record) used for Get Sensor Reading. */
  sensorNum: number | null;
  id: string; // e.g. "CPU1 Temp"
  type: string; // human-readable sensor type
  reading: number | null; // converted engineering value (°C, V, A, %, RPM, W)
  rawReading: number | null; // raw byte from Get Sensor Reading (null if unreadable)
  unit: string;
  state: 'ok' | 'warning' | 'critical';
}

/** One FRU field (area + decoded text). */
export interface FruField {
  area: string; // 'chassis' | 'board' | 'product'
  key: string;
  value: string;
}

/** One SEL entry. */
export interface SelEntry {
  recordId: number;
  timestamp: string; // ISO (from the unix-epoch seconds) or '' when invalid
  severity: 'ok' | 'warning' | 'critical';
  sensorType: string;
  event: string;
  raw: string;
}

/** LAN channel config snapshot (the params UNM can display/edit). */
export interface LanConfig {
  ipAddress: string; // dotted quad or ''
  subnetMask: string;
  defaultGateway: string;
  macAddress: string; // colon form or ''
  ipVersion: 'ipv4' | 'dual-stack';
}

// --- Chassis ---------------------------------------------------------------------------

/** Get chassis status (netfn CHASSIS cmd 0x01). */
export async function getChassisStatus(client: IpmiClient): Promise<ChassisStatus> {
  const data = await client.sendCommand(NETFN_CHASSIS, CHASSIS_GET_STATUS);
  if (data.length < 2) throw new IpmiError('Chassis status response too short', 'protocol');
  const powerState = data[0];
  const info = data[1];
  const restoreBits = (info >> 6) & 0x03;
  return {
    poweredOn: (powerState & 0x01) === 1,
    powerControlLost: (info & 0x80) === 0x80,
    restorePolicy: restoreBits === 2 ? 'always-on' : restoreBits === 1 ? 'previous-state' : 'always-off',
    raw: powerState | (info << 8),
  };
}

/** System power control (netfn CHASSIS cmd 0x06). Codes per IPMI v2 spec table 9-3. */
export async function setSystemPower(client: IpmiClient, op: 'on' | 'soft-off' | 'hard-off' | 'reset'): Promise<void> {
  // Spec codes: 0=Power Down (hard off), 1=Power Up, 2=Power Cycle, 3=Hard Reset,
  //             4=Pulse Diag Interrupt, 5=ACPI Soft Off.
  const code = op === 'on' ? 0x01 : op === 'soft-off' ? 0x05 : op === 'hard-off' ? 0x00 : 0x03;
  await client.sendCommand(NETFN_CHASSIS, CHASSIS_SYSTEM_POWER_CTRL, Buffer.from([code]));
}

/** Set system boot options (netfn CHASSIS cmd 0x08). */
export async function setBootOptions(client: IpmiClient, opts: { servicePartitionSelector?: number; servicePartitionScan?: boolean; bootFlags?: number }): Promise<void> {
  const data = Buffer.alloc(4);
  data[0] = (opts.servicePartitionSelector ?? 1) & 0x0f; // selector (default: BIOS)
  data[1] = opts.servicePartitionScan ? 0x80 : 0x00; // scan bit
  data[2] = (opts.bootFlags ?? 0) & 0xff;
  data[3] = 0x03; // boot param info: set flags valid
  await client.sendCommand(NETFN_CHASSIS, CHASSIS_SET_BOOT_OPTIONS, data);
}

/** Get system boot options (netfn CHASSIS cmd 0x09). */
export async function getBootOptions(client: IpmiClient): Promise<{ servicePartitionSelector: number; bootFlags: number }> {
  const data = await client.sendCommand(NETFN_CHASSIS, CHASSIS_GET_SYS_BOOT_OPTIONS);
  if (data.length < 3) throw new IpmiError('Get Boot Options response too short', 'protocol');
  return { servicePartitionSelector: data[0] & 0x0f, bootFlags: data[2] };
}

// --- SDR / sensors ---------------------------------------------------------------------------

/** Walks the SDR repository and returns every full sensor record (optionally with live readings). */
export async function getSensorReadings(client: IpmiClient, opts?: { withReadings?: boolean }): Promise<SensorReading[]> {
  const withReadings = opts?.withReadings ?? true;

  // Get SDR info → [version(1), recordCount(u16 LE @1..2), freeSpace(u16)@3..4, ...].
  const info = await client.sendCommand(NETFN_STORAGE, STORAGE_GET_SDR_INFO);
  if (info.length < 4) throw new IpmiError('Get SDR Info response too short', 'protocol');
  const recordCount = info[1] | (info[2] << 8);

  // Reserve the repository.
  let reservationId = 0;
  try {
    const resv = await client.sendCommand(NETFN_STORAGE, STORAGE_RESERVE_SDR, Buffer.from([0, 0, 0, 0]));
    if (resv.length >= 4) reservationId = resv[0] | (resv[1] << 8);
  } catch {
    /* some BMCs don't support reserve — continue without it */
  }

  const sensors: SensorReading[] = [];
  let nextId = 0;
  for (let n = 0; n < recordCount && nextId !== 0xffff; ++n) {
    // Get SDR request: [reserveId(2), recordId(2), offset(1)=0, length(1)=0xff].
    // Response data: next_id(2) + rec_id(2) + version(1)=0x51 + type(1) + length(1)
    //   + content... (content starts at response-data offset 7).
    const req = Buffer.alloc(8);
    req[0] = reservationId & 0xff;
    req[1] = (reservationId >> 8) & 0xff;
    req[2] = nextId & 0xff;
    req[3] = (nextId >> 8) & 0xff;
    req[4] = 0x00; // offset
    req[5] = 0xff; // length (max)

    let rsp: Buffer;
    try {
      rsp = await client.sendCommand(NETFN_STORAGE, STORAGE_GET_SDR, req);
    } catch (e) {
      if (e instanceof IpmiError && e.kind === 'comcode') break; // end of repository
      throw e;
    }
    if (rsp.length < 7) break;

    const nextRecordId = rsp[0] | (rsp[1] << 8);
    const recordType = rsp[5];
    const content = rsp.subarray(7); // after the 7-byte header

    // Full sensor records have type byte == 0x01.
    if (recordType === 0x01 && content.length >= 43) {
      try {
        sensors.push(parseFullSensorRecord(rsp, content));
      } catch {
        /* malformed record — skip */
      }
    }
    nextId = nextRecordId;
  }

  // Fetch live readings for each sensor (Get Sensor Reading: netfn SENSING(0x2) cmd 0x2D).
  if (withReadings) {
    for (const s of sensors) {
      if (s.sensorNum === null) continue;
      try {
        // openipmi sends Get Sensor Reading on netfn SE (0x4), cmd 0x2d.
        const rd = await client.sendCommand(NETFN_SE, CMD_GET_SENSOR_READING, Buffer.from([s.sensorNum & 0xff]));
        // Response: [status(1), reading(1)]. Status bit 5 (0x20) = reading unavailable.
        if (rd.length >= 2 && (rd[0] & 0x20) === 0) {
          s.rawReading = rd[1];
          s.reading = convertSensorValue(s, rd[1]);
          s.state = determineState(s);
        } else {
          s.rawReading = null;
          s.reading = null;
        }
      } catch {
        /* sensor not readable — leave reading null */
      }
    }
  }

  return sensors;
}

/** Internal conversion metadata carried on a SensorReading (not serialized to UNM). */
interface ConversionMeta {
  analogFormat: number; // 0=unsigned,1=1's comp,2=2's comp,3=discrete/NA
  m: number;
  b: number;
  k1: number;
  k2: number;
  upperNonRecRaw: number | null;
  upperCritRaw: number | null;
  upperNonCritRaw: number | null;
  lowerNonRecRaw: number | null;
  lowerCritRaw: number | null;
  lowerNonCritRaw: number | null;
}

// Attach conversion metadata via a WeakMap so the public interface stays clean.
const meta = new WeakMap<SensorReading, ConversionMeta>();

/** Parses one full sensor SDR record (type 0x01) into identity + thresholds. */
function parseFullSensorRecord(rsp: Buffer, content: Buffer): SensorReading {
  // Content-relative offsets (IPMI v2 spec table 20-4 / openipmi sdr_record_full_sensor):
  //   [0]=owner_id, [1]=channel/lun/resv, [2]=sensor_num,
  //   [3]=entity id, [4]=entity instance/logical,
  //   [5]=init, [6]=capabilities, [7]=sensor type code, [8]=event/reading type,
  //   [9..14]=mask (6 bytes),
  //   [15]=unit analog/rate/modifier/pct, [16]=base unit, [17]=modifier unit,
  //   [18]=linearization, [19..20]=mtol(u16 LE), [21..24]=bacc(u32 LE),
  //   [25]=analog_flag, [26]=nominal_read, [27]=normal_max(raw), [28]=normal_min(raw),
  //   [29]=sensor_max(raw), [30]=sensor_min(raw),
  //   [31..33]=upper{non_recover,critical,non_critical}(raw),
  //   [34..36]=lower{non_recover,critical,non_critical}(raw),
  //   [37..38]=hysteresis{pos,neg}, [39..40]=reserved, [41]=oem,
  //   [42]=id_code, [43..58]=id_string.
  const recordId = rsp[2] | (rsp[3] << 8);
  const sensorNum = content[2];
  const typeCode = content[7];

  const mtolU16 = content[19] | (content[20] << 8);
  const baccU32 = content[21] | (content[22] << 8) | (content[23] << 16) | ((content[24] << 24) >>> 0);

  // ID string: id_code at [42]; if non-zero the following bytes are ASCII.
  let id = '';
  const idCode = content.length > 42 ? content[42] : 0;
  if (idCode !== 0 && content.length >= 59) {
    id = content.subarray(43, 59).toString('ascii').replace(/\0+$/, '').trim();
  }

  const reading: SensorReading = {
    recordId,
    sensorNum,
    id: id || `sensor-${sensorNum.toString(16)}`,
    type: sensorTypeName(typeCode),
    reading: null,
    rawReading: null,
    unit: sensorUnit(content[7]),
    state: 'ok',
  };

  meta.set(reading, {
    analogFormat: (content[15] >> 6) & 0x03, // byte [15] bits [7:6] = analog data format
    m: toM(mtolU16),
    b: toB(baccU32),
    k1: toBExp(baccU32),
    k2: toRExp(baccU32),
    upperNonRecRaw: content[31],
    upperCritRaw: content[32],
    upperNonCritRaw: content[33],
    lowerNonRecRaw: content[34],
    lowerCritRaw: content[35],
    lowerNonCritRaw: content[36],
  });

  return reading;
}

/** Converts a raw sensor byte to engineering units using the record's m/b/k1/k2. */
function convertSensorValue(s: SensorReading, raw: number): number | null {
  const cm = meta.get(s);
  if (!cm) return null;
  if (cm.analogFormat === 3) return null; // discrete / no analog reading

  let val: number;
  switch (cm.analogFormat) {
    case 1:
      val = raw & 0x80 ? (raw + 1) : raw; // openipmi's 1's-complement handling, then signed below
      val = val > 127 ? val - 256 : val;
      break;
    case 2:
      val = raw > 127 ? raw - 256 : raw; // two's complement
      break;
    default:
      val = raw; // unsigned
  }

  const result = (cm.m * val + cm.b * Math.pow(10, cm.k1)) * Math.pow(10, cm.k2);
  return roundTo(result, 2);
}

/** Determines ok/warning/critical from the converted reading vs. thresholds. */
function determineState(s: SensorReading): 'ok' | 'warning' | 'critical' {
  const cm = meta.get(s);
  if (!cm || s.reading === null) return 'ok';
  const r = s.reading;

  // A threshold is "present" when its raw byte is neither 0x00 nor 0xff (invalid).
  const present = (raw: number | null): boolean => raw !== null && raw !== 0x00 && raw !== 0xff;
  const conv = (raw: number | null): number | null => (present(raw) ? convertSensorValue(s, raw as number) : null);

  const upperCrit = conv(cm.upperCritRaw);
  const lowerCrit = conv(cm.lowerCritRaw);
  const upperNonRec = conv(cm.upperNonRecRaw);
  const lowerNonRec = conv(cm.lowerNonRecRaw);
  const upperNonCrit = conv(cm.upperNonCritRaw);
  const lowerNonCrit = conv(cm.lowerNonCritRaw);

  if ((upperCrit !== null && r >= upperCrit) || (lowerCrit !== null && r <= lowerCrit)) return 'critical';
  if ((upperNonRec !== null && r >= upperNonRec) || (lowerNonRec !== null && r <= lowerNonRec)) return 'critical';
  if ((upperNonCrit !== null && r >= upperNonCrit) || (lowerNonCrit !== null && r <= lowerNonCrit)) return 'warning';
  return 'ok';
}

// --- m/b/k1/k2 extraction (mirrors openipmi's __TO_* macros + tos32 sign extension) ----

function toM(mtolU16: number): number {
  const v = ((mtolU16 & 0xff00) >> 8) | ((mtolU16 & 0xc0) << 2); // 10-bit field
  return signExtend(v, 10);
}

function toB(baccU32: number): number {
  const v = ((baccU32 & 0xff000000) >>> 24) | ((baccU32 & 0xc00000) >> 14); // 10-bit field
  return signExtend(v, 10);
}

function toRExp(baccU32: number): number {
  const v = (baccU32 & 0xf0) >> 4; // 4-bit field
  return signExtend(v, 4);
}

function toBExp(baccU32: number): number {
  const v = baccU32 & 0xf; // 4-bit field
  return signExtend(v, 4);
}

function signExtend(value: number, bits: number): number {
  const mask = (1 << bits) - 1;
  value &= mask;
  if (value & (1 << (bits - 1))) return value - (1 << bits);
  return value;
}

function roundTo(n: number, decimals: number): number {
  const f = Math.pow(10, decimals);
  return Math.round(n * f) / f;
}

/** Human-readable sensor type name from the IPMI v2 spec table 5-1 (base types). */
function sensorTypeName(code: number): string {
  const names: Record<number, string> = {
    0x01: 'Temperature',
    0x02: 'Voltage',
    0x03: 'Current',
    0x04: 'Fan',
    0x05: 'Physical Security',
    0x06: 'Memory',
    0x07: 'OEM-specific',
    0x08: 'Cooling Device Failure',
    0x09: 'Other Units',
    0x0a: 'State of Health',
    0x0b: 'Performance Degradation',
    0x0c: 'Memory Correctable Errors',
    0x0d: 'Memory Uncorrectable Errors',
    0x0e: 'Memory Error Count',
    0x0f: 'Power Supply',
    0x10: 'Power Cooling Unit',
    0x11: 'Power Cooling Redundancy',
    0x12: 'Powering State',
    0x13: 'Hot-Swap / Hot-Spare',
    0x14: 'Event Logging Disabled',
    0x15: 'Watchdog Timer',
    0x16: 'Platform Security',
    0x17: 'Mission Map',
    0x18: 'OEM-specific',
    0x19: 'Management Sub-System Health',
    0x1a: 'Battery',
    0x1b: 'Session Active',
    0x1c: 'Event Type',
    0x1d: 'FRU State',
    0x1e: 'FRU Control Field',
    0x1f: 'OEM-specific',
  };
  return names[code] ?? `Type 0x${code.toString(16)}`;
}

/** Unit string for a sensor type code (base types only — rate/OEM variants fall back to ''). */
function sensorUnit(code: number): string {
  switch (code) {
    case 0x01:
      return '°C';
    case 0x02:
      return 'V';
    case 0x03:
      return 'A';
    case 0x04:
      return 'RPM';
    case 0x0a:
      return '%';
    case 0x15:
      return 's';
    default:
      return '';
  }
}

// --- FRU ---------------------------------------------------------------------------

/** Reads the FRU data for `fruId` (default 0 = chassis) and decodes the standard fields. */
export async function readFru(client: IpmiClient, fruId = 0): Promise<FruField[]> {
  // Read the 8-byte FRU header to learn where each area starts.
  let header: Buffer;
  try {
    header = await client.sendCommand(NETFN_STORAGE, STORAGE_READ_FRU_DATA, Buffer.from([fruId & 0xff, 0x00, 0x08]));
  } catch (e) {
    if (e instanceof IpmiError && e.kind === 'comcode') return []; // no FRU on this id
    throw e;
  }
  if (header.length < 5) return [];

  const areas: Array<[string, number]> = [
    ['chassis', header[2]],
    ['board', header[3]],
    ['product', header[4]],
  ];

  // Each area's byte range ends where the NEXT present area starts (or at EOF).
  // Reading past it would bleed into the next area's fields.
  const fields: FruField[] = [];
  for (let a = 0; a < areas.length; ++a) {
    const [area, startOffset] = areas[a];
    if (startOffset === 0) continue; // area not present
    let endOffset = Number.MAX_SAFE_INTEGER;
    for (let b = a + 1; b < areas.length; ++b) {
      if (areas[b][1] > startOffset) {
        endOffset = areas[b][1];
        break;
      }
    }
    try {
      fields.push(...(await readFruArea(client, fruId, area, startOffset, Math.max(0, endOffset - startOffset))));
    } catch {
      /* area unreadable — skip */
    }
  }
  return fields;
}

/** Reads one FRU area (length-prefixed [type,len,value] fields) starting at `startOffset`,
 *  collecting at most `maxBytes` bytes (the area's declared extent). */
async function readFruArea(client: IpmiClient, fruId: number, area: string, startOffset: number, maxBytes: number): Promise<FruField[]> {
  const chunks: Buffer[] = [];
  let offset = startOffset;
  for (let i = 0; i < 16 && chunks.reduce((n, c) => n + c.length, 0) < maxBytes; ++i) {
    try {
      const want = Math.min(32, maxBytes - chunks.reduce((n, c) => n + c.length, 0));
      const chunk = await client.sendCommand(NETFN_STORAGE, STORAGE_READ_FRU_DATA, Buffer.from([fruId & 0xff, offset & 0xff, want]));
      if (chunk.length === 0) break;
      chunks.push(chunk);
      offset += chunk.length;
    } catch {
      break; // end of area or unsupported
    }
  }
  const data = Buffer.concat(chunks).subarray(0, maxBytes);
  return decodeFruArea(area, data);
}

/** Decodes the standard FRU fields from one area's byte stream. */
function decodeFruArea(area: string, data: Buffer): FruField[] {
  const out: FruField[] = [];
  if (data.length < 2) return out;

  // data[0] is the area length; fields start at data[1]. Each field: [type(1), len(1), value(len)].
  let i = 1;
  while (i + 2 <= data.length) {
    const type = data[i];
    if (type === 0x00) break; // end of area
    const len = data[i + 1];
    if (len === 0 || i + 2 + len > data.length) break;
    const value = data.subarray(i + 2, i + 2 + len).toString('ascii').replace(/\0+$/, '').trim();
    if (value) out.push({ area, key: fruFieldKey(area, type), value });
    i += 2 + len;
  }
  return out;
}

/** Maps a FRU field type code to a human-readable key. */
function fruFieldKey(area: string, type: number): string {
  const chassisKeys: Record<number, string> = { 1: 'manufacturer', 2: 'product-name', 3: 'part-number', 4: 'version', 5: 'serial-number', 6: 'asset-tag' };
  const boardKeys: Record<number, string> = { 1: 'mfg-date', 2: 'manufacturer', 3: 'product-name', 4: 'serial-number', 5: 'part-number', 6: 'version', 7: 'extra-product-info' };
  const productKeys: Record<number, string> = { 1: 'manufacturer', 2: 'product-name', 3: 'part-number', 4: 'version', 5: 'serial-number', 6: 'asset-tag', 7: 'fru-file-id' };
  if (area === 'chassis') return chassisKeys[type] ?? `field-${type}`;
  if (area === 'board') return boardKeys[type] ?? `field-${type}`;
  return productKeys[type] ?? `field-${type}`;
}

// --- SEL ---------------------------------------------------------------------------

/** Reads the last `count` SEL entries (newest first). */
export async function getSelEntries(client: IpmiClient, count = 50): Promise<SelEntry[]> {
  // Get SEL Info → [version(1), entryCount(u16 LE @1..2), freeSpace(u16)@3..4,
  //   lastAddTime(4)@5..8, lastDelTime(4)@9..12, supportedCmds(1)@13].
  const info = await client.sendCommand(NETFN_STORAGE, SE_GET_SEL_INFO);
  if (info.length < 4) throw new IpmiError('Get SEL Info response too short', 'protocol');
  const recordCount = info[1] | (info[2] << 8);
  if (recordCount === 0) return [];

  // Reserve the SEL — openipmi sends an EMPTY request.
  let reservationId = 0;
  try {
    const resv = await client.sendCommand(NETFN_STORAGE, SE_RESERVE_SEL, Buffer.alloc(0));
    if (resv.length >= 2) reservationId = resv[0] | (resv[1] << 8);
  } catch {
    /* continue without reserve */
  }

  // Walk BACKWARDS: Get SEL Entry request [reserveId(2), id(2), offset(1)=0,
  //   length(1)=0xff]; starting at id=0 with the "previous" semantics returns the
  //   NEWEST record first, and each response's next_id points further back until
  //   it reaches the 0xffff end sentinel (openipmi ipmi_sel_get_std_entry).
  const entries: SelEntry[] = [];
  let nextId = 0x0000; // start → BMC returns the most recent entry first
  for (let n = 0; n < count && nextId !== 0xffff; ++n) {
    const req = Buffer.alloc(6);
    req[0] = reservationId & 0xff;
    req[1] = (reservationId >> 8) & 0xff;
    req[2] = nextId & 0xff;
    req[3] = (nextId >> 8) & 0xff;
    req[4] = 0x00; // offset
    req[5] = 0xff; // length (max)

    let rsp: Buffer;
    try {
      rsp = await client.sendCommand(NETFN_STORAGE, SE_GET_SEL_ENTRY, req);
    } catch (e) {
      if (e instanceof IpmiError && e.kind === 'comcode') break; // no more records
      throw e;
    }
    if (rsp.length < 18) break;

    const recordId = rsp[2] | (rsp[3] << 8);
    const recordType = rsp[4];
    if (recordType >= 0xc0) {
      // OEM record — keep it but with minimal decoding.
      entries.push({
        recordId,
        timestamp: '',
        severity: 'ok',
        sensorType: `OEM (type 0x${recordType.toString(16)})`,
        event: 'OEM-defined event',
        raw: [...rsp].map((b) => b.toString(16).padStart(2, '0')).join(' '),
      });
    } else {
      // Standard-spec record (openipmi offsets): timestamp=u32 LE @[5..8] = unix epoch seconds.
      const tsRaw = rsp[5] | (rsp[6] << 8) | (rsp[7] << 16) | ((rsp[8] << 24) >>> 0);
      const sensorTypeCode = rsp[12];
      const sensorNum = rsp[13];
      const eventByte = rsp[14];
      const eventType = eventByte & 0x7f;
      const eventDir = (eventByte >> 7) & 0x01; // 0=assertion, 1=deassertion
      const eventData = rsp.subarray(15, 18);

      entries.push({
        recordId,
        timestamp: decodeSelTimestamp(tsRaw),
        severity: selSeverity(eventType, eventDir),
        sensorType: `${sensorTypeName(sensorTypeCode)} #${sensorNum}`,
        event: describeSelEvent(eventType, eventDir),
        raw: [...rsp].map((b) => b.toString(16).padStart(2, '0')).join(' '),
      });
    }

    // Next record id is in the first 2 bytes of the response.
    nextId = rsp[0] | (rsp[1] << 8);
    if (nextId === recordId) break; // no more records
  }

  return entries.reverse(); // oldest → newest for display
}

/** SEL timestamp is seconds since Unix epoch (IPMI v2 spec table 34-2). */
function decodeSelTimestamp(tsRaw: number): string {
  if (tsRaw === 0) return ''; // never set / invalid
  const d = new Date(tsRaw * 1000);
  if (isNaN(d.getTime()) || d.getFullYear() < 1970) return '';
  return d.toISOString();
}

/** SEL event severity from the event type + direction. Deassertions are recoveries → ok. */
function selSeverity(eventType: number, eventDir: number): 'ok' | 'warning' | 'critical' {
  if (eventDir === 1) return 'ok'; // deassertion = recovery

  switch (eventType) {
    case 0x02: // upper non-critical going high
    case 0x06: // upper non-critical going low
    case 0x07: // lower non-critical going high
      return 'warning';
    case 0x03: // lower critical going low
    case 0x04: // upper critical going high
    case 0x05: // lower critical going low (alt)
    case 0x08: // upper critical going low
    case 0x0a: // pre-failure
      return 'critical';
    case 0x01: // discrete event
    case 0x09: // limit exceeded
      return 'warning';
    default:
      return 'ok';
  }
}

/** Human-readable SEL event description. */
function describeSelEvent(eventType: number, eventDir: number): string {
  const dir = eventDir === 1 ? 'deasserted' : 'asserted';
  const types: Record<number, string> = {
    0x01: `Discrete ${dir}`,
    0x02: `Upper non-critical going high (${dir})`,
    0x03: `Lower critical going low (${dir})`,
    0x04: `Upper critical going high (${dir})`,
    0x05: `Lower critical going low (${dir})`,
    0x06: `Upper non-critical going low (${dir})`,
    0x07: `Lower non-critical going high (${dir})`,
    0x08: `Upper critical going low (${dir})`,
    0x09: `Limit exceeded (${dir})`,
    0x0a: `Pre-failure (${dir})`,
    0x16: 'Firmware-initiated reset',
  };
  return types[eventType] ?? `Event type 0x${eventType.toString(16)} (${dir})`;
}

/** Clears the SEL (openipmi: netfn STORAGE cmd 0x47, request = reserveId(2) + 'CLR' + 0xaa). */
export async function clearSel(client: IpmiClient): Promise<void> {
  // Reserve first so we can pass a valid reservation id in the clear request.
  let reservationId = 0;
  try {
    const resv = await client.sendCommand(NETFN_STORAGE, SE_RESERVE_SEL, Buffer.alloc(0));
    if (resv.length >= 2) reservationId = resv[0] | (resv[1] << 8);
  } catch {
    /* continue without reserve */
  }
  const req = Buffer.from([reservationId & 0xff, (reservationId >> 8) & 0xff, 0x43, 0x4c, 0x52, 0xaa]); // 'C','L','R',0xaa
  await client.sendCommand(NETFN_STORAGE, SE_CLEAR_SEL, req);
}

// --- LAN config ---------------------------------------------------------------------------

/** Reads the LAN channel's IP configuration (params on channel `channel`). */
export async function getLanConfig(client: IpmiClient, channel = 1): Promise<LanConfig> {
  const readParam = async (paramId: number): Promise<Buffer> => {
    // Get LAN Config Parameters: [channel(1), paramSelector(2 LE)].
    const req = Buffer.alloc(3);
    req[0] = channel & 0xff;
    req[1] = paramId & 0xff;
    req[2] = (paramId >> 8) & 0xff;
    return client.sendCommand(NETFN_TRANSPORT, TRANSPORT_GET_LAN_CONFIG_PARAMS, req);
  };

  const ipParam = await readParam(0x0001).catch(() => Buffer.alloc(0)); // IP address (4 bytes) or empty for DHCP
  const maskParam = await readParam(0x0002).catch(() => Buffer.alloc(0)); // subnet mask
  const gwParam = await readParam(0x0003).catch(() => Buffer.alloc(0)); // default gateway
  const macParam = await readParam(0x0004).catch(() => Buffer.alloc(0)); // MAC address (6 bytes)

  return {
    ipAddress: ipParam.length >= 4 ? [...ipParam.subarray(0, 4)].map((b) => b.toString()).join('.') : '',
    subnetMask: maskParam.length >= 4 ? [...maskParam.subarray(0, 4)].map((b) => b.toString()).join('.') : '',
    defaultGateway: gwParam.length >= 4 ? [...gwParam.subarray(0, 4)].map((b) => b.toString()).join('.') : '',
    macAddress: macParam.length >= 6 ? [...macParam.subarray(0, 6)].map((b) => b.toString(16).padStart(2, '0')).join(':').toUpperCase() : '',
    ipVersion: 'ipv4',
  };
}

/** Writes one LAN config parameter (netfn TRANSPORT cmd 0x51). */
export async function setLanParam(client: IpmiClient, channel: number, paramId: number, value: Buffer): Promise<void> {
  // Set LAN Config Parameters: [channel(1), paramSelector(2 LE), inData...].
  const req = Buffer.concat([Buffer.from([channel & 0xff, paramId & 0xff, (paramId >> 8) & 0xff]), value]);
  await client.sendCommand(NETFN_TRANSPORT, TRANSPORT_SET_LAN_CONFIG_PARAMS, req);
}
