/**
 * Self-contained IPMI 2.0 / RMCP+ client (UDP port 623) — no external
 * dependency, and NO ipmitool subprocess: the BMC password lives only in
 * process memory (Node crypto), fed into the RAKP1-4 challenge/response to
 * derive SHA-1 HMAC session keys K1/K2. It never touches argv, env or disk.
 *
 * Wire protocol facts verified against openipmi's lanplus plugin:
 *   - RMCP+ packets carry NO ASF header — they start directly with the 4-byte
 *     RMCP header (ver=0x06, reserved=0x00, seq=0xff, class=0x07) followed by
 *     the 10-byte IPMI session header; payload starts at offset 16.
 *   - Session header: [4]=authtype 0x06 (RMCP+), [5]=payload type (+0x80 when
 *     encrypted, +0x40 when authenticated once the session is ACTIVE),
 *     [6..9]=session id LE, [10..13]=sequence number LE, [14..15]=payload len LE.
 *   - Kuid = raw password bytes zero-padded to 20 (IPMI_AUTHCODE_BUFFER_SIZE).
 *   - The ROLEm byte used in every RAKP HMAC is the EXACT byte sent as
 *     RAKP1[24] — privilege level OR'd with the lookup bit (0x10), which we set
 *     by default so a user whose max privilege is below admin still authenticates.
 *   - Random numbers are byte-reversed between their stored/HMAC form and their
 *     wire form (openipmi's array_letoh).
 *   - RAKP2 HMAC input: SIDm(4LE)+SIDc(4LE)+Rm(16)+Rc(16)+GUIDc(16)+ROLEm(1)
 *     +ULENGTHm(1)+username, keyed with Kuid (full 20-byte digest compared).
 *   - RAKP3 authcode input: Rc(16)+SIDm(4LE)+ROLEm(1)+ULENGTHm(1)+username,
 *     keyed with Kuid. After sending: SIK → K1 → K2 (in that order).
 *   - RAKP4 ICV check: HMAC-SHA1(Rm(16)+SIDc(4LE)+GUIDc(16)) keyed with SIK,
 *     first 12 bytes compared.
 *   - Regular commands: IPMI message header inside the payload (rsAddr=0x20,
 *     netfn<<2|lun, csum, rqAddr=0x81, seq<<2, cmd, data, csum). Once ACTIVE
 *     with cipher 3 the payload is AES-CBC-128 encrypted (random 16-byte IV +
 *     ciphertext; padding = bytes 1..n followed by a pad-length byte) and an
 *     integrity trailer follows: 0xFF pad so that (12+payloadLen+padLenField+
 *     nextHeaderField) %4 == 0, then padLength, then 0x07, then the first 12
 *     bytes of HMAC-SHA1 over [authtype .. nextHeader] keyed with K1.
 */

import dgram from 'node:dgram';
import crypto from 'node:crypto';

// --- Constants ------------------------------------------------------------------

const RMCP_VERSION = 0x06; // RMCP 1.0
const RMCP_CLASS_IPMI = 0x07;
const AUTHTYPE_RMCP_PLUS = 0x06;

const PAYLOAD_TYPE_IPMI = 0x00;
const PAYLOAD_TYPE_SOL = 0x01;
// Pre-session payload types — REQUEST and RESPONSE have DISTINCT ids (spec table 13-2):
const PAYLOAD_TYPE_OPEN_REQUEST = 0x10;
const PAYLOAD_TYPE_OPEN_RESPONSE = 0x11;
const PAYLOAD_TYPE_RAKP_1 = 0x12;
const PAYLOAD_TYPE_RAKP_2 = 0x13;
const PAYLOAD_TYPE_RAKP_3 = 0x14;
const PAYLOAD_TYPE_RAKP_4 = 0x15;

// Session header offsets (relative to packet start).
const OFF_AUTHTYPE = 4;
const OFF_PAYLOAD_TYPE = 5;
const OFF_SESSION_ID = 6;
const OFF_SEQUENCE_NUM = 10;
const OFF_PAYLOAD_SIZE = 14;
const OFF_PAYLOAD = 16;

// Algorithm ids (IPMI v2 spec table 13-19 / cipher suite definitions).
const AUTH_NONE = 0x00;
const AUTH_RAKP_HMAC_SHA1 = 0x01;
const INTEGRITY_NONE = 0x00;
const INTEGRITY_HMAC_SHA1_96 = 0x01;
const CRYPT_NONE = 0x00;
const CRYPT_AES_CBC_128 = 0x01;

// Cipher suites (table 25-3 of the IPMI v2.0 spec).
export interface CipherSuite {
  id: number;
  auth: number;
  integrity: number;
  crypt: number;
}
const CIPHER_SUITE_0: CipherSuite = { id: 0, auth: AUTH_NONE, integrity: INTEGRITY_NONE, crypt: CRYPT_NONE };
const CIPHER_SUITE_3: CipherSuite = { id: 3, auth: AUTH_RAKP_HMAC_SHA1, integrity: INTEGRITY_HMAC_SHA1_96, crypt: CRYPT_AES_CBC_128 };

// Privilege levels.
export const PRIV_CALLBACK = 1;
export const PRIV_OPERATOR = 2;
export const PRIV_ADMIN = 3;
const LOOKUP_BIT = 0x10; // RAKP1[24] bit: "use the user's max privilege"

const KUID_SIZE = 20; // IPMI_AUTHCODE_BUFFER_SIZE
const SHA1_TRUNCATED = 12; // HMAC-SHA1-96 authcode size
const AES_BLOCK = 16;

// RAKP return codes.
export const RAKP_OK = 0x00;

/** Error with a machine-readable classification so callers can react (auth vs transport). */
export class IpmiError extends Error {
  constructor(
    message: string,
    public readonly kind: 'transport' | 'auth' | 'protocol' | 'comcode',
    /** IPMI completion code when kind === 'comcode'. */
    public readonly comCode?: number,
  ) {
    super(message);
    this.name = 'IpmiError';
  }
}

/** Human-readable completion codes for the common ones (IPMI v2 spec table 9-1). */
export function describeComCode(cc: number): string {
  const known: Record<number, string> = {
    0x80: 'unspecified error',
    0xc1: 'invalid data field in request',
    0xcf: 'duplicate request (retry)',
    0xd0: 'sensor not present',
    0xd2: 'insufficient privilege level',
    0xd3: 'cannot make requested state change',
    0xd4: 'cannot perform requested action',
    0xd5: 'data area invalid',
    0xd6: 'request length invalid',
    0xd7: 'sensor not readable',
    0xd9: 'invalid channel number',
    0xda: 'invalid record ID in request',
    0xdc: 'requested records not present',
    0xe0: 'invalid FRU ID in request',
    0xe4: 'FRU device not found',
    0xf0: 'invalid field in request',
    0xf1: 'cannot set requested value',
    0xf2: 'object not in defined state',
    0xf3: 'object is in an unexpected state',
    0xf4: 'object not available',
    0xf5: 'hardware error in object',
    0xfa: 'invalid data in request',
    0xff: 'unknown command',
  };
  return known[cc] ?? `completion code 0x${cc.toString(16)}`;
}

// --- Crypto helpers ------------------------------------------------------------------

function hmacSha1(key: Buffer, ...parts: Buffer[]): Buffer {
  const h = crypto.createHmac('sha1', key);
  for (const p of parts) h.update(p);
  return h.digest();
}

/** Raw password → Kuid: zero-padded to 20 bytes. Kept in memory only. */
function deriveKuid(password: string): Buffer {
  const buf = Buffer.alloc(KUID_SIZE, 0);
  const pw = Buffer.from(password, 'utf8');
  pw.copy(buf, 0, 0, Math.min(pw.length, KUID_SIZE));
  return buf;
}

/** K2 is a full 20-byte SHA-1 digest; AES-128 uses only its first 16 bytes
 *  (openipmi passes the whole buffer to EVP_aes_128_cbc, which reads 16). */
function aesKey(k2: Buffer): Buffer {
  return k2.subarray(0, 16);
}

/** AES-CBC-128 encrypt with the IPMI confidentiality framing: random IV + ciphertext.
 *  Padding scheme (openipmi): pad bytes are 1..n followed by a final pad-length byte. */
function aesEncrypt(k2: Buffer, plaintext: Buffer): Buffer {
  const mod = (plaintext.length + 1) % AES_BLOCK;
  const padLength = mod ? AES_BLOCK - mod : 0;
  const padded = Buffer.alloc(plaintext.length + padLength + 1);
  plaintext.copy(padded, 0);
  for (let i = 0; i < padLength; ++i) padded[plaintext.length + i] = i + 1;
  padded[plaintext.length + padLength] = padLength;

  const iv = crypto.randomBytes(AES_BLOCK);
  const cipher = crypto.createCipheriv('aes-128-cbc', aesKey(k2), iv);
  cipher.setAutoPadding(false);
  const ct = Buffer.concat([cipher.update(padded), cipher.final()]);
  return Buffer.concat([iv, ct]);
}

/** AES-CBC-128 decrypt of an IPMI confidentiality-framed payload (IV + ciphertext). */
function aesDecrypt(k2: Buffer, framed: Buffer): Buffer {
  const iv = framed.subarray(0, AES_BLOCK);
  const ct = framed.subarray(AES_BLOCK);
  const decipher = crypto.createDecipheriv('aes-128-cbc', aesKey(k2), iv);
  decipher.setAutoPadding(false);
  let plain: Buffer;
  try {
    plain = Buffer.concat([decipher.update(ct), decipher.final()]);
  } catch (e) {
    throw new IpmiError(`AES decryption failed: ${e instanceof Error ? e.message : String(e)}`, 'protocol');
  }
  // Strip the IPMI padding: last byte is the pad length, preceded by bytes 1..n.
  const padLength = plain[plain.length - 1];
  if (padLength < 0 || padLength > AES_BLOCK + 1) throw new IpmiError('Invalid AES padding in BMC response', 'protocol');
  return plain.subarray(0, plain.length - 1 - padLength);
}

// --- Low-level UDP transport ------------------------------------------------------------------

interface Pending {
  resolve: (buf: Buffer) => void;
  reject: (err: Error) => void;
  timer: NodeJS.Timeout;
  onMessage: (msg: Buffer) => void;
}

/** One RMCP+ session to one BMC. All state is per-connection; the password
 *  never leaves this object's memory. Requests are serialized internally so a
 *  monitoring poll and an active SOL console can share one client safely. */
export class IpmiClient {
  private readonly host: string;
  private readonly port: number;
  private readonly timeoutMs: number;
  private readonly socket = dgram.createSocket({ type: 'udp4', reuseAddr: false });

  // Session state (populated by connect()).
  private bmcId = 0;
  private consoleId = 0;
  private outSeq = 1;
  private authAlg = AUTH_NONE;
  private integrityAlg = INTEGRITY_NONE;
  private cryptAlg = CRYPT_NONE;
  private kuid: Buffer | null = null;
  private sik: Buffer | null = null;
  private k1: Buffer | null = null;
  private k2: Buffer | null = null;
  private active = false;

  // SOL state.
  private solSeq = 0;
  /** Registered async data sink for unsolicited SOL packets (the console). */
  onSolData: ((data: Buffer) => void) | null = null;
  /** The in-flight request, if any — used to route matching responses vs. async SOL data. */
  private pendingRequest: Pending | null = null;
  /** FIFO so only one packet is ever in flight (RMCP+ has no correlation id). */
  private queue: Promise<unknown> = Promise.resolve();

  constructor(opts: { host: string; port?: number; timeoutMs?: number }) {
    this.host = opts.host;
    this.port = opts.port ?? 623;
    this.timeoutMs = opts.timeoutMs ?? 10_000;
    this.socket.on('error', (err) => {
      // Surface transport errors to the in-flight request, if any.
      const p = this.pendingRequest;
      if (p) {
        clearTimeout(p.timer);
        this.removeMessageListener(p);
        this.pendingRequest = null;
        p.reject(new IpmiError(`UDP socket error: ${err.message}`, 'transport'));
      }
    });
  }

  /** Closes the UDP socket. Idempotent. */
  close(): void {
    try {
      const p = this.pendingRequest;
      if (p) {
        clearTimeout(p.timer);
        this.removeMessageListener(p);
        this.pendingRequest = null;
        p.reject(new IpmiError('client closed', 'transport'));
      }
      this.socket.close();
    } catch {
      /* already closed */
    }
  }

  // --- Session lifecycle ------------------------------------------------------------------

  /**
   * Runs the full RMCP+ session establishment: Open Session Request/Response,
   * RAKP1-4 (with cipher-suite negotiation), then Set Session Privilege Level.
   * Throws IpmiError on any failure; on success `isActive` is true and
   * sendCommand() can be used.
   */
  async connect(username: string, password: string, opts?: { cipherSuiteId?: number; privLevel?: number; noLookup?: boolean }): Promise<void> {
    const suite = (opts?.cipherSuiteId ?? 3) === 0 ? CIPHER_SUITE_0 : CIPHER_SUITE_3;
    let privLevel = opts?.privLevel ?? PRIV_ADMIN;
    this.kuid = deriveKuid(password);

    // --- Open Session Request ---------------------------------------------------------
    const openReq = Buffer.alloc(32, 0);
    openReq[0] = 0; // message tag
    openReq[1] = 0; // max priv level: 0 = "highest supported" (BMC decides)
    this.consoleId = crypto.randomInt(0x10000000, 0xffffffff);
    writeLe32(openReq, 4, this.consoleId);
    openReq[8] = 0; // auth payload selector
    openReq[11] = 8; // auth payload length
    openReq[12] = suite.auth;
    openReq[16] = 1; // integrity payload selector
    openReq[19] = 8;
    openReq[20] = suite.integrity;
    openReq[24] = 2; // confidentiality payload selector
    openReq[27] = 8;
    openReq[28] = suite.crypt;

    const openRsp = await this.sendRaw(PAYLOAD_TYPE_OPEN_REQUEST, PAYLOAD_TYPE_OPEN_RESPONSE, openReq);
    if (openRsp.length < 40) throw new IpmiError('Open Session response too short', 'protocol');
    const osReturnCode = openRsp[1];
    if (osReturnCode !== RAKP_OK) {
      throw new IpmiError(`Open Session rejected by BMC (return code 0x${osReturnCode.toString(16)})`, 'auth');
    }
    this.bmcId = readLe32(openRsp, 8);
    const maxPrivLevel = openRsp[2]; // BMC's ceiling for this session
    if (maxPrivLevel > 0 && privLevel > maxPrivLevel) privLevel = maxPrivLevel;
    const agreedAuth = openRsp[16];
    const agreedIntegrity = openRsp[24];
    const agreedCrypt = openRsp[32];

    // Verify the BMC agreed to our cipher suite. A legacy BMC may answer with a
    // weaker combo — accept it only when we explicitly asked for suite 0.
    if (suite.id === 3) {
      if (agreedAuth !== AUTH_RAKP_HMAC_SHA1 || agreedIntegrity !== INTEGRITY_HMAC_SHA1_96 || agreedCrypt !== CRYPT_AES_CBC_128) {
        throw new IpmiError(
          `BMC did not agree to cipher suite 3 (auth=0x${agreedAuth.toString(16)}, integrity=0x${agreedIntegrity.toString(16)}, crypt=0x${agreedCrypt.toString(16)}) — try cipherSuiteId 0 for legacy BMCs`,
          'protocol',
        );
      }
    } else if (agreedAuth !== AUTH_NONE || agreedIntegrity !== INTEGRITY_NONE || agreedCrypt !== CRYPT_NONE) {
      throw new IpmiError(`BMC did not agree to cipher suite 0 (auth=0x${agreedAuth.toString(16)})`, 'protocol');
    }
    this.authAlg = agreedAuth;
    this.integrityAlg = agreedIntegrity;
    this.cryptAlg = agreedCrypt;

    // --- RAKP1 ------------------------------------------------------------------------
    const usernameBuf = Buffer.from(username, 'utf8');
    if (usernameBuf.length > 16) throw new IpmiError('IPMI user name too long (max 16)', 'protocol');
    const consoleRand = crypto.randomBytes(16); // stored form — used in HMACs

    // ROLEm: the exact byte sent as RAKP1[24] — privilege | lookup bit. The BMC
    // echoes this into its own HMAC inputs, so it must match what we hash with.
    const roleByte = (privLevel | ((opts?.noLookup ?? false) ? 0 : LOOKUP_BIT)) & 0xff;

    const rakp1Len = 28 + usernameBuf.length; // tag+rc+resv(2)+bmcId(4)+rand(16)+role(1)+resv(2)+ulen(1)+username
    const rakp1 = Buffer.alloc(rakp1Len, 0);
    rakp1[0] = 0; // message tag
    writeLe32(rakp1, 4, this.bmcId);
    consoleRand.copy(rakp1, 8);
    reverseInPlace(rakp1.subarray(8, 24)); // wire form is byte-reversed (openipmi array_letoh)
    rakp1[24] = roleByte;
    rakp1[27] = usernameBuf.length;
    usernameBuf.copy(rakp1, 28);

    const rakp2 = await this.sendRaw(PAYLOAD_TYPE_RAKP_1, PAYLOAD_TYPE_RAKP_2, rakp1);
    if (rakp2.length < 40) throw new IpmiError('RAKP2 response too short', 'protocol');
    const rakp2ReturnCode = rakp2[1];

    let bmcRand: Buffer; // stored form — used in HMACs
    let bmcGuid: Buffer; // stored form — used in HMACs
    if (rakp2ReturnCode === RAKP_OK) {
      bmcRand = Buffer.from(rakp2.subarray(8, 24));
      reverseInPlace(bmcRand);
      bmcGuid = Buffer.from(rakp2.subarray(24, 40));
      reverseInPlace(bmcGuid);

      // --- Verify RAKP2 HMAC (the BMC authenticated itself to us) ---------------------
      const rakp2Input = Buffer.concat([
        le32(this.consoleId), // SIDm
        le32(this.bmcId), // SIDc
        consoleRand, // Rm
        bmcRand, // Rc
        bmcGuid, // GUIDc
        Buffer.from([roleByte]), // ROLEm (the exact byte we sent)
        Buffer.from([usernameBuf.length]), // ULENGTHm
        usernameBuf,
      ]);
      const expectedMac = hmacSha1(this.kuid, rakp2Input);
      if (!expectedMac.equals(rakp2.subarray(40, 60))) {
        throw new IpmiError('RAKP2 HMAC mismatch — BMC authentication failed (wrong password or user?)', 'auth');
      }

      // --- RAKP3 ----------------------------------------------------------------------
      const rakp3Input = Buffer.concat([bmcRand, le32(this.consoleId), Buffer.from([roleByte]), Buffer.from([usernameBuf.length]), usernameBuf]);
      const rakp3Authcode = hmacSha1(this.kuid, rakp3Input);

      const rakp3 = Buffer.concat([Buffer.from([0x00, RAKP_OK, 0, 0]), le32(this.bmcId), rakp3Authcode]);
      // Generate SIK → K1 → K2 (in that order) before sending, per openipmi.
      const sikInput = Buffer.concat([consoleRand, bmcRand, Buffer.from([roleByte]), Buffer.from([usernameBuf.length]), usernameBuf]);
      this.sik = hmacSha1(this.kuid, sikInput);
      this.k1 = hmacSha1(this.sik, Buffer.alloc(20, 0x01));
      this.k2 = hmacSha1(this.sik, Buffer.alloc(20, 0x02));

      const rakp4 = await this.sendRaw(PAYLOAD_TYPE_RAKP_3, PAYLOAD_TYPE_RAKP_4, rakp3);
      if (rakp4.length < 8 + SHA1_TRUNCATED) throw new IpmiError('RAKP4 response too short', 'protocol');
      const rakp4ReturnCode = rakp4[1];
      if (rakp4ReturnCode !== RAKP_OK) {
        throw new IpmiError(`RAKP4 rejected by BMC (return code 0x${rakp4ReturnCode.toString(16)})`, 'auth');
      }
      // Verify the RAKP4 ICV: HMAC-SHA1(Rm + SIDc + GUIDc) keyed with SIK, first 12 bytes.
      const rakp4Input = Buffer.concat([consoleRand, le32(this.bmcId), bmcGuid]);
      const expectedIcv = hmacSha1(this.sik!, rakp4Input).subarray(0, SHA1_TRUNCATED);
      if (!expectedIcv.equals(rakp4.subarray(8, 8 + SHA1_TRUNCATED))) {
        throw new IpmiError('RAKP4 ICV mismatch — session integrity check failed', 'auth');
      }
    } else {
      // RAKP2 reported an error (e.g. bad credentials) — send a bare RAKP3 to
      // acknowledge, then fail with the BMC's return code.
      const bareRakp3 = Buffer.concat([Buffer.from([0x00, rakp2ReturnCode, 0, 0]), le32(this.bmcId)]);
      await this.sendRaw(PAYLOAD_TYPE_RAKP_3, PAYLOAD_TYPE_RAKP_4, bareRakp3).catch(() => undefined);
      throw new IpmiError(`RAKP2 rejected by BMC (return code 0x${rakp2ReturnCode.toString(16)}) — check username/password`, 'auth');
    }

    this.active = true;

    // --- Set Session Privilege Level ----------------------------------------------------
    if (privLevel > PRIV_CALLBACK) {
      const privReq = Buffer.from([0, 0, privLevel]); // reserved(2) + requested level
      try {
        await this.sendCommand(NETFN_APP, CMD_SET_SESSION_PRIVILEGE, privReq);
      } catch (e) {
        if (e instanceof IpmiError && e.kind === 'comcode' && e.comCode === 0xd2) {
          // User's max privilege is below what we asked — retry at operator.
          await this.sendCommand(NETFN_APP, CMD_SET_SESSION_PRIVILEGE, Buffer.from([0, 0, PRIV_OPERATOR])).catch(() => undefined);
        } else {
          throw e;
        }
      }
    }
  }

  /** True once the RAKP handshake completed and the session is usable. */
  get isActive(): boolean {
    return this.active;
  }

  // --- Command layer ------------------------------------------------------------------

  /** Sends one IPMI command inside the (possibly encrypted) RMCP+ payload and
   *  returns the response data AFTER the completion code byte. Throws IpmiError
   *  on transport/protocol problems or a non-zero completion code. */
  async sendCommand(netfn: number, cmd: number, data: Buffer = Buffer.alloc(0), opts?: { expectComCode?: boolean }): Promise<Buffer> {
    if (!this.active) throw new IpmiError('Session not established — call connect() first', 'protocol');

    // IPMI message header (figure 13-4 of the spec): rsAddr, netfn<<2|lun, csum,
    // rqAddr=0x81, seq<<2, cmd, data..., csum.
    const msg = Buffer.alloc(7 + data.length);
    let i = 0;
    msg[i++] = 0x20; // rsAddr (BMC slave address)
    msg[i++] = netfn << 2; // netfn | lun=0
    msg[i] = ipmiCsum(msg.subarray(0, i)); // csum over rsAddr..netfn
    const rqStart = i + 1; // index of rqAddr (the trailing checksum covers rqAddr..data)
    i++;
    msg[i++] = 0x81; // rqAddr (remote SW)
    msg[i++] = this.outSeq << 2; // request sequence | lun=0
    msg[i++] = cmd;
    data.copy(msg, i);
    i += data.length;
    msg[i] = ipmiCsum(msg.subarray(rqStart)); // csum over rqAddr..data (spec fig 13-4)

    const payload = await this.sendSessionPayload(PAYLOAD_TYPE_IPMI, msg);

    // Response: rsAddr(0x20), netfn<<2|lun (extended bit may be set → netfn+1 for
    // responses), csum, rqAddr, seq<<2, cmd, comCode, data...
    if (payload.length < 7) throw new IpmiError('IPMI response too short', 'protocol');
    const comCode = payload[6];
    if (comCode !== RAKP_OK && !opts?.expectComCode) {
      throw new IpmiError(`IPMI command 0x${cmd.toString(16)} failed: ${describeComCode(comCode)}`, 'comcode', comCode);
    }
    return payload.subarray(7);
  }

  // --- SOL ------------------------------------------------------------------

  /** Activates the SOL payload on `channel` (default 1). Returns the BMC's max
   *  character count per packet. Throws IpmiError when SOL is unavailable. */
  async activateSol(channel = 1): Promise<number> {
    const rsp = await this.sendCommand(NETFN_APP, CMD_ACTIVATE_PAYLOAD, Buffer.from([channel & 0xff, PAYLOAD_TYPE_SOL]));
    if (rsp.length < 2) throw new IpmiError('Activate Payload response too short', 'protocol');
    return Math.max(16, rsp[1]); // max characters per packet
  }

  /** Deactivates the SOL payload on `channel` (best-effort). */
  async deactivateSol(channel = 1): Promise<void> {
    try {
      await this.sendCommand(NETFN_APP, CMD_DEACTIVATE_PAYLOAD, Buffer.from([channel & 0xff, PAYLOAD_TYPE_SOL]));
    } catch {
      /* best effort — the session may already be gone */
    }
  }

  /** Sends one SOL data packet (up to `maxChars` bytes) and waits for its ACK.
   *  Unsolicited BMC→console data arriving meanwhile is routed to onSolData. */
  async sendSolPacket(data: Buffer, maxChars = 128): Promise<void> {
    if (!this.active) throw new IpmiError('Session not established', 'protocol');
    const chunk = data.subarray(0, Math.min(data.length, maxChars));

    // SOL payload header (4 bytes): seq, acked, accepted char count, flags.
    const hdr = Buffer.alloc(4);
    hdr[0] = this.solSeq & 0xff;
    if (chunk.length > 0) {
      this.solSeq++;
      if (this.solSeq === 0) this.solSeq = 1;
    }

    const payload = Buffer.concat([hdr, chunk]);
    await this.sendSessionPayload(PAYLOAD_TYPE_SOL, payload, { solSentSeq: hdr[0] });
  }

  // --- Packet building + sending ------------------------------------------------------------------

  /** Sends a pre-session RMCP+ packet (never encrypted/authenticated). Pre-session
   *  request and response payload types are DISTINCT ids (0x10→0x11, 0x12→0x13,
   *  0x14→0x15), so both must be given. */
  private async sendRaw(requestType: number, responseType: number, payload: Buffer): Promise<Buffer> {
    const pkt = Buffer.alloc(OFF_PAYLOAD + payload.length);
    writeRmcpHeader(pkt);
    pkt[OFF_AUTHTYPE] = AUTHTYPE_RMCP_PLUS;
    pkt[OFF_PAYLOAD_TYPE] = requestType;
    // Pre-session: no session id / sequence number (zeroed).
    writeLe16(pkt, OFF_PAYLOAD_SIZE, payload.length);
    payload.copy(pkt, OFF_PAYLOAD);

    const rsp = await this.sendUdp(pkt, { match: (r) => (r[OFF_PAYLOAD_TYPE] & 0x3f) === responseType });
    return parsePreSessionResponse(rsp, responseType);
  }

  /** Sends an in-session IPMI/SOL payload with encryption + integrity trailer. */
  private async sendSessionPayload(payloadType: number, plaintext: Buffer, extra?: { solSentSeq?: number }): Promise<Buffer> {
    let wire = plaintext;
    if (this.cryptAlg === CRYPT_AES_CBC_128) wire = aesEncrypt(this.k2!, plaintext);

    const trailerLen = this.integrityAlg !== INTEGRITY_NONE ? 4 + 2 + SHA1_TRUNCATED : 0; // max pad + fields + authcode
    const pkt = Buffer.alloc(OFF_PAYLOAD + wire.length + trailerLen, 0xff);
    writeRmcpHeader(pkt);
    pkt[OFF_AUTHTYPE] = AUTHTYPE_RMCP_PLUS;
    let pt = payloadType;
    if (this.cryptAlg !== CRYPT_NONE) pt |= 0x80; // encrypted flag
    if (this.integrityAlg !== INTEGRITY_NONE) pt |= 0x40; // authenticated flag
    pkt[OFF_PAYLOAD_TYPE] = pt;
    writeLe32(pkt, OFF_SESSION_ID, this.bmcId);
    writeLe32(pkt, OFF_SEQUENCE_NUM, this.outSeq);
    writeLe16(pkt, OFF_PAYLOAD_SIZE, wire.length); // payload size = encrypted (or plaintext) length
    wire.copy(pkt, OFF_PAYLOAD);

    let totalLen = OFF_PAYLOAD + wire.length;
    if (this.integrityAlg !== INTEGRITY_NONE) {
      // Integrity pad: make (12 + payloadLen + 1 + 1) a multiple of 4. The 0xFF
      // pre-fill already pads the region; compute how many bytes belong to the
      // pad vs. the two fixed trailer fields.
      const lengthBeforeAuthcode = 12 + wire.length + 1 + 1;
      const integrityPadSize = (4 - (lengthBeforeAuthcode % 4)) % 4;
      const trailerStart = OFF_PAYLOAD + wire.length;
      pkt[trailerStart + integrityPadSize] = integrityPadSize; // padLength field
      pkt[trailerStart + integrityPadSize + 1] = 0x07; // next header (spec table 13-8)

      const hmacInputSize = 12 + wire.length + integrityPadSize + 2;
      const mac = hmacSha1(this.k1!, pkt.subarray(OFF_AUTHTYPE, OFF_AUTHTYPE + hmacInputSize));
      mac.copy(pkt, trailerStart + integrityPadSize + 2);

      totalLen = trailerStart + integrityPadSize + 2 + SHA1_TRUNCATED;
    }

    this.outSeq++;
    if (this.outSeq === 0) this.outSeq = 1; // sequence numbers are non-zero

    const match = (r: Buffer): boolean => {
      if ((r[OFF_PAYLOAD_TYPE] & 0x3f) !== payloadType) return false;
      if (readLe32(r, OFF_SESSION_ID) !== this.bmcId) return false;
      // SOL ACK matching. In a plaintext session we can read the "acked" field of
      // the 4-byte SOL header directly from the wire bytes. In an encrypted
      // session those bytes are ciphertext — but EVERY BMC→console SOL packet
      // carries an acked field in its (encrypted) header, and our serialized
      // queue guarantees exactly one outstanding request at a time, so ANY
      // matching SOL-type packet IS the ACK for the send we just made.
      if (payloadType === PAYLOAD_TYPE_SOL && extra?.solSentSeq !== undefined) {
        if (this.cryptAlg !== CRYPT_NONE) return true;
        if (r.length < OFF_PAYLOAD + 4) return false;
        const acked = r[OFF_PAYLOAD + 1];
        const delta = (acked - extra.solSentSeq + 256) % 256;
        return delta <= 4; // tolerate slight out-of-order / wraparound
      }
      return true;
    };

    const rsp = await this.sendUdp(pkt.subarray(0, totalLen), { match });
    return this.parseSessionResponse(rsp);
  }

  /** Parses an in-session response: verifies the integrity trailer (when
   *  present) and decrypts the payload (when encrypted). Returns plaintext. */
  private parseSessionResponse(rsp: Buffer): Buffer {
    if (rsp.length < OFF_PAYLOAD + 2) throw new IpmiError('Malformed RMCP+ response (too short)', 'protocol');
    checkRmcpHeader(rsp);

    const payloadLen = readLe16(rsp, OFF_PAYLOAD_SIZE);
    const end = OFF_PAYLOAD + payloadLen;

    if (this.integrityAlg !== INTEGRITY_NONE) {
      // Trailer layout after the payload: 0xFF pad*, padLength(1), nextHeader(1), authcode(12).
      let padSize = -1;
      for (let s = 0; s <= 3; ++s) {
        if ((12 + payloadLen + 2 + s) % 4 === 0 && end + s + 2 + SHA1_TRUNCATED === rsp.length) padSize = s;
      }
      if (padSize < 0) throw new IpmiError('Response integrity trailer malformed', 'protocol');

      const nextHeader = rsp[end + padSize + 1];
      if (nextHeader !== 0x07) throw new IpmiError(`Unexpected next-header byte in BMC response (0x${nextHeader.toString(16)})`, 'protocol');

      const hmacInputSize = 12 + payloadLen + padSize + 2;
      const expectedMac = hmacSha1(this.k1!, rsp.subarray(OFF_AUTHTYPE, OFF_AUTHTYPE + hmacInputSize)).subarray(0, SHA1_TRUNCATED);
      if (!expectedMac.equals(rsp.subarray(end + padSize + 2, end + padSize + 2 + SHA1_TRUNCATED))) {
        throw new IpmiError('Response integrity check failed (K1 mismatch?)', 'protocol');
      }
    }

    const framed = rsp.subarray(OFF_PAYLOAD, end);
    if (this.cryptAlg === CRYPT_AES_CBC_128) return aesDecrypt(this.k2!, framed);
    return framed;
  }

  // --- UDP plumbing ------------------------------------------------------------------

  private sendUdp(pkt: Buffer, opts: { match: (rsp: Buffer) => boolean }): Promise<Buffer> {
    const run = (): Promise<Buffer> =>
      new Promise<Buffer>((resolve, reject) => {
        const onMessage = (msg: Buffer): void => {
          // A BMC→console SOL packet may carry terminal data EVEN when it is the
          // ACK for our in-flight send — so parse/decrypt SOL packets FIRST and
          // route any payload to the console sink, then apply the match condition.
          if ((msg[OFF_PAYLOAD_TYPE] & 0x3f) === PAYLOAD_TYPE_SOL && this.onSolData) {
            try {
              const solPayload = this.parseSessionResponse(msg);
              const data = solPayload.subarray(4); // skip the 4-byte SOL header
              if (data.length > 0) this.onSolData(data);
            } catch {
              /* not a parseable SOL packet — ignore */
            }
          }

          if (opts.match(msg)) {
            clearTimeout(pending.timer);
            this.removeMessageListener(pending);
            this.pendingRequest = null;
            resolve(msg);
            return;
          }
        };

        const pending: Pending = {
          resolve,
          reject,
          timer: setTimeout(() => {
            if (this.pendingRequest === pending) this.pendingRequest = null;
            this.removeMessageListener(pending);
            reject(new IpmiError(`BMC ${this.host}:${this.port} did not respond within ${this.timeoutMs} ms`, 'transport'));
          }, this.timeoutMs),
          onMessage,
        };

        this.socket.on('message', onMessage);
        this.pendingRequest = pending;
        try {
          // dgram.send() is fire-and-forget; failures surface via the socket's
          // 'error' event, which rejects the in-flight request.
          this.socket.send(pkt, 0, pkt.length, this.port, this.host);
        } catch (err) {
          clearTimeout(pending.timer);
          this.removeMessageListener(pending);
          this.pendingRequest = null;
          reject(new IpmiError(`UDP send to ${this.host}:${this.port} failed: ${err instanceof Error ? err.message : String(err)}`, 'transport'));
        }
      });

    // Serialize: RMCP+ has no correlation id, so only one packet may be in flight.
    const p = this.queue.then(run);
    this.queue = p.catch(() => undefined);
    return p;
  }

  private removeMessageListener(p: Pending): void {
    this.socket.removeListener('message', p.onMessage);
  }
}

// --- Netfn / command ids used by the client itself ------------------------------------

const NETFN_APP = 0x06;
const CMD_SET_SESSION_PRIVILEGE = 0x42;
const CMD_ACTIVATE_PAYLOAD = 0x48;
const CMD_DEACTIVATE_PAYLOAD = 0x49;

// --- Response parsing (pre-session) ------------------------------------------------------

/** Parses a pre-session RMCP+ response: validates the header and returns the payload. */
function parsePreSessionResponse(rsp: Buffer, expectedType: number): Buffer {
  if (rsp.length < OFF_PAYLOAD + 2) throw new IpmiError('Malformed RMCP+ response (too short)', 'protocol');
  checkRmcpHeader(rsp);
  const rspType = rsp[OFF_PAYLOAD_TYPE] & 0x3f;
  if (rspType !== expectedType) {
    throw new IpmiError(`Response payload type mismatch (got 0x${rspType.toString(16)}, want 0x${expectedType.toString(16)})`, 'protocol');
  }
  const payloadLen = readLe16(rsp, OFF_PAYLOAD_SIZE);
  if (rsp.length < OFF_PAYLOAD + payloadLen) throw new IpmiError('Response payload truncated', 'protocol');
  return rsp.subarray(OFF_PAYLOAD, OFF_PAYLOAD + payloadLen);
}

function checkRmcpHeader(rsp: Buffer): void {
  if (rsp[0] !== RMCP_VERSION || rsp[3] !== RMCP_CLASS_IPMI) {
    throw new IpmiError(`Unexpected RMCP+ response header (${hex(rsp.subarray(0, 4))})`, 'protocol');
  }
  if (rsp[OFF_AUTHTYPE] !== AUTHTYPE_RMCP_PLUS) {
    throw new IpmiError(`Response is not RMCP+ (authtype 0x${rsp[OFF_AUTHTYPE].toString(16)}) — BMC may only support IPMI v1.5`, 'protocol');
  }
}

// --- Byte helpers ------------------------------------------------------------------

function writeRmcpHeader(pkt: Buffer): void {
  pkt[0] = RMCP_VERSION;
  pkt[1] = 0x00; // reserved
  pkt[2] = 0xff; // no RMCP ack
  pkt[3] = RMCP_CLASS_IPMI;
}

function writeLe32(buf: Buffer, offset: number, value: number): void {
  buf[offset] = value & 0xff;
  buf[offset + 1] = (value >>> 8) & 0xff;
  buf[offset + 2] = (value >>> 16) & 0xff;
  buf[offset + 3] = (value >>> 24) & 0xff;
}

function readLe32(buf: Buffer, offset: number): number {
  return buf[offset] | (buf[offset + 1] << 8) | (buf[offset + 2] << 16) | ((buf[offset + 3] << 24) >>> 0);
}

function writeLe16(buf: Buffer, offset: number, value: number): void {
  buf[offset] = value & 0xff;
  buf[offset + 1] = (value >>> 8) & 0xff;
}

function readLe16(buf: Buffer, offset: number): number {
  return buf[offset] | (buf[offset + 1] << 8);
}

function le32(value: number): Buffer {
  const b = Buffer.alloc(4);
  writeLe32(b, 0, value >>> 0);
  return b;
}

/** IPMI checksum: two's complement of the sum so that total ≡ 0 (mod 256). */
function ipmiCsum(buf: Buffer): number {
  let sum = 0;
  for (const b of buf) sum += b;
  return (256 - (sum & 0xff)) & 0xff;
}

/** Reverses a byte range in place (openipmi's array_letoh between stored and wire form). */
function reverseInPlace(buf: Buffer): void {
  for (let i = 0, j = buf.length - 1; i < j; ++i, --j) {
    const t = buf[i];
    buf[i] = buf[j];
    buf[j] = t;
  }
}

function hex(buf: Buffer): string {
  return [...buf].map((b) => b.toString(16).padStart(2, '0')).join(' ');
}
