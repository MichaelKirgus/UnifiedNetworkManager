/**
 * acmeClient — a minimal RFC 8555 (ACME) client for UNM's step-ca, built on
 * Node core modules only (crypto/https/http). No dependencies.
 *
 * Every protocol quirk here was verified live against smallstep/step-ca 0.30.2
 * (see docs + /memories/repo/acme-stepca-facts.md):
 *   - JWS is sent as the HTTP BODY: flattened JSON {protected,payload,signature}
 *     with Content-Type application/jose+json (NOT an Authorization header).
 *   - ES256 signatures are raw r‖s (64 bytes for P-256); Node's crypto.sign
 *     returns DER ASN.1 which must be converted (derToRawSig).
 *   - Authenticated reads are POST-as-GET: a JWS with an EMPTY payload ""
 *     (RFC 8555 §7.3.1) — for authorizations, order polling and certificate
 *     download alike.
 *   - http-01 keyAuth is `<token>.<jwkThumbprint>` — TOKEN FIRST (step-ca's
 *     KeyAuthorization() does fmt.Sprintf("%s.%s", token, thumbprint)). A
 *     mismatch surfaces as the misleading `rejectedIdentifier` error.
 *   - The CSR MUST present exactly the order's identifier set: {CN} ∪ SAN(dns)
 *     == identifiers (step-ca counts the CN as a DNS name; compared
 *     lowercased/deduped/sorted). Mismatch → generic `badCSR`.
 *   - step-ca fetches http://<identifier>/.well-known/acme-challenge/<token> on
 *     port 80 FROM INSIDE THE CA CONTAINER — every identifier must resolve from
 *     the CA to the plugin. localhost/127.0.0.1 can never validate this way.
 */

import crypto from 'crypto';
import https from 'https';

// ---------- base64url ----------
const b64u = (buf: Buffer): string =>
  buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

/** RFC 7638 JWK thumbprint (canonical form: crv,kty,x,y in that key order). */
export function jwkThumbprint(jwk: { crv?: string; kty?: string; x?: string; y?: string }): string {
  const canon = JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y });
  return b64u(crypto.createHash('sha256').update(canon).digest());
}

/**
 * Converts a DER-encoded ECDSA signature (SEQUENCE{INTEGER r, INTEGER s}) to
 * the raw r‖s form required by JWS ES256. Each integer is stripped of its sign
 * padding zero and left-padded to 32 bytes (P-256).
 */
export function derToRawSig(der: Buffer): Buffer {
  let i = 0;
  if (der[i] !== 0x30) throw new Error('derToRawSig: not a DER sequence');
  i++; // skip 0x30
  const first = der.readUIntBE(i, 1);
  i += 1 + (first > 127 ? 1 : 0); // long-form length is rare for P-256 but handled
  function readInt(): Buffer {
    if (der[i] !== 0x02) throw new Error(`derToRawSig: expected INTEGER tag, got 0x${der[i].toString(16)}`);
    i++;
    const n = der.readUIntBE(i, 1);
    i++;
    let bytes = der.subarray(i, i + n);
    i += n;
    if (bytes[0] === 0x00 && bytes.length > 32) bytes = bytes.subarray(1); // sign padding
    const out = Buffer.alloc(32);
    bytes.copy(out, 32 - Math.min(bytes.length, 32));
    return out;
  }
  return Buffer.concat([readInt(), readInt()]);
}

// ---------- minimal DER builders (PKCS#10 only) ----------
function derLen(n: number): Buffer {
  if (n < 128) return Buffer.from([n]);
  const b: number[] = [];
  let v = n;
  while (v > 0) { b.unshift(v & 0xff); v >>= 8; }
  return Buffer.concat([Buffer.from([0x80 | b.length]), Buffer.from(b)]);
}
function tlv(tag: number, content: Buffer): Buffer {
  return Buffer.concat([Buffer.from([tag]), derLen(content.length), content]);
}
const concat = (arr: Buffer[]): Buffer => Buffer.concat(arr);
function derOid(oidStr: string): Buffer {
  const p = oidStr.split('.').map(Number);
  const bytes = [p[0] * 40 + p[1]];
  for (let i = 2; i < p.length; i++) {
    let v = p[i];
    const enc = [v & 0x7f];
    v >>= 7;
    while (v > 0) { enc.unshift((v & 0x7f) | 0x80); v >>= 7; }
    bytes.push(...enc);
  }
  return tlv(0x06, Buffer.from(bytes));
}
function derInt(n: number): Buffer {
  const b: number[] = [];
  let v = n;
  do { b.unshift(v & 0xff); v >>= 8; } while (v > 0);
  if (b[0] & 0x80) b.unshift(0);
  return tlv(0x02, Buffer.from(b.length ? b : [0]));
}
function derUtf8(s: string): Buffer {
  return tlv(0x0c, Buffer.from(s, 'utf8'));
}

/**
 * Builds a PKCS#10 CSR (DER) with CN + SAN dns[] — hand-rolled because Node has
 * no X509CertificateRequest API. Structure verified byte-for-byte against an
 * openssl-generated reference:
 *   CertificationRequestInfo = SEQ { INTEGER 0, Name(CN), SPKI BIT STRING,
 *     attributes [0] { extensionRequest Attribute } }        ← [0] directly contains the attribute
 *   extensionRequest = SEQ { OID 1.2.840.113549.1.9.14, SET { Extensions = SEQ OF
 *     Extension = SEQ { OID 2.5.29.17, OCTET STRING( GeneralNames ) } } }
 *   GeneralNames = SEQ of dNSName [2] PRIMITIVE (tag 0x82) IA5String
 * Signed with ecdsa-with-SHA256; the CSR signature is DER (NOT raw r‖s).
 */
export function buildCsr(privateKey: crypto.KeyObject, cn: string, sanDns: string[]): Buffer {
  const spki = crypto.createPublicKey(privateKey).export({ type: 'spki', format: 'der' });
  // subject Name: CN only
  const name = tlv(0x30, tlv(0x31, tlv(0x30, concat([derOid('2.5.4.3'), derUtf8(cn)]))));
  const generalNames = tlv(0x30, concat(sanDns.map((n) => tlv(0x82, Buffer.from(n, 'utf8')))));
  const sanExtension = tlv(0x30, concat([derOid('2.5.29.17'), tlv(0x04, generalNames)]));
  const extensionsSeq = tlv(0x30, sanExtension); // Extensions ::= SEQUENCE OF Extension
  const extReqAttr = tlv(0x30, concat([derOid('1.2.840.113549.1.9.14'), tlv(0x31, extensionsSeq)]));
  const attrs = tlv(0xA0, extReqAttr); // [0] directly contains the Attribute (openssl/Go style)
  const cri = tlv(0x30, concat([derInt(0), name, spki, attrs]));
  const sigAlgId = tlv(0x30, concat([derOid('1.2.840.10045.4.3.2'), tlv(0x05, Buffer.alloc(0))])); // ecdsa-with-SHA256 + NULL
  const sig = crypto.sign('sha256', cri, privateKey); // DER SEQUENCE{r,s} — correct for PKCS#10
  return tlv(0x30, concat([cri, sigAlgId, tlv(0x03, concat([Buffer.from([0]), sig]))]));
}

// ---------- ACME wire types (the subset UNM uses) ----------
export interface AcmeDirectory {
  newNonce: string;
  newAccount: string;
  newOrder: string;
  [k: string]: unknown;
}
export interface AcmeChallenge {
  type: string;
  status: 'pending' | 'valid' | 'invalid';
  token: string;
  url: string;
  error?: { type?: string; detail?: string };
}
export interface AcmeAuthorization {
  identifier: { type: string; value: string };
  status: 'pending' | 'valid' | 'invalid';
  challenges: AcmeChallenge[];
  expires?: string;
}
export interface AcmeOrder {
  id: string;
  status: 'pending' | 'ready' | 'processing' | 'valid' | 'invalid';
  identifiers: Array<{ type: string; value: string }>;
  authorizations: string[];
  finalize: string;
  certificate?: string;
  expires?: string;
  error?: { type?: string; detail?: string };
}

export interface AcmeClientOptions {
  /** ACME directory URL, e.g. https://unm-ca:9000/acme/acme/directory */
  directoryUrl: string;
  /** PEM of the CA root certificate — the only trust anchor for all ACME calls. */
  rootPem: string;
  log?: (msg: string) => void;
}

export class AcmeError extends Error {
  constructor(message: string, readonly status?: number, readonly body?: string) {
    super(message);
    this.name = 'AcmeError';
  }
}

/**
 * Minimal ACME client. One instance per process; the account key is supplied by
 * the caller (persisted by ensureTlsIdentity). All methods are async and throw
 * AcmeError on protocol failures.
 */
export class AcmeClient {
  private readonly agent: https.Agent;
  private nonce: string | null = null;

  constructor(private readonly opts: AcmeClientOptions) {
    this.agent = new https.Agent({ ca: [opts.rootPem] });
  }

  private log(msg: string): void {
    this.opts.log?.(msg);
  }

  /** Low-level request. `jose` selects the application/jose+json content type. */
  private req(method: 'GET' | 'HEAD' | 'POST', url: string, body?: Buffer, jose = false): Promise<{ status: number; headers: NodeJS.Dict<string | string[]>; body: string }> {
    return new Promise((resolve, reject) => {
      const r = https.request(
        url,
        { method, agent: this.agent, headers: jose && body ? { 'Content-Type': 'application/jose+json' } : {} },
        (res) => {
          let d = '';
          res.on('data', (c) => (d += c));
          res.on('end', () => resolve({ status: res.statusCode ?? 0, headers: res.headers, body: d }));
        },
      );
      r.on('error', reject);
      if (body) r.write(body);
      r.end();
    });
  }

  /** Signs a flattened JWS (RFC 7515 JSON serialization — the ACME request BODY). */
  private signJws(privateKey: crypto.KeyObject, protectedHeader: Record<string, unknown>, payloadObj: unknown, emptyPayload = false): string {
    const h = b64u(Buffer.from(JSON.stringify(protectedHeader)));
    // POST-as-GET (RFC 8555 §7.3.1) uses the EMPTY payload "" — not "{}".
    const p = emptyPayload ? '' : b64u(Buffer.from(JSON.stringify(payloadObj)));
    const derSig = crypto.sign('sha256', Buffer.from(`${h}.${p}`), privateKey);
    return JSON.stringify({ protected: h, payload: p, signature: b64u(derToRawSig(derSig)) });
  }

  /** Fetches a fresh nonce via HEAD on the directory's newNonce URL. */
  private async getNonce(newNonceUrl: string): Promise<string> {
    const r = await this.req('HEAD', newNonceUrl);
    const n = r.headers['replay-nonce'];
    if (typeof n !== 'string' || !n) throw new AcmeError(`no Replay-Nonce from HEAD ${newNonceUrl}`);
    return n;
  }

  /**
   * POSTs a JWS, refreshing the nonce once on a badNonce/badNonce error.
   * Returns the parsed JSON body (or raw text when not JSON).
   */
  private async postJws(
    privateKey: crypto.KeyObject,
    url: string,
    protectedHeader: Record<string, unknown>,
    payloadObj: unknown,
    emptyPayload = false,
  ): Promise<{ status: number; headers: NodeJS.Dict<string | string[]>; json: any; raw: string }> {
    for (let attempt = 0; attempt < 2; attempt++) {
      if (!this.nonce) throw new AcmeError('no nonce available — call fetchDirectory() first');
      // step-ca's validateJWS middleware REQUIRES the `url` member in EVERY JWS
      // protected header (RFC 8555 §6.4), including POST-as-GET reads — callers
      // that omit it get a generic "malformed" error, so enforce it here.
      const prot = { ...protectedHeader, nonce: this.nonce, url };
      const body = Buffer.from(this.signJws(privateKey, prot, payloadObj, emptyPayload));
      const r = await this.req('POST', url, body, true);
      const fresh = r.headers['replay-nonce'];
      if (typeof fresh === 'string' && fresh) this.nonce = fresh;
      let json: any;
      try { json = JSON.parse(r.body); } catch { json = null; }
      // badNonce → refresh and retry once.
      if ((r.status === 400 || r.status === 401) && attempt === 0 && /badNonce|expiredNonce/i.test(r.body)) {
        this.nonce = null;
        continue;
      }
      return { status: r.status, headers: r.headers, json, raw: r.body };
    }
    throw new AcmeError('unreachable');
  }

  /** Fetches the directory and primes a nonce. */
  async fetchDirectory(): Promise<AcmeDirectory> {
    const r = await this.req('GET', this.opts.directoryUrl);
    if (r.status !== 200) throw new AcmeError(`directory fetch failed: ${r.status} ${r.body.slice(0, 200)}`, r.status, r.body);
    const dir = JSON.parse(r.body) as AcmeDirectory;
    this.nonce = typeof r.headers['replay-nonce'] === 'string' ? (r.headers['replay-nonce'] as string) : await this.getNonce(dir.newNonce);
    return dir;
  }

  /** Creates (or re-uses via onlyReturnExisting) an account. Returns the account URL. */
  async ensureAccount(accountKey: crypto.KeyObject): Promise<string> {
    // RFC 8555 §7.4 — the JWK MUST be the PUBLIC key. Exporting the private
    // KeyObject as JWK would leak the `d` scalar, and step-ca rejects such a
    // request with a generic "malformed" error.
    const jwk = crypto.createPublicKey(accountKey).export({ format: 'jwk' }) as Record<string, unknown>;
    const dir = await this.fetchDirectory();
    const r = await this.postJws(
      accountKey,
      dir.newAccount,
      { alg: 'ES256', url: dir.newAccount, jwk },
      { termsOfServiceAgreed: true, contact: [] },
    );
    if (r.status !== 201 && r.status !== 200) throw new AcmeError(`newAccount failed: ${r.status} ${r.raw.slice(0, 300)}`, r.status, r.raw);
    const loc = r.headers.location;
    return typeof loc === 'string' ? loc : (r.json?.account as string);
  }

  /** Creates an order for the given dns identifiers. Returns the canonical order. */
  async newOrder(accountKey: crypto.KeyObject, accountUrl: string, identifiers: string[]): Promise<AcmeOrder> {
    const dir = await this.fetchDirectory();
    const r = await this.postJws(
      accountKey,
      dir.newOrder,
      { alg: 'ES256', url: dir.newOrder, kid: accountUrl },
      { identifiers: identifiers.map((value) => ({ type: 'dns', value })) },
    );
    if (r.status !== 201) throw new AcmeError(`newOrder failed: ${r.status} ${r.raw.slice(0, 300)}`, r.status, r.raw);
    const order = r.json as AcmeOrder;
    const loc = r.headers.location;
    if (typeof loc === 'string') order.finalize = loc.replace(/\/$/, '') + '/finalize';
    return order;
  }

  /** POST-as-GET read of an authenticated resource (JSON). */
  async postAsGet(accountKey: crypto.KeyObject, accountUrl: string, url: string): Promise<any> {
    const r = await this.postJws(accountKey, url, { alg: 'ES256', kid: accountUrl }, {}, true);
    if (r.status !== 200) throw new AcmeError(`POST-as-GET ${url} failed: ${r.status} ${r.raw.slice(0, 300)}`, r.status, r.raw);
    return r.json;
  }

  /** POST-as-GET read returning the RAW body (certificate downloads are PEM, not JSON). */
  private async postAsGetRaw(accountKey: crypto.KeyObject, accountUrl: string, url: string): Promise<string> {
    const r = await this.postJws(accountKey, url, { alg: 'ES256', kid: accountUrl }, {}, true);
    if (r.status !== 200) throw new AcmeError(`POST-as-GET ${url} failed: ${r.status} ${r.raw.slice(0, 300)}`, r.status, r.raw);
    return r.raw;
  }

  /**
   * Runs the full http-01 validation for every authorization in the order.
   * `setChallenge(token)` must make `<token>` retrievable at
   * /.well-known/acme-challenge/<token> on port 80 (serving keyAuth);
   * `clearChallenge()` is called when done. Polls each authz until valid,
   * honoring Retry-After where present.
   */
  async validateHttp01(
    accountKey: crypto.KeyObject,
    accountUrl: string,
    order: AcmeOrder,
    jwkThumbprintValue: string,
    setChallenge: (token: string, keyAuth: string) => void,
    clearChallenge?: () => void,
  ): Promise<void> {
    try {
      for (const authzUrl of order.authorizations) {
        const authz = await this.postAsGet(accountKey, accountUrl, authzUrl);
        if (authz.status === 'valid') continue;
        const ch: AcmeChallenge | undefined = authz.challenges?.find((c: AcmeChallenge) => c.type === 'http-01');
        if (!ch) throw new AcmeError(`no http-01 challenge in ${authzUrl}: ${JSON.stringify(authz).slice(0, 300)}`);
        // RFC 8555 §8.1 — TOKEN FIRST: keyAuth = token . base64url(sha256(jwkThumbprint)).
        const keyAuth = `${ch.token}.${jwkThumbprintValue}`;
        setChallenge(ch.token, keyAuth);
        this.log(`serving http-01 challenge ${ch.token} for identifier`);
        // Trigger validation (empty payload).
        const cr = await this.postJws(accountKey, ch.url, { alg: 'ES256', kid: accountUrl }, {});
        if (cr.status !== 200) throw new AcmeError(`challenge POST failed: ${cr.status} ${cr.raw.slice(0, 300)}`, cr.status, cr.raw);
        // Poll the authorization until valid.
        for (let i = 0; i < 60; i++) {
          const pa = await this.postAsGet(accountKey, accountUrl, authzUrl);
          if (pa.status === 'valid') break;
          if (pa.status === 'invalid') {
            const detail = JSON.stringify(pa.challenges?.find((c: AcmeChallenge) => c.error)?.error ?? pa).slice(0, 400);
            throw new AcmeError(`authorization invalid for ${authz.identifier?.value}: ${detail}`);
          }
          await sleep(1000);
        }
        const final = await this.postAsGet(accountKey, accountUrl, authzUrl);
        if (final.status !== 'valid') throw new AcmeError(`authorization for ${authz.identifier?.value} did not become valid in time`);
      }
    } finally {
      clearChallenge?.();
    }
  }

  /**
   * Finalizes the order with a CSR derived EXACTLY from the order identifiers
   * (CN = first identifier, SANs = the rest — step-ca requires {CN} ∪ SAN ==
   * identifiers), polls until valid and downloads the certificate chain.
   * Returns the PEM chain (leaf + intermediates; NO root).
   */
  async finalizeAndDownload(accountKey: crypto.KeyObject, accountUrl: string, order: AcmeOrder, leafKey: crypto.KeyObject): Promise<string> {
    const ids = order.identifiers.map((i) => i.value);
    const csrDer = buildCsr(leafKey, ids[0], ids.slice(1));
    this.log(`finalizing order with CSR (CN=${ids[0]}, SANs=[${ids.slice(1).join(', ')}])`);
    let r = await this.postJws(accountKey, order.finalize, { alg: 'ES256', kid: accountUrl }, { csr: b64u(csrDer) });
    if (r.status !== 200 && r.status !== 201) throw new AcmeError(`finalize failed: ${r.status} ${r.raw.slice(0, 300)}`, r.status, r.raw);
    // Poll the order until valid.
    let o = r.json as AcmeOrder;
    for (let i = 0; i < 60 && o?.status !== 'valid'; i++) {
      await sleep(1000);
      o = await this.postAsGet(accountKey, accountUrl, order.finalize.replace(/\/finalize$/, ''));
    }
    if (!o || o.status !== 'valid' || !o.certificate) throw new AcmeError(`order did not reach valid: ${JSON.stringify(o).slice(0, 300)}`);
    const pem = await this.postAsGetRaw(accountKey, accountUrl, o.certificate);
    if (!/-----BEGIN CERTIFICATE-----/.test(pem)) throw new AcmeError('certificate download returned non-PEM');
    return pem;
  }

  /** Full enrollment: order → http-01 validate → finalize → chain PEM. */
  async enroll(
    accountKey: crypto.KeyObject,
    leafKey: crypto.KeyObject,
    identifiers: string[],
    setChallenge: (token: string, keyAuth: string) => void,
    clearChallenge?: () => void,
  ): Promise<string> {
    // Public-key JWK only (see ensureAccount) — the thumbprint is over crv/kty/x/y.
    const jwk = crypto.createPublicKey(accountKey).export({ format: 'jwk' }) as Record<string, unknown>;
    const thumbprint = jwkThumbprint(jwk);
    const accountUrl = await this.ensureAccount(accountKey);
    const order = await this.newOrder(accountKey, accountUrl, identifiers);
    await this.validateHttp01(accountKey, accountUrl, order, thumbprint, setChallenge, clearChallenge);
    return this.finalizeAndDownload(accountKey, accountUrl, order, leafKey);
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((res) => setTimeout(res, ms));
}
