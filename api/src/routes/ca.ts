import { Router, Response } from 'express';
import * as fs from 'fs';
import * as crypto from 'crypto';
import { db } from '../db';
import { caCertificates, wifiClientCerts } from '../db/schema';
import { eq } from 'drizzle-orm';
import { requireAuth, requirePermission } from '../auth/middleware';
import { getCaStatus, revokeCertificate } from '../ca/stepCaAdmin';
import { renewApiMtls } from '../ca/apiMtls';
import { enrollEapTlsClient, EnrollValidationError } from '../ca/enroll';
import { encryptKeyPem, decryptKeyPem } from '../ca/keyVault';
import { buildPkcs12 } from '../ca/pkcs12';
import { registerLeaf } from '../ca/registry';

/**
 * Certificate Authority management (the unm-ca service — step-ca).
 *
 *   GET  /ca/status      -> CA version + root fingerprint/expiry (public CA endpoints)
 *   GET  /ca/certificates-> issued leaves tracked in the ca_certificates registry
 *   POST /ca/revoke      -> passive revocation by serial (step-ca DB + local registry)
 *   POST /ca/renew       -> force a fresh leaf for ONE UNM identity ('api' | 'mcp')
 *
 * WiFi (EAP-TLS) client certificates — long-lived certs for 802.1X supplicants:
 *
 *   POST /ca/enroll                  -> issue one EAP-TLS client cert (keygen + sign via CA)
 *   GET  /ca/wifi-certs              -> list enrolled WiFi client certs (no keys)
 *   POST /ca/wifi-certs/:serial/revoke -> revoke one by serial (CA-first, then registry)
 *   GET  /ca/wifi-certs/:serial/download -> install bundle: PEM (default) or P12 (?format=p12)
 *   GET  /ca/root-bundle             -> the CA root PEM for client trust stores
 *   POST /ca/renew-intermediate      -> trigger an intermediate renewal in the CA container
 *
 * Reading requires `ca:read`; enrolling/revoking/downloading/renewing requires
 * `ca:manage`. The CA's signing keys live on a volume only the CA container
 * mounts — these routes never touch them; they read public endpoints and UNM's
 * own registry. WiFi private keys are stored AES-256-GCM encrypted (keyVault)
 * and decrypted ONLY for the download route.
 */

const ROOT_PEM_PATH = '/data/ca/root_ca.crt';

const router = Router();

// GET /ca/status - CA health + identity (root fingerprint/expiry, version).
router.get(
  '/ca/status',
  requireAuth,
  requirePermission('ca:read'),
  async (_req, res: Response) => {
    try {
      const status = await getCaStatus();
      res.status(200).json({ status });
    } catch (err) {
      // CA container down / not yet bootstrapped — report as unavailable rather
      // than a 500 so the UI can show a "CA offline" state.
      const e = err as { message?: string };
      res.status(503).json({ error: `Certificate authority unavailable: ${e.message ?? 'unknown error'}` });
    }
  }
);

// GET /ca/certificates - issued leaves from the local registry (see schema.ts).
router.get(
  '/ca/certificates',
  requireAuth,
  requirePermission('ca:read'),
  async (_req, res: Response) => {
    try {
      const rows = await db.query.caCertificates.findMany();
      res.status(200).json({ certificates: rows });
    } catch (err) {
      const e = err as { status?: number; message?: string };
      res.status(e.status ?? 500).json({ error: e.message ?? 'Failed to list CA certificates' });
    }
  }
);

// POST /ca/revoke - passively revoke a leaf by serial (hex, no 0x prefix).
router.post(
  '/ca/revoke',
  requireAuth,
  requirePermission('ca:manage'),
  async (req, res: Response) => {
    const body = (req.body ?? {}) as Record<string, unknown>;
    const serial = typeof body.serial === 'string' ? body.serial.trim() : '';
    if (!/^[0-9a-fA-F]{1,64}$/.test(serial)) {
      res.status(400).json({ error: '"serial" must be a hex string (the certificate serial number)' });
      return;
    }

    // 1. Ask step-ca to mark it revoked in its own DB (authoritative for the CA).
    let caResult: { status: number; body: unknown } | null = null;
    try {
      caResult = await revokeCertificate(serial);
    } catch (err) {
      const e = err as { message?: string };
      res.status(502).json({ error: `CA unreachable — revocation NOT applied: ${e.message ?? 'unknown error'}` });
      return;
    }

    // 2. Mirror the state in UNM's registry (drives UI badges + notifications).
    const rows = await db.query.caCertificates.findMany({ where: eq(caCertificates.serial, serial) });
    for (const row of rows) {
      if (row.status !== 'revoked') {
        await db.update(caCertificates).set({ status: 'revoked', revokedAt: new Date().toISOString() }).where(eq(caCertificates.id, row.id));
      }
    }

    res.status(200).json({ serial, caStatus: caResult.status, caResponse: caResult.body });
  }
);

// POST /ca/renew - force a FRESH leaf for one of UNM's own non-plugin mTLS
// identities. Body: { subject: 'api' | 'mcp' }. Plugins are renewed through
// POST /plugins/:id/tls/renew (they run their own enrollment). The old leaf
// stays valid until its expiry — this is rotation, not revocation. Gated on
// ca:manage like revocation.
router.post(
  '/ca/renew',
  requireAuth,
  requirePermission('ca:manage'),
  async (req, res: Response) => {
    const body = (req.body ?? {}) as Record<string, unknown>;
    const subject = typeof body.subject === 'string' ? body.subject.trim() : '';
    if (!['api', 'mcp'].includes(subject)) {
      res.status(400).json({ error: '"subject" must be "api" or "mcp" (plugins use POST /plugins/:id/tls/renew)' });
      return;
    }

    try {
      if (subject === 'api') {
        const result = await renewApiMtls();
        res.status(result.ok ? 200 : 502).json({ subject, ...result });
        return;
      }

      // mcp: broker through the MCP server's own /tls/renew (it owns its ACME
      // account + dispatcher rebuild). Reached over plain HTTP — it's a local
      // compose service and this is an operational action.
      const debugKey = process.env.MCP_DEBUG_KEY ?? '';
      if (!debugKey) {
        res.status(503).json({ error: 'MCP_DEBUG_KEY not configured on the API — cannot reach the MCP renew endpoint' });
        return;
      }
      const mcpBase = (process.env.UNM_MCP_URL ?? 'http://mcp:3901').replace(/\/+$/, '');
      const r = await fetch(`${mcpBase}/tls/renew`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${debugKey}` },
        signal: AbortSignal.timeout(60_000),
      });
      const data = (await r.json().catch(() => ({}))) as Record<string, unknown>;
      res.status(r.ok ? 200 : 502).json({ subject, ...(data as object) });
    } catch (err) {
      const e = err as { message?: string };
      console.warn(`[ca] renew for "${subject}" failed:`, e.message);
      res.status(502).json({ error: `Re-enrollment of "${subject}" failed: ${e.message ?? 'unknown error'}` });
    }
  }
);

// POST /ca/enroll - issue ONE WiFi (EAP-TLS) client certificate. Body:
// { name, cn?, organization?, organizationalUnit?, sans?: string[], keyType?, days? }.
// The private key is generated here, stored ENCRYPTED in wifi_client_certs and
// returned to the caller ONCE in the response (the UI offers an immediate
// download); afterwards it is only reachable via GET /ca/wifi-certs/:serial/
// download. Validation errors → 400; CA failures → 502; duplicate name → 409.
router.post(
  '/ca/enroll',
  requireAuth,
  requirePermission('ca:manage'),
  async (req, res: Response) => {
    const body = (req.body ?? {}) as Record<string, unknown>;

    // Duplicate-name check BEFORE signing — otherwise a duplicate request would
    // burn a CA signature and leave an untracked leaf in the CA's own DB.
    try {
      const existing = await db.query.wifiClientCerts.findMany({ where: eq(wifiClientCerts.name, String(body.name)) });
      if (existing.length > 0) {
        res.status(409).json({ error: `A WiFi client certificate named "${String(body.name)}" already exists` });
        return;
      }
    } catch (e) {
      const err = e as { message?: string };
      console.warn('[ca] duplicate-name precheck failed:', err.message);
      res.status(500).json({ error: 'Failed to check for an existing certificate with that name' });
      return;
    }

    try {
      const enrolled = await enrollEapTlsClient({
        name: body.name as string,
        cn: typeof body.cn === 'string' ? body.cn : undefined,
        organization: typeof body.organization === 'string' ? body.organization : undefined,
        organizationalUnit: typeof body.organizationalUnit === 'string' ? body.organizationalUnit : undefined,
        sans: Array.isArray(body.sans) ? (body.sans as string[]) : undefined,
        keyType: typeof body.keyType === 'string' ? (body.keyType as never) : undefined,
        days: typeof body.days === 'number' ? body.days : undefined,
      });

      const now = new Date().toISOString();
      try {
        await db.insert(wifiClientCerts).values({
          id: crypto.randomUUID(),
          name: String(body.name), // unique enrollment label (CN defaults to it but may differ)
          cn: enrolled.subject,
          organization: typeof body.organization === 'string' ? body.organization.trim() : '',
          organizationalUnit: typeof body.organizationalUnit === 'string' ? body.organizationalUnit.trim() : '',
          sansJson: JSON.stringify(Array.isArray(body.sans) ? (body.sans as string[]) : []),
          keyType: typeof body.keyType === 'string' ? body.keyType : 'ec-p256',
          serial: enrolled.serial,
          issuer: 'UNM CA Intermediate CA',
          notBefore: enrolled.notBefore,
          notAfter: enrolled.notAfter,
          status: 'issued',
          keyEncrypted: encryptKeyPem(enrolled.keyPem),
          certPem: enrolled.chainPem,
          createdAt: now,
        });
      } catch (e) {
        const err = e as { code?: string; message?: string };
        if (err.code === '23505') {
          // Lost a race with a concurrent enrollment of the same name — the CA
          // already signed a leaf we cannot track. Revoke it so nothing
          // untracked stays valid, then report the conflict.
          console.warn(`[ca] duplicate-name race for "${String(body.name)}" (serial ${enrolled.serial}) — revoking the orphaned leaf`);
          try { await revokeCertificate(enrolled.serial); } catch { /* CA may be unreachable; log only */ }
          res.status(409).json({ error: `A WiFi client certificate named "${String(body.name)}" already exists` });
          return;
        }
        // Never echo the raw DB error — it embeds every SQL parameter, i.e.
        // the encrypted private key and the full cert chain.
        console.error('[ca] failed to store the enrolled WiFi certificate:', err.message);
        res.status(500).json({ error: 'The certificate was issued but could not be stored — check the API logs' });
        return;
      }

      // Mirror into the unified leaf registry (kind='wifi') so revocation +
      // expiry tooling see it alongside mTLS leaves.
      await registerLeaf({
        serial: enrolled.serial,
        sans: [enrolled.subject],
        issuer: 'UNM CA Intermediate CA',
        notBefore: enrolled.notBefore,
        notAfter: enrolled.notAfter,
        subject: enrolled.subject,
        source: 'plugin',
        kind: 'wifi',
      });

      res.status(201).json({
        serial: enrolled.serial,
        cn: enrolled.subject,
        notBefore: enrolled.notBefore,
        notAfter: enrolled.notAfter,
        ...(enrolled.clamped !== undefined ? { clamped: enrolled.clamped } : {}),
        ...(enrolled.clampReason !== undefined ? { clampReason: enrolled.clampReason } : {}),
      });
    } catch (err) {
      if (err instanceof EnrollValidationError) {
        res.status(400).json({ error: err.message });
        return;
      }
      const e = err as { message?: string };
      console.warn('[ca] EAP-TLS enrollment failed:', e.message);
      // Only CA HTTP errors ("CA /1.0/…") are safe to surface verbatim — DB and
      // internal errors embed SQL parameters (key material) in their messages.
      const detail = /^CA \//.test(e.message ?? '') ? `: ${e.message}` : '';
      res.status(502).json({ error: `Certificate authority sign request failed${detail}` });
    }
  }
);

// GET /ca/wifi-certs - list enrolled WiFi client certs (metadata only — the
// private key is NEVER returned here; use the download route for that).
router.get(
  '/ca/wifi-certs',
  requireAuth,
  requirePermission('ca:read'),
  async (_req, res: Response) => {
    try {
      const rows = await db.query.wifiClientCerts.findMany();
      const certificates = rows.map((r) => ({
        name: r.name,
        cn: r.cn,
        organization: r.organization,
        organizationalUnit: r.organizationalUnit,
        sans: JSON.parse(r.sansJson || '[]') as string[],
        keyType: r.keyType,
        serial: r.serial,
        issuer: r.issuer,
        notBefore: r.notBefore,
        notAfter: r.notAfter,
        status: r.status,
        revokedAt: r.revokedAt,
        createdAt: r.createdAt,
      }));
      res.status(200).json({ certificates });
    } catch (err) {
      const e = err as { message?: string };
      res.status(500).json({ error: e.message ?? 'Failed to list WiFi client certificates' });
    }
  }
);

// POST /ca/wifi-certs/:serial/revoke - revoke one WiFi client cert by serial.
// CA-first (step-ca marks it revoked in its own DB), then mirror into both the
// unified registry and wifi_client_certs. Idempotent: an already-revoked row is
// a no-op 200; unknown serial → 404; CA unreachable → 502 (NOT applied).
router.post(
  '/ca/wifi-certs/:serial/revoke',
  requireAuth,
  requirePermission('ca:manage'),
  async (req, res: Response) => {
    const serial = String(req.params.serial ?? '').trim();
    if (!/^[0-9a-fA-F]{1,64}$/.test(serial)) {
      res.status(400).json({ error: 'serial must be a hex string' });
      return;
    }

    const rows = await db.query.wifiClientCerts.findMany({ where: eq(wifiClientCerts.serial, serial) });
    if (rows.length === 0) {
      res.status(404).json({ error: `No WiFi client certificate with serial ${serial}` });
      return;
    }

    let caResult: { status: number; body: unknown } | null = null;
    try {
      caResult = await revokeCertificate(serial);
    } catch (err) {
      const e = err as { message?: string };
      res.status(502).json({ error: `CA unreachable — revocation NOT applied: ${e.message ?? 'unknown error'}` });
      return;
    }

    const now = new Date().toISOString();
    for (const row of rows) {
      if (row.status !== 'revoked') {
        await db.update(wifiClientCerts).set({ status: 'revoked', revokedAt: now }).where(eq(wifiClientCerts.id, row.id));
      }
    }
    const regRows = await db.query.caCertificates.findMany({ where: eq(caCertificates.serial, serial) });
    for (const row of regRows) {
      if (row.status !== 'revoked') {
        await db.update(caCertificates).set({ status: 'revoked', revokedAt: now }).where(eq(caCertificates.id, row.id));
      }
    }

    res.status(200).json({ serial, caStatus: caResult.status });
  }
);

// GET /ca/wifi-certs/:serial/download - the full install bundle for a supplicant.
// Default (or ?format=pem): cert chain + private key as one PEM file.
// ?format=p12: PKCS#12 (.p12) — what Windows/Android/iOS/macOS import dialogs
// expect; JSON response { p12Base64, password } with a freshly generated random
// import password (returned ONCE). Revoked certs → 409 (the key is still stored
// but must not be handed out). The decrypted key never touches logs.
router.get(
  '/ca/wifi-certs/:serial/download',
  requireAuth,
  requirePermission('ca:manage'),
  async (req, res: Response) => {
    const serial = String(req.params.serial ?? '').trim();
    if (!/^[0-9a-fA-F]{1,64}$/.test(serial)) {
      res.status(400).json({ error: 'serial must be a hex string' });
      return;
    }

    const format = String(req.query.format ?? 'pem').toLowerCase();
    if (format !== 'pem' && format !== 'p12') {
      res.status(400).json({ error: '"format" must be "pem" or "p12"' });
      return;
    }

    const rows = await db.query.wifiClientCerts.findMany({ where: eq(wifiClientCerts.serial, serial) });
    if (rows.length === 0) {
      res.status(404).json({ error: `No WiFi client certificate with serial ${serial}` });
      return;
    }
    const row = rows[0];
    if (row.status === 'revoked') {
      res.status(409).json({ error: 'This certificate has been revoked — download is disabled' });
      return;
    }

    let keyPem: string;
    try {
      keyPem = decryptKeyPem(row.keyEncrypted);
    } catch (err) {
      const e = err as { message?: string };
      res.status(500).json({ error: `Failed to decrypt the stored private key: ${e.message ?? 'unknown error'}` });
      return;
    }

    if (format === 'p12') {
      try {
        const bundle = await buildPkcs12(row.certPem, keyPem);
        res.status(200).json({ format: 'p12', p12Base64: bundle.p12Base64, password: bundle.password });
      } catch (err) {
        const e = err as { message?: string };
        console.warn('[ca] P12 build failed:', e.message);
        res.status(500).json({ error: `Failed to build the PKCS#12 bundle: ${e.message ?? 'unknown error'}` });
      }
      return;
    }

    const bundle = `${row.certPem.replace(/\n+$/, '')}\n${keyPem.replace(/\n+$/, '')}\n`;
    res.setHeader('Content-Type', 'application/x-pem-file');
    res.setHeader('Content-Disposition', `attachment; filename="${row.cn}-eaptls.pem"`);
    res.status(200).send(bundle);
  }
);

// GET /ca/root-bundle - the CA root PEM (for client trust stores / RADIUS servers).
router.get(
  '/ca/root-bundle',
  requireAuth,
  requirePermission('ca:read'),
  async (_req, res: Response) => {
    try {
      const pem = fs.readFileSync(ROOT_PEM_PATH, 'utf8');
      res.setHeader('Content-Type', 'application/x-pem-file');
      res.setHeader('Content-Disposition', 'attachment; filename="unm-ca-root.pem"');
      res.status(200).send(pem);
    } catch (err) {
      const e = err as { message?: string };
      res.status(503).json({ error: `Root certificate not available: ${e.message ?? 'unknown error'}` });
    }
  }
);

// POST /ca/renew-intermediate - ask the CA container to renew its intermediate
// cert NOW (same key, new validity window clamped to the root expiry − 7d). The
// entrypoint's watch loop picks up the trigger file and does the work; we poll
// getCaStatus() for the new notAfter. This is the manual counterpart of the
// automatic <90-day renewal — use it after a root rekey or to force rotation.
router.post(
  '/ca/renew-intermediate',
  requireAuth,
  requirePermission('ca:manage'),
  async (_req, res: Response) => {
    const triggerPath = '/data/ca/renew-trigger';
    try {
      fs.writeFileSync(triggerPath, new Date().toISOString(), 'utf8');
    } catch (err) {
      const e = err as { message?: string };
      res.status(500).json({ error: `Could not write the renewal trigger file: ${e.message ?? 'unknown error'}` });
      return;
    }

    // Poll for the CA to report a NEW intermediate expiry (the entrypoint SIGHUPs
    // step-ca after replacing the cert, so /1.0/intermediates.pem updates fast).
    const before = await getCaStatus().catch(() => null);
    const deadline = Date.now() + 90_000;
    while (Date.now() < deadline) {
      await new Promise((r) => setTimeout(r, 2_000));
      try {
        const status = await getCaStatus();
        if (status.intermediateNotAfter && before?.intermediateNotAfter && status.intermediateNotAfter !== before.intermediateNotAfter) {
          res.status(200).json({ renewed: true, intermediateNotAfter: status.intermediateNotAfter });
          return;
        }
      } catch {
        /* CA briefly unreachable during reload — keep polling */
      }
    }

    // No change within the window. The trigger file may still be pending (the
    // entrypoint retries on a cooldown) or the renewal failed — surface both.
    res.status(504).json({
      error: 'The CA did not report a renewed intermediate within 90s — check the unm-ca container logs',
      triggerPending: fs.existsSync(triggerPath),
    });
  }
);

export default router;
