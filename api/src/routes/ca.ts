import { Router, Response } from 'express';
import * as fs from 'fs';
import * as crypto from 'crypto';
import { db, pgErrorCode } from '../db';
import { caCertificates, clientCertTemplates, wifiClientCerts } from '../db/schema';
import { eq } from 'drizzle-orm';
import { requireAuth, requirePermission } from '../auth/middleware';
import { getCaStatus, revokeCertificate } from '../ca/stepCaAdmin';
import { renewApiMtls } from '../ca/apiMtls';
import { decryptKeyPem } from '../ca/keyVault';
import { buildPkcs12 } from '../ca/pkcs12';
import { recordRevokedSerial } from '../ca/mutations';

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
 *   GET  /ca/wifi-certs              -> list enrolled WiFi client certs (no keys)
 *   GET  /ca/wifi-certs/:serial/download -> install bundle: PEM (default) or P12 (?format=p12)
 *   GET  /ca/root-bundle             -> the CA root PEM for client trust stores
 *   POST /ca/renew-intermediate      -> trigger an intermediate renewal in the CA container
 *
 * Client-cert templates (reusable enrollment presets — pure metadata, NOT plan-gated):
 *
 *   GET    /ca/client-cert-templates        -> list all templates
 *   POST   /ca/client-cert-templates        -> create one
 *   PATCH  /ca/client-cert-templates/:id    -> update fields (partial ok)
 *   DELETE /ca/client-cert-templates/:id    -> remove one
 *
 * Enrolling and revoking WiFi certs is PLAN-GATED (no direct mutation routes):
 * the webapp creates system plans via POST /plans/system with intentActionId
 * ca.client-cert.enroll / ca.client-cert.revoke / ca.client-cert.bulk-revoke, executed
 * through the 2FA-gated plan workflow. The executor runs the shared functions in
 * api/src/ca/mutations.ts locally — every cert change is auditable, retryable,
 * schedulable and automatable.
 *
 * Reading requires `ca:read`; downloading/renewing (and creating/executing the
 * WiFi-cert plans) require `ca:manage`. The CA's signing keys live on a volume
 * only the CA container mounts — these routes never touch them; they read public
 * endpoints and UNM's own registry. WiFi private keys are stored AES-256-GCM
 * encrypted (keyVault) and decrypted ONLY for the download route.
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

    // 3. Per-auth enforcement for WiFi EAP-TLS clients (FreeRADIUS revocation check).
    const subject = rows[0]?.subject ?? '';
    await recordRevokedSerial(serial, subject);

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

// NOTE: there is deliberately NO direct POST /ca/enroll route. Enrolling a WiFi
// (EAP-TLS) client certificate is plan-gated like every other RADIUS/CA mutation:
// the webapp creates a system plan via POST /plans/system with intentActionId
// ca.client-cert.enroll and executes it through the 2FA-gated plan workflow. The
// executor runs enrollWifiCert() from api/src/ca/mutations.ts locally; the new
// serial lands in the step result (steps[0].result.serial) for the UI to pick up
// and offer the install download.

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

// NOTE: there is deliberately NO direct revoke route (single or bulk) for WiFi
// client certs. Revocation is plan-gated like every other RADIUS/CA mutation:
// the webapp creates a system plan via POST /plans/system with intentActionId
// ca.client-cert.revoke (one serial per step input) or ca.client-cert.bulk-revoke
// ({ serials } in one step), executed through the 2FA-gated plan workflow. The
// executor runs revokeWifiCert()/revokeWifiCerts() from api/src/ca/mutations.ts
// locally; per-serial outcomes land in each step's result.

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

/**
 * Client-cert template CRUD — reusable enrollment presets for EAP-TLS client
 * certificates. Templates are pure metadata: creating/updating/deleting them
 * never touches the CA and is NOT plan-gated (no cert changes, no 2FA needed).
 * USING a template (enrollment) goes through POST /plans/system with
 * ca.client-cert.enroll like every other cert mutation.
 *
 *   GET    /ca/client-cert-templates        -> list all templates
 *   POST   /ca/client-cert-templates        -> create one (201)
 *   PATCH  /ca/client-cert-templates/:id    -> update fields (partial ok)
 *   DELETE /ca/client-cert-templates/:id    -> remove (204)
 */

const TEMPLATE_KEY_TYPES = ['ec-p256', 'ec-p384', 'rsa-2048', 'rsa-3072', 'rsa-4096'];
const TEMPLATE_NAME_RE = /^[A-Za-z0-9._-]{1,64}$/;

/** Validates one template payload (create or partial update). Returns the normalized fields. */
function validateTemplateInput(body: Record<string, unknown>, partial: boolean): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  if (!partial || body.name !== undefined) {
    const name = typeof body.name === 'string' ? body.name.trim() : '';
    if (name.length < 1 || name.length > 64) throw Object.assign(new Error('"name" must be 1–64 characters'), { status: 400 });
    out.name = name;
  }
  for (const field of ['cn', 'organization', 'organizationalUnit'] as const) {
    if (body[field] === undefined) continue;
    if (typeof body[field] !== 'string' || body[field].trim().length > 64) {
      throw Object.assign(new Error(`"${field}" must be a string of at most 64 characters`), { status: 400 });
    }
    out[field] = (body[field] as string).trim();
  }
  if (body.sans !== undefined) {
    if (!Array.isArray(body.sans)) throw Object.assign(new Error('"sans" must be an array of DNS names'), { status: 400 });
    for (const s of body.sans as unknown[]) {
      if (typeof s !== 'string' || !TEMPLATE_NAME_RE.test(s)) {
        throw Object.assign(new Error(`each SAN must be 1–64 chars of [A-Za-z0-9._-] (got ${JSON.stringify(s)})`), { status: 400 });
      }
    }
    out.sansJson = JSON.stringify(Array.from(new Set(body.sans as string[])));
  }
  if (body.keyType !== undefined) {
    if (!TEMPLATE_KEY_TYPES.includes(String(body.keyType))) {
      throw Object.assign(new Error(`"keyType" must be one of ${TEMPLATE_KEY_TYPES.join(', ')}`), { status: 400 });
    }
    out.keyType = String(body.keyType);
  }
  if (body.days !== undefined) {
    if (body.days === null || body.days === '') {
      out.days = null; // explicit "use the CA default"
    } else {
      const d = Number(body.days);
      if (!Number.isInteger(d) || d < 1 || d > 3650) throw Object.assign(new Error('"days" must be an integer between 1 and 3650 (or null for the CA default)'), { status: 400 });
      out.days = d;
    }
  }
  if (!partial && !out.name) throw Object.assign(new Error('"name" is required'), { status: 400 });
  return out;
}

function serializeTemplate(r: (typeof clientCertTemplates.$inferSelect)): Record<string, unknown> {
  return {
    id: r.id,
    name: r.name,
    cn: r.cn,
    organization: r.organization,
    organizationalUnit: r.organizationalUnit,
    sans: JSON.parse(r.sansJson || '[]') as string[],
    keyType: r.keyType,
    days: r.days,
    createdAt: r.createdAt,
    updatedAt: r.updatedAt,
  };
}

// GET /ca/client-cert-templates - list all enrollment presets.
router.get(
  '/ca/client-cert-templates',
  requireAuth,
  requirePermission('ca:read'),
  async (_req, res: Response) => {
    try {
      const rows = await db.query.clientCertTemplates.findMany();
      res.status(200).json({ templates: rows.map(serializeTemplate) });
    } catch (err) {
      const e = err as { message?: string };
      res.status(500).json({ error: e.message ?? 'Failed to list client-cert templates' });
    }
  }
);

// POST /ca/client-cert-templates - create one enrollment preset.
router.post(
  '/ca/client-cert-templates',
  requireAuth,
  requirePermission('ca:manage'),
  async (req, res: Response) => {
    try {
      const fields = validateTemplateInput((req.body ?? {}) as Record<string, unknown>, false);
      if (!fields.keyType) fields.keyType = 'ec-p256'; // default key type
      if (fields.days === undefined) fields.days = null; // CA default validity
      const now = new Date().toISOString();
      const id = crypto.randomUUID();
      try {
        await db.insert(clientCertTemplates).values({
          id,
          name: String(fields.name),
          cn: typeof fields.cn === 'string' ? fields.cn : '',
          organization: typeof fields.organization === 'string' ? fields.organization : '',
          organizationalUnit: typeof fields.organizationalUnit === 'string' ? fields.organizationalUnit : '',
          sansJson: typeof fields.sansJson === 'string' ? fields.sansJson : '[]',
          keyType: String(fields.keyType),
          days: typeof fields.days === 'number' ? fields.days : null,
          createdAt: now,
          updatedAt: now,
        });
      } catch (e) {
        if (pgErrorCode(e) === '23505') {
          res.status(409).json({ error: `A client-cert template named "${String(fields.name)}" already exists` });
          return;
        }
        throw e;
      }
      const row = (await db.query.clientCertTemplates.findFirst({ where: eq(clientCertTemplates.id, id) }))!;
      res.status(201).json(serializeTemplate(row));
    } catch (err) {
      const e = err as { status?: number; message?: string };
      res.status(e.status ?? 500).json({ error: e.message ?? 'Failed to create client-cert template' });
    }
  }
);

// PATCH /ca/client-cert-templates/:id - update one preset (partial ok).
router.patch(
  '/ca/client-cert-templates/:id',
  requireAuth,
  requirePermission('ca:manage'),
  async (req, res: Response) => {
    const id = String(req.params.id ?? '');
    try {
      const fields = validateTemplateInput((req.body ?? {}) as Record<string, unknown>, true);
      if (Object.keys(fields).length === 0) throw Object.assign(new Error('No valid fields to update'), { status: 400 });
      const existing = await db.query.clientCertTemplates.findFirst({ where: eq(clientCertTemplates.id, id) });
      if (!existing) {
        res.status(404).json({ error: `No client-cert template with id ${id}` });
        return;
      }
      // Name uniqueness across OTHER rows (23505 would also fire for self-equal).
      if (fields.name && fields.name !== existing.name) {
        const clash = await db.query.clientCertTemplates.findFirst({ where: eq(clientCertTemplates.name, String(fields.name)) });
        if (clash && clash.id !== id) {
          res.status(409).json({ error: `A client-cert template named "${String(fields.name)}" already exists` });
          return;
        }
      }
      const set: Record<string, unknown> = { ...fields, updatedAt: new Date().toISOString() };
      await db.update(clientCertTemplates)
        .set(set as Partial<typeof clientCertTemplates.$inferInsert>)
        .where(eq(clientCertTemplates.id, id));
      const row = (await db.query.clientCertTemplates.findFirst({ where: eq(clientCertTemplates.id, id) }))!;
      res.status(200).json(serializeTemplate(row));
    } catch (err) {
      const e = err as { status?: number; message?: string };
      res.status(e.status ?? 500).json({ error: e.message ?? 'Failed to update client-cert template' });
    }
  }
);

// DELETE /ca/client-cert-templates/:id - remove one preset (204).
router.delete(
  '/ca/client-cert-templates/:id',
  requireAuth,
  requirePermission('ca:manage'),
  async (req, res: Response) => {
    const id = String(req.params.id ?? '');
    try {
      const result = await db.delete(clientCertTemplates).where(eq(clientCertTemplates.id, id)).returning({ id: clientCertTemplates.id });
      if (result.length === 0) {
        res.status(404).json({ error: `No client-cert template with id ${id}` });
        return;
      }
      res.status(204).send();
    } catch (err) {
      const e = err as { message?: string };
      res.status(500).json({ error: e.message ?? 'Failed to delete client-cert template' });
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
