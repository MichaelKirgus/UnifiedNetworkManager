import { Router, Response } from 'express';
import { db } from '../db';
import { caCertificates } from '../db/schema';
import { eq } from 'drizzle-orm';
import { requireAuth, requirePermission } from '../auth/middleware';
import { getCaStatus, revokeCertificate } from '../ca/stepCaAdmin';
import { renewApiMtls } from '../ca/apiMtls';

/**
 * Certificate Authority management (the unm-ca service — step-ca).
 *
 *   GET  /ca/status      -> CA version + root fingerprint/expiry (public CA endpoints)
 *   GET  /ca/certificates-> issued leaves tracked in the ca_certificates registry
 *   POST /ca/revoke      -> passive revocation by serial (step-ca DB + local registry)
 *   POST /ca/renew       -> force a fresh leaf for ONE UNM identity ('api' | 'mcp')
 *
 * Reading requires `ca:read`; revoking/renewing requires `ca:manage`. The CA's
 * signing keys live on a volume only the CA container mounts — these routes
 * never touch them; they read public endpoints and UNM's own registry.
 */

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

export default router;
