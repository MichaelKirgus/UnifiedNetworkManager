/**
 * mcpMtls — the MCP server's OWN mTLS identity (Stage 2).
 *
 * The MCP server is a CLIENT-only mTLS participant: it presents its CA-signed
 * leaf to the API's :8443 listener and to mTLS-live plugins, but never serves
 * TLS itself. Enrollment reuses the SDK's shared client path
 * (startClientMtls → ensureTlsIdentity, ACME http-01) — the same primitive
 * every plugin and the API use; only two things are MCP-specific:
 *   - Trust bundle: built LOCALLY from the CA config volume (mounted
 *     read-only: /data/ca/root_ca.crt) + step-ca's public intermediates
 *     endpoint. No HTTP round-trip through the API, no x-plugin-api-key.
 *   - Outbound transport: an undici Agent dispatcher for fetch() — Node's
 *     global fetch cannot present a client cert without one.
 *
 * Its identifier is 'mcp' (the compose service name; in the default
 * caAllowedDnsNames allow-list). The CA fetches http://mcp/.well-known/… on
 * port 80 — ensureTlsIdentity's transient challenge listener answers it for
 * the duration of enrollment only.
 *
 * Gated behind UNM_TLS=1 (same switch as the rest of the fleet). While
 * enrollment is pending or failing, callers fall back to plain HTTP against
 * :3000 — so a late-bootstrapping CA never breaks the MCP tools.
 */

import fs from 'fs';
import https from 'https';
import { Agent } from 'undici';
import type { Dispatcher } from 'undici';
import { startClientMtls, TlsIdentity } from '@unm/plugin-sdk';

const CA_BASE = process.env.UNM_CA_URL ?? 'https://unm-ca:9000';
const ROOT_PEM_PATH = '/data/ca/root_ca.crt';
const TLS_DIR = process.env.UNM_MCP_TLS_DIR ?? '/data/tls';
const IDENTIFIER = 'mcp';

/** True when the fleet-wide mTLS switch is on (same env as plugins/api). */
export function mtlsEnabled(): boolean {
  return process.env.UNM_TLS === '1';
}

/** The CA trust bundle, built locally: root from the shared config volume +
 *  intermediate(s) from step-ca's public endpoint. Same recipe as the API's
 *  getCaBundlePem() — MCP mounts the cfg volume read-only instead of asking
 *  the API to broker it (it has no x-plugin-api-key). */
async function localCaBundle(): Promise<string> {
  const rootPem = fs.readFileSync(ROOT_PEM_PATH, 'utf8');
  let intermediates = '';
  try {
    const interPem = await rawText(`${CA_BASE}/1.0/intermediates.pem`);
    if (interPem) intermediates = interPem.endsWith('\n') ? interPem : `${interPem}\n`;
  } catch {
    /* CA not ready — root alone still lets clients verify the ACME endpoint's chain */
  }
  return `${rootPem.trimEnd()}\n${intermediates}`;
}

/** GETs a CA endpoint and returns the raw response body as text (PEM endpoints). */
function rawText(url: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const req = https.get(url, (res) => {
      let data = '';
      res.on('data', (c) => (data += c));
      res.on('end', () => resolve(data));
    });
    req.on('error', reject);
  });
}

/** Builds the undici dispatcher from identity material (client cert + UNM root trust). */
function buildDispatcher(id: TlsIdentity): Agent {
  return new Agent({
    connect: { ca: id.caBundlePem, key: id.keyPem, cert: id.certChainPem, rejectUnauthorized: true },
  });
}

let dispatcher: Agent | null = null;
// Material the live dispatcher was built from — early renewal checks (the SDK
// clamps long delays to ~24.8d) come back with the SAME reused leaf and must
// NOT rebuild the Agent (that would discard pooled connections for no reason).
let loadedKeyPem: string | null = null;
let loadedCertPem: string | null = null;

const handle = mtlsEnabled()
  ? startClientMtls({
      identity: IDENTIFIER,
      identifiers: [IDENTIFIER],
      dir: TLS_DIR,
      fetchCaBundle: localCaBundle,
      log: (m) => console.error(`[unm-mcp][tls] ${m}`),
      onLive: (id) => {
        if (dispatcher && id.keyPem === loadedKeyPem && id.certChainPem === loadedCertPem) return;
        const next = buildDispatcher(id);
        dispatcher?.close();
        dispatcher = next;
        loadedKeyPem = id.keyPem;
        loadedCertPem = id.certChainPem;
      },
    })
  : null;

/** True once the MCP's own leaf is live (callers may then prefer https). */
export function mtlsLive(): boolean {
  return handle ? handle.live() : false;
}

/** The mTLS dispatcher for outbound fetch() — undefined until enrollment succeeds. */
export function apiDispatcher(): Dispatcher | undefined {
  return dispatcher ?? undefined;
}

/** Is this error a "wrong transport" failure (connection refused / TLS mismatch)? */
export function isTransportError(err: unknown): boolean {
  const e = err as { code?: string; cause?: { code?: string }; message?: string };
  if (!e) return false;
  const codes = [e.code, e.cause?.code].filter((c): c is string => typeof c === 'string');
  if (codes.includes('ECONNREFUSED') || codes.includes('ECONNRESET') || codes.includes('ETIMEDOUT')) return true;
  // Node/undici TLS-vs-plain mismatches surface as these:
  return /wrong version number|record layer failure|unexpected eof|tls handshake|EPROTO/i.test(e.message ?? '');
}
