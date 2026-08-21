import express from 'express';
import cors from 'cors';
import { Bonjour } from 'bonjour-service';
import { encrypt, decrypt } from './crypto';
import { storeSecret, listSecrets, getSecret, deleteSecret, updateSecret } from './apiClient';
import { GENERATABLE_TYPES } from './keygen';

export const PLUGIN_UUID = '00000000-0000-4000-8000-000000000002';
export const PLUGIN_NAME = 'Secrets Provider (Device Credentials)';

/**
 * Multi-instance support: set `PLUGIN_INSTANCE_ID` (e.g. "site-a") to run several
 * instances of the same plugin type — each advertises a distinct identity
 * (`<uuid>:<instanceId>`) so the API registers them as separate plugins.
 * `PLUGIN_DISPLAY_NAME` optionally overrides the advertised name; without it,
 * the instance id is appended. Unset = single-instance behavior.
 */
const INSTANCE_ID = process.env.PLUGIN_INSTANCE_ID?.trim() ?? '';
export const EFFECTIVE_UUID = INSTANCE_ID ? `${PLUGIN_UUID}:${INSTANCE_ID}` : PLUGIN_UUID;
export const DISPLAY_NAME =
  process.env.PLUGIN_DISPLAY_NAME?.trim() || (INSTANCE_ID ? `${PLUGIN_NAME} (${INSTANCE_ID})` : PLUGIN_NAME);
export const PLUGIN_VERSION = '0.1.0';
export const PLUGIN_VENDORS = ['unm'];
export const PLUGIN_CAPABILITIES = ['secretsProvider'];
export const PLUGIN_AUTH_TYPE = 'token';

const PORT = Number(process.env.PORT ?? 4003);
const ADVERTISED_ENDPOINT = process.env.ADVERTISED_ENDPOINT ?? `http://localhost:${PORT}`;

/**
 * The secret types this provider serves, with a field schema for each. The
 * webapp renders forms dynamically from this, and the API validates/relays the
 * fields. This is the provider-declared contract (flexible: a provider can
 * offer custom types).
 */
export interface SecretField {
  name: string;
  label: string;
  input: 'text' | 'password' | 'select';
  secret?: boolean;
  required?: boolean;
  options?: string[];
}

export interface SecretType {
  type: string;
  label: string;
  fields: SecretField[];
  /**
   * True when the provider can CREATE this secret's material itself (via
   * POST /generate) and ROTATE it in place (POST /regenerate). The webapp uses
   * this to offer a "Generate" button instead of manual entry, and the API's
   * plan-provisioning flow relies on it to fulfill provisionRequests without
   * any human typing keys.
   */
  generatable?: boolean;
}

export const SECRET_TYPES: SecretType[] = [
  {
    type: 'apiKey',
    label: 'API Key / Secret',
    fields: [
      { name: 'apiKey', label: 'API Key', input: 'text', required: true },
      { name: 'apiSecret', label: 'API Secret', input: 'password', secret: true, required: true },
    ],
  },
  {
    type: 'usernamePassword',
    label: 'Username / Password',
    fields: [
      { name: 'username', label: 'Username', input: 'text', required: true },
      { name: 'password', label: 'Password', input: 'password', secret: true, required: true },
    ],
  },
  {
    type: 'snmp',
    label: 'SNMP Credentials (Community / v3 USM)',
    fields: [
      { name: 'version', label: 'SNMP Version', input: 'select', options: ['v1', 'v2c', 'v3'], required: false },
      // v1/v2c — community string. Optional in the schema because it is not
      // used for v3; the SNMP plugin enforces it at runtime with a clear error.
      { name: 'community', label: 'Community String (v1/v2c)', input: 'text', secret: true, required: false },
      // v3 (USM) — only needed when version is v3. All optional here so the
      // form stays usable for community-based secrets; the SNMP plugin
      // validates the per-security-level field set at runtime.
      { name: 'username', label: 'USM Username (v3)', input: 'text', required: false },
      {
        name: 'securityLevel',
        label: 'Security Level (v3)',
        input: 'select',
        options: ['noAuthNoPriv', 'authNoPriv', 'authPriv'],
        required: false,
      },
      { name: 'authProtocol', label: 'Auth Protocol (v3)', input: 'select', options: ['MD5', 'SHA'], required: false },
      { name: 'authPassword', label: 'Auth Password (v3)', input: 'password', secret: true, required: false },
      { name: 'privProtocol', label: 'Priv Protocol (v3)', input: 'select', options: ['DES', 'AES'], required: false },
      { name: 'privPassword', label: 'Priv Password (v3)', input: 'password', secret: true, required: false },
    ],
  },
  // --- Generatable key material (created/rotated by this provider) -----------
  {
    type: 'wireguardKeyPair',
    label: 'WireGuard Key Pair (X25519)',
    generatable: true,
    fields: [
      { name: 'publicKey', label: 'Public Key (base64)', input: 'text', required: true },
      { name: 'privateKey', label: 'Private Key (base64)', input: 'password', secret: true, required: true },
    ],
  },
  {
    type: 'tunnelPsk',
    label: 'IPsec Pre-Shared Key',
    generatable: true,
    fields: [{ name: 'psk', label: 'Pre-Shared Key (hex)', input: 'password', secret: true, required: true }],
  },
  {
    type: 'openvpnProfile',
    label: 'OpenVPN Certificate Bundle (CA + cert + key)',
    generatable: true,
    fields: [
      { name: 'commonName', label: 'Common Name / CN', input: 'text', required: false },
      { name: 'ca', label: 'CA Certificate (PEM)', input: 'password', secret: true, required: true },
      { name: 'cert', label: 'Certificate (PEM)', input: 'password', secret: true, required: true },
      { name: 'key', label: 'Private Key (PEM)', input: 'password', secret: true, required: true },
    ],
  },
];

const app = express();
app.use(cors());
app.use(express.json());

/**
 * Authenticates the calling UnifiedNetworkManager API using the shared
 * `x-plugin-api-key` (the same convention the API uses for its internal
 * plugin-facing routes). When `PLUGIN_API_KEY` is unset (dev), the check is
 * skipped to match the API's own behavior.
 */
function requirePluginKey(req: express.Request, res: express.Response, next: express.NextFunction): void {
  const expected = process.env.PLUGIN_API_KEY;
  const provided = req.headers['x-plugin-api-key'];
  if (expected && provided !== expected) {
    res.status(403).json({ error: 'Forbidden: Invalid plugin API key' });
    return;
  }
  next();
}

app.get('/healthz', (_req, res) => {
  res.status(200).json({ status: 'ok' });
});

/**
 * Plugin identity endpoint. The `secretsProvider` capability marks this plugin
 * as the secrets manager; the API broker delegates secret CRUD + crypto to it.
 */
app.get('/discover', (_req, res) => {
  res.status(200).json({
    uuid: EFFECTIVE_UUID,
    name: DISPLAY_NAME,
    version: PLUGIN_VERSION,
    vendors: PLUGIN_VENDORS,
    capabilities: PLUGIN_CAPABILITIES,
    endpoint: ADVERTISED_ENDPOINT,
    authType: PLUGIN_AUTH_TYPE,
    secretsProvider: { algorithm: 'aes-256-gcm', secretTypes: SECRET_TYPES },
  });
});

/**
 * Create a secret. The plugin encrypts the fields object (it owns the key) and
 * stores the ciphertext via the API, tagged with the secret `type` and this
 * provider's id. Returns the new id + createdAt.
 */
app.post('/secrets', requirePluginKey, async (req, res) => {
  const { type, fields, label, expiresAt, userId } = req.body ?? {};
  if (!type || typeof type !== 'string') {
    res.status(400).json({ error: 'type is required' });
    return;
  }
  if (!fields || typeof fields !== 'object') {
    res.status(400).json({ error: 'fields object is required' });
    return;
  }
  if (!userId || typeof userId !== 'string') {
    res.status(401).json({ error: 'User ID not found in token' });
    return;
  }

  try {
    const encryptedValue = encrypt(JSON.stringify(fields));
    const record = await storeSecret({
      type,
      providerId: EFFECTIVE_UUID,
      label: label ?? null,
      encryptedValue,
      userId,
      expiresAt: expiresAt ?? null,
    });
    res.status(201).json({ id: record.id, createdAt: record.createdAt });
  } catch (err) {
    res.status(500).json({ error: (err as Error).message });
  }
});

/**
 * List secret metadata (no ciphertext, no decrypted values).
 */
app.get('/secrets', requirePluginKey, async (_req, res) => {
  try {
    const secrets = await listSecrets();
    res.status(200).json(secrets);
  } catch (err) {
    res.status(500).json({ error: (err as Error).message });
  }
});

/**
 * Retrieve a secret, decrypted. The plugin fetches the ciphertext from the API
 * and decrypts it locally (it owns the key).
 */
app.get('/secrets/:id', requirePluginKey, async (req, res) => {
  const { id } = req.params;
  try {
    const record = await getSecret(id);
    if (!record) {
      res.status(404).json({ error: 'Secret not found' });
      return;
    }
    const fields = JSON.parse(decrypt(record.encryptedValue));
    res.status(200).json({ type: record.type, fields });
  } catch (err) {
    res.status(500).json({ error: (err as Error).message });
  }
});

/**
 * Delete a secret.
 */
app.delete('/secrets/:id', requirePluginKey, async (req, res) => {
  const { id } = req.params;
  try {
    await deleteSecret(id);
    res.status(204).send();
  } catch (err) {
    res.status(500).json({ error: (err as Error).message });
  }
});

/**
 * Generate a new secret of a GENERATABLE type. The provider creates the key
 * material itself (X25519 pair, PSK, or CA+cert bundle), encrypts it and stores
 * it — no human types any keys. `fields` may carry non-material context (e.g.
 * an OpenVPN commonName) which is preserved alongside the generated values.
 *
 * Body: { type, fields?, label?, expiresAt? }  → 201 { id, createdAt, type }
 */
app.post('/generate', requirePluginKey, async (req, res) => {
  const { type, fields, label, expiresAt, userId } = req.body ?? {};
  if (!type || typeof type !== 'string') {
    res.status(400).json({ error: 'type is required' });
    return;
  }

  const gen = GENERATABLE_TYPES[type];
  if (!gen) {
    res.status(400).json({
      error: `Type "${type}" is not generatable. Generatable types: ${Object.keys(GENERATABLE_TYPES).join(', ')}`,
    });
    return;
  }

  // User identity: body field (matches POST /secrets) or the x-unm-user-id header.
  const uid = typeof userId === 'string' && userId ? userId : req.headers['x-unm-user-id'];
  if (!uid || typeof uid !== 'string') {
    res.status(401).json({ error: 'User ID not found in token' });
    return;
  }

  try {
    // Context fields (e.g. commonName) are kept; generated material overwrites
    // any same-named field so a stale value can never survive generation.
    const context = (fields && typeof fields === 'object' ? fields : {}) as Record<string, unknown>;
    const generated = gen.generate(context);
    const merged: Record<string, string> = { ...context, ...generated } as Record<string, string>;

    const encryptedValue = encrypt(JSON.stringify(merged));
    const record = await storeSecret({
      type,
      providerId: EFFECTIVE_UUID,
      label: typeof label === 'string' ? label : null,
      encryptedValue,
      userId: uid,
      expiresAt: (typeof expiresAt === 'string' && expiresAt) || null,
    });
    res.status(201).json({ id: record.id, createdAt: record.createdAt, type });
  } catch (err) {
    res.status(500).json({ error: (err as Error).message });
  }
});

/**
 * Regenerate a secret's key material IN PLACE — the SAME id is preserved so
 * every assignment/plan referencing it keeps working. Only generatable types
 * can be regenerated; non-material context fields (labels, CN) are carried over.
 *
 * Body: { id }  → 200 { id, type }   (404 if unknown, 400 if not generatable)
 */
app.post('/regenerate', requirePluginKey, async (req, res) => {
  const { id } = req.body ?? {};
  if (!id || typeof id !== 'string') {
    res.status(400).json({ error: 'id is required' });
    return;
  }

  try {
    const record = await getSecret(id);
    if (!record) {
      res.status(404).json({ error: 'Secret not found' });
      return;
    }

    const gen = GENERATABLE_TYPES[record.type];
    if (!gen) {
      res.status(400).json({ error: `Type "${record.type}" is not generatable` });
      return;
    }

    // Decrypt the existing fields, keep non-material context (e.g. commonName),
    // re-roll the material, and re-encrypt under the SAME id.
    const existing = JSON.parse(decrypt(record.encryptedValue)) as Record<string, unknown>;
    const generated = gen.generate(existing);
    const merged: Record<string, string> = { ...existing, ...generated } as Record<string, string>;

    await updateSecret(id, encrypt(JSON.stringify(merged)));
    res.status(200).json({ id: record.id, type: record.type });
  } catch (err) {
    res.status(500).json({ error: (err as Error).message });
  }
});

/**
 * Advertises this plugin over mDNS/DNS-SD so the API can discover it
 * automatically (service type `_unm-plugin._tcp`). Best-effort; the API also
 * polls known plugin endpoints as a fallback.
 */
function startMdnsAdvertising(): void {
  try {
    const bonjour = new Bonjour();
    bonjour.publish({
      name: DISPLAY_NAME,
      type: 'unm-plugin',
      port: PORT,
      txt: {
        uuid: EFFECTIVE_UUID,
        name: DISPLAY_NAME,
        version: PLUGIN_VERSION,
        vendors: PLUGIN_VENDORS.join(','),
        capabilities: PLUGIN_CAPABILITIES.join(','),
        endpoint: ADVERTISED_ENDPOINT,
        authType: PLUGIN_AUTH_TYPE,
      },
    });
    // eslint-disable-next-line no-console
    console.log(`[secrets-provider] advertising via mDNS as "${DISPLAY_NAME}" (${EFFECTIVE_UUID})`);
  } catch (err) {
    // eslint-disable-next-line no-console
    console.warn('[secrets-provider] mDNS advertising unavailable:', (err as Error).message);
  }
}

app.listen(PORT, () => {
  // eslint-disable-next-line no-console
  console.log(`[secrets-provider] listening on port ${PORT}`);
  startMdnsAdvertising();
});
