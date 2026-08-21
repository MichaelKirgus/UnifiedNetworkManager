import express from 'express';
import cors from 'cors';
import { Bonjour } from 'bonjour-service';
import { encrypt, decrypt } from './crypto';
import { storeSecret, listSecrets, getSecret, deleteSecret } from './apiClient';

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
    label: 'SNMP Community',
    fields: [
      { name: 'community', label: 'Community String', input: 'text', secret: true, required: true },
      { name: 'version', label: 'SNMP Version', input: 'select', options: ['v1', 'v2c', 'v3'], required: false },
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
