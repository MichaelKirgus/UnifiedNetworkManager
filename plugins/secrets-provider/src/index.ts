import type { PluginOptionDescriptor, SecretField, SecretType } from '@unm/plugin-sdk';
import {
  createPluginLogger,
  createPluginServer,
  readSettings,
  requirePluginKey,
  resolvePluginIdentity,
} from '@unm/plugin-sdk';
import { encrypt, decrypt } from './crypto';
import { storeSecret, listSecrets, getSecret, deleteSecret, updateSecret } from './apiClient';
import { GENERATABLE_TYPES, generateSshKeyPair } from './keygen';

export const PLUGIN_UUID = '00000000-0000-4000-8000-000000000002';
export const PLUGIN_NAME = 'Secrets Provider (Device Credentials)';

/**
 * Multi-instance support: set `PLUGIN_INSTANCE_ID` (e.g. "site-a") to run several
 * instances of the same plugin type — each advertises a distinct identity
 * (`<uuid>:<instanceId>`) so the API registers them as separate plugins.
 * `PLUGIN_DISPLAY_NAME` optionally overrides the advertised name; without it,
 * the instance id is appended. Unset = single-instance behavior.
 * (Convention implemented in @unm/plugin-sdk's resolvePluginIdentity.)
 */
const identity = resolvePluginIdentity({
  uuid: PLUGIN_UUID,
  name: PLUGIN_NAME,
  version: '0.1.0',
  vendors: ['unm'],
  capabilities: ['secretsProvider'],
  authType: 'token',
});

/**
 * The secret types this provider serves, with a field schema for each (the
 * shared contract types come from @unm/plugin-sdk). The webapp renders forms
 * dynamically from this, and the API validates/relays the fields. This is the
 * provider-declared contract (flexible: a provider can offer custom types).
 */
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
    // Generic single-field bearer key — for APIs that authenticate with ONE key
    // (e.g. mailcow's X-API-Key header) instead of a key+secret pair like `apiKey`.
    type: 'apiKeyNoSecret',
    label: 'API Key (without secret)',
    fields: [
      { name: 'apiKey', label: 'API Key', input: 'password', secret: true, required: true },
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
  {
    type: 'sshKeyPair',
    label: 'SSH Key Pair (ed25519 PEM)',
    generatable: true,
    fields: [
      { name: 'username', label: 'Username', input: 'text', required: false },
      // Multi-line — the field is a full PEM block. `secret` keeps it masked in
      // any UI that renders secret fields; the value only ever leaves on submit.
      { name: 'privateKey', label: 'Private Key (PEM)', input: 'textarea', secret: true, required: true },
      { name: 'passphrase', label: 'Key Passphrase (optional)', input: 'password', secret: true, required: false },
    ],
  },
  // --- Client-certificate bundles for outbound TLS connections ---------------
  {
    type: 'dockerTls',
    label: 'Docker TLS Client Certificates (CA + cert + key)',
    fields: [
      { name: 'ca', label: 'CA Certificate (PEM)', input: 'textarea', secret: true, required: false },
      // Optional so the form stays usable for CA-only verification; the docker
      // plugin enforces client-cert completeness at runtime with a clear error.
      { name: 'cert', label: 'Client Certificate (PEM)', input: 'textarea', secret: true, required: false },
      { name: 'key', label: 'Client Private Key (PEM)', input: 'textarea', secret: true, required: false },
    ],
  },
];

/**
 * Configurable options. This plugin is called by the API's secrets broker (not
 * the telemetry loop), but the settings header still flows through — so
 * `logToApi` works here exactly like in device-facing plugins.
 */
const PLUGIN_OPTIONS: PluginOptionDescriptor[] = [
  {
    key: 'logToApi',
    label: 'Send logs to UNM',
    type: 'boolean' as const,
    default: true,
    description:
      'Ship structured log entries (secret CRUD/crypto failures) to the UNM API for the Logs view. Disable to keep logging container-local only.',
  },
];

// Pre-wired app (cors + json + /healthz + /discover, mDNS on listen) comes from
// @unm/plugin-sdk — this file only registers its own routes. The
// `secretsProvider` capability marks this plugin as the secrets manager; the API
// broker delegates secret CRUD + crypto to it.
const server = createPluginServer({
  identity,
  logTag: 'secrets-provider',
  discovery: {
    secretsProvider: { algorithm: 'aes-256-gcm', secretTypes: SECRET_TYPES },
    options: PLUGIN_OPTIONS,
  },
});
const app = server.app;

// Structured logs shipped to the API (see docs/PLUGIN-DEVELOPMENT.md, Logging).
// Emission is gated per call by the `logToApi` option via setEnabled() — it
// flows through the settings loop, so it works globally and per-device.
const logger = createPluginLogger(identity);

/**
 * Create a secret. The plugin encrypts the fields object (it owns the key) and
 * stores the ciphertext via the API, tagged with the secret `type` and this
 * provider's id. Returns the new id + createdAt.
 */
app.post('/secrets', requirePluginKey, async (req, res) => {
  const { type, fields, label, expiresAt, userId, interactiveLoginAllowed, fileAccessAllowed } = req.body ?? {};
  logger.setEnabled(readSettings(req, PLUGIN_OPTIONS).logToApi === true);
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
      providerId: identity.effectiveUuid,
      label: label ?? null,
      encryptedValue,
      userId,
      expiresAt: expiresAt ?? null,
      // Interactive-session usage flags (opt-in per secret; default false).
      interactiveLoginAllowed: typeof interactiveLoginAllowed === 'boolean' ? interactiveLoginAllowed : false,
      fileAccessAllowed: typeof fileAccessAllowed === 'boolean' ? fileAccessAllowed : false,
    });
    res.status(201).json({ id: record.id, createdAt: record.createdAt });
  } catch (err) {
    logger.error(`Failed to store secret of type ${type}: ${(err as Error).message}`, { context: { type, userId } });
    res.status(500).json({ error: (err as Error).message });
  }
});

/**
 * List secret metadata (no ciphertext, no decrypted values).
 */
app.get('/secrets', requirePluginKey, async (_req, res) => {
  logger.setEnabled(readSettings(_req, PLUGIN_OPTIONS).logToApi === true);
  try {
    const secrets = await listSecrets();
    res.status(200).json(secrets);
  } catch (err) {
    logger.error(`Failed to list secrets: ${(err as Error).message}`);
    res.status(500).json({ error: (err as Error).message });
  }
});

/**
 * Retrieve a secret, decrypted. The plugin fetches the ciphertext from the API
 * and decrypts it locally (it owns the key).
 */
app.get('/secrets/:id', requirePluginKey, async (req, res) => {
  const { id } = req.params;
  logger.setEnabled(readSettings(req, PLUGIN_OPTIONS).logToApi === true);
  try {
    const record = await getSecret(id);
    if (!record) {
      res.status(404).json({ error: 'Secret not found' });
      return;
    }
    const fields = JSON.parse(decrypt(record.encryptedValue));
    res.status(200).json({ type: record.type, fields });
  } catch (err) {
    logger.error(`Failed to retrieve/decrypt secret ${id}: ${(err as Error).message}`, { context: { id } });
    res.status(500).json({ error: (err as Error).message });
  }
});

/**
 * Delete a secret.
 */
app.delete('/secrets/:id', requirePluginKey, async (req, res) => {
  const { id } = req.params;
  logger.setEnabled(readSettings(req, PLUGIN_OPTIONS).logToApi === true);
  try {
    await deleteSecret(id);
    res.status(204).send();
  } catch (err) {
    logger.error(`Failed to delete secret ${id}: ${(err as Error).message}`, { context: { id } });
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
  logger.setEnabled(readSettings(req, PLUGIN_OPTIONS).logToApi === true);
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
      providerId: identity.effectiveUuid,
      label: typeof label === 'string' ? label : null,
      encryptedValue,
      userId: uid,
      expiresAt: (typeof expiresAt === 'string' && expiresAt) || null,
    });
    // Echo back NON-SECRET generated material so the UI can show it to the
    // creator (e.g. the paste-ready ssh-ed25519 public key line). Secret fields
    // NEVER leave the provider in any response.
    const typeDef = SECRET_TYPES.find((t) => t.type === type);
    const secretNames = new Set((typeDef?.fields ?? []).filter((f) => f.secret).map((f) => f.name));
    const publicFields: Record<string, string> = {};
    for (const [k, v] of Object.entries(generated)) {
      if (!secretNames.has(k) && typeof v === 'string') publicFields[k] = v;
    }
    res.status(201).json({
      id: record.id,
      createdAt: record.createdAt,
      type,
      ...(Object.keys(publicFields).length > 0 ? { publicFields } : {}),
    });
  } catch (err) {
    logger.error(`Failed to generate secret of type ${type}: ${(err as Error).message}`, { context: { type, userId: uid } });
    res.status(500).json({ error: (err as Error).message });
  }
});

/**
 * Update a secret's fields IN PLACE — the SAME id is preserved so every
 * assignment/plan referencing it keeps working. Works for ALL secret types:
 * the caller sends the full new field map (as rendered by the type schema),
 * this provider re-encrypts and stores it. `label` / `expiresAt` are optional
 * metadata updates applied alongside.
 *
 * Body: { id, fields, label?, expiresAt? }  → 200 { id }   (404 if unknown)
 */
app.post('/update', requirePluginKey, async (req, res) => {
  const { id, fields, label, expiresAt, interactiveLoginAllowed, fileAccessAllowed } = req.body ?? {};
  logger.setEnabled(readSettings(req, PLUGIN_OPTIONS).logToApi === true);
  if (!id || typeof id !== 'string') {
    res.status(400).json({ error: 'id is required' });
    return;
  }
  if (!fields || typeof fields !== 'object' || Array.isArray(fields)) {
    res.status(400).json({ error: 'fields object is required' });
    return;
  }

  try {
    const record = await getSecret(id);
    if (!record) {
      res.status(404).json({ error: 'Secret not found' });
      return;
    }

    // Full replacement of the field map (the edit form always submits every
    // declared field), re-encrypted under the SAME id. `expiresAt` is only
    // forwarded when the API actually sent it — a fields-only update must not
    // wipe an existing expiry.
    const body = req.body ?? {};
    const encryptedValue = encrypt(JSON.stringify(fields));
    await updateSecret(
      id,
      encryptedValue,
      typeof label === 'string' ? label : undefined,
      'expiresAt' in body ? (typeof expiresAt === 'string' && expiresAt ? expiresAt : null) : undefined,
      // Usage flags are only forwarded when the API actually sent them — a
      // fields-only update must not reset an existing flag.
      typeof interactiveLoginAllowed === 'boolean' || typeof fileAccessAllowed === 'boolean'
        ? {
            ...(typeof interactiveLoginAllowed === 'boolean' ? { interactiveLoginAllowed } : {}),
            ...(typeof fileAccessAllowed === 'boolean' ? { fileAccessAllowed } : {}),
          }
        : undefined
    );
    res.status(200).json({ id: record.id });
  } catch (err) {
    logger.error(`Failed to update secret ${id}: ${(err as Error).message}`, { context: { id } });
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
  logger.setEnabled(readSettings(req, PLUGIN_OPTIONS).logToApi === true);
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
    logger.error(`Failed to regenerate secret ${id}: ${(err as Error).message}`, { context: { id } });
    res.status(500).json({ error: (err as Error).message });
  }
});

// listen() binds the conventional plugin port (4080 by default) and starts
// mDNS advertising — both handled by @unm/plugin-sdk.
server.listen().catch((err) => {
  console.error('[secrets-provider] fatal startup error:', err);
  process.exit(1);
});
