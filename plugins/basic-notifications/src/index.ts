/**
 * UNM Basic Notification Plugin (capability `notificationSender`).
 *
 * A GLOBAL service plugin (no device assignment): it is a STATELESS TRANSPORT
 * for rendered UNM notifications. The API owns the whole notification model —
 * rules (which events fire), channels (where they go, incl. bound secrets) and
 * templates (what gets sent). When a rule matches, the API renders title+body
 * from the user's templates, decrypts the channel's bound secret on demand and
 * POSTs one message here:
 *
 *   body  { channelType, config, credentials, severity, title, body }
 *     channelType — key into this plugin's catalog (validated by the API)
 *     config      — non-secret fields, validated against the descriptor
 *     credentials — decrypted fields of the bound secret ({}, when none)
 *   resp  { success: true, details? } | { success: false, error }
 *
 * The plugin knows nothing about UNM's notification model — it only knows how
 * to deliver ONE rendered message over ONE channel type. Adding a new service
 * later = another catalog entry here (or another plugin with this capability);
 * no API or webapp changes needed.
 *
 * Catalog (advertised via /discover `notificationChannels`):
 *   smtp     — email through an SMTP server (nodemailer). Credentials: a bound
 *              "Username / Password" secret (auth optional when absent).
 *   webhook  — POST/PUT the message as JSON or plain text to any HTTP endpoint.
 *              Optional bound "API Key (without secret)" → Bearer header.
 *   telegram — Telegram Bot API sendMessage. Credentials: a bound
 *              "API Key (without secret)" holding the bot token.
 */

import axios, { AxiosError } from 'axios';
import nodemailer from 'nodemailer';
import type { Transporter } from 'nodemailer';
import type {
  MetricDescriptor,
  NotificationChannelDescriptor,
  NotifyRequestBody,
  NotifyResponseBody,
} from '@unm/plugin-sdk';
import {
  createPluginLogger,
  createPluginServer,
  requirePluginKey,
  resolvePluginIdentity,
} from '@unm/plugin-sdk';
import { BASIC_NOTIFICATIONS_DEVICE_SUPPORT } from './deviceSupport';

export const PLUGIN_UUID = '00000000-0000-4000-8000-0000000014';
export const PLUGIN_NAME = 'Basic Notification Plugin';

const identity = resolvePluginIdentity({
  uuid: PLUGIN_UUID,
  name: PLUGIN_NAME,
  description:
    'Notification transport — delivers rendered UNM notifications over email (SMTP), generic webhooks and Telegram bot messages.',
  version: '0.1.0',
  vendors: ['unm'],
  capabilities: ['notificationSender'],
});

// ── Channel catalog (drives the webapp's dynamic forms + API validation) ────

const CHANNEL_CATALOG: NotificationChannelDescriptor[] = [
  {
    type: 'smtp',
    label: 'Email (SMTP)',
    description: 'Sends the notification as a plain-text email through an SMTP server.',
    fields: [
      { name: 'host', label: 'SMTP host', input: 'text', required: true, placeholder: 'mail.example.com' },
      { name: 'port', label: 'Port', input: 'number', required: true, placeholder: '587 (starttls) / 465 (implicit)' },
      { name: 'tls', label: 'TLS mode', input: 'select', required: true, options: ['starttls', 'implicit', 'none'] },
      { name: 'fromAddress', label: 'From address', input: 'text', required: true, placeholder: 'unm@example.com' },
      { name: 'toAddresses', label: 'To addresses (comma-separated)', input: 'text', required: true, placeholder: 'ops@example.com, oncall@example.com' },
      { name: 'subjectPrefix', label: 'Subject prefix', input: 'text', placeholder: '[UNM]' },
    ],
    secretTypes: ['usernamePassword'],
  },
  {
    type: 'webhook',
    label: 'Webhook (HTTP)',
    description: 'POSTs (or PUTs) the notification as JSON or plain text to any HTTP endpoint.',
    fields: [
      { name: 'url', label: 'Endpoint URL', input: 'text', required: true, placeholder: 'https://hooks.example.com/unm' },
      { name: 'method', label: 'HTTP method', input: 'select', required: true, options: ['POST', 'PUT'] },
      { name: 'contentType', label: 'Content type', input: 'select', required: true, options: ['json', 'text'] },
    ],
    secretTypes: ['apiKeyNoSecret'],
  },
  {
    type: 'telegram',
    label: 'Telegram (Bot)',
    description: 'Sends the notification to a Telegram chat via the Bot API.',
    fields: [
      { name: 'chatId', label: 'Chat ID', input: 'text', required: true, placeholder: '-1001234567890 or 123456789' },
      { name: 'parseMode', label: 'Parse mode', input: 'select', required: true, options: ['plain', 'markdown', 'html'] },
    ],
    secretTypes: ['apiKeyNoSecret'],
  },
];

// ── Runtime configuration (env — global service, no per-device settings) ────

/** Per-send timeout; kept below the API's /notify timeout so failures surface as plugin errors. */
const SEND_TIMEOUT_MS = Math.max(5_000, Number(process.env.NOTIFY_SEND_TIMEOUT_MS ?? 12_000));

const stats = {
  notifyTotal: 0,
  notifyFailuresTotal: 0,
  lastNotifyMs: null as number | null,
};

// ── Metric descriptors (rendered on the Plugins page) ───────────────────────

const METRIC_DESCRIPTORS: MetricDescriptor[] = [
  { key: 'notify.total', label: 'Notifications sent (total)', type: 'number', visualization: 'text', group: 'Notifications' },
  { key: 'notify.failuresTotal', label: 'Failed deliveries (total)', type: 'number', visualization: 'text', group: 'Notifications' },
];

const server = createPluginServer({
  identity,
  logTag: 'basic-notifications-plugin',
  discovery: {
    // License/docs metadata for UNM's Plugins page (see ./deviceSupport.ts).
    deviceSupport: BASIC_NOTIFICATIONS_DEVICE_SUPPORT,
    requiredSecretType: null,
    metrics: METRIC_DESCRIPTORS,
    options: [],
    notificationChannels: CHANNEL_CATALOG,
  },
  selfMetricsExtra: () => ({
    notifyTotal: stats.notifyTotal,
    notifyFailuresTotal: stats.notifyFailuresTotal,
  }),
});

// Structured logs shipped to the API (boot errors, delivery failures).
const logger = createPluginLogger(identity);

// ── Small helpers ────────────────────────────────────────────────────────────

/** Trims a config value to a non-empty string ('' when absent/invalid). */
function strField(value: unknown): string {
  return typeof value === 'string' ? value.trim() : '';
}

/** Human-readable error text for any thrown value. */
function errMsg(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

const fail = (error: string): NotifyResponseBody => ({ success: false, error });

// ── Channel handlers ─────────────────────────────────────────────────────────

/** smtp — plain-text email via nodemailer. */
async function sendSmtp(req: NotifyRequestBody): Promise<NotifyResponseBody> {
  const cfg = req.config ?? {};
  const host = strField(cfg.host);
  if (!host) return fail('Missing "host" in channel config');

  const tlsMode = String(cfg.tls ?? 'starttls');
  if (tlsMode !== 'none' && tlsMode !== 'starttls' && tlsMode !== 'implicit') {
    return fail(`Invalid TLS mode "${tlsMode}" (expected starttls, implicit or none)`);
  }
  const port = Number(cfg.port) || (tlsMode === 'implicit' ? 465 : 587);

  const from = strField(cfg.fromAddress);
  if (!from) return fail('Missing "fromAddress" in channel config');
  const toRaw = strField(cfg.toAddresses);
  if (!toRaw) return fail('Missing "toAddresses" in channel config');
  const to = toRaw.split(',').map((s) => s.trim()).filter(Boolean);
  if (to.length === 0) return fail('"toAddresses" contains no addresses');

  const prefix = strField(cfg.subjectPrefix ?? '');
  const subject = [prefix, req.title].filter(Boolean).join(' ');

  let transport: Transporter;
  try {
    transport = nodemailer.createTransport({
      host,
      port,
      secure: tlsMode === 'implicit', // implicit TLS (port 465)
      ignoreTLS: tlsMode === 'none', // starttls is the default when not ignored
      auth: req.credentials?.username
        ? { user: req.credentials.username, pass: req.credentials.password ?? '' }
        : undefined,
    });
  } catch (e) {
    return fail(`SMTP setup failed: ${errMsg(e)}`);
  }

  try {
    const info = await transport.sendMail({ from, to, subject, text: req.body || req.title });
    return { success: true, details: { messageId: info.messageId ?? null } };
  } catch (e) {
    return fail(`SMTP send failed: ${errMsg(e)}`);
  }
}

/** webhook — JSON or plain-text POST/PUT to any HTTP endpoint. */
async function sendWebhook(req: NotifyRequestBody): Promise<NotifyResponseBody> {
  const cfg = req.config ?? {};
  let url: URL;
  try {
    url = new URL(strField(cfg.url));
  } catch {
    return fail('Missing or invalid "url" in channel config');
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    return fail(`Unsupported protocol "${url.protocol}"`);
  }

  const method = String(cfg.method ?? 'POST') === 'PUT' ? 'PUT' : 'POST';
  const asText = cfg.contentType === 'text';

  const headers: Record<string, string> = {};
  if (req.credentials?.apiKey) headers.Authorization = `Bearer ${req.credentials.apiKey}`;

  try {
    await axios.request({
      url: url.toString(),
      method,
      timeout: SEND_TIMEOUT_MS,
      validateStatus: (s) => s >= 200 && s < 300,
      headers: asText ? { ...headers, 'Content-Type': 'text/plain; charset=utf-8' } : { ...headers, 'Content-Type': 'application/json' },
      data: asText
        ? `${req.title}\n\n${req.body}`
        : { severity: req.severity, title: req.title, body: req.body },
    });
    return { success: true };
  } catch (e) {
    const ax = e as AxiosError;
    if (ax.response) return fail(`Webhook returned HTTP ${ax.response.status}`);
    if (ax.code === 'ECONNABORTED' || ax.code === 'ETIMEDOUT') return fail(`Webhook timed out after ${SEND_TIMEOUT_MS} ms`);
    return fail(`Webhook request failed: ${errMsg(e)}`);
  }
}

/** telegram — Bot API sendMessage to a chat. */
async function sendTelegram(req: NotifyRequestBody): Promise<NotifyResponseBody> {
  const token = req.credentials?.apiKey;
  if (!token) return fail('No bot token bound — attach a secret of type "API Key (without secret)"');

  const cfg = req.config ?? {};
  const chatId = strField(cfg.chatId);
  if (!chatId) return fail('Missing "chatId" in channel config');

  const parseMode = String(cfg.parseMode ?? 'plain');
  if (!['plain', 'markdown', 'html'].includes(parseMode)) {
    return fail(`Invalid parse mode "${parseMode}" (expected plain, markdown or html)`);
  }

  try {
    const res = await axios.post(
      `https://api.telegram.org/bot${encodeURIComponent(token)}/sendMessage`,
      {
        chat_id: chatId,
        text: `${req.title}\n\n${req.body}`,
        ...(parseMode !== 'plain' ? { parse_mode: parseMode } : {}),
      },
      { timeout: SEND_TIMEOUT_MS },
    );
    if (res.data?.ok === false) return fail(`Telegram API error: ${String(res.data.description ?? 'unknown')}`);
    return { success: true, details: { messageId: res.data?.result?.message_id ?? null } };
  } catch (e) {
    const ax = e as AxiosError<{ description?: string }>;
    if (ax.response) return fail(`Telegram API error ${ax.response.status}: ${ax.response.data?.description ?? errMsg(e)}`);
    if (ax.code === 'ECONNABORTED' || ax.code === 'ETIMEDOUT') return fail(`Telegram timed out after ${SEND_TIMEOUT_MS} ms`);
    return fail(`Telegram request failed: ${errMsg(e)}`);
  }
}

const HANDLERS: Record<string, (req: NotifyRequestBody) => Promise<NotifyResponseBody>> = {
  smtp: sendSmtp,
  webhook: sendWebhook,
  telegram: sendTelegram,
};

// ── Routes ───────────────────────────────────────────────────────────────────

/**
 * POST /notify — deliver ONE already-rendered message over the given channel.
 * The API (notificationDispatch.ts) is the only caller; it validates the
 * channelType against this catalog and decrypts credentials before calling.
 */
server.app.post('/notify', requirePluginKey, async (req, res) => {
  const body = req.body as Partial<NotifyRequestBody> | undefined;
  if (!body || typeof body.channelType !== 'string' || !HANDLERS[body.channelType]) {
    res.status(400).json({ success: false, error: `Unknown channel type "${String(body?.channelType ?? '')}"` });
    return;
  }

  const started = Date.now();
  let result: NotifyResponseBody;
  try {
    result = await HANDLERS[body.channelType](body as NotifyRequestBody);
  } catch (e) {
    // Defensive — handlers never throw, but a bug must not crash the process.
    result = fail(errMsg(e));
  }

  stats.notifyTotal += 1;
  if (!result.success) {
    stats.notifyFailuresTotal += 1;
    logger.warn(`Delivery failed (${body.channelType}): ${result.error}`);
  } else {
    stats.lastNotifyMs = Date.now() - started;
  }

  // Always 200 with success:false on transport failure — the API records a
  // 'failed' delivery row from the body, not the HTTP status.
  res.status(200).json(result);
});

server.listen().catch((err) => {
  // eslint-disable-next-line no-console
  console.error('[basic-notifications] failed to start HTTP server:', err.message);
  process.exit(1);
});
