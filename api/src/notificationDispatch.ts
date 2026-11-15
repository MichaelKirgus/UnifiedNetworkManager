import { v4 as uuidv4 } from 'uuid';
import { and, desc, eq } from 'drizzle-orm';
import { db } from './db';
import * as schema from './db/schema';
import { getSecret } from './secretsProvider';
import { pluginAxios } from './utils/pluginHttp';
import { renderTemplate } from './automations/engine';

/**
 * Notification dispatch — the bridge between UNM's notification center and
 * external delivery endpoints (email, webhooks, chat messengers, …).
 *
 * Architecture: the API owns WHAT gets sent and TO WHOM. `notification_rules`
 * define filters over the notification center (severity, source, device
 * tags/vendors/types, title/message regex) plus {{token}} templates;
 * `notification_channels` are configured delivery endpoints whose transport is
 * a notification-sender plugin (capability 'notificationSender'). The API
 * renders title/body and brokers POST /notify to the sender plugin with the
 * channel's non-secret config + decrypted bound secret — the plugin is a
 * stateless transport that never sees UNM's notification model.
 *
 * Hook point: emitNotification() calls dispatchNotification(id) fire-and-forget
 * after INSERTING a new open row (dedupe upserts of an ongoing condition do
 * NOT re-send; recovery one-shots are themselves new rows and DO send). This
 * function NEVER throws — a delivery failure must not break the emitter.
 */

/** Filter document stored on notification_rules.filter (all dimensions optional). */
export interface NotificationRuleFilter {
  /** Only these severities fire (absent/empty = all). Values: info|warning|critical. */
  severities?: string[];
  /** Only these sources fire (absent/empty = all). Values: system|device|plugin. */
  sources?: string[];
  /** Any-match against the device's user tags (requires a deviceId on the row). */
  deviceTags?: string[];
  /** Case-insensitive match against the device's vendor. */
  vendors?: string[];
  /** Any-match against the device's role types (router/firewall/…). */
  deviceTypes?: string[];
  /** Case-insensitive regex matched against the notification title. */
  titleRegex?: string;
  /** Case-insensitive regex matched against the notification message. */
  messageRegex?: string;
}

/**
 * Audience document stored on notification_rules.audience — WHO a rule targets.
 * `type:'all'` (the default) keeps today's semantics: shared channels fire for
 * everyone, no per-user fan-out. With `roles`/`users` + non-empty `fanOutTypes`,
 * each audience member ALSO gets the message on their PERSONAL channels of those
 * types (notification_channels.ownerId = the user). Roles are the appliance's
 * existing named user collections (users.roles ∩ roleNames); a pure membership
 * group concept can be added later as another `type` without migration.
 */
export interface NotificationRuleAudience {
  type: 'all' | 'roles' | 'users';
  /** Required when type='roles': the user matches if ANY of their roles is listed. */
  roleNames?: string[];
  /** Required when type='users': explicit user id list. */
  userIds?: string[];
  /** Channel types to fan out to each member's personal channels (absent/empty = none). */
  fanOutTypes?: string[];
}

/** Minimal user shape the audience checks need (avoids importing the full row type). */
export interface AudienceUser {
  id: string;
  roles: string[];
  disabled: boolean;
}

const DEFAULT_AUDIENCE: NotificationRuleAudience = { type: 'all' };

/** Trims, drops empties and dedupes a JSON string array (order-preserving). */
function strArray(v: unknown): string[] {
  if (!Array.isArray(v)) return [];
  const out = new Set<string>();
  for (const x of v) {
    if (typeof x === 'string' && x.trim() !== '') out.add(x.trim());
  }
  return [...out];
}

/**
 * Parses + normalizes a stored audience document; anything malformed degrades to "all".
 * The result is COMPACT — empty lists are omitted, so the default serializes as exactly
 * {"type":"all"} (matters for comparisons and storage hygiene).
 */
export function parseAudience(raw: string | null | undefined): NotificationRuleAudience {
  if (!raw) return { ...DEFAULT_AUDIENCE };
  try {
    const v = JSON.parse(raw);
    if (!v || typeof v !== 'object' || Array.isArray(v)) return { ...DEFAULT_AUDIENCE };
    const out: NotificationRuleAudience = { type: v.type === 'roles' || v.type === 'users' ? v.type : 'all' };
    const roleNames = strArray(v.roleNames);
    if (roleNames.length > 0) out.roleNames = roleNames;
    const userIds = strArray(v.userIds);
    if (userIds.length > 0) out.userIds = userIds;
    // Lowercase FIRST so "Telegram"/"telegram" dedupe to one entry.
    const fanOutTypes = [...new Set(strArray(v.fanOutTypes).map((t) => t.toLowerCase()))];
    if (fanOutTypes.length > 0) out.fanOutTypes = fanOutTypes;
    return out;
  } catch {
    return { ...DEFAULT_AUDIENCE };
  }
}

/** Pure membership test — exported for unit tests. Disabled users never match. */
export function audienceIncludesUser(audience: NotificationRuleAudience, user: AudienceUser): boolean {
  if (user.disabled) return false;
  switch (audience.type) {
    case 'all':
      return true;
    case 'roles': {
      const names = strArray(audience.roleNames);
      return names.length > 0 && user.roles.some((r) => names.includes(r));
    }
    case 'users':
      return strArray(audience.userIds).includes(user.id);
    default:
      return false;
  }
}

interface DeviceInfo {
  name: string;
  address: string | null;
  vendor: string;
  tags: string[];
  deviceTypes: string[];
  siteName: string | null;
  status: string;
}

const ONLINE_WINDOW_MS = 5 * 60 * 1000;
/** Per-delivery budget for the POST /notify hop (the plugin does its own work within it). */
const NOTIFY_TIMEOUT_MS = 15_000;

function parseStrArray(raw: string | null): string[] {
  if (!raw) return [];
  try {
    const v = JSON.parse(raw);
    return Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string') : [];
  } catch {
    return [];
  }
}

function parseFilter(raw: string | null): NotificationRuleFilter {
  if (!raw) return {};
  try {
    const v = JSON.parse(raw);
    return v && typeof v === 'object' ? (v as NotificationRuleFilter) : {};
  } catch {
    return {};
  }
}

/** Loads the device a notification row refers to (null when absent/unknown). */
async function loadDeviceInfo(deviceId: string | null): Promise<DeviceInfo | null> {
  if (!deviceId) return null;
  const dev = await db.query.devices.findFirst({ where: eq(schema.devices.id, deviceId) });
  if (!dev) return null;
  let siteName: string | null = null;
  if (dev.siteId) {
    const site = await db.query.sites.findFirst({ where: eq(schema.sites.id, dev.siteId) });
    siteName = site?.name ?? null;
  }
  return {
    name: dev.name,
    address: dev.managementAddress,
    vendor: dev.vendor,
    tags: parseStrArray(dev.tags),
    deviceTypes: parseStrArray(dev.deviceTypes),
    siteName,
    status: dev.status,
  };
}

/** True when the rule's filter matches the notification row (device joined lazily). */
export function ruleMatches(filter: NotificationRuleFilter, row: { severity: string; source: string; title: string; message: string }, device: DeviceInfo | null): boolean {
  const list = (v: unknown) => (Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string' && x.trim() !== '') : []);

  const severities = list(filter.severities);
  if (severities.length > 0 && !severities.includes(row.severity)) return false;

  const sources = list(filter.sources);
  if (sources.length > 0 && !sources.includes(row.source)) return false;

  const tags = list(filter.deviceTags);
  if (tags.length > 0) {
    if (!device || !device.tags.some((t) => tags.includes(t))) return false;
  }

  const vendors = list(filter.vendors).map((v) => v.toLowerCase());
  if (vendors.length > 0) {
    if (!device || !vendors.includes(device.vendor.toLowerCase())) return false;
  }

  const types = list(filter.deviceTypes).map((t) => t.toLowerCase());
  if (types.length > 0) {
    if (!device || !device.deviceTypes.some((t) => types.includes(t.toLowerCase()))) return false;
  }

  for (const [pattern, text] of [
    [filter.titleRegex, row.title],
    [filter.messageRegex, row.message],
  ] as Array<[string | undefined, string]>) {
    if (!pattern) continue;
    let re: RegExp;
    try {
      re = new RegExp(pattern, 'i');
    } catch {
      // Invalid regex (should be impossible — validated at rule write time):
      // treat the dimension as unconstrained rather than blocking delivery.
      console.warn(`[notification-dispatch] invalid regex in rule filter: ${pattern}`);
      continue;
    }
    if (!re.test(text)) return false;
  }

  return true;
}

/** Builds the flat {{token}} map for one notification row (see renderTemplate). */
export function buildNotificationVars(row: { title: string; message: string; severity: string; source: string; status: string; createdAt: string; lastSeenAt: string; occurrences: number }, device: DeviceInfo | null, pluginName: string | null, context: Record<string, unknown> | null): Record<string, string> {
  const vars: Record<string, string> = {
    'notification.title': row.title,
    'notification.message': row.message,
    'notification.severity': row.severity,
    'notification.source': row.source,
    'notification.status': row.status,
    'notification.createdAt': row.createdAt,
    'notification.lastSeenAt': row.lastSeenAt,
    'notification.occurrences': String(row.occurrences),
  };
  if (device) {
    vars['device.name'] = device.name;
    if (device.address) vars['device.address'] = device.address;
    vars['device.vendor'] = device.vendor;
    if (device.tags.length > 0) vars['device.tags'] = device.tags.join(', ');
    if (device.deviceTypes.length > 0) vars['device.types'] = device.deviceTypes.join(', ');
    if (device.siteName) vars['device.site'] = device.siteName;
    vars['device.status'] = device.status;
  }
  if (pluginName) vars['plugin.name'] = pluginName;
  // context.* — dot-paths into the structured details object (e.g. {{context.from}}).
  if (context && typeof context === 'object') {
    for (const [k, v] of Object.entries(context)) {
      if (v !== null && typeof v !== 'object') vars[`context.${k}`] = String(v);
    }
  }
  return vars;
}

/**
 * True when a delivery fired within the cooldown window. Without `channelId` this is
 * RULE-level (any delivery of the rule suppresses it — shared-channel semantics);
 * with one it is per-(rule, channel), so audience fan-out rate-limits each person's
 * personal channel individually.
 */
async function inCooldown(ruleId: string, cooldownSec: number, channelId?: string): Promise<boolean> {
  if (cooldownSec <= 0) return false;
  const where = channelId
    ? and(eq(schema.notificationDeliveries.ruleId, ruleId), eq(schema.notificationDeliveries.channelId, channelId))
    : eq(schema.notificationDeliveries.ruleId, ruleId);
  const last = await db.query.notificationDeliveries.findFirst({
    where,
    orderBy: [desc(schema.notificationDeliveries.sentAt)],
  });
  if (!last) return false;
  const t = Date.parse(last.sentAt);
  return !Number.isNaN(t) && Date.now() - t < cooldownSec * 1000;
}

async function recordDelivery(ruleId: string | null, channelId: string, notificationId: string | null, status: 'sent' | 'failed', error: string | null): Promise<void> {
  await db.insert(schema.notificationDeliveries).values({
    id: uuidv4(),
    ruleId,
    channelId,
    notificationId,
    status,
    error,
    sentAt: new Date().toISOString(),
  });
}

/** True when the plugin row exists and was seen within the online window. */
async function isPluginOnline(pluginId: string): Promise<boolean> {
  const row = await db.query.plugins.findFirst({ where: eq(schema.plugins.id, pluginId) });
  if (!row || !row.lastSeenAt) return false;
  const t = Date.parse(row.lastSeenAt);
  return !Number.isNaN(t) && Date.now() - t <= ONLINE_WINDOW_MS;
}

/**
 * Delivers one rendered message to ONE channel. The channel row is the
 * authority for type + config (the caller only supplies the rendered message).
 * Returns the error string on failure (null on success). Never throws — every
 * failure mode becomes a 'failed' delivery record, not an exception up-stack.
 */
async function deliverToChannel(
  channelId: string,
  payload: { severity: string; title: string; body: string },
): Promise<{ error: string | null }> {
  const channel = await db.query.notificationChannels.findFirst({ where: eq(schema.notificationChannels.id, channelId) });
  if (!channel || !channel.enabled) return { error: 'Channel not found or disabled' };

  if (!(await isPluginOnline(channel.pluginId))) {
    return { error: `Sender plugin ${channel.pluginId} is offline` };
  }
  const plugin = await db.query.plugins.findFirst({ where: eq(schema.plugins.id, channel.pluginId) });
  if (!plugin) return { error: 'Sender plugin row missing' };

  // Credentials — decrypted on demand from the pluggable secrets provider.
  let credentials: Record<string, string> = {};
  if (channel.secretId) {
    try {
      const secret = await getSecret(channel.secretId);
      credentials = secret.fields ?? {};
    } catch (err) {
      return { error: `Could not decrypt bound secret: ${(err as Error).message}` };
    }
  }

  let config: Record<string, unknown> = {};
  try {
    const parsed = JSON.parse(channel.config || '{}');
    if (parsed && typeof parsed === 'object') config = parsed;
  } catch { /* malformed stored config — send with empty config and let the plugin report it */ }

  try {
    const res = await pluginAxios(plugin.endpoint, {
      timeout: NOTIFY_TIMEOUT_MS,
      headers: { 'x-plugin-api-key': process.env.PLUGIN_API_KEY ?? '' },
    }).post('/notify', {
      channelType: channel.channelType,
      config,
      credentials,
      severity: payload.severity,
      title: payload.title,
      body: payload.body,
    });
    const out = (res.data ?? {}) as { success?: boolean; error?: string };
    if (out.success === false) return { error: out.error || 'Sender plugin reported failure' };
    return { error: null };
  } catch (err) {
    const e = err as { response?: { data?: unknown; status?: number }; message: string };
    let detail = '';
    try {
      const raw = e.response?.data;
      const body = typeof raw === 'string' ? raw : JSON.stringify(raw ?? '');
      const parsed = JSON.parse(body) as { error?: unknown };
      if (parsed && typeof parsed.error === 'string') detail = `: ${parsed.error}`;
    } catch { /* non-JSON body — keep axios message */ }
    return { error: `POST /notify failed${detail || ` (${e.message})`}` };
  }
}

/**
 * Dispatches one NEWLY INSERTED notification row through every enabled rule.
 * Fire-and-forget by contract (the caller does not await it); never throws.
 */
export async function dispatchNotification(notificationId: string): Promise<void> {
  try {
    const row = await db.query.notifications.findFirst({ where: eq(schema.notifications.id, notificationId) });
    if (!row || !['open', 'acknowledged'].includes(row.status)) return;

    const rules = await db.query.notificationRules.findMany({ where: eq(schema.notificationRules.enabled, true) });
    if (rules.length === 0) return;

    // Join the device once — every rule filter shares it.
    const device = await loadDeviceInfo(row.deviceId);
    let pluginName: string | null = null;
    if (row.pluginId) {
      const p = await db.query.plugins.findFirst({ where: eq(schema.plugins.id, row.pluginId) });
      pluginName = p?.name ?? null;
    }

    // Lazy cache of all users — audience fan-out needs it; loaded at most once per dispatch.
    let userCache: AudienceUser[] | null = null;
    const loadAudienceUsers = async (): Promise<AudienceUser[]> => {
      if (!userCache) {
        const users = await db.query.users.findMany();
        userCache = users.map((u) => ({ id: u.id, roles: parseStrArray(u.roles), disabled: u.disabled }));
      }
      return userCache;
    };

    for (const rule of rules) {
      const filter = parseFilter(rule.filter);
      if (!ruleMatches(filter, row, device)) continue;

      const cooldownSec = Number(rule.cooldownSec) || 0;
      const audience = parseAudience(rule.audience);
      const fanOutTypes = audience.fanOutTypes ?? [];

      const vars = buildNotificationVars(
        { title: row.title, message: row.message ?? '', severity: row.severity, source: row.source, status: row.status, createdAt: row.createdAt, lastSeenAt: row.lastSeenAt, occurrences: row.occurrences ?? 1 },
        device,
        pluginName,
        (row.context as Record<string, unknown> | null) ?? null,
      );
      const title = renderTemplate(rule.titleTemplate || '{{notification.title}}', vars).slice(0, 300);
      const body = renderTemplate(rule.bodyTemplate || '', vars).slice(0, 4000);

      const sharedChannelIds = parseStrArray(rule.channelIds);
      if (sharedChannelIds.length === 0 && fanOutTypes.length === 0) continue;

      // Shared channels — rule-level cooldown: any delivery of THIS rule within the window suppresses it.
      if (sharedChannelIds.length > 0 && !(await inCooldown(rule.id, cooldownSec))) {
        for (const channelId of sharedChannelIds) {
          const result = await deliverToChannel(channelId, { severity: row.severity, title, body });
          await recordDelivery(rule.id, channelId, row.id, result.error ? 'failed' : 'sent', result.error);
        }
      }

      // Audience fan-out — each member's PERSONAL channels of the listed types get the message,
      // rate-limited per (rule, personal channel) so every person has their own cooldown window.
      if (fanOutTypes.length > 0) {
        const users = await loadAudienceUsers();
        for (const user of users) {
          if (!audienceIncludesUser(audience, user)) continue;
          const personal = await db.query.notificationChannels.findMany({
            where: and(eq(schema.notificationChannels.ownerId, user.id), eq(schema.notificationChannels.enabled, true)),
          });
          for (const ch of personal) {
            if (!fanOutTypes.includes(ch.channelType.toLowerCase())) continue;
            if (await inCooldown(rule.id, cooldownSec, ch.id)) continue;
            const result = await deliverToChannel(ch.id, { severity: row.severity, title, body });
            await recordDelivery(rule.id, ch.id, row.id, result.error ? 'failed' : 'sent', result.error);
          }
        }
      }
    }
  } catch (err) {
    // Dispatch is best-effort by contract — a failure here must never break the emitter.
    console.error('[notification-dispatch] dispatch failed:', err);
  }
}

/**
 * Sends a test message through ONE channel (the UI's "Send test" button).
 * Uses fixed sample content so no rule/template is involved; records a delivery
 * row with ruleId null for the audit trail. Returns the error string or null.
 */
export async function sendChannelTest(channelId: string): Promise<{ error: string | null }> {
  const result = await deliverToChannel(channelId, {
    severity: 'info',
    title: '[UNM] Test notification',
    body: `This is a test message sent by Unified Network Manager at ${new Date().toISOString()}. If you can read this, the channel works.`,
  });
  await recordDelivery(null, channelId, null, result.error ? 'failed' : 'sent', result.error);
  return result;
}
