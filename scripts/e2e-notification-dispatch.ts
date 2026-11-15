#!/usr/bin/env tsx
/**
 * Live E2E for pluggable notification dispatch (rules → templates → channels):
 *   0. Pre-clean — idempotently removes residue from previous/interrupted runs.
 *   A. Sender plugin — asserts a registered, online plugin advertises the
 *      notificationSender capability and its channel catalog (smtp/webhook/
 *      telegram) is persisted on the plugins row.
 *   B. Channel + test send — creates a webhook channel pointing at a local
 *      HTTP sink (container→host via bridge gateway), fires POST /test and
 *      asserts the sink received "[UNM] Test notification" plus a 'sent'
 *      delivery row (ruleId null).
 *   C. Rule + real dispatch — creates an always-match rule with templates and
 *      a critical-only negative rule, pushes a warning notification through
 *      POST /v1/plugin/notifications (the same internal endpoint plugins use),
 *      and asserts: the sink got the RENDERED title/body, a 'sent' delivery
 *      row exists for the rule, and the negative rule produced nothing.
 *   D. Cooldown — a 3600s-cooldown rule fires exactly once across two
 *      back-to-back triggers (second is suppressed by the delivery window).
 *   E. Cleanup (set KEEP=1 to leave the test data in place).
 *
 * All test rows carry distinctive values (e2e-notify-* names) so cleanup
 * deletes precisely what this script created. Requires the dev stack with the
 * basic-notifications plugin running (docker compose up basic-notifications-plugin).
 *
 * Usage: tsx scripts/e2e-notification-dispatch.ts   (from repo root; reads UNM_API_TOKEN + PLUGIN_API_KEY from .env)
 */
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { execSync } from 'node:child_process';

// Run from the repo root (tsx scripts/e2e-notification-dispatch.ts).
const API = process.env.API_URL || 'http://localhost:8080/v1';
const KEEP = process.env.KEEP === '1';
const SINK_PORT = Number(process.env.SINK_PORT ?? 9377);

// ── Plumbing ─────────────────────────────────────────────────────────────────
function sleep(ms: number): Promise<void> { return new Promise((r) => setTimeout(r, ms)); }
let failures = 0;
function check(name: string, ok: boolean, extra = ''): void {
  console.log(`  ${ok ? 'ok  ' : 'FAIL'} ${name}${extra ? ` — ${extra}` : ''}`);
  if (!ok) failures += 1;
}

const envFile = path.resolve(process.cwd(), '.env');
function envValue(key: string, fallback = ''): string {
  if (process.env[key]) return process.env[key];
  if (fs.existsSync(envFile)) {
    const line = fs.readFileSync(envFile, 'utf8').split('\n').find((l) => l.startsWith(`${key}=`));
    if (line) return line.slice(line.indexOf('=') + 1).trim().replace(/^"|"$/g, '');
  }
  return fallback;
}

const token = envValue('UNM_API_TOKEN');
if (!token) { console.error('No UNM_API_TOKEN found (.env or env) — aborting'); process.exit(2); }
// The internal /plugin/* routes authenticate with the shared plugin key.
const pluginKey = envValue('PLUGIN_API_KEY', 'dev-plugin-key');

async function api<T>(method: string, p: string, body?: unknown, headers: Record<string, string> = {}): Promise<{ status: number; data: T }> {
  const res = await fetch(`${API}${p}`, {
    method,
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}`, ...headers },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  let data: T;
  try { data = (await res.json()) as T; } catch { data = undefined as unknown as T; }
  return { status: res.status, data };
}

async function pollUntil(timeoutMs: number, fn: () => Promise<boolean>): Promise<boolean> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try { if (await fn()) return true; } catch { /* retry */ }
    await sleep(2_000);
  }
  return false;
}

/** Container→host address for the local sink (docker bridge gateway). */
function discoverHostForContainers(): string {
  const raw = execSync(`docker inspect unifiednetworkmanager-api-1 --format '{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}'`, { encoding: 'utf8' }).trim();
  const ip = raw.split(/\s+/)[0];
  if (!ip || !ip.includes('.')) throw new Error(`could not determine API container IP (got "${raw}")`);
  return `${ip.split('.').slice(0, 3).join('.')}.1`; // standard bridge gateway x.y.0.1
}

// ── Local webhook sink ───────────────────────────────────────────────────────
interface SinkHit { title: string; body: string; severity: string }
const sinkHits: SinkHit[] = [];
let sinkServer: http.Server | null = null;

function startSink(): Promise<void> {
  return new Promise((resolve) => {
    sinkServer = http.createServer((req, res) => {
      let raw = '';
      req.on('data', (c) => { raw += c; });
      req.on('end', () => {
        try {
          const j = JSON.parse(raw || '{}') as Record<string, unknown>;
          sinkHits.push({ title: String(j.title ?? ''), body: String(j.body ?? ''), severity: String(j.severity ?? '') });
        } catch { /* non-JSON — ignore */ }
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end('{"ok":true}');
      });
    });
    sinkServer.listen(SINK_PORT, '0.0.0.0', () => resolve());
  });
}

// ── Types (mirrors of the API's serialized shapes) ───────────────────────────
interface PluginRow { id: string; name: string; capabilities: string[]; lastSeenAt?: string | null; notificationChannels?: Array<{ type: string; label: string }> | null }
interface ChannelRow { id: string; name: string; channelType: string; enabled: boolean; config: Record<string, unknown>; secretId?: string | null; lastDelivery?: { status: string; sentAt: string; error: string | null } | null }
interface RuleRow { id: string; name: string; filter: Record<string, unknown>; channelIds: string[]; titleTemplate: string; bodyTemplate: string; cooldownSec: number }
interface DeliveryRow { id: string; ruleId?: string | null; channelId: string; status: 'sent' | 'failed'; error?: string | null; sentAt: string }

// ── 0. Pre-clean ─────────────────────────────────────────────────────────────
async function preClean(): Promise<void> {
  console.log('\n[0] Pre-clean — removing residue from previous runs');
  const rules = await api<RuleRow[]>('GET', '/notification-rules');
  for (const r of rules.data ?? []) if (r.name.startsWith('e2e-notify-')) await api('DELETE', `/notification-rules/${r.id}`);
  const channels = await api<ChannelRow[]>('GET', '/notification-channels');
  for (const c of channels.data ?? []) if (c.name.startsWith('e2e-notify-')) await api('DELETE', `/notification-channels/${c.id}`);
  // Leftover test users from a crashed run (their personal channels are gone by now).
  const users = await api<Array<{ id: string; username: string }>>('GET', '/users');
  for (const u of users.data ?? []) if (u.username.startsWith('e2e-notify-')) { await api('DELETE', `/users/${u.id}`); console.log(`  deleted user ${u.username}`); }
  const notes = await api<Array<{ id: string; title: string }>>('GET', '/notifications?search=e2e-notify-dispatch&all=true');
  for (const n of notes.data ?? []) await api('DELETE', `/notifications/${n.id}`);
}

// ── A. Sender plugin present + catalog persisted ─────────────────────────────
async function phaseA(): Promise<PluginRow> {
  console.log('\n[A] Sender plugin — capability + channel catalog');
  const r = await api<PluginRow[]>('GET', '/plugins');
  check('plugin list fetched (200)', r.status === 200, `status=${r.status}`);
  const sender = (r.data ?? []).find((p) => p.capabilities?.includes('notificationSender'));
  if (!sender) {
    console.error('No online plugin advertises notificationSender — start the basic-notifications plugin first:');
    console.error('  docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d --build basic-notifications-plugin');
    process.exit(2);
  }
  check(`sender plugin found (${sender.name})`, true, sender.id.slice(0, 8));
  const types = (sender.notificationChannels ?? []).map((c) => c.type).sort();
  check('catalog persisted with smtp/webhook/telegram', JSON.stringify(types) === JSON.stringify(['smtp', 'telegram', 'webhook']), `got ${types.join(',')}`);
  return sender;
}

// ── B. Channel + test send ───────────────────────────────────────────────────
async function phaseB(sender: PluginRow): Promise<string> {
  console.log('\n[B] Webhook channel + test send');
  const host = discoverHostForContainers();
  const url = `http://${host}:${SINK_PORT}/sink`;

  const created = await api<ChannelRow>('POST', '/notification-channels', {
    name: 'e2e-notify-channel',
    pluginId: sender.id,
    channelType: 'webhook',
    config: { url, method: 'POST', contentType: 'json' },
  });
  check('channel created (201)', created.status === 201, `status=${created.status} ${JSON.stringify(created.data ?? {}).slice(0, 80)}`);
  const channelId = created.data?.id ?? '';

  // Validation guard: an unknown channel type must be rejected.
  const badType = await api<{ error?: string }>('POST', '/notification-channels', {
    name: 'e2e-notify-badtype', pluginId: sender.id, channelType: 'carrier-pigeon', config: {},
  });
  check('unknown channel type rejected (400)', badType.status === 400, `status=${badType.status}`);

  const test = await api<{ sent?: boolean; error?: string }>('POST', `/notification-channels/${channelId}/test`);
  check('test send accepted (200 + sent)', test.status === 200 && test.data?.sent === true, `status=${test.status} ${JSON.stringify(test.data ?? {})}`);

  const gotTest = await pollUntil(15_000, async () => sinkHits.some((h) => h.title.includes('[UNM] Test notification')));
  check('sink received the test message', gotTest, `hits=${sinkHits.length}`);

  const deliveries = await api<DeliveryRow[]>('GET', `/notification-deliveries?channelId=${channelId}&limit=10`);
  const sentRow = (deliveries.data ?? []).find((d) => d.status === 'sent' && !d.ruleId);
  check("delivery row recorded (status=sent, ruleId null)", Boolean(sentRow), JSON.stringify(deliveries.data?.[0] ?? {}));

  return channelId;
}

// ── C. Rule + real dispatch through the notification center ──────────────────
async function phaseC(sender: PluginRow, channelId: string): Promise<void> {
  console.log('\n[C] Rule matching + template rendering (real notification row)');
  const rule = await api<RuleRow>('POST', '/notification-rules', {
    name: 'e2e-notify-rule',
    filter: {},
    channelIds: [channelId],
    titleTemplate: '[E2E] {{notification.title}}',
    bodyTemplate: 'sev={{notification.severity}} msg={{notification.message}} via={{plugin.name}}',
    cooldownSec: 0,
  });
  check('always-match rule created (201)', rule.status === 201, `status=${rule.status}`);
  const ruleId = rule.data?.id ?? '';

  // Negative control — critical-only filter must NOT fire on a warning row.
  const negRule = await api<RuleRow>('POST', '/notification-rules', {
    name: 'e2e-notify-negrule',
    filter: { severities: ['critical'] },
    channelIds: [channelId],
    titleTemplate: '[E2E-NEG] {{notification.title}}',
    bodyTemplate: 'should never arrive',
    cooldownSec: 0,
  });
  check('negative rule created (201)', negRule.status === 201);
  const negRuleId = negRule.data?.id ?? '';

  // Push a warning notification through the same internal endpoint plugins use.
  const before = sinkHits.length;
  const push = await api<{ accepted?: number }>('POST', '/plugin/notifications', {
    pluginId: sender.id,
    notifications: [{ severity: 'warning', title: 'e2e-notify-dispatch-title', message: 'e2e body text' }],
  }, { 'x-plugin-api-key': pluginKey });
  check('notification accepted (201 + accepted=1)', push.status === 201 && push.data?.accepted === 1, `status=${push.status} ${JSON.stringify(push.data ?? {})}`);

  // Dispatch is fire-and-forget — poll the delivery row.
  const delivered = await pollUntil(30_000, async () => {
    const d = await api<DeliveryRow[]>('GET', `/notification-deliveries?ruleId=${ruleId}&limit=10`);
    return (d.data ?? []).some((x) => x.status === 'sent');
  });
  check('delivery row for the rule (status=sent)', delivered);

  const gotRendered = await pollUntil(15_000, async () => sinkHits.slice(before).some((h) => h.title.includes('[E2E] e2e-notify-dispatch-title')));
  check('sink received the RENDERED title', gotRendered, `hits=${JSON.stringify(sinkHits.slice(before), null, 0).slice(0, 160)}`);
  const hit = sinkHits.find((h) => h.title.includes('[E2E] e2e-notify-dispatch-title'));
  check('body rendered from template (severity + message)', Boolean(hit && hit.body.includes('sev=warning') && hit.body.includes('msg=e2e body text')), `body=${hit?.body ?? '—'}`);

  // Give the negative rule a moment, then assert it stayed silent.
  await sleep(3_000);
  const negDeliveries = await api<DeliveryRow[]>('GET', `/notification-deliveries?ruleId=${negRuleId}&limit=10`);
  check('negative (critical-only) rule did not fire on a warning row', (negDeliveries.data ?? []).length === 0, `rows=${(negDeliveries.data ?? []).length}`);
}

// ── D. Cooldown suppression ──────────────────────────────────────────────────
async function phaseD(sender: PluginRow, channelId: string): Promise<void> {
  console.log('\n[D] Cooldown — one fire per window');
  const rule = await api<RuleRow>('POST', '/notification-rules', {
    name: 'e2e-notify-coolrule',
    filter: {},
    channelIds: [channelId],
    titleTemplate: '[E2E-COOL] {{notification.title}}',
    bodyTemplate: 'cooldown probe',
    cooldownSec: 3600,
  });
  check('cooldown rule created (201)', rule.status === 201);
  const ruleId = rule.data?.id ?? '';

  const pushOne = async (title: string) => {
    await api('POST', '/plugin/notifications', { pluginId: sender.id, notifications: [{ severity: 'warning', title }] }, { 'x-plugin-api-key': pluginKey });
  };

  await pushOne('e2e-notify-dispatch-cool-1');
  const first = await pollUntil(30_000, async () => {
    const d = await api<DeliveryRow[]>('GET', `/notification-deliveries?ruleId=${ruleId}&limit=10`);
    return (d.data ?? []).some((x) => x.status === 'sent');
  });
  check('first trigger delivered', first);

  // Second trigger inside the window — must be suppressed.
  await pushOne('e2e-notify-dispatch-cool-2');
  await sleep(5_000);
  const d = await api<DeliveryRow[]>('GET', `/notification-deliveries?ruleId=${ruleId}&limit=10`);
  const sentCount = (d.data ?? []).filter((x) => x.status === 'sent').length;
  check('second trigger suppressed by cooldown (exactly one delivery)', sentCount === 1, `sentRows=${sentCount}`);
}

// ── F. Audience fan-out to personal channels ────────────────────────────────
async function phaseF(sender: PluginRow): Promise<void> {
  console.log('\n[F] Audience — per-user fan-out to personal channels');
  const host = discoverHostForContainers();
  const url = `http://${host}:${SINK_PORT}/sink`;

  // 1. Test user (the admin token carries users:create).
  const createdUser = await api<{ user?: { id: string } }>('POST', '/users', {
    username: 'e2e-notify-user',
    password: 'E2eNotify!passw0rd',
  });
  check('test user created (201)', createdUser.status === 201, `status=${createdUser.status} ${JSON.stringify(createdUser.data ?? {}).slice(0, 80)}`);
  const userId = createdUser.data?.user?.id ?? '';

  // 2. Personal webhook channel owned by that user (admin has users:write).
  const ch = await api<ChannelRow>('POST', '/notification-channels', {
    name: 'e2e-notify-personal',
    pluginId: sender.id,
    channelType: 'webhook',
    config: { url, method: 'POST', contentType: 'json' },
    ownerId: userId,
  });
  check('personal channel created for the test user (201 + ownerId set)', ch.status === 201 && ch.data?.ownerId === userId, `status=${ch.status} owner=${ch.data?.ownerId ?? '—'}`);
  const personalChannelId = ch.data?.id ?? '';

  // Validation guard: an unknown owner must be rejected.
  const badOwner = await api<{ error?: string }>('POST', '/notification-channels', {
    name: 'e2e-notify-badowner', pluginId: sender.id, channelType: 'webhook', config: {},
    ownerId: '00000000-0000-4000-8000-00000000dead',
  });
  check('unknown owner rejected (400)', badOwner.status === 400, `status=${badOwner.status}`);

  // 3. Rule: NO shared channels — audience = the test user only, fan-out to webhooks.
  const rule = await api<RuleRow>('POST', '/notification-rules', {
    name: 'e2e-notify-fanrule',
    filter: {},
    channelIds: [],
    audience: { type: 'users', userIds: [userId], fanOutTypes: ['webhook'] },
    titleTemplate: '[E2E-FAN] {{notification.title}}',
    bodyTemplate: 'fan-out probe sev={{notification.severity}}',
    cooldownSec: 0,
  });
  check('fan-out rule created (201 + audience persisted)', rule.status === 201 && rule.data?.audience?.type === 'users' && JSON.stringify(rule.data?.audience?.userIds ?? []) === JSON.stringify([userId]), `status=${rule.status} ${JSON.stringify(rule.data?.audience ?? {})}`);
  const ruleId = rule.data?.id ?? '';

  // Validation guard: an unknown user id in the audience must be rejected.
  const badAudience = await api<{ error?: string }>('POST', '/notification-rules', {
    name: 'e2e-notify-badaud', filter: {}, channelIds: [],
    audience: { type: 'users', userIds: ['00000000-0000-4000-8000-00000000dead'], fanOutTypes: ['webhook'] },
    titleTemplate: 'x', cooldownSec: 0,
  });
  check('unknown audience user rejected (400)', badAudience.status === 400, `status=${badAudience.status}`);

  // 4. Trigger — the message must arrive via the PERSONAL channel.
  const before = sinkHits.length;
  await api('POST', '/plugin/notifications', { pluginId: sender.id, notifications: [{ severity: 'warning', title: 'e2e-notify-dispatch-fanout' }] }, { 'x-plugin-api-key': pluginKey });

  const delivered = await pollUntil(30_000, async () => {
    const d = await api<DeliveryRow[]>('GET', `/notification-deliveries?ruleId=${ruleId}&limit=10`);
    return (d.data ?? []).some((x) => x.status === 'sent' && x.channelId === personalChannelId);
  });
  check('fan-out delivery row for the PERSONAL channel (status=sent)', delivered);

  const gotFan = await pollUntil(15_000, async () => sinkHits.slice(before).some((h) => h.title.includes('[E2E-FAN]')));
  check('sink received the fan-out message', gotFan, `hits=${JSON.stringify(sinkHits.slice(before), null, 0).slice(0, 160)}`);

  // Negative control: an audience WITHOUT fanOutTypes (and no shared channels)
  // must stay completely silent.
  const noFan = await api<RuleRow>('POST', '/notification-rules', {
    name: 'e2e-notify-nofanrule', filter: {}, channelIds: [],
    audience: { type: 'users', userIds: [userId] },
    titleTemplate: '[E2E-NOFAN] {{notification.title}}', bodyTemplate: '', cooldownSec: 0,
  });
  const noFanId = noFan.data?.id ?? '';
  await api('POST', '/plugin/notifications', { pluginId: sender.id, notifications: [{ severity: 'warning', title: 'e2e-notify-dispatch-nofan' }] }, { 'x-plugin-api-key': pluginKey });
  await sleep(4_000);
  const noFanDeliveries = await api<DeliveryRow[]>('GET', `/notification-deliveries?ruleId=${noFanId}&limit=10`);
  check('audience without fanOutTypes stays silent (no shared channels either)', (noFanDeliveries.data ?? []).length === 0, `rows=${(noFanDeliveries.data ?? []).length}`);

  if (!KEEP) {
    await api('DELETE', `/notification-rules/${ruleId}`);
    await api('DELETE', `/notification-rules/${noFanId}`);
    await api('DELETE', `/notification-channels/${personalChannelId}`);
    await api('DELETE', `/users/${userId}`);
  }
}

// ── E. Cleanup ───────────────────────────────────────────────────────────────
async function cleanup(): Promise<void> {
  if (KEEP) { console.log('\n[E] KEEP=1 — leaving test data in place'); return; }
  console.log('\n[E] Cleanup');
  const rules = await api<RuleRow[]>('GET', '/notification-rules');
  for (const r of rules.data ?? []) if (r.name.startsWith('e2e-notify-')) { await api('DELETE', `/notification-rules/${r.id}`); console.log(`  deleted rule ${r.name}`); }
  const channels = await api<ChannelRow[]>('GET', '/notification-channels');
  for (const c of channels.data ?? []) if (c.name.startsWith('e2e-notify-')) { await api('DELETE', `/notification-channels/${c.id}`); console.log(`  deleted channel ${c.name}`); }
  const notes = await api<Array<{ id: string; title: string }>>('GET', '/notifications?search=e2e-notify-dispatch&all=true');
  for (const n of notes.data ?? []) { await api('DELETE', `/notifications/${n.id}`); console.log(`  closed notification "${n.title}"`); }
}

// ── Main ─────────────────────────────────────────────────────────────────────
async function main(): Promise<void> {
  console.log(`UNM notification dispatch E2E — API=${API}, sink=:${SINK_PORT}`);
  await startSink();
  try {
    await preClean();
    const sender = await phaseA();
    const channelId = await phaseB(sender);
    await phaseC(sender, channelId);
    await phaseD(sender, channelId);
    await phaseF(sender);
  } finally {
    await cleanup().catch((e) => console.error('cleanup error:', e.message));
    sinkServer?.close();
  }

  console.log(failures === 0 ? '\nALL CHECKS PASSED' : `\n${failures} CHECK(S) FAILED`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error('E2E crashed:', e);
  sinkServer?.close();
  process.exit(1);
});
