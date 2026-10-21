/**
 * The netcup SCP action registry — plan-gated writes served to UNM's plans system.
 *
 * Modules:
 *   - Servers    : power (start/stop/reboot), hostname, nickname
 *   - Snapshots  : create / delete / revert
 *   - Rescue     : activate / deactivate the netcup rescue system
 *   - ISO        : attach / detach boot media
 *   - Image      : full OS re-install (DANGEROUS — wipes the disk)
 *   - Firewall   : policy CRUD + apply a policy set to one interface
 *   - rDNS       : set / delete reverse DNS for v4/v6 addresses
 *   - Tasks      : cancel a running SCP task
 *
 * Conventions (mirrors zabbix/truenas):
 *   - A ScpApiError means the API ANSWERED — hard/final failure. Transport-level
 *     errors are marked retryable so the plan executor re-dispatches per policy.
 *   - Power actions set retryOnDispatchFailure:false (flapping guard).
 *   - Writes verify by RE-READING state afterwards (pollUntil) and report
 *     verified:true only when the target state was actually observed; async 202+TaskInfo
 *     endpoints are verified via task polling.
 */

import { ActionDescriptor, ActionResult, createRegistry, isTransientTransportError, pollUntil } from '@unm/plugin-sdk';
import type { ScpClient, ScpServer, ScpSnapshot, ScpFirewallPolicy, ScpFirewallRule, ScpTaskInfo } from './client/scpClient';
import { ScpApiError } from './client/scpClient';

/** Executor context for one /config step — the client is already bound + authenticated. */
export interface ScpActionContext {
  client: ScpClient;
  /** Effective plugin settings (defaults ⊕ per-device overrides). */
  settings: Record<string, unknown>;
}

function errMsg(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

/** Classifies a failure into an ActionResult — API errors are final, transport errors retryable. */
function failureResult(err: unknown): ActionResult {
  const retryable = !(err instanceof ScpApiError) && isTransientTransportError(err);
  return { success: false, error: errMsg(err), ...(retryable ? { retryable: true } : {}) };
}

/** Resolves the numeric server id from input (accepts number or numeric string). */
function serverIdOf(input: Record<string, unknown>): number | null {
  const v = input['serverId'];
  if (typeof v === 'number' && Number.isInteger(v) && v > 0) return v;
  if (typeof v === 'string' && /^\d+$/.test(v.trim())) return parseInt(v.trim(), 10);
  return null;
}

/** Waits for an async SCP task to reach a terminal state. */
async function waitForTask(client: ScpClient, task: ScpTaskInfo | undefined, timeoutMs = 300_000): Promise<{ ok: boolean; task?: ScpTaskInfo }> {
  if (!task?.uuid) return { ok: false };
  const wait = await pollUntil(
    async () => client.getTask(task.uuid),
    (t) => t.state === 'FINISHED' || t.state === 'ERROR' || t.state === 'CANCELED',
    { timeoutMs, intervalMs: 3_000 },
  );
  const final = wait.value;
  return { ok: !!final && final.state === 'FINISHED', task: final };
}

// --- Servers ---------------------------------------------------------------------

const serverStartAction: ActionDescriptor<ScpActionContext> = {
  id: 'server.start',
  label: 'Start server (VM)',
  description: 'Powers the VM on (state ON). Verified by polling until the server reports RUNNING.',
  module: 'Servers',
  riskLevel: 'write' as const,
  deviceCount: 1 as const,
  retryOnDispatchFailure: false,
  timeoutMs: 300_000,
  inputSchema: {
    serverId: { type: 'number', required: true, min: 1, description: 'SCP server id (see the Servers metric table)' },
  },
  async execute(ctx, input) {
    const id = serverIdOf(input);
    if (!id) return { success: false, error: 'serverId must be a positive integer' };
    try {
      const before = await ctx.client.getServer(id).catch(() => null);
      await ctx.client.patchServerState(id, 'ON');
      const wait = await pollUntil(
        async () => (await ctx.client.getServer(id)).serverLiveInfo?.state ?? 'unknown',
        (s) => s === 'RUNNING',
        { timeoutMs: 180_000, intervalMs: 5_000 },
      );
      return { success: true, applied: true, verified: wait.ok, details: { before: before?.serverLiveInfo?.state ?? null, after: wait.value ?? null } };
    } catch (err) {
      return failureResult(err);
    }
  },
};

const serverStopAction: ActionDescriptor<ScpActionContext> = {
  id: 'server.stop',
  label: 'Stop server (VM)',
  description: 'Powers the VM off (state OFF, POWEROFF). Verified by polling until SHUTOFF. DANGEROUS for workloads — use a plan with confirmation.',
  module: 'Servers',
  riskLevel: 'dangerous' as const,
  deviceCount: 1 as const,
  retryOnDispatchFailure: false,
  timeoutMs: 300_000,
  inputSchema: {
    serverId: { type: 'number', required: true, min: 1, description: 'SCP server id (see the Servers metric table)' },
  },
  async execute(ctx, input) {
    const id = serverIdOf(input);
    if (!id) return { success: false, error: 'serverId must be a positive integer' };
    try {
      const before = await ctx.client.getServer(id).catch(() => null);
      await ctx.client.patchServerState(id, 'OFF');
      const wait = await pollUntil(
        async () => (await ctx.client.getServer(id)).serverLiveInfo?.state ?? 'unknown',
        (s) => s === 'SHUTOFF' || s === 'BLOCKED',
        { timeoutMs: 180_000, intervalMs: 5_000 },
      );
      return { success: true, applied: true, verified: wait.ok, details: { before: before?.serverLiveInfo?.state ?? null, after: wait.value ?? null } };
    } catch (err) {
      return failureResult(err);
    }
  },
};

const serverRebootAction: ActionDescriptor<ScpActionContext> = {
  id: 'server.reboot',
  label: 'Reboot server (VM)',
  description: 'Reboots the VM. stateOption POWERCYCLE = hard power cycle; RESET = ACPI reset (graceful when the guest cooperates). Verified by polling until RUNNING again.',
  module: 'Servers',
  riskLevel: 'dangerous' as const,
  deviceCount: 1 as const,
  retryOnDispatchFailure: false,
  timeoutMs: 300_000,
  inputSchema: {
    serverId: { type: 'number', required: true, min: 1, description: 'SCP server id (see the Servers metric table)' },
    stateOption: { type: 'string', required: false, enum: ['POWERCYCLE', 'RESET'], default: 'POWERCYCLE', description: 'Reboot mode' },
  },
  async execute(ctx, input) {
    const id = serverIdOf(input);
    if (!id) return { success: false, error: 'serverId must be a positive integer' };
    const option = typeof input['stateOption'] === 'string' ? (input['stateOption'] as string) : 'POWERCYCLE';
    try {
      const before = await ctx.client.getServer(id).catch(() => null);
      await ctx.client.patchServerState(id, 'ON', option);
      const wait = await pollUntil(
        async () => (await ctx.client.getServer(id)).serverLiveInfo?.state ?? 'unknown',
        (s) => s === 'RUNNING',
        { timeoutMs: 180_000, intervalMs: 5_000 },
      );
      return { success: true, applied: true, verified: wait.ok, details: { before: before?.serverLiveInfo?.state ?? null, after: wait.value ?? null, stateOption: option } };
    } catch (err) {
      return failureResult(err);
    }
  },
};

const serverHostnameAction: ActionDescriptor<ScpActionContext> = {
  id: 'server.hostname.set',
  label: 'Set server hostname',
  description: 'Sets the VM\'s hostname attribute (merge-patch). Verified by re-reading the server.',
  module: 'Servers',
  riskLevel: 'write' as const,
  deviceCount: 1 as const,
  inputSchema: {
    serverId: { type: 'number', required: true, min: 1, description: 'SCP server id' },
    hostname: { type: 'string', required: true, minLength: 1, maxLength: 255, pattern: '(?=^([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\\-]{0,61}[a-zA-Z0-9])(\\.[a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\\-]{0,61}[a-zA-Z0-9]))*$).{1,255}', description: 'New hostname (RFC 1123)' },
  },
  async execute(ctx, input) {
    const id = serverIdOf(input);
    if (!id) return { success: false, error: 'serverId must be a positive integer' };
    const hostname = String(input['hostname']);
    try {
      await ctx.client.patchServerHostname(id, hostname);
      const wait = await pollUntil(
        async () => (await ctx.client.getServer(id)).hostname ?? null,
        (h) => h === hostname,
        { timeoutMs: 30_000, intervalMs: 2_000 },
      );
      return { success: true, applied: true, verified: wait.ok, details: { hostname } };
    } catch (err) {
      return failureResult(err);
    }
  },
};

const serverNicknameAction: ActionDescriptor<ScpActionContext> = {
  id: 'server.nickname.set',
  label: 'Set server nickname',
  description: 'Sets the VM\'s display nickname (merge-patch). Verified by re-reading the server.',
  module: 'Servers',
  riskLevel: 'write' as const,
  deviceCount: 1 as const,
  inputSchema: {
    serverId: { type: 'number', required: true, min: 1, description: 'SCP server id' },
    nickname: { type: 'string', required: true, minLength: 1, maxLength: 255, description: 'Display name shown in the SCP UI' },
  },
  async execute(ctx, input) {
    const id = serverIdOf(input);
    if (!id) return { success: false, error: 'serverId must be a positive integer' };
    const nickname = String(input['nickname']);
    try {
      await ctx.client.patchServerNickname(id, nickname);
      const wait = await pollUntil(
        async () => (await ctx.client.getServer(id)).nickname ?? null,
        (n) => n === nickname,
        { timeoutMs: 30_000, intervalMs: 2_000 },
      );
      return { success: true, applied: true, verified: wait.ok, details: { nickname } };
    } catch (err) {
      return failureResult(err);
    }
  },
};

// --- Snapshots ---------------------------------------------------------------------

const snapshotCreateAction: ActionDescriptor<ScpActionContext> = {
  id: 'snapshot.create',
  label: 'Create VM snapshot',
  description: 'Creates a disk snapshot (async task). onlineSnapshot=true snapshots the running VM without stopping it; when false, diskName selects which disk. Verified by polling until the snapshot appears.',
  module: 'Snapshots',
  riskLevel: 'write' as const,
  deviceCount: 1 as const,
  timeoutMs: 600_000,
  inputSchema: {
    serverId: { type: 'number', required: true, min: 1, description: 'SCP server id' },
    name: { type: 'string', required: true, minLength: 1, maxLength: 255, description: 'Snapshot name (unique per VM)' },
    description: { type: 'string', required: false, maxLength: 255, description: 'Optional snapshot description' },
    onlineSnapshot: { type: 'boolean', required: false, default: true, description: 'true = live snapshot without stopping the VM; false requires diskName' },
    diskName: { type: 'string', required: false, description: 'Disk to snapshot (required when onlineSnapshot=false)' },
  },
  async execute(ctx, input) {
    const id = serverIdOf(input);
    if (!id) return { success: false, error: 'serverId must be a positive integer' };
    const name = String(input['name']);
    try {
      const online = typeof input['onlineSnapshot'] === 'boolean' ? (input['onlineSnapshot'] as boolean) : true;
      const body: { name: string; description?: string | null; diskName?: string | null; onlineSnapshot?: boolean } = { name, onlineSnapshot: online };
      if (typeof input['description'] === 'string') body.description = input['description'];
      if (!online || typeof input['diskName'] === 'string') body.diskName = typeof input['diskName'] === 'string' ? input['diskName'] : null;
      const task = await ctx.client.createSnapshot(id, body);
      const [taskRes, listRes] = await Promise.all([
        waitForTask(ctx.client, task, 300_000),
        pollUntil(
          async () => (await ctx.client.listSnapshots(id)).find((s) => s.name === name) ?? null,
          (s) => s !== null,
          { timeoutMs: 300_000, intervalMs: 5_000 },
        ),
      ]);
      const snap = listRes.value as ScpSnapshot | undefined;
      return {
        success: taskRes.ok && listRes.ok,
        applied: true,
        verified: listRes.ok,
        details: { name, uuid: snap?.uuid ?? null, taskState: taskRes.task?.state ?? 'unknown', ...(taskRes.task?.responseError ? { taskError: `${taskRes.task.responseError.code}: ${taskRes.task.responseError.message}` } : {}) },
      };
    } catch (err) {
      return failureResult(err);
    }
  },
};

const snapshotDeleteAction: ActionDescriptor<ScpActionContext> = {
  id: 'snapshot.delete',
  label: 'Delete VM snapshot',
  description: 'Deletes a disk snapshot by name (async task). DANGEROUS — the snapshot data is gone afterwards.',
  module: 'Snapshots',
  riskLevel: 'dangerous' as const,
  deviceCount: 1 as const,
  timeoutMs: 600_000,
  inputSchema: {
    serverId: { type: 'number', required: true, min: 1, description: 'SCP server id' },
    name: { type: 'string', required: true, minLength: 1, maxLength: 255, description: 'Snapshot name to delete' },
  },
  async execute(ctx, input) {
    const id = serverIdOf(input);
    if (!id) return { success: false, error: 'serverId must be a positive integer' };
    const name = String(input['name']);
    try {
      const task = await ctx.client.deleteSnapshot(id, name);
      const [taskRes, listRes] = await Promise.all([
        waitForTask(ctx.client, task, 300_000),
        pollUntil(
          async () => (await ctx.client.listSnapshots(id)).find((s) => s.name === name) ?? null,
          (s) => s === null,
          { timeoutMs: 300_000, intervalMs: 5_000 },
        ),
      ]);
      return { success: taskRes.ok && listRes.ok, applied: true, verified: listRes.ok, details: { name, taskState: taskRes.task?.state ?? 'unknown' } };
    } catch (err) {
      return failureResult(err);
    }
  },
};

const snapshotRevertAction: ActionDescriptor<ScpActionContext> = {
  id: 'snapshot.revert',
  label: 'Revert VM to snapshot',
  description: 'Restores the VM\'s disks from a named snapshot (async task). DANGEROUS — all changes made after the snapshot are LOST.',
  module: 'Snapshots',
  riskLevel: 'dangerous' as const,
  deviceCount: 1 as const,
  retryOnDispatchFailure: false,
  timeoutMs: 900_000,
  inputSchema: {
    serverId: { type: 'number', required: true, min: 1, description: 'SCP server id' },
    name: { type: 'string', required: true, minLength: 1, maxLength: 255, description: 'Snapshot name to revert to' },
  },
  async execute(ctx, input) {
    const id = serverIdOf(input);
    if (!id) return { success: false, error: 'serverId must be a positive integer' };
    const name = String(input['name']);
    try {
      const task = await ctx.client.revertSnapshot(id, name);
      const taskRes = await waitForTask(ctx.client, task, 600_000);
      return { success: taskRes.ok, applied: true, verified: taskRes.ok, details: { name, taskState: taskRes.task?.state ?? 'unknown', ...(taskRes.task?.responseError ? { taskError: `${taskRes.task.responseError.code}: ${taskRes.task.responseError.message}` } : {}) } };
    } catch (err) {
      return failureResult(err);
    }
  },
};

// --- Rescue system ---------------------------------------------------------------------

const rescueActivateAction: ActionDescriptor<ScpActionContext> = {
  id: 'rescue.activate',
  label: 'Activate rescue system',
  description: 'Boots the VM into the netcup rescue system (async task). Verified by polling until active=true.',
  module: 'Rescue',
  riskLevel: 'write' as const,
  deviceCount: 1 as const,
  timeoutMs: 300_000,
  inputSchema: {
    serverId: { type: 'number', required: true, min: 1, description: 'SCP server id' },
  },
  async execute(ctx, input) {
    const id = serverIdOf(input);
    if (!id) return { success: false, error: 'serverId must be a positive integer' };
    try {
      await ctx.client.activateRescueSystem(id);
      const wait = await pollUntil(
        async () => (await ctx.client.getRescueSystem(id)).active,
        (a) => a === true,
        { timeoutMs: 180_000, intervalMs: 5_000 },
      );
      return { success: true, applied: true, verified: wait.ok, details: {} };
    } catch (err) {
      return failureResult(err);
    }
  },
};

const rescueDeactivateAction: ActionDescriptor<ScpActionContext> = {
  id: 'rescue.deactivate',
  label: 'Deactivate rescue system',
  description: 'Disables the netcup rescue system so the VM boots its own disk again (async task). Verified by polling until active=false.',
  module: 'Rescue',
  riskLevel: 'write' as const,
  deviceCount: 1 as const,
  timeoutMs: 300_000,
  inputSchema: {
    serverId: { type: 'number', required: true, min: 1, description: 'SCP server id' },
  },
  async execute(ctx, input) {
    const id = serverIdOf(input);
    if (!id) return { success: false, error: 'serverId must be a positive integer' };
    try {
      await ctx.client.deactivateRescueSystem(id);
      const wait = await pollUntil(
        async () => (await ctx.client.getRescueSystem(id)).active,
        (a) => a === false,
        { timeoutMs: 180_000, intervalMs: 5_000 },
      );
      return { success: true, applied: true, verified: wait.ok, details: {} };
    } catch (err) {
      return failureResult(err);
    }
  },
};

// --- ISO ---------------------------------------------------------------------

const isoAttachAction: ActionDescriptor<ScpActionContext> = {
  id: 'iso.attach',
  label: 'Attach ISO to VM',
  description: 'Attaches boot media — either a catalog image (isoId from the server\'s ISO list) or an uploaded user ISO (userIsoName). Optionally switches the boot device to CD-ROM. Verified by re-reading the attached ISO.',
  module: 'ISO',
  riskLevel: 'write' as const,
  deviceCount: 1 as const,
  timeoutMs: 300_000,
  inputSchema: {
    serverId: { type: 'number', required: true, min: 1, description: 'SCP server id' },
    isoId: { type: 'number', required: false, min: 1, description: 'Catalog ISO image id (alternative to userIsoName)' },
    userIsoName: { type: 'string', required: false, minLength: 1, maxLength: 255, description: 'Uploaded user ISO name (alternative to isoId)' },
    changeBootDeviceToCdrom: { type: 'boolean', required: false, default: false, description: 'Also switch the boot device to CD-ROM' },
  },
  async execute(ctx, input) {
    const id = serverIdOf(input);
    if (!id) return { success: false, error: 'serverId must be a positive integer' };
    const body: Record<string, unknown> = {};
    if (typeof input['isoId'] === 'number') body['isoId'] = input['isoId'];
    if (typeof input['userIsoName'] === 'string') body['userIsoName'] = input['userIsoName'];
    if (!body['isoId'] && !body['userIsoName']) return { success: false, error: 'Provide isoId or userIsoName' };
    if (typeof input['changeBootDeviceToCdrom'] === 'boolean') body['changeBootDeviceToCdrom'] = input['changeBootDeviceToCdrom'];
    try {
      const task = await ctx.client.attachIso(id, body);
      const [taskRes, readRes] = await Promise.all([
        waitForTask(ctx.client, task, 180_000),
        pollUntil(
          async () => (await ctx.client.getAttachedIso(id)).isoAttached === true,
          (a) => a === true,
          { timeoutMs: 180_000, intervalMs: 5_000 },
        ),
      ]);
      return { success: taskRes.ok && readRes.ok, applied: true, verified: readRes.ok, details: { isoId: body['isoId'] ?? null, userIsoName: (body['userIsoName'] as string) ?? null } };
    } catch (err) {
      return failureResult(err);
    }
  },
};

const isoDetachAction: ActionDescriptor<ScpActionContext> = {
  id: 'iso.detach',
  label: 'Detach ISO from VM',
  description: 'Removes the attached boot media. Verified by re-reading until no ISO is attached.',
  module: 'ISO',
  riskLevel: 'write' as const,
  deviceCount: 1 as const,
  timeoutMs: 300_000,
  inputSchema: {
    serverId: { type: 'number', required: true, min: 1, description: 'SCP server id' },
  },
  async execute(ctx, input) {
    const id = serverIdOf(input);
    if (!id) return { success: false, error: 'serverId must be a positive integer' };
    try {
      await ctx.client.detachIso(id);
      const wait = await pollUntil(
        async () => (await ctx.client.getAttachedIso(id)).isoAttached === true,
        (a) => a === false,
        { timeoutMs: 120_000, intervalMs: 5_000 },
      );
      return { success: true, applied: true, verified: wait.ok, details: {} };
    } catch (err) {
      return failureResult(err);
    }
  },
};

// --- Image setup ---------------------------------------------------------------------

const imageSetupAction: ActionDescriptor<ScpActionContext> = {
  id: 'image.setup',
  label: 'Install OS image on VM',
  description:
    'Re-installs the operating system from a catalog flavour (async task, several minutes). DANGEROUS — WIPES THE DISK. Optional provisioning: hostname, locale, timezone, additional user + password, SSH key ids, custom script.',
  module: 'Image',
  riskLevel: 'dangerous' as const,
  deviceCount: 1 as const,
  retryOnDispatchFailure: false,
  timeoutMs: 1_800_000, // image installs can take well over ten minutes
  inputSchema: {
    serverId: { type: 'number', required: true, min: 1, description: 'SCP server id' },
    imageFlavourId: { type: 'number', required: true, min: 1, description: 'Catalog flavour id (see the flavours list in the SCP UI)' },
    hostname: { type: 'string', required: false, maxLength: 255, description: 'Hostname to provision' },
    locale: { type: 'string', required: false, description: 'Locale (e.g. en_US.UTF-8)' },
    timezone: { type: 'string', required: false, description: 'Timezone (e.g. Europe/Berlin)' },
    additionalUserUsername: { type: 'string', required: false, pattern: '^[a-z][a-z0-9_]{0,30}$', description: 'Additional user to create' },
    additionalUserPassword: { type: 'string', required: false, minLength: 8, description: 'Password for the additional user (upper+lower+digit)' },
    rootPartitionFullDiskSize: { type: 'boolean', required: false, default: true, description: 'Use the full disk for the root partition' },
    sshKeyIds: { type: 'array', required: false, items: { type: 'number' as const }, description: 'SCP SSH key ids to install' },
    customScript: { type: 'string', required: false, description: 'Custom setup script (run at first boot)' },
  },
  async execute(ctx, input) {
    const id = serverIdOf(input);
    if (!id) return { success: false, error: 'serverId must be a positive integer' };
    const flavourId = typeof input['imageFlavourId'] === 'number' ? (input['imageFlavourId'] as number) : null;
    if (!flavourId) return { success: false, error: 'imageFlavourId is required' };
    try {
      const body: Record<string, unknown> = { imageFlavourId: flavourId, rootPartitionFullDiskSize: input['rootPartitionFullDiskSize'] !== false };
      for (const k of ['hostname', 'locale', 'timezone', 'additionalUserUsername', 'additionalUserPassword', 'customScript']) {
        if (typeof input[k] === 'string' && (input[k] as string) !== '') body[k] = input[k];
      }
      if (Array.isArray(input['sshKeyIds'])) body['sshKeyIds'] = input['sshKeyIds'];
      const task = await ctx.client.setupImage(id, body);
      const taskRes = await waitForTask(ctx.client, task, 1_500_000);
      return {
        success: taskRes.ok,
        applied: true,
        verified: taskRes.ok,
        details: { imageFlavourId: flavourId, taskState: taskRes.task?.state ?? 'unknown', ...(taskRes.task?.responseError ? { taskError: `${taskRes.task.responseError.code}: ${taskRes.task.responseError.message}` } : {}) },
      };
    } catch (err) {
      return failureResult(err);
    }
  },
};

// --- Firewall ---------------------------------------------------------------------

const RULE_ITEM = {
  type: 'object' as const,
  properties: {
    direction: { type: 'string' as const, required: true, enum: ['INGRESS', 'EGRESS'], description: 'Rule direction' },
    protocol: { type: 'string' as const, required: true, enum: ['TCP', 'UDP', 'ICMP', 'ICMPv6'], description: 'Protocol' },
    action: { type: 'string' as const, required: true, enum: ['ACCEPT', 'DROP'], description: 'Action' },
    sources: { type: 'array' as const, items: { type: 'string' as const }, description: 'Source IPs/CIDRs (empty = any)' },
    sourcePorts: { type: 'string' as const, description: 'Source ports (e.g. "1024-65535")' },
    destinations: { type: 'array' as const, items: { type: 'string' as const }, description: 'Destination IPs/CIDRs (empty = any)' },
    destinationPorts: { type: 'string' as const, description: 'Destination ports (e.g. "22" or "80 443")' },
    description: { type: 'string' as const, maxLength: 255, description: 'Rule description' },
  },
};

/** Resolves the SCP user id bound to this token (needed for policy endpoints). */
async function requireUserId(ctx: ScpActionContext): Promise<number | null> {
  return ctx.client.resolveUserId();
}

const firewallPolicyCreateAction: ActionDescriptor<ScpActionContext> = {
  id: 'firewall.policy.create',
  label: 'Create firewall policy',
  description: 'Creates a named firewall policy with rules (account-scoped). Verified by re-reading the policy list. Apply it to an interface with firewall.interface.apply.',
  module: 'Firewall',
  riskLevel: 'write' as const,
  deviceCount: 1 as const,
  inputSchema: {
    name: { type: 'string', required: true, minLength: 1, maxLength: 255, description: 'Policy name (unique per account)' },
    description: { type: 'string', required: false, maxLength: 255, description: 'Policy description' },
    rules: { type: 'array', required: true, items: RULE_ITEM, description: 'Ordered rule list' },
  },
  async execute(ctx, input) {
    const userId = await requireUserId(ctx);
    if (userId === null) return { success: false, error: 'Could not resolve the SCP user id for this token — no tasks with an executing user were found. Run any task in the SCP UI once, then retry.' };
    const name = String(input['name']);
    try {
      // validateInput already checked every rule against RULE_ITEM (enums + shapes).
      const rules = Array.isArray(input['rules']) ? (input['rules'] as ScpFirewallRule[]) : [];
      const body: { name: string; description?: string; rules: ScpFirewallRule[] } = { name, rules };
      if (typeof input['description'] === 'string') body.description = input['description'];
      const created = await ctx.client.createFirewallPolicy(userId, body);
      const wait = await pollUntil(
        async () => (await ctx.client.listFirewallPolicies(userId)).find((p) => p.id === created.id) ?? null,
        (p) => p !== null,
        { timeoutMs: 30_000, intervalMs: 2_000 },
      );
      return { success: true, applied: true, verified: wait.ok, details: { policyId: created.id, name } };
    } catch (err) {
      return failureResult(err);
    }
  },
};

const firewallPolicyUpdateAction: ActionDescriptor<ScpActionContext> = {
  id: 'firewall.policy.update',
  label: 'Update firewall policy',
  description: 'Replaces a policy\'s name/description/rules (PUT). Verified by re-reading the policy list.',
  module: 'Firewall',
  riskLevel: 'write' as const,
  deviceCount: 1 as const,
  inputSchema: {
    policyId: { type: 'number', required: true, min: 1, description: 'Policy id to update' },
    name: { type: 'string', required: false, minLength: 1, maxLength: 255, description: 'New name (omit to keep)' },
    description: { type: 'string', required: false, maxLength: 255, description: 'New description' },
    rules: { type: 'array', required: true, items: RULE_ITEM, description: 'Full replacement rule list' },
  },
  async execute(ctx, input) {
    const userId = await requireUserId(ctx);
    if (userId === null) return { success: false, error: 'Could not resolve the SCP user id for this token — no tasks with an executing user were found.' };
    const policyId = typeof input['policyId'] === 'number' ? (input['policyId'] as number) : null;
    if (!policyId) return { success: false, error: 'policyId must be a positive integer' };
    try {
      const rules = Array.isArray(input['rules']) ? (input['rules'] as ScpFirewallRule[]) : [];
      const body: { name?: string; description?: string; rules?: ScpFirewallRule[] } = { rules };
      if (typeof input['name'] === 'string') body.name = input['name'];
      if (typeof input['description'] === 'string') body.description = input['description'];
      await ctx.client.updateFirewallPolicy(userId, policyId, body);
      const wait = await pollUntil(
        async () => (await ctx.client.listFirewallPolicies(userId)).find((p) => p.id === policyId) ?? null,
        (p) => p !== null,
        { timeoutMs: 30_000, intervalMs: 2_000 },
      );
      return { success: true, applied: true, verified: wait.ok, details: { policyId } };
    } catch (err) {
      return failureResult(err);
    }
  },
};

const firewallPolicyDeleteAction: ActionDescriptor<ScpActionContext> = {
  id: 'firewall.policy.delete',
  label: 'Delete firewall policy',
  description: 'Deletes a firewall policy. DANGEROUS — interfaces still referencing it lose those rules on their next re-apply.',
  module: 'Firewall',
  riskLevel: 'dangerous' as const,
  deviceCount: 1 as const,
  inputSchema: {
    policyId: { type: 'number', required: true, min: 1, description: 'Policy id to delete' },
  },
  async execute(ctx, input) {
    const userId = await requireUserId(ctx);
    if (userId === null) return { success: false, error: 'Could not resolve the SCP user id for this token — no tasks with an executing user were found.' };
    const policyId = typeof input['policyId'] === 'number' ? (input['policyId'] as number) : null;
    if (!policyId) return { success: false, error: 'policyId must be a positive integer' };
    try {
      await ctx.client.deleteFirewallPolicy(userId, policyId);
      const wait = await pollUntil(
        async () => (await ctx.client.listFirewallPolicies(userId)).find((p) => p.id === policyId) ?? null,
        (p) => p === null,
        { timeoutMs: 30_000, intervalMs: 2_000 },
      );
      return { success: true, applied: true, verified: wait.ok, details: { policyId } };
    } catch (err) {
      return failureResult(err);
    }
  },
};

const firewallInterfaceApplyAction: ActionDescriptor<ScpActionContext> = {
  id: 'firewall.interface.apply',
  label: 'Apply firewall policies to interface',
  description:
    'Sets the policy set on one VM network interface (PUT — replaces copiedPolicies + userPolicies). DANGEROUS — a wrong rule set can cut off SSH access. Verified by task completion.',
  module: 'Firewall',
  riskLevel: 'dangerous' as const,
  deviceCount: 1 as const,
  retryOnDispatchFailure: false,
  timeoutMs: 300_000,
  inputSchema: {
    serverId: { type: 'number', required: true, min: 1, description: 'SCP server id' },
    mac: { type: 'string', required: true, minLength: 8, maxLength: 23, pattern: '^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$', description: 'Interface MAC (see the Networks metric rows)' },
    userPolicies: { type: 'array', required: true, items: { type: 'number' as const }, description: 'Own policy ids to apply (ordered)' },
    copiedPolicies: { type: 'array', required: false, items: { type: 'number' as const }, default: [], description: 'Copied/shared policy ids to include' },
    active: { type: 'boolean', required: false, default: true, description: 'Firewall active flag (default true)' },
  },
  async execute(ctx, input) {
    const id = serverIdOf(input);
    if (!id) return { success: false, error: 'serverId must be a positive integer' };
    const mac = String(input['mac']);
    const userPolicies = Array.isArray(input['userPolicies']) ? (input['userPolicies'] as number[]) : [];
    const copiedPolicies = Array.isArray(input['copiedPolicies']) ? (input['copiedPolicies'] as number[]) : [];
    try {
      const task = await ctx.client.putInterfaceFirewall(id, mac, { userPolicies, copiedPolicies, active: input['active'] !== false });
      const taskRes = await waitForTask(ctx.client, task, 180_000);
      return { success: taskRes.ok, applied: true, verified: taskRes.ok, details: { mac, userPolicies, copiedPolicies, taskState: taskRes.task?.state ?? 'unknown' } };
    } catch (err) {
      return failureResult(err);
    }
  },
};

// --- rDNS ---------------------------------------------------------------------

const rdnsSetAction: ActionDescriptor<ScpActionContext> = {
  id: 'rdns.set',
  label: 'Set reverse DNS (rDNS)',
  description: 'Sets the PTR record for an IPv4 or IPv6 address (auto-detected from the address). Verified by re-reading the rDNS entry.',
  module: 'rDNS',
  riskLevel: 'write' as const,
  deviceCount: 1 as const,
  inputSchema: {
    ip: { type: 'string', required: true, minLength: 3, description: 'IPv4 or IPv6 address to set the PTR for' },
    rdns: { type: 'string', required: true, minLength: 1, maxLength: 255, description: 'Reverse DNS name (FQDN)' },
  },
  async execute(ctx, input) {
    const ip = String(input['ip']);
    const rdns = String(input['rdns']);
    const isV6 = ip.includes(':');
    try {
      if (isV6) await ctx.client.setRdnsIpv6(ip, rdns);
      else await ctx.client.setRdnsIpv4(ip, rdns);
      const wait = await pollUntil(
        async () => ((isV6 ? await ctx.client.getRdnsIpv6(ip) : await ctx.client.getRdnsIpv4(ip)).rdns ?? null),
        (r) => r === rdns,
        { timeoutMs: 30_000, intervalMs: 2_000 },
      );
      return { success: true, applied: true, verified: wait.ok, details: { ip, rdns } };
    } catch (err) {
      return failureResult(err);
    }
  },
};

const rdnsDeleteAction: ActionDescriptor<ScpActionContext> = {
  id: 'rdns.delete',
  label: 'Delete reverse DNS (rDNS)',
  description: 'Removes the PTR record for an IPv4 or IPv6 address. Verified by re-reading until empty.',
  module: 'rDNS',
  riskLevel: 'write' as const,
  deviceCount: 1 as const,
  inputSchema: {
    ip: { type: 'string', required: true, minLength: 3, description: 'IPv4 or IPv6 address to clear the PTR for' },
  },
  async execute(ctx, input) {
    const ip = String(input['ip']);
    const isV6 = ip.includes(':');
    try {
      if (isV6) await ctx.client.deleteRdnsIpv6(ip);
      else await ctx.client.deleteRdnsIpv4(ip);
      const wait = await pollUntil(
        async () => ((isV6 ? await ctx.client.getRdnsIpv6(ip) : await ctx.client.getRdnsIpv4(ip)).rdns ?? null),
        (r) => r === null || r === '',
        { timeoutMs: 30_000, intervalMs: 2_000 },
      );
      return { success: true, applied: true, verified: wait.ok, details: { ip } };
    } catch (err) {
      return failureResult(err);
    }
  },
};

// --- Tasks ---------------------------------------------------------------------

const taskCancelAction: ActionDescriptor<ScpActionContext> = {
  id: 'task.cancel',
  label: 'Cancel running SCP task',
  description: 'Requests cancellation of a pending/running task by uuid. DANGEROUS — cancelling mid-flight can leave the VM in an intermediate state.',
  module: 'Tasks',
  riskLevel: 'dangerous' as const,
  deviceCount: 1 as const,
  inputSchema: {
    taskUuid: { type: 'string', required: true, minLength: 8, description: 'Task uuid (see the Tasks metric table)' },
  },
  async execute(ctx, input) {
    const uuid = String(input['taskUuid']);
    try {
      await ctx.client.cancelTask(uuid);
      const wait = await pollUntil(
        async () => (await ctx.client.getTask(uuid)).state,
        (s) => s === 'CANCELED' || s === 'FINISHED' || s === 'ERROR',
        { timeoutMs: 60_000, intervalMs: 3_000 },
      );
      return { success: true, applied: true, verified: wait.ok, details: { taskUuid: uuid, state: wait.value ?? null } };
    } catch (err) {
      return failureResult(err);
    }
  },
};

// --- Registry ---------------------------------------------------------------------

export const registry = createRegistry<ScpActionContext>([
  serverStartAction,
  serverStopAction,
  serverRebootAction,
  serverHostnameAction,
  serverNicknameAction,
  snapshotCreateAction,
  snapshotDeleteAction,
  snapshotRevertAction,
  rescueActivateAction,
  rescueDeactivateAction,
  isoAttachAction,
  isoDetachAction,
  imageSetupAction,
  firewallPolicyCreateAction,
  firewallPolicyUpdateAction,
  firewallPolicyDeleteAction,
  firewallInterfaceApplyAction,
  rdnsSetAction,
  rdnsDeleteAction,
  taskCancelAction,
]);
