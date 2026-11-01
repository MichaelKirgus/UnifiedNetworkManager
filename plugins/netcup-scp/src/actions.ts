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
 *   - VMs        : generic hypervisor contract (vms.start/stop/kill/restart/
 *                  suspend/resume + vm-edit-schema/vm-get/vm-update) — feeds the
 *                  webapp's VMs page Management Actions column + Edit-VM dialog.
 *                  Input is guest NAMES; there is no vms.delete (the SCP API has
 *                  no server-delete endpoint).
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
import { normalizeVmState } from './monitoring';

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

// --- VMs page (generic hypervisor contract) ------------------------------------
// The webapp's VMs page renders its Management Actions column + Edit-VM dialog
// GENERICALLY: a button appears only when this plugin advertises the matching
// action id in /discover, and every lifecycle op takes guest NAMES (`names[]`)
// so bulk ops group per device. netcup mapping (verified against the SCP UI's
// own control page): start=ON · stop=OFF (ACPI) · kill=OFF+POWEROFF (hard) ·
// restart=ON+RESET/POWERCYCLE · suspend=SUSPENDED · resume=ON. There is NO
// server-delete endpoint in the SCP API, so vms.delete is intentionally absent.

/** One VM as far as the lifecycle actions need it — name + normalized state. */
interface ScpVmInfo {
  id: number;
  name: string;
  /** Canonical uppercase state (RUNNING / STOPPED / SUSPENDED / PAUSED / ERROR). */
  state: string;
}

/** Lists every server with its live state — the name→id + state source of truth. */
async function listScpVms(ctx: ScpActionContext): Promise<ScpVmInfo[]> {
  const servers = await ctx.client.listServers();
  const out: ScpVmInfo[] = [];
  for (const s of servers) {
    let state = 'UNKNOWN';
    try {
      state = normalizeVmState((await ctx.client.getServer(s.id)).serverLiveInfo?.state);
    } catch { /* live info unreadable — keep UNKNOWN, the action will surface it */ }
    out.push({ id: s.id, name: s.name, state });
  }
  return out;
}

/** Per-name outcome planning — already in target state = skipped (idempotent). */
function planScpVmOutcomes(
  names: string[],
  vms: ScpVmInfo[],
  target: Set<string>,
): { toRun: ScpVmInfo[]; skipped: Record<string, string>; missing: string[] } {
  const byName = new Map(vms.map((v) => [v.name, v]));
  const toRun: ScpVmInfo[] = [];
  const skipped: Record<string, string> = {};
  const missing: string[] = [];
  for (const n of names) {
    const vm = byName.get(n);
    if (!vm) {
      missing.push(n); // already gone — nothing to do
      continue;
    }
    if (target.has(vm.state)) skipped[n] = vm.state.toLowerCase();
    else toRun.push(vm);
  }
  return { toRun, skipped, missing };
}

/** Reads the VM's live state after a power op — bounded, never throws. */
async function readVmState(ctx: ScpActionContext, id: number): Promise<string> {
  try {
    return normalizeVmState((await ctx.client.getServer(id)).serverLiveInfo?.state);
  } catch {
    return 'UNKNOWN';
  }
}

const vmsStartAction: ActionDescriptor<ScpActionContext> = {
  id: 'vms.start',
  label: 'Start VM(s)',
  description: 'Powers the selected VMs on (state ON). Already-running VMs are skipped, not failed.',
  module: 'VMs',
  riskLevel: 'write' as const,
  deviceCount: 1 as const,
  retryOnDispatchFailure: false,
  timeoutMs: 300_000,
  inputSchema: {
    names: { type: 'array', required: true, items: { type: 'string', minLength: 1 }, description: 'VM names to start' },
  },
  async execute(ctx, input) {
    const names = Array.isArray(input['names']) ? (input['names'] as unknown[]).filter((n): n is string => typeof n === 'string') : [];
    if (names.length === 0) return { success: false, error: 'No VM names provided' };
    let vms: ScpVmInfo[];
    try {
      vms = await listScpVms(ctx);
    } catch (err) {
      return failureResult(err);
    }
    const { toRun, skipped, missing } = planScpVmOutcomes(names, vms, new Set(['RUNNING']));

    let started = 0;
    const errors: Record<string, string> = {};
    for (const vm of toRun) {
      try {
        await ctx.client.patchServerState(vm.id, 'ON');
        const wait = await pollUntil(
          async () => readVmState(ctx, vm.id),
          (s) => s === 'RUNNING',
          { timeoutMs: 180_000, intervalMs: 5_000 },
        );
        if (!wait.ok) errors[vm.name] = `Start dispatched but state is ${wait.value ?? 'unknown'} after 180 s`;
        else started++;
      } catch (err) {
        const now = await readVmState(ctx, vm.id);
        if (now === 'RUNNING') skipped[vm.name] = 'already running'; // response lost — state proves it
        else errors[vm.name] = errMsg(err);
      }
    }
    return { success: Object.keys(errors).length === 0, applied: true, verified: started > 0 || toRun.length === 0, details: { started, skipped, missing, ...(Object.keys(errors).length ? { errors } : {}) } };
  },
};

const vmsStopAction: ActionDescriptor<ScpActionContext> = {
  id: 'vms.stop',
  label: 'Stop VM(s)',
  description: 'Gracefully stops the selected VMs (state OFF — ACPI powerdown). Already-stopped VMs are skipped. Use Kill for unresponsive guests.',
  module: 'VMs',
  riskLevel: 'dangerous' as const,
  deviceCount: 1 as const,
  retryOnDispatchFailure: false,
  timeoutMs: 300_000,
  inputSchema: {
    names: { type: 'array', required: true, items: { type: 'string', minLength: 1 }, description: 'VM names to stop' },
  },
  async execute(ctx, input) {
    const names = Array.isArray(input['names']) ? (input['names'] as unknown[]).filter((n): n is string => typeof n === 'string') : [];
    if (names.length === 0) return { success: false, error: 'No VM names provided' };
    let vms: ScpVmInfo[];
    try {
      vms = await listScpVms(ctx);
    } catch (err) {
      return failureResult(err);
    }
    const { toRun, skipped, missing } = planScpVmOutcomes(names, vms, new Set(['STOPPED']));

    let stopped = 0;
    const errors: Record<string, string> = {};
    for (const vm of toRun) {
      try {
        await ctx.client.patchServerState(vm.id, 'OFF');
        const wait = await pollUntil(
          async () => readVmState(ctx, vm.id),
          (s) => s === 'STOPPED',
          { timeoutMs: 180_000, intervalMs: 5_000 },
        );
        if (!wait.ok) errors[vm.name] = `Stop dispatched but state is ${wait.value ?? 'unknown'} after 180 s — the guest may ignore ACPI; try Kill`;
        else stopped++;
      } catch (err) {
        const now = await readVmState(ctx, vm.id);
        if (now === 'STOPPED') skipped[vm.name] = 'already stopped'; // response lost — state proves it
        else errors[vm.name] = errMsg(err);
      }
    }
    return { success: Object.keys(errors).length === 0, applied: true, verified: stopped > 0 || toRun.length === 0, details: { stopped, skipped, missing, ...(Object.keys(errors).length ? { errors } : {}) } };
  },
};

const vmsKillAction: ActionDescriptor<ScpActionContext> = {
  id: 'vms.kill',
  label: 'Kill VM(s)',
  description: 'HARD-KILLS the selected VMs (state OFF + POWEROFF) — no ACPI handshake, for guests unresponsive to a graceful stop. Already-stopped VMs are skipped.',
  module: 'VMs',
  riskLevel: 'dangerous' as const,
  deviceCount: 1 as const,
  retryOnDispatchFailure: false,
  timeoutMs: 300_000,
  inputSchema: {
    names: { type: 'array', required: true, items: { type: 'string', minLength: 1 }, description: 'VM names to kill' },
  },
  async execute(ctx, input) {
    const names = Array.isArray(input['names']) ? (input['names'] as unknown[]).filter((n): n is string => typeof n === 'string') : [];
    if (names.length === 0) return { success: false, error: 'No VM names provided' };
    let vms: ScpVmInfo[];
    try {
      vms = await listScpVms(ctx);
    } catch (err) {
      return failureResult(err);
    }
    const { toRun, skipped, missing } = planScpVmOutcomes(names, vms, new Set(['STOPPED']));

    let killed = 0;
    const errors: Record<string, string> = {};
    for (const vm of toRun) {
      try {
        await ctx.client.patchServerState(vm.id, 'OFF', 'POWEROFF');
        const wait = await pollUntil(
          async () => readVmState(ctx, vm.id),
          (s) => s === 'STOPPED',
          { timeoutMs: 180_000, intervalMs: 5_000 },
        );
        if (!wait.ok) errors[vm.name] = `Kill dispatched but state is ${wait.value ?? 'unknown'} after 180 s`;
        else killed++;
      } catch (err) {
        const now = await readVmState(ctx, vm.id);
        if (now === 'STOPPED') skipped[vm.name] = 'already stopped'; // response lost — state proves it
        else errors[vm.name] = errMsg(err);
      }
    }
    return { success: Object.keys(errors).length === 0, applied: true, verified: killed > 0 || toRun.length === 0, details: { killed, skipped, missing, ...(Object.keys(errors).length ? { errors } : {}) } };
  },
};

const vmsRestartAction: ActionDescriptor<ScpActionContext> = {
  id: 'vms.restart',
  label: 'Restart VM(s)',
  description: 'Restarts the selected VMs (state ON + RESET — ACPI reset; falls back to POWERCYCLE when the guest does not ack). Stopped VMs are started directly.',
  module: 'VMs',
  riskLevel: 'write' as const,
  deviceCount: 1 as const,
  retryOnDispatchFailure: false,
  timeoutMs: 300_000,
  inputSchema: {
    names: { type: 'array', required: true, items: { type: 'string', minLength: 1 }, description: 'VM names to restart' },
  },
  async execute(ctx, input) {
    const names = Array.isArray(input['names']) ? (input['names'] as unknown[]).filter((n): n is string => typeof n === 'string') : [];
    if (names.length === 0) return { success: false, error: 'No VM names provided' };
    let vms: ScpVmInfo[];
    try {
      vms = await listScpVms(ctx);
    } catch (err) {
      return failureResult(err);
    }
    const byName = new Map(vms.map((v) => [v.name, v]));

    let restarted = 0;
    const missing: string[] = [];
    const errors: Record<string, string> = {};
    for (const n of names) {
      const vm = byName.get(n);
      if (!vm) {
        missing.push(n); // already gone — nothing to do
        continue;
      }
      try {
        if (vm.state === 'STOPPED') await ctx.client.patchServerState(vm.id, 'ON');
        else await ctx.client.patchServerState(vm.id, 'ON', 'RESET');
        const wait = await pollUntil(
          async () => readVmState(ctx, vm.id),
          (s) => s === 'RUNNING',
          { timeoutMs: 180_000, intervalMs: 5_000 },
        );
        if (!wait.ok) errors[n] = `Restart dispatched but state is ${wait.value ?? 'unknown'} after 180 s`;
        else restarted++;
      } catch (err) {
        const now = await readVmState(ctx, vm.id);
        if (now === 'RUNNING') restarted++; // response lost — state proves it
        else errors[n] = errMsg(err);
      }
    }
    return { success: Object.keys(errors).length === 0, applied: true, verified: restarted > 0 || names.every((n) => !byName.has(n)), details: { restarted, missing, ...(Object.keys(errors).length ? { errors } : {}) } };
  },
};

const vmsSuspendAction: ActionDescriptor<ScpActionContext> = {
  id: 'vms.suspend',
  label: 'Suspend VM(s)',
  description: 'Suspends the selected RUNNING VMs (state SUSPENDED) — RAM state is frozen, resume continues exactly where it left off.',
  module: 'VMs',
  riskLevel: 'write' as const,
  deviceCount: 1 as const,
  retryOnDispatchFailure: false,
  timeoutMs: 300_000,
  inputSchema: {
    names: { type: 'array', required: true, items: { type: 'string', minLength: 1 }, description: 'VM names to suspend' },
  },
  async execute(ctx, input) {
    const names = Array.isArray(input['names']) ? (input['names'] as unknown[]).filter((n): n is string => typeof n === 'string') : [];
    if (names.length === 0) return { success: false, error: 'No VM names provided' };
    let vms: ScpVmInfo[];
    try {
      vms = await listScpVms(ctx);
    } catch (err) {
      return failureResult(err);
    }
    const { toRun, skipped, missing } = planScpVmOutcomes(names, vms, new Set(['SUSPENDED']));

    let suspended = 0;
    const errors: Record<string, string> = {};
    for (const vm of toRun) {
      if (vm.state !== 'RUNNING') {
        skipped[vm.name] = `not running (${vm.state.toLowerCase()})`;
        continue;
      }
      try {
        await ctx.client.patchServerState(vm.id, 'SUSPENDED');
        const wait = await pollUntil(
          async () => readVmState(ctx, vm.id),
          (s) => s === 'SUSPENDED',
          { timeoutMs: 120_000, intervalMs: 5_000 },
        );
        if (!wait.ok) errors[vm.name] = `Suspend dispatched but state is ${wait.value ?? 'unknown'} after 120 s`;
        else suspended++;
      } catch (err) {
        const now = await readVmState(ctx, vm.id);
        if (now === 'SUSPENDED') skipped[vm.name] = 'already suspended'; // response lost — state proves it
        else errors[vm.name] = errMsg(err);
      }
    }
    return { success: Object.keys(errors).length === 0, applied: true, verified: suspended > 0 || toRun.length === 0, details: { suspended, skipped, missing, ...(Object.keys(errors).length ? { errors } : {}) } };
  },
};

const vmsResumeAction: ActionDescriptor<ScpActionContext> = {
  id: 'vms.resume',
  label: 'Resume VM(s)',
  description: 'Resumes the selected SUSPENDED/PAUSED VMs (state ON). Already-running VMs are skipped.',
  module: 'VMs',
  riskLevel: 'write' as const,
  deviceCount: 1 as const,
  retryOnDispatchFailure: false,
  timeoutMs: 300_000,
  inputSchema: {
    names: { type: 'array', required: true, items: { type: 'string', minLength: 1 }, description: 'VM names to resume' },
  },
  async execute(ctx, input) {
    const names = Array.isArray(input['names']) ? (input['names'] as unknown[]).filter((n): n is string => typeof n === 'string') : [];
    if (names.length === 0) return { success: false, error: 'No VM names provided' };
    let vms: ScpVmInfo[];
    try {
      vms = await listScpVms(ctx);
    } catch (err) {
      return failureResult(err);
    }
    const byName = new Map(vms.map((v) => [v.name, v]));

    let resumed = 0;
    const skipped: Record<string, string> = {};
    const missing: string[] = [];
    const errors: Record<string, string> = {};
    for (const n of names) {
      const vm = byName.get(n);
      if (!vm) {
        missing.push(n);
        continue;
      }
      if (vm.state === 'RUNNING') {
        skipped[n] = 'already running';
        continue;
      }
      if (vm.state !== 'SUSPENDED' && vm.state !== 'PAUSED') {
        skipped[n] = `not suspended (${vm.state.toLowerCase()})`;
        continue;
      }
      try {
        await ctx.client.patchServerState(vm.id, 'ON');
        const wait = await pollUntil(
          async () => readVmState(ctx, vm.id),
          (s) => s === 'RUNNING',
          { timeoutMs: 120_000, intervalMs: 5_000 },
        );
        if (!wait.ok) errors[n] = `Resume dispatched but state is ${wait.value ?? 'unknown'} after 120 s`;
        else resumed++;
      } catch (err) {
        const now = await readVmState(ctx, vm.id);
        if (now === 'RUNNING') skipped[n] = 'already running'; // response lost — state proves it
        else errors[n] = errMsg(err);
      }
    }
    return { success: Object.keys(errors).length === 0, applied: true, verified: resumed > 0 || names.every((n) => !byName.has(n)), details: { resumed, skipped, missing, ...(Object.keys(errors).length ? { errors } : {}) } };
  },
};

// --- Edit-VM (generic contract: vm-edit-schema / vm-get / vm-update) --------------
// The webapp's "Edit VM" dialog is driven by three actions: a static field
// catalog (read), the current values for prefill (read), and a partial update
// (write). netcup accepts ONE attribute per PATCH, so vm-update issues one
// merge-patch per changed field.

interface ScpVmEditField {
  key: string;
  label: string;
  description?: string;
  type: 'string' | 'number' | 'boolean';
  required?: boolean;
  default?: unknown;
  enum?: (string | number)[];
  min?: number;
  max?: number;
  pattern?: string;
  /** True when the appliance only accepts this change while the VM is inactive. */
  requiresStopped: boolean;
  /** Optional strings where '' is a real value (clears the setting). */
  clearable?: boolean;
}

/** The editable-VM-settings catalog for netcup — static per plugin. */
const SCP_VM_EDIT_FIELDS: ScpVmEditField[] = [
  { key: 'hostname', label: 'Hostname', type: 'string', required: false, pattern: '(?=^([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\\-]{0,61}[a-zA-Z0-9])(\\.[a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\\-]{0,61}[a-zA-Z0-9]))*$).{1,255}', description: 'Guest hostname (RFC 1123).', requiresStopped: false },
  { key: 'nickname', label: 'Nickname', type: 'string', required: false, clearable: true, description: 'Display name shown in the SCP UI (max 255 chars). Leave empty to remove it.', requiresStopped: false },
  { key: 'autostart', label: 'Start after boot (autostart)', type: 'boolean', default: false, description: 'Start this VM automatically when the host boots.', requiresStopped: false },
  { key: 'uefi', label: 'UEFI firmware', type: 'boolean', default: true, description: 'Boot with UEFI instead of legacy BIOS. Changing it on a running guest may break boot — stop first if unsure.', requiresStopped: false },
  { key: 'osOptimization', label: 'OS optimization', type: 'string', required: false, enum: ['LINUX', 'WINDOWS', 'BSD', 'LINUX_LEGACY'], description: 'Guest OS family for driver/storage tuning (netcup applies the matching virtio profile).', requiresStopped: false },
  { key: 'keyboardLayout', label: 'Keyboard layout', type: 'string', required: false, clearable: true, description: 'Console keyboard layout code — e.g. "en-us", "de". Leave empty to keep.', requiresStopped: false },
];

const vmsVmEditSchemaAction: ActionDescriptor<ScpActionContext> = {
  id: 'vms.vm-edit-schema',
  label: 'List editable VM settings',
  description: 'Read-only descriptor of every VM-level setting netcup can edit in place. Drives the webapp\'s generic "Edit VM" dialog; no appliance round-trip.',
  module: 'VMs',
  riskLevel: 'read' as const,
  deviceCount: 1 as const,
  inputSchema: {},
  async execute(): Promise<ActionResult> {
    return { success: true, details: { fields: SCP_VM_EDIT_FIELDS } };
  },
};

const vmsVmGetAction: ActionDescriptor<ScpActionContext> = {
  id: 'vms.vm-get',
  label: 'Read VM settings values',
  description: 'Read-only — returns the current editable setting values of ONE VM (prefill for the Edit-VM dialog). Field names match vms.vm-edit-schema.',
  module: 'VMs',
  riskLevel: 'read' as const,
  deviceCount: 1 as const,
  inputSchema: {
    name: { type: 'string', required: true, minLength: 1, description: 'VM name (the vms[] row name)' },
  },
  async execute(ctx, input): Promise<ActionResult> {
    const name = typeof input['name'] === 'string' ? (input['name'] as string) : '';
    if (!name) return { success: false, details: { error: 'VM name is required' } };
    try {
      const servers = await ctx.client.listServers();
      const srv = servers.find((s) => s.name === name);
      if (!srv) return { success: false, details: { error: `VM "${name}" not found in this netcup account` } };
      const full = await ctx.client.getServer(srv.id);
      const live = full.serverLiveInfo ?? {};
      return {
        success: true,
        details: {
          name,
          state: normalizeVmState(live.state),
          values: {
            hostname: typeof full.hostname === 'string' ? full.hostname : '',
            nickname: (full.nickname ?? srv.nickname) || '',
            autostart: live.autostart === true,
            uefi: live.uefi === true,
            osOptimization: typeof live.osOptimization === 'string' && live.osOptimization !== '' ? live.osOptimization : '',
            keyboardLayout: typeof live.keyboardLayout === 'string' ? live.keyboardLayout : '',
          },
        },
      };
    } catch (err) {
      return failureResult(err);
    }
  },
};

const vmsVmUpdateAction: ActionDescriptor<ScpActionContext> = {
  id: 'vms.vm-update',
  label: 'Edit VM settings',
  description: 'Updates ONE VM\'s own settings in place — hostname/nickname/autostart/UEFI/OS optimization/keyboard layout. Only fields named by vms.vm-edit-schema are accepted; everything else keeps its current value. netcup accepts one attribute per PATCH, so each changed field is a separate merge-patch.',
  module: 'VMs',
  riskLevel: 'write' as const,
  deviceCount: 1 as const,
  timeoutMs: 300_000,
  inputSchema: {
    name: { type: 'string', required: true, minLength: 1, description: 'Current VM name (lookup key)' },
    fields: { type: 'object', required: true, properties: {}, description: 'Changed settings (names match vms.vm-edit-schema; empty string clears nickname/keyboardLayout/osOptimization)' },
  },
  async execute(ctx, input): Promise<ActionResult> {
    const name = typeof input['name'] === 'string' ? (input['name'] as string) : '';
    if (!name) return { success: false, error: 'VM name is required' };
    const fieldsRaw = input['fields'];
    if (!fieldsRaw || typeof fieldsRaw !== 'object' || Array.isArray(fieldsRaw)) {
      return { success: false, error: 'fields (object) is required' };
    }
    const fields = fieldsRaw as Record<string, unknown>;

    try {
      const servers = await ctx.client.listServers();
      const srv = servers.find((s) => s.name === name);
      if (!srv) return { success: false, error: `VM "${name}" not found in this netcup account` };

      // Map generic field names onto SCP attributes — one merge-patch each.
      const patches: Record<string, unknown>[] = [];
      const updated: string[] = [];
      if ('hostname' in fields) {
        const v = String(fields['hostname']);
        if (v !== '') { patches.push({ hostname: v }); updated.push('hostname'); }
      }
      if ('nickname' in fields) {
        // Empty string CLEARS the nickname — a legitimate change.
        patches.push({ nickname: String(fields['nickname']) });
        updated.push('nickname');
      }
      if ('autostart' in fields && typeof fields['autostart'] === 'boolean') {
        patches.push({ autostart: fields['autostart'] });
        updated.push('autostart');
      }
      if ('uefi' in fields && typeof fields['uefi'] === 'boolean') {
        patches.push({ uefi: fields['uefi'] });
        updated.push('uefi');
      }
      if ('osOptimization' in fields) {
        const v = String(fields['osOptimization']);
        if (v !== '') { patches.push({ os_optimization: v }); updated.push('osOptimization'); }
      }
      if ('keyboardLayout' in fields) {
        // Empty string CLEARS the layout override.
        patches.push({ keyboardLayout: String(fields['keyboardLayout']) });
        updated.push('keyboardLayout');
      }
      if (patches.length === 0) return { success: false, error: 'No editable fields provided' };

      for (const p of patches) await ctx.client.patchServerAttribute(srv.id, p);

      // Verify by re-reading — EVERY driven field must show its new value.
      const checks: Array<(now: Record<string, unknown>) => boolean> = [];
      if ('hostname' in fields && String(fields['hostname']) !== '') {
        const want = String(fields['hostname']);
        checks.push((now) => now.hostname === want);
      }
      if ('nickname' in fields) {
        const want = String(fields['nickname']);
        checks.push((now) => now.nickname === want);
      }
      if ('autostart' in fields && typeof fields['autostart'] === 'boolean') {
        const want = fields['autostart'];
        checks.push((now) => now.autostart === want);
      }
      if ('uefi' in fields && typeof fields['uefi'] === 'boolean') {
        const want = fields['uefi'];
        checks.push((now) => now.uefi === want);
      }
      if ('osOptimization' in fields && String(fields['osOptimization']) !== '') {
        const want = String(fields['osOptimization']);
        checks.push((now) => now.osOptimization === want);
      }
      if ('keyboardLayout' in fields) {
        const want = String(fields['keyboardLayout']);
        checks.push((now) => now.keyboardLayout === want);
      }
      const wait = await pollUntil(
        async () => {
          const full = await ctx.client.getServer(srv.id);
          const live = full.serverLiveInfo ?? {};
          return {
            hostname: typeof full.hostname === 'string' ? full.hostname : '',
            nickname: (full.nickname ?? '') || '',
            autostart: live.autostart === true,
            uefi: live.uefi === true,
            osOptimization: typeof live.osOptimization === 'string' ? live.osOptimization : '',
            keyboardLayout: typeof live.keyboardLayout === 'string' ? live.keyboardLayout : '',
          };
        },
        (now) => checks.every((c) => c(now)),
        { timeoutMs: 30_000, intervalMs: 2_000 },
      );
      return { success: wait.ok, applied: true, verified: wait.ok, details: { name, updated } };
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
  vmsStartAction,
  vmsStopAction,
  vmsKillAction,
  vmsRestartAction,
  vmsSuspendAction,
  vmsResumeAction,
  vmsVmEditSchemaAction,
  vmsVmGetAction,
  vmsVmUpdateAction,
]);
