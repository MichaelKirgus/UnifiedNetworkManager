import { pluginAxios } from '../utils/pluginHttp';
import { and, asc, eq, isNotNull } from 'drizzle-orm';
import { db } from '../db';
import * as schema from '../db/schema';
import { enqueuePlanExecution } from './planExecutor';
import { LEADER_KEYS } from './leader';
import { initWorker, trackBeat } from './stats';
import { emitNotification } from '../notifications';

const TICK_INTERVAL_MS = 15_000; // how often the leader scans for due plans
/** run-asap retry backoff: min(2^attempts * BASE, CAP) — 30s, 60s, 120s, … capped at 15m. */
const BACKOFF_BASE_MS = 30_000;
const BACKOFF_CAP_MS = 15 * 60_000;

interface SchedulablePlan {
  id: string;
  pluginId: string;
  intentActionId: string;
  status: string;
  createdBy: string;
  scheduledAt: string | null;
  schedulePolicy: string | null;
  preScheduleStatus: string | null;
  scheduleAttempts: number;
}

function parseJson<T>(raw: string | null, fallback: T): T {
  if (!raw) return fallback;
  try {
    const parsed = JSON.parse(raw);
    return (parsed ?? fallback) as T;
  } catch {
    return fallback;
  }
}

/**
 * Is this failure "the plugin/stack is not reachable" — i.e. the kind of thing
 * a schedule policy can act on? A 4xx from the plugin means the plan itself is
 * invalid (bad action, bad input) and retrying will never help; those fail the
 * plan normally regardless of policy.
 */
function isUnreachableError(err: unknown): boolean {
  const e = err as { response?: { status?: number }; code?: string; message?: string };
  if (e.response?.status && e.response.status < 500) return false; // plugin answered — real rejection
  return true; // network error, timeout, or 5xx: unreachable / not responding
}

/**
 * Startup sweep for plans that were DUE while UNM itself was down. The scheduler
 * only runs while the API is up, so a plan whose scheduledAt passed during an
 * outage can never be picked up by the normal tick — decide per policy NOW:
 *  - 'skip'     → mark skipped (the user said "don't run it if we missed it").
 *  - 'run-asap' → execute immediately (as soon as possible = now).
 */
async function sweepOverduePlans(): Promise<void> {
  const rows = await db.query.plans.findMany({ where: (p) => eq(p.status, 'scheduled') });
  for (const row of rows as SchedulablePlan[]) {
    if (!row.scheduledAt || new Date(row.scheduledAt).getTime() > Date.now()) continue; // not due yet
    const policy = row.schedulePolicy === 'skip' ? 'skip' : 'run-asap';
    try {
      if (policy === 'skip') {
        await markSkipped(row, `Missed its scheduled time (${row.scheduledAt}) while UNM was down — skipped per schedule policy`);
      } else {
        // eslint-disable-next-line no-console
        console.log(`[planScheduler] plan ${row.id} was due during an outage — running it now (run-asap)`);
        await enqueuePlanExecution(row.id, row.createdBy ?? null);
      }
    } catch (err) {
      // eslint-disable-next-line no-console
      console.error(`[planScheduler] startup sweep failed for plan ${row.id}:`, err);
    }
  }
}

/** Marks a scheduled plan skipped (terminal, re-schedulable by the user). */
async function markSkipped(plan: SchedulablePlan, reason: string): Promise<void> {
  const now = new Date().toISOString();
  await db.update(schema.plans)
    .set({ status: 'skipped', error: reason, updatedAt: now, finishedAt: now, recentlyFinishedAt: now })
    .where(eq(schema.plans.id, plan.id));
  try {
    const plugin = await db.query.plugins.findFirst({ where: eq(schema.plugins.id, plan.pluginId) });
    await emitNotification({
      severity: 'warning',
      source: 'system',
      title: `Scheduled plan skipped${plugin ? ` (${plugin.name})` : ''}`,
      message: reason,
      dedupeKey: `plan-skipped:${plan.id}:${now.slice(0, 16)}`,
      pluginId: plan.pluginId ?? null,
      context: { planId: plan.id, intentActionId: plan.intentActionId },
    });
  } catch {
    // Best-effort by contract.
  }
}

/**
 * One scheduler tick: find every 'scheduled' plan whose due instant has passed
 * and act on it. Plans are handled one at a time (the executor itself runs them
 * strictly sequentially, so enqueuing several is safe).
 */
async function tick(): Promise<void> {
  const nowIso = new Date().toISOString();
  const rows = await db.query.plans.findMany({
    where: (p) => and(eq(p.status, 'scheduled'), isNotNull(p.scheduledAt)), // scheduled AND has a due time
    orderBy: [asc(schema.plans.scheduledAt)],
  });

  for (const row of rows as SchedulablePlan[]) {
    if (!row.scheduledAt || new Date(row.scheduledAt).getTime() > Date.now()) continue; // not due yet
    const policy = row.schedulePolicy === 'skip' ? 'skip' : 'run-asap';

    try {
      // Reachability probe: the plugin must answer /healthz before we commit to
      // an execution. This is what makes the "stack down / plugin not responding"
      // control meaningful — a due plan whose plugin is unreachable never flips
      // to 'executing' (no half-applied steps), it stays scheduled and follows
      // its policy instead.
      const plugin = await db.query.plugins.findFirst({ where: eq(schema.plugins.id, row.pluginId) });
      if (!plugin) {
        // The plugin is gone — retrying will never help; fail the plan clearly.
        await db.update(schema.plans)
          .set({ status: 'failed', error: 'Plugin no longer registered (scheduled execution)', updatedAt: nowIso, finishedAt: nowIso, recentlyFinishedAt: nowIso })
          .where(eq(schema.plans.id, row.id));
        continue;
      }

      let reachable = true;
      try {
        await pluginAxios(plugin.endpoint).get('/healthz', { timeout: 5_000 });
      } catch (err) {
        if (!isUnreachableError(err)) throw err; // unexpected — surface it below
        reachable = false;
      }

      if (reachable) {
        await enqueuePlanExecution(row.id, row.createdBy ?? null);
        continue;
      }

      // Plugin not responding at the due instant → apply the policy.
      if (policy === 'skip') {
        await markSkipped(row, `Plugin "${plugin.name}" was not responding when this plan became due (${row.scheduledAt}) — skipped per schedule policy`);
      } else {
        // run-asap: keep it scheduled and retry with exponential backoff.
        const attempts = (row.scheduleAttempts ?? 0) + 1;
        const delayMs = Math.min(BACKOFF_BASE_MS * 2 ** Math.max(0, attempts - 1), BACKOFF_CAP_MS);
        const nextDue = new Date(Date.now() + delayMs).toISOString();
        await db.update(schema.plans)
          .set({ scheduledAt: nextDue, scheduleAttempts: attempts, updatedAt: nowIso })
          .where(eq(schema.plans.id, row.id));
        // eslint-disable-next-line no-console
        console.log(`[planScheduler] plan ${row.id} due but plugin unreachable — retrying at ${nextDue} (attempt ${attempts})`);
      }
    } catch (err) {
      // eslint-disable-next-line no-console
      console.error(`[planScheduler] failed handling scheduled plan ${row.id}:`, err);
    }
  }
}

/**
 * Starts the plan scheduling loop (leader-gated like every other worker).
 * Returns a stop function for graceful shutdown / step-down.
 */
export function startPlanSchedulerWorker(): () => void {
  initWorker('planScheduler', LEADER_KEYS.planScheduler);
  // eslint-disable-next-line no-console
  console.log(`[planScheduler] worker started, scanning every ${TICK_INTERVAL_MS / 1000}s`);

  void sweepOverduePlans().catch((err) => {
    // eslint-disable-next-line no-console
    console.error('[planScheduler] startup sweep failed:', err);
  });

  let chain: Promise<void> = Promise.resolve();
  const timer = setInterval(() => {
    chain = chain.then(() => trackBeat('planScheduler', () => tick())).catch((err) => {
      // eslint-disable-next-line no-console
      console.error('[planScheduler] tick failed:', err);
    });
  }, TICK_INTERVAL_MS);

  return () => clearInterval(timer);
}
