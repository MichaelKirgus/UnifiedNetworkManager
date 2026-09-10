import { eq } from 'drizzle-orm';
import { db } from '../db';
import * as schema from '../db/schema';
import { LEADER_KEYS } from './leader';
import { initWorker, trackBeat } from './stats';
import { getGlobalPolicy, isInactiveDisabled } from '../auth/credentialPolicy';

/**
 * Inactivity auto-disable sweep.
 *
 * Enforces the credential policy's `inactiveDisableAfterDays` rule: a user who
 * has not logged on for N days gets their account DISABLED (users.disabled =
 * true). A disabled user is rejected at login with `user_disabled` and their
 * live sessions terminate (requireAuth returns 401), so the webapp signs them
 * out. An admin re-enables the account from the Users page (PATCH /users/:id/status)
 * — or clears the rule entirely by setting inactiveDisableAfterDays to null.
 *
 * Only the GLOBAL policy's rule is applied here: per-user overrides of this
 * field are honored at login/session time via resolveCredentialPolicy, but the
 * sweep keeps a single predictable cadence from the global default. The check
 * reads each user's `lastLoginAt` (stamped on every successful authentication)
 * and never disables an account that has never logged on — that would lock out
 * a freshly created user before their first sign-in.
 */

const SWEEP_INTERVAL_MS = 3_600_000; // hourly — cheap at any fleet size

async function sweepInactiveUsers(): Promise<void> {
  const policy = await getGlobalPolicy();
  if (typeof policy.inactiveDisableAfterDays !== 'number' || policy.inactiveDisableAfterDays <= 0) {
    return; // rule off globally — nothing to do
  }

  const rows = await db.query.users.findMany({ columns: { id: true, username: true, disabled: true, lastLoginAt: true } });
  for (const row of rows) {
    if (row.disabled) continue; // already disabled
    if (!isInactiveDisabled(policy, row.lastLoginAt)) continue;

    await db.update(schema.users).set({ disabled: true }).where(eq(schema.users.id, row.id));
    // eslint-disable-next-line no-console
    console.log(`[inactive-users] disabled "${row.username}" (no login for > ${policy.inactiveDisableAfterDays} days)`);
  }
}

/**
 * Starts the inactivity sweep. Must be called only after the API has bound its
 * port (same rule as every other worker — see index.ts app.listen callback).
 */
export function startInactiveUsersWorker(): () => void {
  initWorker('inactiveUsers', LEADER_KEYS.inactiveUsers);
  // eslint-disable-next-line no-console
  console.log('[inactive-users] worker started (rule read live from the global credential policy)');

  // First sweep runs immediately so accounts that crossed the threshold before
  // this feature existed are caught without waiting an hour.
  void trackBeat('inactiveUsers', sweepInactiveUsers).catch((err) => {
    // eslint-disable-next-line no-console
    console.error('[inactive-users] initial sweep failed:', err);
  });

  const timer = setInterval(() => {
    void trackBeat('inactiveUsers', sweepInactiveUsers).catch((err) => {
      // eslint-disable-next-line no-console
      console.error('[inactive-users] sweep failed:', err);
    });
  }, SWEEP_INTERVAL_MS);

  return () => clearInterval(timer);
}
