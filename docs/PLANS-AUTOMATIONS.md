# Plans, configuration jobs & automations

The two workflow engines of UNM: **plans** (audited multi-step writes to devices) and **automations** (ITTT-style rules that react to schedules, metrics, logs, device state, flows and updates). Plan *intents* — the per-plugin building blocks plans are made of — are catalogued in [INTENTS.md](INTENTS.md).

## Plans & configuration jobs

- **Config jobs** — single-device action submissions (`POST /devices/:deviceId/config-jobs` with an explicit `pluginId`), executed by the config-job worker against that plugin assignment. Require `configs:apply` + 2FA.
- **Plans** — multi-step workflows with per-step dependencies, reordering (cycle-checked while draft/ready), and `${steps[N].result.details.<key>}` token substitution from earlier step results. The executor runs one plan at a time, persists the *resolved* input of each step before dispatch, honors `bestEffort` flags, and marks orphaned executing plans failed on startup. Plan creation can **provision secrets** (e.g. WireGuard key pairs) through the secrets provider with rollback on failure; provisioned material is referenced by id in steps and never stored in plaintext anywhere.
- E2E test suite: `scripts/e2e-plans.ts` against the mock OPNsense appliance (`docker compose --profile test up -d mock-appliance`; the service is hidden behind the `test` profile so productive `up`s never start it).

## Automations (ITTT rules)

The **Automations** page (gated on `automations:read` / `automations:write`) manages ITTT-style rules — *triggers* + *actions*, stored as opaque JSON in the `automations` table and evaluated by a leader-gated worker every 15 s. Rules have an optional per-rule cooldown; every firing writes one row to `automation_runs` (status `succeeded` / `partial` / `failed` / `skipped`, with plan ids and error details).

**Triggers:** `schedule` (cron / interval / dailyAt), `metric` (threshold on a telemetry metric, optional hold-duration), `log` (new lines matching a regex in plugin logs), `deviceStatus` (online/offline transitions — event-driven from the telemetry commit point), `flow` (traffic thresholds over sliding windows), `containerLog` (new lines in an app's log tail), and **`updateAvailable`** (transitions in the Updates page data: a row appearing, its version advancing, or disappearing).

The `updateAvailable` trigger is the automation path for applying updates unattended:
- `condition: 'available' | 'resolved'` selects which transitions fire; optional filters narrow by plugin, kinds, exact names, name regex, and the reboot flag (rows with a *null* flag never match — unknown ≠ safe to auto-apply).
- **Deferral** (`defer.schedule` + optional `maxWaitHours`) holds each firing until the next occurrence of the schedule spec (e.g. a nightly 02:00 window); one pending window per update row is tracked in `automation_state`. A vanished row cancels its window silently; a version advance refreshes the snapshot without moving the slot; `maxWaitHours` caps how long an event waits before firing immediately.
- **Intent actions** can carry `resolveFromTrigger: 'update'`, which fills `pluginId` / `actionId` / input from the *firing row's own* apply path (`device_updates.applyActionId` + `applyInput`) — so one rule applies whatever each plugin reports, and rows without an apply path are skipped with a logged reason. `requireNoReboot: true` hard-skips any row whose `rebootRequired` flag is set (a guard skip is recorded on the run, not counted as a failure).
- Template variables for action templates include `{{update.kind}}`, `{{update.name}}`, `{{update.currentVersion}}`, `{{update.latestVersion}}`, `{{update.rebootRequired}}`.

**Template catalog:** `GET /automations/templates` serves built-in rule drafts (e.g. *Auto-update apps without reboot (nightly window)*) plus any templates plugins advertise in their `/discover` payload (`automationTemplates`). The webapp renders them as one-click cards that open the builder **pre-filled — everything stays editable before saving**. The Updates page has a matching quick-create: select update rows → *Create automation* hands off a draft (kinds/names/plugin pre-filled, no-reboot guards on) to the Automations page via `sessionStorage`; nothing is created until you save there.

**Verification:** unit tests in `api/src/automations/engine.test.ts` (deterministic deferral math); live E2E in `scripts/verify-update-automations.ts` seeds pending windows + update rows and asserts the evaluator tick fires them — including a real plan creation through `resolveFromTrigger` on a read-risk action.
