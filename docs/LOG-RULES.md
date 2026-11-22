# Log rules — Sigma-based detection over ingested device logs (plan)

Detect security-relevant patterns in the log lines UNM already ingests
(`security_events`: syslog forwarding + rotation-aware file tailing), using the
**Sigma** rule format as the user-facing standard, and feed hits into the
existing findings pipeline (`flow_security_findings` → notifications →
`securityFinding` automation trigger) with zero engine changes.

Status: **planned**. Phases below are ordered; each is independently shippable.

## 1. Why Sigma

- De-facto neutral standard for log detection (SigmaHQ/sigma, LGPL-3.0 — fine to
  ship as data / fetchable feeds, same pattern as IOC sources).
- Rules carry **MITRE ATT&CK tags** → findings become actionable
  ("T1110 Brute Force") instead of "regex matched".
- Users who know Wazuh/fail2ban/Elastic recognize the format; community rules
  are importable (with validation, see §4).

We implement the **single-line rule subset** (+ a small UNM extension for
thresholds, §5) — NOT full Sigma aggregation (`count() by …`), which is a
separate engine and out of scope. Unsupported constructs are rejected at import
time with actionable errors, never silently ignored.

## 2. Architecture

```
security_events (syslog + file-tail lines)          log_rules table
        │  watermark scan (tsMs > wm, capped)      (builtin seeded at boot
        ▼                                          + user rules via API)
┌─────────────────────────────┐   compiled rule cache (precompiled predicates,
│ workers/logRules.ts (60 s)  │◄── logsource-scoped index: appname/facility → rules
│  per row: evaluate matching │
│  rules; threshold counters  │
└────────────┬────────────────┘
             ▼ hit
   upsertFinding(kind='log-rule', dedupeKey=`log-rule:${ruleId}:${deviceId}`)
             │
             ├── flow_security_findings (occurrences++, auto-resolve 24 h — existing sweep)
             ├── emitNotification (new findings only, severity = rule level or override)
             └── securityFinding automation trigger (existing watermark pattern)
```

Everything downstream of `upsertFinding` already exists and is kind-agnostic.

## 3. Schema changes (`api/src/db.ts`, idempotent boot DDL + drizzle defs in schema.ts)

1. **`flow_security_findings`** — log-rule hits are not always IP-centric
   (service crashes, config changes):
   - `ALTER TABLE flow_security_findings ALTER COLUMN "srcIp" DROP NOT NULL`
     (and `"dstIp"` stays nullable). Existing rows unaffected.
   - New column `"dedupeKey" TEXT` + partial unique index
     `UNIQUE ("dedupeKey") WHERE status = 'open' AND "dedupeKey" IS NOT NULL`.
   - `upsertFinding` gains an optional `dedupeKey`: when present it is the
     upsert key (IP columns become plain attributes); absent → existing
     `(kind, srcIp, dstIp)` behavior unchanged for all current kinds.
2. **New table `log_rules`**:

   | column | type | notes |
   |---|---|---|
   | id | TEXT PK | uuid |
   | name | TEXT UNIQUE | display name (defaults to Sigma `title`) |
   | source | TEXT | `'builtin' \| 'user'` |
   | sigmaYaml | TEXT NOT NULL | raw YAML — single source of truth, re-parsed on load |
   | enabled | BOOLEAN default true | user toggle; builtins seed enabled |
   | severityOverride | TEXT nullable | `info\|warning\|critical`; null = rule's own level mapping |
   | lastError | TEXT nullable | parse/eval error surfaced in UI |

   No file-repo involvement (YAML is small, lives in the table).
3. **Built-in seeding** at boot (`workers/logRules.ts` or a `seedBuiltinLogRules()`
   called from index.ts after db init): for each built-in rule — insert if name
   absent; if present and `source='builtin'`, refresh `sigmaYaml` to the image's
   version but **preserve** user's `enabled`/`severityOverride`. User rules are
   never touched. (Same "owned by the API" pattern as `BUILTIN_TEMPLATES` in
   automations/templates.ts.)

## 4. Sigma subset — supported / rejected

Parsed with the existing `yaml` dependency (`^2.9.1`) in a pure module
(`api/src/logRules/sigma.ts`, fully unit-tested, no DB access).

**Supported fields:** `title`, `id`, `status`, `description`, `references[]`,
`level` (low/medium/high/critical), `tags[]` (esp. `att&ck.*`),
`logsource {product|category|service}` (→ scope filter, §5), `detection{}`,
`condition`.

**Detection matchers:** exact (`=`, plain value), `contains` (substring,
case-insensitive — friendlier for logs; documented deviation from Sigma's
default), `startswith`, `endswith`, `re` (JS regex, unanchored search). Values:
string/number/boolean; a list of values = OR.

**Condition grammar:** boolean expressions over selection names with
`and` / `or` / `not` and parentheses — small recursive-descent parser producing
a predicate tree evaluated per row.

**Field mapping** (rule field → `security_events` column):
`message`, `appname`, `facility`, `hostname`, `srcIp`, `dstIp`. Anything else
(`winlog.*`, `process.name`, Elastic fields, …) → **import error**:
"field 'X' is not available in UNM log lines".

**Rejected at import (explicit errors naming the offending construct):**
aggregations (`count/sum/min/max`), `re_all`/`all` matchers, cross-logsource
correlation, `contains` on non-string fields, unknown condition operators.

**Level → severity:** low→info, medium→warning, high/critical→critical;
per-rule overridable in the UI (`severityOverride`).

## 5. UNM extension: thresholds (unlocks brute-force detection)

Single-line rules can't express "N failures within W minutes" — yet that is the
#1 use case. Optional namespaced extension (keeps the rule valid Sigma for the
rest):

```yaml
detection:
  sel_failed: { message: 'Failed password' }
condition: sel_failed
unm.threshold:            # UNM-only; ignored by other Sigma consumers
  count: 5                # fire after N hits …
  withinMinutes: 5        # … inside a rolling window …
  groupBy: srcIp          # … per this key (srcIp | hostname | device)
```

Worker keeps an in-memory ring buffer `Map<ruleId+':'+groupKey, ts[]>`
(pruned to the window each beat). Below threshold → no finding (optionally a
debug log); at/above → one finding per group with `occurrences` tracking.
Without `unm.threshold`, every matching line fires (dedupe collapses repeats of
the same condition via the existing upsert).

## 6. Worker — `api/src/workers/logRules.ts`

- Leader key **9024** (next free per threat-intel memory), beat 60 s,
  overlap guard (`busy`) like flowSecurity.
- **Watermark**: module-level `wmMs = Date.now()` at boot; each beat scans
  `security_events WHERE "tsMs" > wm AND "tsMs" < now - 5s` (future-guard),
  capped at e.g. 20k rows/beat (`logRulesScanLimitPerBeat` setting); watermark
  advances to max scanned tsMs. Same documented limitation as threatIntel:
  rows older than boot are never replayed; exposed in stats for E2E.
- **Rule cache**: compiled rules loaded once + reloaded when the `log_rules`
  table changes (version counter / mtime check per beat is cheap at this size).
  Index by logsource scope: row's `appname`/`facility` → candidate rule list,
  so an `sshd`-scoped rule never evaluates DNS lines.
- **Hit handling**: `upsertFinding({ kind:'log-rule', dedupeKey:
  'log-rule:${ruleId}:${deviceId ?? "global"}' + (threshold ? ':'+groupValue : ''),
  srcIp/dstIp from the row when present, severity, detail = rule title + line
  excerpt, context: { ruleId, ruleName, tags[], hostname, appname,
  messageExcerpt } })`; notification only on `isNew`, dedupeKey mirrors the
  finding key.
- Stats for GET endpoint: `{ lastRunAt, lastError, watermarkMs, rulesEnabled,
  hitsLast24h }`.

## 7. API routes (all in OpenAPI — **validator 404s undocumented paths**)

| route | perm | purpose |
|---|---|---|
| `GET /v1/log-rules` | security:read | `{ enabled, worker{…}, rules[] }` — each rule + lastHitAt/occurrences joined from open findings |
| `POST /v1/log-rules` | system:write | create user rule `{ name?, yaml }`; 400 with structured parse errors |
| `PATCH /v1/log-rules/:id` | system:write | enable/disable, severityOverride; YAML replace for **user** rules only (builtins: disable/override only) |
| `DELETE /v1/log-rules/:id` | system:write | user rules only |
| `POST /v1/log-rules/import` | system:write | multi-doc YAML (`---` separated); per-rule result `{ name, status: created\|duplicate\|error, error? }` — the community-import path |

OpenAPI schemas: `LogRule`, `LogRulesResponse`, import result. Webapp client
types + methods mirror (client.ts).

## 8. Webapp

- **Security page**: new "Log rules" section next to Threat Intel
  (`webapp/src/pages/Security.tsx`): table with title, source badge
  (Built-in/User), severity badge (+ override indicator), enabled toggle, last
  hit, occurrences; row actions: edit dialog (YAML textarea + live validation
  errors from the API on save), enable/disable. Import button → paste/multi-doc
  dialog showing per-rule results.
- **Kind rendering**: add `'log-rule'` to every place kinds are mapped —
  `client.ts` types, `Flows.tsx` security section label map, `Security.tsx`
  recentHits, `RuleBuilderDialog.tsx` kinds multi-select (automation trigger).
  Finding detail for log-rule rows shows rule title + ATT&CK tags + matched line.

## 9. Settings (`systemSettings.ts`, category Security)

- `logRulesEnabled` (bool, default true; env `UNM_LOG_RULES_ENABLED`) — master switch.
- `logRulesScanLimitPerBeat` (int, default 20000).
Findings retention reuses the existing `flowSecurityFindingsRetentionDays`.

## 10. Built-in rule pack (Phase 1, ~25 rules)

UNM-authored Sigma YAML as inline TS data in `api/src/logRules/builtin.ts`
(one module, no asset pipeline — same pattern as BUILTIN_TEMPLATES). Tuned to
the sources we actually ingest (`auth.log`, `daemon.log`, syslog facilities,
app logs via file-tail):

- **SSH** (T1110/T1078): failed password (threshold 5/5m by srcIp → brute
  force), invalid user attempts (thresholded), direct root login success,
  "Connection closed by authenticating user" bursts.
- **sudo / privilege**: sudo command execution (info audit), "user NOT in
  sudoers", repeated sudo password failures (thresholded).
- **Auth general** (T1110): PAM `authentication failure` bursts, account not
  found.
- **System health → security-relevant**: OOM killer kills, segfault/core dump,
  kernel audit denials (`audit: DENIED`).
- **Web/app logs** (file-tail sources): SQL-injection pattern (`re`), path
  traversal (`../` sequences), XSS patterns, repeated 401/403 from one srcIp
  (thresholded).
- Each rule gets `att&ck.*` tags where a technique applies; the rest stay
  untagged (honesty — no invented mappings).

## 11. Phases & acceptance criteria

**Phase 1 — core engine + built-in pack** (the whole feature, usable):
DDL changes (§3), sigma parser + jest tests (§4: matchers × values, condition
grammar incl. nesting/negation, every rejection case named), threshold logic
tests, worker with watermark, seeding of the §10 pack, routes + OpenAPI,
webapp section + kind labels, settings.
*Acceptance:* `scripts/e2e-log-rules.ts` green — seeds synthetic
`security_events` rows (direct PG insert, tsMs past the exposed watermark),
asserts: single-line rule fires exactly one finding; thresholded rule fires at
N-th hit and not before; disabled rule never fires; severity override wins;
import of a bad rule returns structured 400 naming the unsupported field;
cleanup by dedupeKey prefix.

**Phase 2 — community import & ATT&CK UX:** URL-based rule feeds (mirror
threat-intel sources: fetch via webFetchBroker, snapshot semantics), MITRE
ATT&CK technique grouping/filter on findings + per-technique enable/disable,
per-rule hit history view, `plugin_logs` as a second source (message+context).

## 12. Known gotchas (from repo memory — do not relearn)

- **express-openapi-validator 404s undocumented paths** → every new route into
  the spec first; validate with `node validate-openapi.cjs`; rebuild api image
  after spec edits (spec is baked in). No `default:` on optional query params.
- **Watermark semantics**: rows stamped before API boot are never scanned —
  E2E must read `watermarkMs` from the stats endpoint and seed after it; a
  clock-skewed device can push tsMs into the future (hence the `-5s` guard).
- **inet rendering**: Postgres renders inet with `/32`; use inet-equality in
  SQL, never text-key on `"col"::text`.
- **camelCase columns** are quoted identifiers — pg rows keep case (`r.tsMs`).
- `upsertFinding` must stay backward-compatible: existing kinds keep the IP-key
  path; only `log-rule` uses dedupeKey.
