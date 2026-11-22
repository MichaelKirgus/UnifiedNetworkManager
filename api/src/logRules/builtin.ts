/**
 * Built-in log-rule pack (docs/LOG-RULES.md §10) — UNM-authored Sigma rules
 * tuned to the sources UNM actually ingests: syslog forwarding (auth.log,
 * daemon.log, …) and rotation-aware file tailing (app logs).
 *
 * Seeded at boot by workers/logRules.ts (source='builtin'): new names are
 * inserted; existing built-ins get their YAML refreshed to this image's version
 * while the user's enabled/severityOverride choices are preserved. User rules
 * with a colliding name block seeding — user content is never clobbered.
 *
 * Deliberately UNSCOPED (no logsource.service): message patterns below are
 * specific enough, and scoping would make rules silently inert on setups where
 * the same lines arrive under different appnames (e.g. file-tail labels).
 * String.raw keeps regex backslashes intact through the JS layer; YAML
 * single-quoted strings keep them intact through the parse layer.
 */

export interface BuiltinLogRule {
  /** Stable unique name (log_rules.name) — also the seed idempotency key. */
  name: string;
  yaml: string;
}

export const BUILTIN_LOG_RULES: BuiltinLogRule[] = [
  // ── Authentication / brute force ────────────────────────────────────────────
  {
    name: 'ssh-brute-force',
    yaml: String.raw`title: SSH brute force — repeated failed logins
id: unm-ssh-brute-force
status: stable
description: Five or more failed SSH password attempts from one source address within five minutes.
level: high
tags: ['att&ck.t1110', 'att&ck.t1110.001']
detection:
  sel_failed:
    message:
      contains: 'Failed password'
condition: sel_failed
unm.threshold:
  count: 5
  withinMinutes: 5
  groupBy: srcIp
`,
  },
  {
    name: 'ssh-invalid-user-burst',
    yaml: String.raw`title: SSH invalid user burst
id: unm-ssh-invalid-user
status: stable
description: Ten or more attempts against non-existent local users from one source address within ten minutes — typical username enumeration.
level: medium
tags: ['att&ck.t1110']
detection:
  sel_invalid:
    message:
      contains: 'Invalid user'
condition: sel_invalid
unm.threshold:
  count: 10
  withinMinutes: 10
  groupBy: srcIp
`,
  },
  {
    name: 'pam-auth-failure-burst',
    yaml: String.raw`title: PAM authentication failure burst
id: unm-pam-auth-failure
status: stable
description: Five or more PAM authentication failures on one host within five minutes — brute force against any PAM service (SSH, sudo, login).
level: medium
tags: ['att&ck.t1110']
detection:
  sel_pam_fail:
    message:
      re: 'authentication failure'
condition: sel_pam_fail
unm.threshold:
  count: 5
  withinMinutes: 5
  groupBy: hostname
`,
  },
  {
    name: 'ssh-root-login-success',
    yaml: String.raw`title: Direct root SSH login succeeded
id: unm-ssh-root-login
status: stable
description: A successful password or public-key login directly as root — most hardening guides disable direct root logins entirely.
level: high
tags: ['att&ck.t1078', 'att&ck.t1078.003']
detection:
  sel_root_ok:
    message:
      re: 'Accepted (password|publickey) for root from'
condition: sel_root_ok
`,
  },
  {
    name: 'account-not-found-burst',
    yaml: String.raw`title: Repeated logins against unknown accounts
id: unm-account-not-found
status: stable
description: Five or more authentication attempts for accounts that do not exist on one host within ten minutes.
level: low
detection:
  sel_no_account:
    message:
      contains: 'account not found'
condition: sel_no_account
unm.threshold:
  count: 5
  withinMinutes: 10
  groupBy: hostname
`,
  },

  // ── Privilege escalation / sudo ─────────────────────────────────────────────
  {
    name: 'sudo-command-executed',
    yaml: String.raw`title: Sudo command executed (audit)
id: unm-sudo-command
status: stable
description: Every sudo invocation is recorded — an audit trail of privileged commands, useful for post-incident review and insider detection.
level: low
tags: ['att&ck.t1078']
detection:
  sel_sudo_cmd:
    message:
      contains: 'COMMAND='
condition: sel_sudo_cmd
`,
  },
  {
    name: 'sudoers-violation',
    yaml: String.raw`title: Repeated sudo permission denials
id: unm-sudoers-violation
status: stable
description: A user repeatedly tried to run commands they are not allowed to — typos happen once, three times in ten minutes is probing.
level: medium
detection:
  sel_not_sudoer:
    message:
      contains: 'NOT in sudoers'
condition: sel_not_sudoer
unm.threshold:
  count: 3
  withinMinutes: 10
  groupBy: hostname
`,
  },
  {
    name: 'sudo-password-failures',
    yaml: String.raw`title: Repeated sudo password failures
id: unm-sudo-password-failures
status: stable
description: Two or more incorrect sudo password attempts on one host within ten minutes — possible credential guessing against a local account.
level: medium
tags: ['att&ck.t1110']
detection:
  sel_sudo_fail:
    message:
      contains: 'incorrect password attempts'
condition: sel_sudo_fail
unm.threshold:
  count: 2
  withinMinutes: 10
  groupBy: hostname
`,
  },

  // ── Account management ──────────────────────────────────────────────────────
  {
    name: 'password-changed',
    yaml: String.raw`title: Password changed (audit)
id: unm-password-changed
status: stable
description: A user password was changed or reset — audit trail for account manipulation detection.
level: low
tags: ['att&ck.t1098']
detection:
  sel_pw_change:
    message:
      re: 'passwd: (password for|changing password)'
condition: sel_pw_change
`,
  },
  {
    name: 'new-user-account',
    yaml: String.raw`title: New local user account created
id: unm-new-user-account
status: stable
description: A new local user account was created — legitimate admin work, but also the first step of persistence.
level: low
tags: ['att&ck.t1136']
detection:
  sel_new_user:
    message:
      contains: 'new user'
condition: sel_new_user
`,
  },

  // ── System integrity ────────────────────────────────────────────────────────
  {
    name: 'oom-kill',
    yaml: String.raw`title: Process killed by the OOM killer
id: unm-oom-kill
status: stable
description: The kernel out-of-memory killer terminated a process — service disruption (availability) and occasionally a side effect of memory-exhaustion attacks.
level: medium
tags: ['att&ck.t1499']
detection:
  sel_oom:
    message:
      re: 'Out of memory: (Killed process|Kill process)'
condition: sel_oom
`,
  },
  {
    name: 'segfault-core-dump',
    yaml: String.raw`title: Process crashed with segfault or core dump
id: unm-segfault-core-dump
status: stable
description: A binary crashed (segmentation fault / core dumped) — can indicate exploitation attempts against vulnerable services.
level: low
detection:
  sel_crash:
    message:
      re: '(segfault at|core dumped)'
condition: sel_crash
`,
  },
  {
    name: 'time-step-jump',
    yaml: String.raw`title: System clock stepped or jumped
id: unm-time-step-jump
status: stable
description: The time daemon corrected the system clock by a large step — legitimate after NTP re-sync, but also a classic anti-forensics move.
level: medium
tags: ['att&ck.t1563.007']
detection:
  sel_clock:
    message:
      re: '(?i)(time step|clock (stepped|jumped)|step size)'
condition: sel_clock
`,
  },

  // ── Web / application logs (file-tail sources) ──────────────────────────────
  {
    name: 'sql-injection-attempt',
    yaml: String.raw`title: SQL injection attempt in web log
id: unm-sql-injection
status: stable
description: Classic SQLi payloads (union select, information_schema, time-based blind probes) observed in an application or access log.
level: high
tags: ['att&ck.t1190']
detection:
  sel_sqli:
    message:
      re: '(?i)(union\s+(all\s+)?select|information_schema|sleep\(\s*\d+\s*\)|benchmark\(|waitfor\s+delay)'
condition: sel_sqli
`,
  },
  {
    name: 'path-traversal-attempt',
    yaml: String.raw`title: Path traversal attempt in web log
id: unm-path-traversal
status: stable
description: Repeated ../ or URL-encoded ..%2f sequences — attempts to read files outside the document root.
level: medium
tags: ['att&ck.t1190']
detection:
  sel_traversal:
    message:
      re: '(\.\./|%2e%2e(/|\\|%5c|%2f)){2,}'
condition: sel_traversal
`,
  },
  {
    name: 'xss-attempt',
    yaml: String.raw`title: XSS payload in web log
id: unm-xss-attempt
status: stable
description: 'Script injection payloads (script tags, event handlers, javascript: URIs) observed in an application or access log.'
level: medium
tags: ['att&ck.t1059', 'att&ck.t1059.006']
detection:
  sel_xss:
    message:
      re: '(?i)(<script|javascript:|onerror=|onload=|document\\.cookie)'
condition: sel_xss
`,
  },
  {
    name: 'web-auth-failure-burst',
    yaml: String.raw`title: Web authentication failure burst (401/403)
id: unm-web-auth-failure
status: stable
description: Twenty or more 401/403 responses from one source address within ten minutes — credential stuffing or authorization probing against a web service.
level: medium
tags: ['att&ck.t1110']
detection:
  sel_http_auth_fail:
    message:
      re: '\b(401|403)\b'
condition: sel_http_auth_fail
unm.threshold:
  count: 20
  withinMinutes: 10
  groupBy: srcIp
`,
  },

  // ── Kernel audit ────────────────────────────────────────────────────────────
  {
    name: 'kernel-audit-denied',
    yaml: String.raw`title: Kernel audit denial events (auditd)
id: unm-kernel-audit-denied
status: stable
description: Failed syscalls / AVC denials recorded by the Linux audit subsystem — useful where auditd is deployed for compliance monitoring.
level: low
detection:
  sel_audit_denied:
    message:
      re: 'type=(SYSCALL|USER_AVC|CRED_ACQ).*success=no'
condition: sel_audit_denied
`,
  },
];
