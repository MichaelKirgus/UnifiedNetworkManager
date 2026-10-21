#!/usr/bin/env node
// UNM privilege-drop helper — invoked by scripts/docker-entrypoint.sh as root
// (PID 1 after the wrapper execs it). It:
//   1. optionally rewrites the `app` user's uid to UNM_DOCKER_UID (so files it
//      creates match a host uid, e.g. for bind-mounted data dirs);
//   2. optionally joins a host docker GID as a supplementary group of `app`
//      (so a mounted /var/run/docker.sock, owned root:<gid>, is accessible);
//   3. drops to the unprivileged `app` user in-process;
//   4. spawns the real app with stdio inherited and forwards termination
//      signals so Docker's SIGTERM reaches it, then exits with its code.
//
// No external dependencies — only node:child_process + node:fs.

'use strict';

const { spawn } = require('node:child_process');
const fs = require('node:fs');

const APP_USER = 'app';
const DEFAULT_UID = 1001;
const PRIMARY_GID = 1001; // group "unm"

function env(name) {
  return process.env[name] || '';
}

// --- Optional uid override (bind-mount ownership alignment) -------------------
let targetUid = DEFAULT_UID;
if (/^\d+$/.test(env('UNM_DOCKER_UID'))) {
  const u = parseInt(env('UNM_DOCKER_UID'), 10);
  if (u > 0 && u < 65536) {
    targetUid = u;
    try {
      // busybox has no usermod — rewrite the `app` line in /etc/passwd. The
      // shadow file stores no uid, so this is sufficient for setuid().
      const pw = fs.readFileSync('/etc/passwd', 'utf8').split('\n');
      let changed = false;
      for (let i = 0; i < pw.length; ++i) {
        const p = pw[i].split(':');
        if (p[0] === APP_USER && parseInt(p[2], 10) !== targetUid) {
          p[2] = String(targetUid);
          pw[i] = p.join(':');
          changed = true;
        }
      }
      if (changed) fs.writeFileSync('/etc/passwd', pw.join('\n'));
    } catch (e) {
      process.stderr.write(`[unm] WARN: could not set app uid to ${targetUid}: ${e.message}\n`);
    }
  } else {
    process.stderr.write(`[unm] WARN: UNM_DOCKER_UID=${env('UNM_DOCKER_UID')} out of range — using ${DEFAULT_UID}\n`);
  }
}

// --- Host docker socket access -------------------------------------------------
// The mounted socket is owned root:<host docker gid>. Joining that GID as a
// supplementary group of `app` grants read/write. We are still root here, so we
// may edit /etc/group; initgroups() below then picks the membership up.
const dockerGid = env('UNM_DOCKER_GID');
if (/^\d+$/.test(dockerGid)) {
  try {
    const lines = fs.readFileSync('/etc/group', 'utf8').split('\n');
    let idx = -1;
    for (let i = 0; i < lines.length; ++i) {
      const p = lines[i].split(':');
      if (p.length >= 4 && p[2] === dockerGid) {
        idx = i;
        break;
      }
    }
    if (idx < 0) {
      fs.appendFileSync('/etc/group', `unm-docker:x:${dockerGid}:${APP_USER}\n`);
    } else {
      const p = lines[idx].split(':');
      const members = (p[3] || '').split(',').filter(Boolean);
      if (!members.includes(APP_USER)) members.push(APP_USER);
      p[3] = members.join(',');
      lines[idx] = p.join(':');
      fs.writeFileSync('/etc/group', lines.join('\n') + '\n');
    }
  } catch (e) {
    process.stderr.write(`[unm] WARN: could not set up docker group ${dockerGid}: ${e.message}\n`);
  }
}

// --- Drop privileges -----------------------------------------------------------
try {
  try {
    process.initgroups(APP_USER, 'unm'); // supplementary groups from /etc/group (incl. docker gid)
  } catch (_) {
    /* non-fatal — primary group still set below */
  }
  process.setgid(PRIMARY_GID);
  process.setuid(targetUid);
} catch (e) {
  process.stderr.write(`[unm] WARN: privilege drop failed (${e.message}) — continuing as root\n`);
}

// --- Spawn the app, forward signals, propagate exit code -----------------------
const args = process.argv.slice(2);
if (args.length === 0) {
  process.stderr.write('[unm] ERROR: no command to run after privilege drop\n');
  process.exit(1);
}

let exited = false;
const child = spawn(args[0], args.slice(1), { stdio: 'inherit', env: process.env });

child.on('error', (e) => {
  if (!exited) {
    process.stderr.write(`[unm] failed to start ${args[0]}: ${e.message}\n`);
    exited = true;
    process.exit(127);
  }
});

child.on('exit', (code, signal) => {
  if (exited) return;
  exited = true;
  if (signal) process.kill(process.pid, signal); // re-raise so our status reflects it
  else process.exit(code == null ? 0 : code);
});

for (const sig of ['SIGTERM', 'SIGINT', 'SIGHUP']) {
  process.on(sig, () => {
    if (!exited && child.pid) {
      try {
        child.kill(sig);
      } catch (_) {
        /* already gone */
      }
    }
  });
}
