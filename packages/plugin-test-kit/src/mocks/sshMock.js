/**
 * @unm/plugin-test-kit — in-process mock SSH appliance (ssh2 Server).
 *
 * Accepts password authentication for ANY username/password and answers `exec`
 * channels with canned stdout. It understands the two shapes generic-ssh sends:
 *   - simple commands (`id -u`, `true`) → minimal output, exit 0;
 *   - marker-batched section scripts — one exec whose command is a sequence of
 *     `echo "UNM_SECTION:<name>:BEGIN"; (<cmd>) …; echo "UNM_SECTION:<name>:END"`
 *     blocks. The mock does NOT run the shell; it parses each section and emits
 *     canned output between the literal BEGIN/END markers, which is all the
 *     plugin's parser consumes (it splits stdout on those marker lines).
 *
 * This makes generic-ssh report health 'ok' with zero real commands executed.
 */

import ssh2Pkg from 'ssh2'; // CJS — named exports unavailable via ESM import
import crypto from 'node:crypto';

const { Server } = ssh2Pkg;

/** Canned per-section output for the live-metrics batch. */
function sectionOutput(name, cmd) {
  switch (name) {
    case 'meminfo':
      return [
        'MemTotal:       4096000 kB',
        'MemFree:         512000 kB',
        'MemAvailable:   3072000 kB',
        'Buffers:          64000 kB',
        'Cached:          768000 kB',
      ].join('\n');
    case 'loadavg':
      return '0.50 0.40 0.30 1/234 999';
    case 'stat':
      // Aggregate cpu line: user nice system idle iowait irq softirq steal …
      return 'cpu  1000 0 500 90000 100 0 0 0 0 0';
    case 'counters':
      return 'eth0 12345678 8765432 lo 1000 1000';
    case 'date':
      return new Date().toISOString();
    case 'tz':
      return '/usr/share/zoneinfo/Etc/UTC';
    default:
      // Unknown section (inventory, etc.) — empty body is fine; the plugin treats
      // absent/unparseable sections as best-effort.
      return '';
  }
}

/** Builds canned stdout for a marker-batched command string. */
function batchedOutput(command) {
  const out = [];
  const re = /UNM_SECTION:([^:"]+):(BEGIN|END)/g;
  let m;
  while ((m = re.exec(command)) !== null) {
    if (m[2] === 'BEGIN') out.push(`UNM_SECTION:${m[1]}:BEGIN`);
    else {
      // Find the command between this END and the previous BEGIN to pick output.
      const beginIdx = command.lastIndexOf('UNM_SECTION:' + m[1] + ':BEGIN');
      const seg = command.slice(beginIdx, m.index);
      out.push(sectionOutput(m[1], seg));
      out.push(`UNM_SECTION:${m[1]}:END`);
    }
  }
  return out.join('\n') + '\n';
}

/** Canned stdout for a simple (non-batched) exec command. */
function simpleOutput(command) {
  const c = command.trim();
  if (c === 'id -u' || c === 'id') return '0\n';
  if (c === 'true' || c === '') return '';
  if (/^sudo\s+-n\s+true$/.test(c)) return '';
  // Fallback: empty stdout, exit 0 — best-effort sections tolerate this.
  return '';
}

/**
 * @returns {Promise<{port:number, host:string, requests:Array, stop:()=>Promise<void>}>}
 *   `requests` records each exec command string (for suite assertions).
 */
export function startSshMock() {
  const requests = [];
  return new Promise((resolve, reject) => {
    // A throwaway host key — the plugin's host verifier is TOFU by default
    // (no pin ⇒ accept), so any generated key works. ssh2 wants a PEM string.
    const { privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
    const hostKey = privateKey.export({ type: 'pkcs1', format: 'pem' });

    const server = new Server({ hostKeys: [hostKey] }, (client) => {
      client.on('authentication', (ctx) => {
        // Accept any password auth for any user.
        if (ctx.method === 'password') return ctx.accept();
        ctx.reject(['password']);
      });
      client.on('ready', () => {
        // Canonical ssh2 server pattern (see node_modules/ssh2/test): accept() is
        // synchronous and returns the object; stdout via stream.write(); then
        // stream.exit(code) + stream.end().
        client.on('session', (acceptSession, _rejectSession) => {
          const session = acceptSession();
          session.on('exec', (acceptExec, _rejectExec, info) => {
            const cmd = String(info.command ?? '');
            requests.push(cmd);
            if (requests.length > 500) requests.shift();
            const stream = acceptExec();
            const stdout = /UNM_SECTION:/.test(cmd) ? batchedOutput(cmd) : simpleOutput(cmd);
            stream.write(stdout);
            stream.exit(0);
            stream.end();
          });
          session.on('shell', (acceptShell, _rejectShell) => {
            // generic-ssh uses exec, not interactive shell — accept + close.
            const shell = acceptShell();
            setTimeout(() => shell.end(), 50);
          });
        });
      });
      client.on('error', () => {});
    });

    server.on('client-error', (err) => { /* handshake failures are fine */ });
    server.listen(0, '127.0.0.1', () => {
      const port = server.address().port;
      resolve({
        port,
        host: `127.0.0.1:${port}`,
        requests,
        stop: async () => {
          // close() ends all active client connections.
          await new Promise((res, rej) => server.close((err) => (err ? rej(err) : res())));
        },
      });
    });
  });
}
