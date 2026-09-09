/**
 * @unm/plugin-sdk — WebSocket bridge for the SSH console (capability 'sshConsole').
 *
 * This is the PLUGIN-side half of the web terminal. The UNM API connects to a
 * plugin's `/console` endpoint as a WebSocket CLIENT and pipes raw bytes between
 * the browser's xterm.js and one ssh2 PTY session opened via SshTerminalConnection
 * (see terminal.ts). The transport protocol is deliberately trivial so it can be
 * proxied VERBATIM by the API:
 *
 *   - BINARY frames = raw terminal I/O, both directions (keyboard in, output out).
 *   - TEXT frames  = JSON control messages (ConsoleControlMessage): resize from
 *     the client; ready/exit/error/closed from the server.
 *
 * The FIRST text frame the plugin receives is a ConsoleHelloFrame carrying the
 * device address + FRESH decrypted credentials + a plugin-owned `context`
 * (what to attach to: a host shell, or a container). The plugin's onOpen() maps
 * that context onto an SshTerminalSession and returns it; this module then wires
 * up all the byte pumping. Credentials never touch the browser — they travel only
 * over the authenticated API→plugin hop (gated by ?apiKey=, see below).
 *
 * Usage in a plugin's index.ts:
 *   const server = createPluginServer({ identity, ..., wsUpgrade: handleConsoleUpgrade });
 *   // where handleConsoleUpgrade is built once with your onOpen:
 *   import { makeConsoleUpgrade } from '@unm/plugin-sdk';
 *   const termPool = createTerminalPool();
 *   process.on('SIGTERM', () => termPool.closeAll());
 *   const wsUpgrade = makeConsoleUpgrade({
 *     expectedApiKey: () => process.env.PLUGIN_API_KEY ?? null,
 *     onOpen: async (hello) => {
 *       const creds = resolveSshCredentials(hello.credentials, { slotOnly: true });
 *       if (!creds) throw new Error('No SSH credential bound — console unavailable');
 *       const conn = await termPool.get(hostOf(hello.managementAddress), 22, creds);
 *       return hello.context?.kind === 'container'
 *         ? openContainerShell(conn, creds, hello.context as any)   // your mapping
 *         : conn.openShell(creds);                                   // host login shell
 *     },
 *   });
 */

import type { IncomingMessage } from 'http';
import type { Duplex } from 'stream';
import { WebSocketServer, WebSocket, RawData } from 'ws';
import { SshTerminalSession } from './terminal';
import { ConsoleHelloFrame, ConsoleControlMessage } from './types';

/** Options for makeConsoleUpgrade(). */
export interface ConsoleEndpointOptions {
  /** Expected shared plugin API key. When non-null, upgrades whose `?apiKey=` query
   *  param does not match are rejected with HTTP 401 (the API always sends it). */
  expectedApiKey?: string | null | (() => string | null);
  /** The path the console endpoint lives at (default '/console'). Other paths are dropped. */
  path?: string;
  /** Called once after the API's hello frame arrives. Open + return the terminal session.
   *  Throwing sends a { type:'error' } control message and closes the socket. */
  onOpen: (hello: ConsoleHelloFrame) => Promise<SshTerminalSession>;
}

/** A ready-to-attach Express/http upgrade handler for the console endpoint. */
export type ConsoleUpgradeHandler = (req: IncomingMessage, socket: Duplex, head: Buffer) => void;

// One noServer WebSocketServer is enough — it only performs handshakes on demand
// and holds no state of its own between connections.
const wss = new WebSocketServer({ noServer: true });

/** Builds the upgrade handler a plugin passes to createPluginServer's `wsUpgrade`. */
export function makeConsoleUpgrade(opts: ConsoleEndpointOptions): ConsoleUpgradeHandler {
  const path = opts.path ?? '/console';
  return (req, socket, head) => {
    let url: URL;
    try {
      url = new URL(req.url ?? '', 'http://localhost');
    } catch {
      socket.destroy();
      return;
    }
    if (url.pathname !== path) {
      // Not the console endpoint — drop it so other upgrade handlers can run.
      socket.destroy();
      return;
    }

    const expected = typeof opts.expectedApiKey === 'function' ? opts.expectedApiKey() : opts.expectedApiKey ?? null;
    if (expected && url.searchParams.get('apiKey') !== expected) {
      req.statusCode = 401;
      try { socket.write('HTTP/1.1 401 Unauthorized\r\nConnection: close\r\n\r\n'); } catch { /* noop */ }
      socket.destroy();
      return;
    }

    wss.handleUpgrade(req, socket, head, (ws) => wire(ws, opts));
  };
}

/** Wires one accepted console WebSocket to a terminal session. */
function wire(ws: WebSocket, opts: ConsoleEndpointOptions): void {
  let session: SshTerminalSession | null = null;
  let state: 'awaiting-hello' | 'open' | 'done' = 'awaiting-hello';
  /** Last resize seen BEFORE the session existed — applied once onOpen() resolves. */
  let pendingResize: { cols: number; rows: number } | null = null;

  const sendControl = (msg: ConsoleControlMessage): void => {
    if (ws.readyState !== WebSocket.OPEN) return;
    try { ws.send(JSON.stringify(msg)); } catch { /* socket gone */ }
  };

  const finish = (): void => {
    if (state === 'done') return;
    state = 'done';
    session?.close();
    try { ws.close(); } catch { /* noop */ }
  };

  ws.on('message', async (data: RawData, isBinary: boolean) => {
    // RawData = Buffer | ArrayBuffer | (Buffer|ArrayBuffer)[] — normalize to one Buffer.
    const buf = Buffer.isBuffer(data)
      ? data
      : Array.isArray(data)
        ? Buffer.concat(data.map((d) => Buffer.from(d)))
        : Buffer.from(data);

    // Resize control frames may arrive BEFORE the session exists: the browser
    // sends its initial geometry as soon as ITS websocket opens — long before
    // the SSH handshake + shell allocation below has finished. Buffer the last
    // one and apply it right after onOpen() resolves (like PuTTY re-sending
    // window-change once the PTY is allocated). Dropping them here was exactly
    // why a freshly opened console stayed at 80x24 until any later resize.
    if (!isBinary) {
      let msg: ConsoleControlMessage;
      try {
        msg = JSON.parse(buf.toString('utf8')) as ConsoleControlMessage;
      } catch {
        return; // ignore malformed control frames
      }
      if (msg.type === 'resize' && typeof msg.cols === 'number' && typeof msg.rows === 'number') {
        if (state === 'open' && session) session.resize(msg.cols, msg.rows);
        else pendingResize = { cols: msg.cols, rows: msg.rows };
        return;
      }
    }

    if (state === 'awaiting-hello') {
      // The API's first frame is ALWAYS the hello JSON. A binary frame here means
      // a misbehaving peer — reject cleanly rather than guess.
      if (isBinary) { sendControl({ type: 'error', message: 'Expected console hello' }); finish(); return; }
      let hello: ConsoleHelloFrame;
      try {
        hello = JSON.parse(buf.toString('utf8')) as ConsoleHelloFrame;
      } catch {
        sendControl({ type: 'error', message: 'Malformed console hello' });
        finish();
        return;
      }
      state = 'open'; // stop treating further frames as the hello
      try {
        session = await opts.onOpen(hello);
      } catch (err) {
        sendControl({ type: 'error', message: err instanceof Error ? err.message : String(err) });
        finish();
        return;
      }
      wireSession(session, ws, sendControl, finish);
      if (pendingResize) { session.resize(pendingResize.cols, pendingResize.rows); pendingResize = null; }
      sendControl({ type: 'ready' });
      return;
    }

    if (state !== 'open' || !session) return; // closed — drop late frames

    if (isBinary) {
      // Pass the Buffer VERBATIM — a latin-1 string round-trip would corrupt non-ASCII.
      session.write(buf);
    }
  });

  ws.on('close', finish);
  ws.on('error', () => { /* guarded — close() follows */ });
}

/** Connects a live terminal session's events to the WebSocket. */
function wireSession(
  session: SshTerminalSession,
  ws: WebSocket,
  sendControl: (msg: ConsoleControlMessage) => void,
  finish: () => void,
): void {
  session.on('data', (d: Buffer) => {
    if (ws.readyState === WebSocket.OPEN) {
      try { ws.send(d); } catch { /* socket gone */ }
    }
  });
  session.on('exit', ({ code }: { code: number }) => {
    sendControl({ type: 'exit', code });
    finish();
  });
  session.on('error', (err: Error) => {
    sendControl({ type: 'error', message: err.message });
    finish();
  });
  session.on('close', finish);
}
