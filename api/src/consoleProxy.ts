import type { IncomingMessage } from 'http';
import type { Duplex } from 'stream';
import WebSocket, { WebSocketServer } from 'ws';
import { peekConsoleTicket, redeemConsoleTicket } from './consoleTickets';
import { DeviceConsoleError, resolveConsoleTarget } from './deviceConsole';
import { pluginWsUrl, pluginWsTlsOptions } from './utils/pluginHttp';

/**
 * Console WebSocket PROXY — the API-side half of the SSH console (capability
 * 'sshConsole'). Attached to the HTTP server's 'upgrade' event in index.ts; WS
 * upgrades bypass express entirely, so this is NOT a route.
 *
 * Flow for GET /v1/devices/:id/console/ws?ticket=…:
 *   1. Verify the single-use ticket (minted by POST /devices/:id/console — that
 *      endpoint already enforced JWT + devices:write + capability checks).
 *   2. Resolve the console target (plugin endpoint + FRESH credentials).
 *   3. Connect to the plugin's /console endpoint as a WS client, sending ONE
 *      hello frame with the fresh credentials (the plugin redeems nothing — it
 *      gets what it needs in-band; see the SDK's ConsoleHelloFrame).
 *   4. Upgrade the browser socket and pipe frames VERBATIM both directions:
 *        binary = raw terminal I/O, text = JSON control messages (resize/exit/…).
 *      The proxy never parses or logs frame content — it is a dumb byte pump so
 *      any plugin speaking the SDK's console protocol works unchanged.
 */

/** Error carrying an HTTP status for the pre-upgrade failure path. */
class ProxyError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

const PREFIX = '/v1/devices/';
const SUFFIX = '/console/ws';
/** How long to wait for the plugin's WS handshake before giving up. */
const UPSTREAM_TIMEOUT_MS = 20_000;

/** One noServer WebSocketServer — used only to perform browser-side handshakes on demand. */
const wss = new WebSocketServer({ noServer: true });

/** Performs the HTTP→WS upgrade of an already-accepted request's socket. */
function upgradeBrowser(req: IncomingMessage, socket: Duplex): Promise<WebSocket> {
  return new Promise((resolve, reject) => {
    try {
      wss.handleUpgrade(req, socket, Buffer.alloc(0), (ws) => resolve(ws));
    } catch (err) {
      reject(err instanceof Error ? err : new ProxyError(502, 'WebSocket upgrade failed'));
    }
  });
}

/** Connects to the plugin's /console endpoint and resolves once the handshake completes. */
function connectUpstream(endpoint: string): Promise<WebSocket> {
  return new Promise((resolve, reject) => {
    // mTLS (Stage 1): wss + client cert when the plugin is TLS-live; plain ws
    // otherwise. The apiKey query param stays — it authenticates the upgrade
    // on the plugin side regardless of transport.
    const url = pluginWsUrl(endpoint);
    const tlsOpts = pluginWsTlsOptions(endpoint);
    const ws = new WebSocket(url, { rejectUnauthorized: false, ...tlsOpts });
    const timer = setTimeout(() => {
      try { ws.terminate(); } catch { /* noop */ }
      reject(new ProxyError(502, 'Timed out connecting to the plugin console'));
    }, UPSTREAM_TIMEOUT_MS);
    ws.on('open', () => {
      clearTimeout(timer);
      resolve(ws);
    });
    ws.on('error', (err: Error) => {
      clearTimeout(timer);
      reject(new ProxyError(502, `Plugin console unreachable: ${err.message}`));
    });
  });
}

/** Pipes frames verbatim between two sockets until either side closes. */
function pipePair(a: WebSocket, b: WebSocket): void {
  let done = false;
  const finish = (): void => {
    if (done) return;
    done = true;
    for (const s of [a, b]) {
      try { s.removeAllListeners(); } catch { /* noop */ }
      try { s.close(); } catch { /* noop */ }
    }
  };
  a.on('message', (data: WebSocket.RawData, isBinary: boolean) => {
    if (b.readyState === WebSocket.OPEN) b.send(data, { binary: isBinary });
  });
  b.on('message', (data: WebSocket.RawData, isBinary: boolean) => {
    if (a.readyState === WebSocket.OPEN) a.send(data, { binary: isBinary });
  });
  a.on('close', finish);
  a.on('error', () => { /* guarded — close follows */ });
  b.on('close', finish);
  b.on('error', () => { /* guarded — close follows */ });
}

/** Writes an HTTP error response on a socket that has NOT been upgraded yet. */
function rejectUpgrade(socket: Duplex, status: number, message: string): void {
  try {
    const body = JSON.stringify({ error: message });
    socket.write(
      `HTTP/1.1 ${status} ${status === 401 ? 'Unauthorized' : status === 502 ? 'Bad Gateway' : 'Error'}\r\n` +
        'Connection: close\r\nContent-Type: application/json\r\nContent-Length: ' + Buffer.byteLength(body) + '\r\n\r\n' + body,
    );
  } catch { /* socket already gone */ }
  socket.destroy();
}

/** Anything that emits 'upgrade' — both http.Server and tls.Server qualify. */
interface UpgradeEmitter {
  on(event: 'upgrade', listener: (req: IncomingMessage, socket: Duplex) => void): unknown;
}

/**
 * Attaches the console proxy to a server's upgrade stream. Non-console upgrade
 * paths are left untouched (early return), so other WS consumers can coexist.
 */
export function attachConsoleProxy(server: UpgradeEmitter): void {
  server.on('upgrade', (req: IncomingMessage, socket: Duplex) => {
    let url: URL;
    try {
      url = new URL(req.url ?? '', 'http://localhost');
    } catch {
      return; // malformed — not ours
    }

    if (!url.pathname.startsWith(PREFIX) || !url.pathname.endsWith(SUFFIX)) return; // not a console path

    const deviceId = decodeURIComponent(url.pathname.slice(PREFIX.length, url.pathname.length - SUFFIX.length));
    const ticketId = url.searchParams.get('ticket') ?? '';
    if (!deviceId || !ticketId) {
      rejectUpgrade(socket, 401, 'Missing console ticket');
      return;
    }

    void (async () => {
      let upstream: WebSocket | null = null;
      try {
        // The ticket is the credential: it was minted only after JWT + devices:write
        // + capability checks for exactly this device/assignment.
        const peeked = peekConsoleTicket(ticketId);
        if (!peeked || peeked.deviceId !== deviceId) throw new ProxyError(401, 'Invalid or expired console ticket');

        // The ticket carries the user's chosen session credential (validated at
        // mint time) — it replaces the assignment's bound ssh slot in the hello.
        const target = await resolveConsoleTarget(deviceId, peeked.pluginId, peeked.sessionSecretId);

        // Redeem BEFORE connecting — a failed plugin connect must not leave the
        // ticket reusable (single-use by contract).
        if (!redeemConsoleTicket(ticketId)) throw new ProxyError(401, 'Invalid or expired console ticket');

        const apiKey = process.env.PLUGIN_API_KEY ?? '';
        // The endpoint carries the /console path via connectUpstream's base URL.
        upstream = await connectUpstream(target.endpoint.replace(/\/+$/, '') + '/console' + (apiKey ? `?apiKey=${encodeURIComponent(apiKey)}` : ''));

        // The hello frame is the ONLY frame this proxy ever constructs — it carries
        // fresh credentials to the plugin. Everything after is verbatim piping.
        upstream.send(
          JSON.stringify({
            deviceId,
            managementAddress: target.managementAddress,
            ipAddresses: target.ipAddresses,
            credentials: target.credentials,
            ...(target.settings && Object.keys(target.settings).length > 0 ? { settings: target.settings } : {}),
            ...(peeked.context && Object.keys(peeked.context).length > 0 ? { context: peeked.context } : {}),
          }),
        );

        // RACE GUARD: the plugin may emit terminal output (e.g. the login prompt)
        // BEFORE the browser socket is upgraded below — frames arriving with no
        // 'message' listener would be dropped, so buffer them until wiring starts.
        const pendingUpstream: Array<{ data: WebSocket.RawData; isBinary: boolean }> = [];
        const bufferHandler = (data: WebSocket.RawData, isBinary: boolean): void => {
          pendingUpstream.push({ data, isBinary });
        };
        upstream.on('message', bufferHandler);

        const client = await upgradeBrowser(req, socket);

        // RACE GUARD (reverse direction): the browser's onopen fires as soon as
        // the 101 lands and it may send keyboard/resize frames BEFORE the pump
        // below attaches its listeners — those would be dropped. Buffer them
        // until we can flush into the live pipe. (Synchronous section: no I/O
        // turn runs between listener attach/detach, so nothing slips through.)
        const pendingClient: Array<{ data: WebSocket.RawData; isBinary: boolean }> = [];
        const clientBufferHandler = (data: WebSocket.RawData, isBinary: boolean): void => {
          pendingClient.push({ data, isBinary });
        };
        client.on('message', clientBufferHandler);

        // Flush the pre-wire buffer, then hand over to the verbatim pump.
        upstream.removeListener('message', bufferHandler);
        for (const f of pendingUpstream.splice(0)) {
          if (client.readyState === WebSocket.OPEN) client.send(f.data, { binary: f.isBinary });
        }

        client.removeListener('message', clientBufferHandler); // sync — no frame can slip through
        pipePair(client, upstream);
        for (const f of pendingClient.splice(0)) {
          if (upstream.readyState === WebSocket.OPEN) upstream.send(f.data, { binary: f.isBinary });
        }
      } catch (err) {
        // Close any half-open upstream so a failed handshake leaks nothing.
        if (upstream) {
          try { upstream.removeAllListeners(); upstream.terminate(); } catch { /* noop */ }
        }
        const e = err instanceof ProxyError || err instanceof DeviceConsoleError
          ? err
          : new ProxyError(502, 'Failed to open the console stream');
        rejectUpgrade(socket, e.status ?? 502, e.message);
      }
    })();
  });
}
