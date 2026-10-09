/**
 * @unm/plugin-test-kit — mock TrueNAS appliance for plugins/ix-truenas.
 *
 * The plugin speaks JSON-RPC 2.0 over a WebSocket at `<host>/api/current`. On
 * connect it authenticates with `auth.login_ex` (PASSWORD_PLAIN or API_KEY_PLAIN),
 * then polls a parallel batch whose health-relevant core trio is:
 *   - system.info  → must return an object
 *   - pool.query   → must return an array (empty is fine)
 *   - alert.list   → [] (no CRITICAL/WARNING alerts)
 * All other calls are best-effort and answered with a JSON-RPC error, which the
 * plugin treats as absent. The mock ignores auth specifics and answers purely on
 * `method`, so either credential shape works.
 */

import http from 'node:http';
import { WebSocketServer } from 'ws';

/**
 * @returns {Promise<{port:number, url:string, requests:Array, stop:()=>Promise<void>}>}
 *   `requests` records the JSON-RPC methods received (for suite assertions).
 */
export function startTruenasMock() {
  const calls = [];
  return new Promise((resolve, reject) => {
    const server = http.createServer();
    const wss = new WebSocketServer({ server, path: '/api/current' });

    wss.on('connection', (ws) => {
      ws.on('message', (raw) => {
        let msg;
        try { msg = JSON.parse(raw.toString()); } catch { return; }
        calls.push(msg.method);
        if (calls.length > 500) calls.shift();
        const id = msg.id ?? 1;
        const reply = (result, error) => ws.send(JSON.stringify(error ? { jsonrpc: '2.0', id, error } : { jsonrpc: '2.0', id, result }));

        switch (msg.method) {
          case 'auth.login_ex':
          case 'auth.login':
            reply({ response_type: 'SUCCESS' });
            break;
          case 'system.info':
            reply({ version: '25.04', hostname: 'mock-truenas', cores: 8, loadavg: [1, 1, 1], physmem: 16777216 });
            break;
          case 'pool.query':
            reply([{ name: 'tank', status: 'ONLINE' }]);
            break;
          case 'alert.list':
            reply([]);
            break;
          default:
            // Best-effort inventory calls — error envelope, never counts toward health.
            reply(undefined, { code: -32601, message: `mock: ${msg.method} not implemented` });
        }
      });
    });

    server.on('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const port = server.address().port;
      resolve({
        port,
        url: `ws://127.0.0.1:${port}/api/current`,
        requests: calls,
        stop: async () => {
          for (const c of wss.clients) c.terminate();
          await new Promise((res) => wss.close(res));
          await new Promise((res) => server.close(res));
        },
      });
    });
  });
}
