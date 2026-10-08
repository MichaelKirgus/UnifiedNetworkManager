/**
 * @unm/plugin-test-kit — generic HTTP mock appliance.
 *
 * A plain-HTTP server on an ephemeral port that answers GET with a small JSON
 * body and records every request (method, path, headers) so plugin suites can
 * assert WHAT the plugin asked for. Ported from the pattern in the old
 * the standalone geoip web fixture (../fixtures/geoipWebserver.cjs) — but
 * importable + ephemeral instead of a
 * standalone compose service.
 */

import http from 'node:http';

/**
 * @returns {Promise<{port:number, url:string, requests:Array, stop:()=>Promise<void>}>}
 */
export function startHttpMock({ path = '/', status = 200, body = 'ok', headers = {} } = {}) {
  const requests = [];
  return new Promise((resolve, reject) => {
    const server = http.createServer((req, res) => {
      let data = '';
      req.on('data', (c) => (data += c));
      req.on('end', () => {
        requests.push({ method: req.method, url: req.url, headers: req.headers, body: data });
        if (requests.length > 500) requests.shift();
        res.writeHead(status, { 'Content-Type': 'application/json', ...headers });
        res.end(typeof body === 'string' ? body : JSON.stringify(body));
      });
    });
    server.on('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const port = server.address().port;
      resolve({
        port,
        url: `http://127.0.0.1:${port}`,
        requests,
        stop: () => new Promise((res) => server.close(() => res())),
      });
    });
  });
}
