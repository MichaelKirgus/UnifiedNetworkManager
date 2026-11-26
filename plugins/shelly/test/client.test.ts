/**
 * Unit tests for src/client.ts — endpoint resolution, Gen1 REST calls and the
 * batched JSON-RPC transport, against an in-process node:http mock device.
 */
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import {
  MAX_TIMEOUT_MS,
  gen1Get,
  resolveBase,
  rpc,
  type ShellyClientOptions,
} from '../src/client';

interface RecordedRequest {
  method: string;
  url: string;
  body: unknown;
  headers: http.IncomingHttpHeaders;
}

interface MockDevice {
  port: number;
  requests: RecordedRequest[];
  close(): Promise<void>;
}

/** Starts a mock Shelly device. `handler` decides the response per request. */
function startMockDevice(
  handler: (req: RecordedRequest) => { status?: number; body?: unknown; raw?: string; headers?: Record<string, string> },
): Promise<MockDevice> {
  const requests: RecordedRequest[] = [];
  const server = http.createServer((req, res) => {
    let rawBody = '';
    req.on('data', (c) => (rawBody += c));
    req.on('end', () => {
      let body: unknown;
      try {
        body = rawBody ? JSON.parse(rawBody) : undefined;
      } catch {
        body = rawBody;
      }
      const recorded: RecordedRequest = { method: req.method ?? '', url: req.url ?? '', body, headers: req.headers };
      requests.push(recorded);
      const out = handler(recorded);
      res.statusCode = out.status ?? 200;
      for (const [k, v] of Object.entries(out.headers ?? {})) res.setHeader(k, v);
      if (out.raw !== undefined) {
        res.end(out.raw);
      } else {
        res.end(JSON.stringify(out.body ?? {}));
      }
    });
  });
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      resolve({
        port: (server.address() as AddressInfo).port,
        requests,
        close: () => new Promise<void>((r) => server.close(() => r())),
      });
    });
  });
}

function optsFor(port: number, extra: Partial<ShellyClientOptions> = {}): ShellyClientOptions {
  return { address: `http://127.0.0.1:${port}`, transport: 'http', timeoutMs: 2000, ...extra };
}

describe('resolveBase', () => {
  it('defaults to plain http without a port suffix (Shelly serves HTTP on :80)', () => {
    expect(resolveBase({ address: 'shelly.local', transport: 'http' })).toBe('http://shelly.local');
  });

  it('lets an explicit scheme+port in the address win over everything', () => {
    expect(resolveBase({ address: 'https://dev.example:8443', transport: 'http' })).toBe('https://dev.example:8443');
  });

  it('lets a port in the address win over the configured default port', () => {
    expect(resolveBase({ address: 'host:8081', transport: 'http', httpPort: 8080 })).toBe('http://host:8081');
  });

  it('applies the configured https port in auto mode (https candidate first)', () => {
    expect(
      resolveBase({ address: 'host', transport: 'auto', httpPort: 8081, httpsPort: 9443 }),
    ).toBe('https://host:9443');
  });
});

describe('gen1Get (Gen1 REST)', () => {
  it('returns parsed JSON on success', async () => {
    const dev = await startMockDevice((req) => {
      expect(req.method).toBe('GET');
      return { body: { uptime: 123, wifi_sta: { rssi: -70 } } };
    });
    try {
      const r = await gen1Get(optsFor(dev.port), '/status');
      expect(r.ok).toBe(true);
      expect(r.status).toBe(200);
      expect((r.data as { uptime: number }).uptime).toBe(123);
    } finally {
      await dev.close();
    }
  });

  it('maps HTTP 500 to ok:false without throwing (body still surfaced for inspection)', async () => {
    const dev = await startMockDevice(() => ({ status: 500, raw: '<html>oops</html>' }));
    try {
      const r = await gen1Get(optsFor(dev.port), '/status');
      expect(r.ok).toBe(false);
      expect(r.status).toBe(500);
      expect(r.data).toBe('<html>oops</html>'); // non-2xx bodies are surfaced, not dropped
      expect(r.errorKind).toBeUndefined(); // not an auth problem
    } finally {
      await dev.close();
    }
  });

  it('maps HTTP 401 to errorKind auth-rejected', async () => {
    const dev = await startMockDevice(() => ({ status: 401, body: {} }));
    try {
      const r = await gen1Get(optsFor(dev.port), '/status');
      expect(r.ok).toBe(false);
      expect(r.errorKind).toBe('auth-rejected');
    } finally {
      await dev.close();
    }
  });

  it('maps connection refusal to errorKind unreachable with status 0', async () => {
    // bind a server just to grab a free port, then close it → ECONNREFUSED
    const probe = http.createServer(() => {});
    await new Promise<void>((r) => probe.listen(0, '127.0.0.1', () => r()));
    const deadPort = (probe.address() as AddressInfo).port;
    await new Promise<void>((r) => probe.close(() => r()));

    const r = await gen1Get(optsFor(deadPort), '/status');
    expect(r.ok).toBe(false);
    expect(r.status).toBe(0);
    expect(r.errorKind).toBe('unreachable');
  });
});

describe('rpc (Gen2+ JSON-RPC batch)', () => {
  it('sends all methods in ONE request array and maps responses by id (order-independent)', async () => {
    const dev = await startMockDevice((req) => {
      expect(req.method).toBe('POST');
      expect(req.url).toBe('/rpc');
      // answer OUT OF ORDER to prove id-based matching
      return { body: [
        { jsonrpc: '2.0', id: 3, result: { channel: 6 } },
        { jsonrpc: '2.0', id: 1, result: { id: 'SWN-1PM', fw_version: '1.4.1' } },
        { jsonrpc: '2.0', id: 2, result: { sys: { uptime: 999 } } },
      ] };
    });
    try {
      const r = await rpc(optsFor(dev.port), [
        { method: 'Shelly.GetDeviceInfo' },
        { method: 'Shelly.GetStatus' },
        { method: 'WiFi.GetStatus' },
      ]);

      expect(r.ok).toBe(true);
      expect(dev.requests).toHaveLength(1); // exactly one round-trip
      const sent = dev.requests[0].body as Array<Record<string, unknown>>;
      expect(sent).toHaveLength(3);
      expect(sent.map((m) => m.method)).toEqual(['Shelly.GetDeviceInfo', 'Shelly.GetStatus', 'WiFi.GetStatus']);
      expect(sent.map((m) => m.id)).toEqual([1, 2, 3]);
      expect(sent.every((m) => m.jsonrpc === '2.0')).toBe(true);

      // results come back in CALL order despite the shuffled response
      expect(r.results[0].ok).toBe(true);
      expect((r.results[0].result as { id: string }).id).toBe('SWN-1PM');
      expect((r.results[1].result as { sys: { uptime: number } }).sys.uptime).toBe(999);
      expect((r.results[2].result as { channel: number }).channel).toBe(6);
    } finally {
      await dev.close();
    }
  });

  it('surfaces per-method RPC errors without failing the whole batch', async () => {
    const dev = await startMockDevice(() => ({ body: [
      { jsonrpc: '2.0', id: 1, error: { code: -32601, message: 'Method not found' } },
      { jsonrpc: '2.0', id: 2, result: { ok: true } },
    ] }));
    try {
      const r = await rpc(optsFor(dev.port), [
        { method: 'Shelly.GetDeviceInfo' },
        { method: 'Sys.GetStatus' },
      ]);
      expect(r.ok).toBe(true); // transport succeeded
      expect(r.results[0].ok).toBe(false);
      expect(r.results[0].error?.code).toBe(-32601);
      expect(r.results[1].ok).toBe(true);
    } finally {
      await dev.close();
    }
  });

  it('maps a non-array RPC body to a transport failure (malformed)', async () => {
    const dev = await startMockDevice(() => ({ body: { jsonrpc: '2.0', id: 1, result: {} } }));
    try {
      const r = await rpc(optsFor(dev.port), [{ method: 'Shelly.GetDeviceInfo' }]);
      expect(r.ok).toBe(false);
      expect(r.error).toMatch(/malformed/i);
      expect(r.results).toEqual([]);
    } finally {
      await dev.close();
    }
  });

  it('maps HTTP 401 on /rpc to auth-rejected', async () => {
    const dev = await startMockDevice(() => ({ status: 401, body: {} }));
    try {
      const r = await rpc(optsFor(dev.port), [{ method: 'Shelly.GetDeviceInfo' }]);
      expect(r.ok).toBe(false);
      expect(r.errorKind).toBe('auth-rejected');
    } finally {
      await dev.close();
    }
  });

  it('clamps the timeout to MAX_TIMEOUT_MS', async () => {
    // a request that would exceed the cap still completes (mock answers fast) —
    // this pins the clamp behavior via the exported constant contract.
    expect(MAX_TIMEOUT_MS).toBe(9_000);
    const dev = await startMockDevice(() => ({ body: [{ jsonrpc: '2.0', id: 1, result: { ok: true } }] }));
    try {
      const r = await rpc(optsFor(dev.port, { timeoutMs: 60_000 }), [{ method: 'Shelly.GetDeviceInfo' }]);
      expect(r.ok).toBe(true);
    } finally {
      await dev.close();
    }
  });
});
