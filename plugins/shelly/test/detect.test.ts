/**
 * Unit tests for src/detect.ts — runtime generation/namespace probing against
 * in-process mocks emulating Gen1, Gen2 classic and Gen2 modern devices.
 */
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { detectDevice, DetectionError, clearDetectCache } from '../src/detect';
import type { ShellyClientOptions } from '../src/client';

interface RouteOut {
  status?: number;
  body?: unknown;
}

type RpcHandler = (body: Array<{ id: number; method: string }>) => RouteOut;

interface MockDevice {
  port: number;
  shellyHits: number;
  rpcCalls: Array<Array<{ id: number; method: string }>>;
  close(): Promise<void>;
}

function startMockDevice(
  shellyRoute: RouteOut,
  rpcRoute: RpcHandler,
): Promise<MockDevice> {
  const state: MockDevice = { port: 0, shellyHits: 0, rpcCalls: [], close: async () => {} };
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
      let out: RouteOut;
      if (req.url === '/shelly') {
        state.shellyHits += 1;
        out = shellyRoute;
      } else if (req.url === '/rpc' && req.method === 'POST') {
        const calls = body as Array<{ id: number; method: string }>;
        state.rpcCalls.push(calls);
        out = rpcRoute(calls);
      } else {
        out = { status: 404, body: {} };
      }
      res.statusCode = out.status ?? 200;
      res.end(JSON.stringify(out.body ?? {}));
    });
  });
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      state.port = (server.address() as AddressInfo).port;
      state.close = () => new Promise<void>((r) => server.close(() => r()));
      resolve(state);
    });
  });
}

function optsFor(port: number): ShellyClientOptions {
  return { address: `http://127.0.0.1:${port}`, transport: 'http', timeoutMs: 2000 };
}

beforeEach(() => clearDetectCache());

describe('detectDevice — Gen1 (legacy REST)', () => {
  it('identifies a Gen1 device from the auth-free GET /shelly probe and never touches /rpc', async () => {
    const dev = await startMockDevice(
      { body: { id: 'SHELLYPLUG-BCDCB43E9A0C', mac: 'BCDCB43E9A0C', type: 'SHPLG-1', name: 'Shelly Plug US', fw: '4.3.0' } },
      () => ({ status: 500, body: [] }), // must NOT be called
    );
    try {
      const p = await detectDevice(optsFor(dev.port), undefined, 'test-gen1');
      expect(p).toEqual({ gen: 1, model: 'SHPLG-1', name: 'Shelly Plug US', mac: 'BCDCB43E9A0C', fw: '4.3.0' });
      expect(dev.shellyHits).toBe(1);
      expect(dev.rpcCalls).toHaveLength(0);
    } finally {
      await dev.close();
    }
  });
});

describe('detectDevice — Gen2+ classic namespaces (fw 1.x)', () => {
  it('falls through /shelly to Shelly.GetDeviceInfo and remembers the classic family', async () => {
    const dev = await startMockDevice(
      { status: 404, body: {} },
      (calls) => ({
        body: calls.map((c) =>
          c.method === 'Shelly.GetDeviceInfo'
            ? { jsonrpc: '2.0', id: c.id, result: { id: 'SWN-1PM', name: 'Shelly Plus Wave', mac: '0050C1A63920', fw_version: '1.4.1' } }
            : { jsonrpc: '2.0', id: c.id, error: { code: -32601, message: 'Method not found' } },
        ),
      }),
    );
    try {
      const p = await detectDevice(optsFor(dev.port), undefined, 'test-classic');
      expect(p.gen).toBe(2);
      expect(p.ns).toBe('classic');
      expect(p.model).toBe('SWN-1PM');
      expect(p.fw).toBe('1.4.1');
      // exactly one /rpc round-trip (the classic probe succeeded on the first try)
      expect(dev.rpcCalls).toHaveLength(1);
    } finally {
      await dev.close();
    }
  });
});

describe('detectDevice — Gen2+ modern namespaces (fw 2.x+)', () => {
  it('tries Shelly.* first, then resolves Sys.GetDeviceInfo and remembers the modern family', async () => {
    const dev = await startMockDevice(
      { status: 404, body: {} },
      (calls) => ({
        body: calls.map((c) =>
          c.method === 'Sys.GetDeviceInfo'
            ? { jsonrpc: '2.0', id: c.id, result: { id: 'Pro4Gen4', name: 'Shelly Pro 4 Gen4', mac: 'AABBCCDDEE01', fw_version: '2.0.5' } }
            : { jsonrpc: '2.0', id: c.id, error: { code: -32601, message: 'Method not found' } },
        ),
      }),
    );
    try {
      const p = await detectDevice(optsFor(dev.port), undefined, 'test-modern');
      expect(p.gen).toBe(2);
      expect(p.ns).toBe('modern');
      expect(p.model).toBe('Pro4Gen4');
      // two /rpc round-trips: classic probe failed, modern probe succeeded
      expect(dev.rpcCalls).toHaveLength(2);
      expect(dev.rpcCalls[0][0].method).toBe('Shelly.GetDeviceInfo');
      expect(dev.rpcCalls[1][0].method).toBe('Sys.GetDeviceInfo');
    } finally {
      await dev.close();
    }
  });
});

describe('detectDevice — failures and caching', () => {
  it('throws DetectionError when nothing answers, carrying the last failure reason', async () => {
    const dev = await startMockDevice(
      { status: 404, body: {} },
      (calls) => ({
        body: calls.map((c) => ({ jsonrpc: '2.0', id: c.id, error: { code: -32601, message: 'Method not found' } })),
      }),
    );
    try {
      await expect(detectDevice(optsFor(dev.port), undefined, 'test-unknown')).rejects.toThrow(DetectionError);
      await expect(detectDevice(optsFor(dev.port), undefined, 'test-unknown2')).rejects.toThrow(/could not detect Shelly generation/);
    } finally {
      await dev.close();
    }
  });

  it('caches the profile — a second call within the TTL makes zero device requests', async () => {
    const dev = await startMockDevice(
      { body: { type: 'SHPLG-1', mac: 'BCDCB43E9A0C', fw: '4.3.0' } },
      () => ({ status: 500, body: [] }),
    );
    try {
      const first = await detectDevice(optsFor(dev.port), undefined, 'test-cache');
      const hitsAfterFirst = dev.shellyHits + dev.rpcCalls.length;
      const second = await detectDevice(optsFor(dev.port), undefined, 'test-cache');
      expect(second).toEqual(first);
      expect(dev.shellyHits + dev.rpcCalls.length).toBe(hitsAfterFirst); // no new requests
    } finally {
      await dev.close();
    }
  });

  it('does not cache failures — the next call re-probes', async () => {
    const dev = await startMockDevice(
      { status: 404, body: {} },
      (calls) => ({
        body: calls.map((c) => ({ jsonrpc: '2.0', id: c.id, error: { code: -32601, message: 'Method not found' } })),
      }),
    );
    try {
      await expect(detectDevice(optsFor(dev.port), undefined, 'test-nocache')).rejects.toThrow(DetectionError);
      const hitsAfterFirst = dev.shellyHits + dev.rpcCalls.length;
      await expect(detectDevice(optsFor(dev.port), undefined, 'test-nocache')).rejects.toThrow(DetectionError);
      expect(dev.shellyHits + dev.rpcCalls.length).toBeGreaterThan(hitsAfterFirst); // re-probed
    } finally {
      await dev.close();
    }
  });
});
