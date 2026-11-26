/**
 * Unit tests for the Shelly action catalog (src/actions.ts) — validation and
 * per-generation execute() against an in-process mock device that records
 * exactly which endpoint/method each action hit.
 */
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { validateInput, isValidInput } from '@unm/plugin-sdk';
import { shellyActions, ShellyActionContext } from '../src/actions';
import type { ShellyClientOptions } from '../src/client';
import type { DeviceProfile } from '../src/detect';

interface MockDevice {
  port: number;
  hits: Array<{ method: string; url: string; body?: Record<string, unknown> }>;
  close(): Promise<void>;
}

function startMockDevice(): Promise<MockDevice> {
  const state: MockDevice = { port: 0, hits: [], close: async () => {} };
  const server = http.createServer((req, res) => {
    let rawBody = '';
    req.on('data', (c) => (rawBody += c));
    req.on('end', () => {
      let body: Record<string, unknown> | undefined;
      if (rawBody) {
        try {
          const parsed = JSON.parse(rawBody);
          body = Array.isArray(parsed) ? { __batch: parsed } : parsed;
        } catch { /* non-JSON */ }
      }
      state.hits.push({ method: req.method ?? '', url: req.url ?? '', body });

      if (req.url === '/rpc' && req.method === 'POST') {
        const batch = (body?.__batch ?? []) as Array<{ id: number; method: string }>;
        res.statusCode = 200;
        res.end(JSON.stringify(batch.map((m) => ({ jsonrpc: '2.0', id: m.id, result: {} }))));
      } else if (req.url === '/ota?update=true') {
        res.statusCode = 200;
        res.end(JSON.stringify({ ota: 'pending' }));
      } else if (req.url === '/reboot') {
        res.statusCode = 200;
        res.end('{}');
      } else {
        res.statusCode = 404;
        res.end('{}');
      }
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

function ctxFor(port: number, profile: DeviceProfile): ShellyActionContext {
  const client: ShellyClientOptions = { address: `http://127.0.0.1:${port}`, transport: 'http', timeoutMs: 2000 };
  return { client, profile };
}

const GEN1: DeviceProfile = { gen: 1, model: 'SHSW-1', name: 'Shelly Switch', mac: 'BCDCB43E9A0C', fw: '4.3.0' };
const GEN2_CLASSIC: DeviceProfile = { gen: 2, ns: 'classic', model: 'SWN-1PM', name: 'Plus Wave', mac: '0050C1A63920', fw: '1.4.1' };
const GEN2_MODERN: DeviceProfile = { gen: 2, ns: 'modern', model: 'Pro4Gen4', name: 'Pro 4 Gen4', mac: 'AABBCCDDEE01', fw: '2.0.5' };

describe('shellyActions — registry shape', () => {
  it('exposes both actions in the catalog with correct modules', () => {
    const ids = shellyActions.listCatalog().map((a) => a.id).sort();
    expect(ids).toEqual(['shelly.firmware.update', 'shelly.reboot']);
    expect(shellyActions.listModules().sort()).toEqual(['Firmware', 'System']);
    expect(shellyActions.getAction('shelly.firmware.update')?.riskLevel).toBe('dangerous');
    expect(shellyActions.getAction('shelly.reboot')?.riskLevel).toBe('write');
  });

  it('validates the stage enum — rejects unknown stages, accepts stable/beta/absent', () => {
    const schema = shellyActions.getAction('shelly.firmware.update')!.inputSchema;
    expect(validateInput(schema, { stage: 'nightly' })).toHaveLength(1);
    expect(isValidInput(schema, { stage: 'stable' })).toBe(true);
    expect(isValidInput(schema, { stage: 'beta' })).toBe(true);
    expect(isValidInput(schema, {})).toBe(true); // stage optional — defaults to stable
  });

  it('reboot takes no input', () => {
    const schema = shellyActions.getAction('shelly.reboot')!.inputSchema;
    expect(schema).toEqual({});
  });
});

describe('shelly.firmware.update — Gen1 (GET /ota?update=true)', () => {
  it('triggers the documented endpoint and reports "update started"', async () => {
    const dev = await startMockDevice();
    try {
      const r = await shellyActions.getAction('shelly.firmware.update')!.execute(ctxFor(dev.port, GEN1), {});
      expect(dev.hits).toEqual([{ method: 'GET', url: '/ota?update=true' }]);
      expect(r.success).toBe(true);
      expect(r.applied).toBe(true);
      expect(String((r.details as Record<string, unknown>)?.note)).toMatch(/reboot/i);
    } finally {
      await dev.close();
    }
  });

  it('rejects the beta stage without touching the device (Gen1 is stable-only)', async () => {
    const dev = await startMockDevice();
    try {
      const r = await shellyActions.getAction('shelly.firmware.update')!.execute(ctxFor(dev.port, GEN1), { stage: 'beta' });
      expect(dev.hits).toEqual([]); // no HTTP at all
      expect(r.success).toBe(false);
      expect(String((r.details as Record<string, unknown>)?.error)).toMatch(/stable/i);
    } finally {
      await dev.close();
    }
  });

  it('rejects a custom URL on Gen1', async () => {
    const dev = await startMockDevice();
    try {
      const r = await shellyActions.getAction('shelly.firmware.update')!.execute(ctxFor(dev.port, GEN1), { url: 'http://example.com/fw.bin' });
      expect(dev.hits).toEqual([]);
      expect(r.success).toBe(false);
    } finally {
      await dev.close();
    }
  });
});

describe('shelly.firmware.update — Gen2+ (JSON-RPC)', () => {
  it('classic: Shelly.Update with stage + optional url in params', async () => {
    const dev = await startMockDevice();
    try {
      const r = await shellyActions.getAction('shelly.firmware.update')!.execute(ctxFor(dev.port, GEN2_CLASSIC), { stage: 'beta' });
      expect(dev.hits).toHaveLength(1);
      expect(dev.hits[0].method).toBe('POST');
      expect(dev.hits[0].url).toBe('/rpc');
      const batch = (dev.hits[0].body?.__batch ?? []) as Array<{ method: string; params?: Record<string, unknown> }>;
      expect(batch).toMatchObject([{ method: 'Shelly.Update', params: { stage: 'beta' } }]);
      expect(r.success).toBe(true);
      expect(String((r.details as Record<string, unknown>)?.note)).toMatch(/stage: beta/);
    } finally {
      await dev.close();
    }
  });

  it('modern: Firmware.Update (default stage stable)', async () => {
    const dev = await startMockDevice();
    try {
      await shellyActions.getAction('shelly.firmware.update')!.execute(ctxFor(dev.port, GEN2_MODERN), {});
      const batch = (dev.hits[0].body?.__batch ?? []) as Array<{ method: string; params?: Record<string, unknown> }>;
      expect(batch).toMatchObject([{ method: 'Firmware.Update', params: { stage: 'stable' } }]);
    } finally {
      await dev.close();
    }
  });

  it('passes a custom firmware URL through in params (Gen2+ only)', async () => {
    const dev = await startMockDevice();
    try {
      await shellyActions.getAction('shelly.firmware.update')!.execute(ctxFor(dev.port, GEN2_CLASSIC), { url: 'http://example.com/fw.bin' });
      const batch = (dev.hits[0].body?.__batch ?? []) as Array<{ method: string; params?: Record<string, unknown> }>;
      expect(batch).toMatchObject([{ method: 'Shelly.Update', params: { stage: 'stable', url: 'http://example.com/fw.bin' } }]);
    } finally {
      await dev.close();
    }
  });

  it('surfaces a per-method RPC error as a failed action', async () => {
    const server = http.createServer((req, res) => {
      let rawBody = '';
      req.on('data', (c) => (rawBody += c));
      req.on('end', () => {
        const batch = JSON.parse(rawBody) as Array<{ id: number }>;
        res.statusCode = 200;
        res.end(JSON.stringify(batch.map((m) => ({ jsonrpc: '2.0', id: m.id, error: { code: -32602, message: 'Invalid params' } }))));
      });
    });
    await new Promise<void>((r) => server.listen(0, '127.0.0.1', () => r()));
    const port = (server.address() as AddressInfo).port;
    try {
      const r = await shellyActions.getAction('shelly.firmware.update')!.execute(ctxFor(port, GEN2_CLASSIC), {});
      expect(r.success).toBe(false);
      expect(String((r.details as Record<string, unknown>)?.error)).toMatch(/Invalid params/);
    } finally {
      await new Promise<void>((r) => server.close(() => r()));
    }
  });

  it('fails cleanly when the device is unreachable', async () => {
    const probe = http.createServer(() => {});
    await new Promise<void>((r) => probe.listen(0, '127.0.0.1', () => r()));
    const deadPort = (probe.address() as AddressInfo).port;
    await new Promise<void>((r) => probe.close(() => r()));

    const r = await shellyActions.getAction('shelly.firmware.update')!.execute(ctxFor(deadPort, GEN2_CLASSIC), {});
    expect(r.success).toBe(false);
    expect(String((r.details as Record<string, unknown>)?.error)).toMatch(/unreachable|timed out/i);
  });
});

describe('shelly.reboot — per generation', () => {
  it('Gen1: POST /reboot', async () => {
    const dev = await startMockDevice();
    try {
      const r = await shellyActions.getAction('shelly.reboot')!.execute(ctxFor(dev.port, GEN1), {});
      expect(dev.hits).toEqual([{ method: 'POST', url: '/reboot' }]);
      expect(r.success).toBe(true);
      expect(r.applied).toBe(true);
    } finally {
      await dev.close();
    }
  });

  it('Gen2 classic: Shelly.Reboot; modern: Sys.Reboot', async () => {
    const dev = await startMockDevice();
    try {
      await shellyActions.getAction('shelly.reboot')!.execute(ctxFor(dev.port, GEN2_CLASSIC), {});
      let batch = (dev.hits[0].body?.__batch ?? []) as Array<{ method: string }>;
      expect(batch.map((b) => b.method)).toEqual(['Shelly.Reboot']);

      await shellyActions.getAction('shelly.reboot')!.execute(ctxFor(dev.port, GEN2_MODERN), {});
      batch = (dev.hits[1].body?.__batch ?? []) as Array<{ method: string }>;
      expect(batch.map((b) => b.method)).toEqual(['Sys.Reboot']);
    } finally {
      await dev.close();
    }
  });
});
