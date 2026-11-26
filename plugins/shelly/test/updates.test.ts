/**
 * Unit tests for the Updates-page rows (src/updates.ts) — Gen1 via GET /ota,
 * Gen2+ via a batched Firmware.GetStatus RPC. Verifies the emission contract:
 * has_update true/false mapping and transport failure ⇒ throw (caller omits).
 */
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { getShellyUpdateRows, FIRMWARE_UPDATE_ACTION_ID } from '../src/updates';
import type { ShellyClientOptions } from '../src/client';
import type { DeviceProfile } from '../src/detect';

interface MockDevice {
  port: number;
  hits: string[]; // recorded "METHOD url" lines
  close(): Promise<void>;
}

function startMockDevice(handler: (req: http.IncomingMessage, res: http.ServerResponse, body: string) => void): Promise<MockDevice> {
  const state: MockDevice = { port: 0, hits: [], close: async () => {} };
  const server = http.createServer((req, res) => {
    let rawBody = '';
    req.on('data', (c) => (rawBody += c));
    req.on('end', () => {
      state.hits.push(`${req.method} ${req.url}`);
      handler(req, res, rawBody);
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

const GEN1_PROFILE: DeviceProfile = { gen: 1, model: 'SHSW-1', name: 'Shelly Switch', mac: 'BCDCB43E9A0C', fw: '4.3.0' };
const GEN2_PROFILE: DeviceProfile = { gen: 2, ns: 'classic', model: 'SNS-W01A1EU01HVE', name: 'Shelly Plus Wave', mac: '0050C1A63920', fw: '1.4.1' };

describe('getShellyUpdateRows — Gen1 (GET /ota)', () => {
  it('emits an available row when has_update is true', async () => {
    const dev = await startMockDevice((_req, res) => {
      res.statusCode = 200;
      res.end(JSON.stringify({ ota: 'idle', has_update: true, new_version: '4.5.1', old_version: '4.3.0' }));
    });
    try {
      const rows = await getShellyUpdateRows(optsFor(dev.port), GEN1_PROFILE);
      expect(dev.hits).toEqual(['GET /ota']);
      expect(rows).toHaveLength(1);
      expect(rows[0]).toMatchObject({
        name: 'os',
        kind: 'firmware',
        currentVersion: '4.3.0',
        latestVersion: '4.5.1',
        available: true,
        rebootRequired: true,
        applyActionId: FIRMWARE_UPDATE_ACTION_ID,
      });
    } finally {
      await dev.close();
    }
  });

  it('returns an authoritative empty array when has_update is false', async () => {
    const dev = await startMockDevice((_req, res) => {
      res.statusCode = 200;
      res.end(JSON.stringify({ ota: 'idle', has_update: false, new_version: '', old_version: '4.3.0' }));
    });
    try {
      const rows = await getShellyUpdateRows(optsFor(dev.port), GEN1_PROFILE);
      expect(rows).toEqual([]);
    } finally {
      await dev.close();
    }
  });

  it('annotates the row when an update is already in progress', async () => {
    const dev = await startMockDevice((_req, res) => {
      res.statusCode = 200;
      res.end(JSON.stringify({ ota: 'pending', has_update: true, new_version: '4.5.1', old_version: '4.3.0' }));
    });
    try {
      const rows = await getShellyUpdateRows(optsFor(dev.port), GEN1_PROFILE);
      expect(rows).toHaveLength(1);
      expect((rows[0].extra as { note?: string } | undefined)?.note).toMatch(/in progress/);
    } finally {
      await dev.close();
    }
  });

  it('throws on transport failure (device down) — caller must omit the key', async () => {
    const probe = http.createServer(() => {});
    await new Promise<void>((r) => probe.listen(0, '127.0.0.1', () => r()));
    const deadPort = (probe.address() as AddressInfo).port;
    await new Promise<void>((r) => probe.close(() => r()));

    await expect(getShellyUpdateRows(optsFor(deadPort), GEN1_PROFILE)).rejects.toThrow(/unreachable/);
  });

  it('throws on auth rejection — caller must omit the key', async () => {
    const dev = await startMockDevice((_req, res) => {
      res.statusCode = 401;
      res.end('{}');
    });
    try {
      await expect(getShellyUpdateRows(optsFor(dev.port), GEN1_PROFILE)).rejects.toThrow(/authentication rejected/);
    } finally {
      await dev.close();
    }
  });
});

describe('getShellyUpdateRows — Gen2+ (batched Firmware.GetStatus)', () => {
  it('emits an available row when Firmware.GetStatus reports has_update', async () => {
    const dev = await startMockDevice((req, res, body) => {
      expect(req.url).toBe('/rpc');
      const batch = JSON.parse(body) as Array<{ method: string }>;
      expect(batch.map((b) => b.method)).toEqual(['Firmware.GetStatus']); // single-method batch
      res.statusCode = 200;
      res.end(JSON.stringify([{ jsonrpc: '2.0', id: 1, result: { has_update: true, new_version: '1.5.0', old_version: '1.4.1' } }]));
    });
    try {
      const rows = await getShellyUpdateRows(optsFor(dev.port), GEN2_PROFILE);
      expect(rows).toHaveLength(1);
      expect(rows[0]).toMatchObject({
        currentVersion: '1.4.1',
        latestVersion: '1.5.0',
        available: true,
        applyActionId: FIRMWARE_UPDATE_ACTION_ID,
      });
    } finally {
      await dev.close();
    }
  });

  it('returns an authoritative empty array when no update is available', async () => {
    const dev = await startMockDevice((_req, res) => {
      res.statusCode = 200;
      res.end(JSON.stringify([{ jsonrpc: '2.0', id: 1, result: { has_update: false, new_version: '', old_version: '1.4.1' } }]));
    });
    try {
      const rows = await getShellyUpdateRows(optsFor(dev.port), GEN2_PROFILE);
      expect(rows).toEqual([]);
    } finally {
      await dev.close();
    }
  });

  it('throws when the method itself errors (omit, never wipe)', async () => {
    const dev = await startMockDevice((_req, res) => {
      res.statusCode = 200;
      res.end(JSON.stringify([{ jsonrpc: '2.0', id: 1, error: { code: -32601, message: 'Method not found' } }]));
    });
    try {
      await expect(getShellyUpdateRows(optsFor(dev.port), GEN2_PROFILE)).rejects.toThrow(/Firmware.GetStatus failed/);
    } finally {
      await dev.close();
    }
  });

  it('throws on transport failure (device down) — caller must omit the key', async () => {
    const probe = http.createServer(() => {});
    await new Promise<void>((r) => probe.listen(0, '127.0.0.1', () => r()));
    const deadPort = (probe.address() as AddressInfo).port;
    await new Promise<void>((r) => probe.close(() => r()));

    await expect(getShellyUpdateRows(optsFor(deadPort), GEN2_PROFILE)).rejects.toThrow(/unreachable/);
  });
});
