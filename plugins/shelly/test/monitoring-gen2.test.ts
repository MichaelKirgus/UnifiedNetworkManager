/**
 * Unit tests for the Gen2+ (JSON-RPC) monitoring collector — against an
 * in-process mock device answering POST /rpc batches, for BOTH namespace
 * families (classic fw 1.x and modern fw 2.x+).
 */
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { collectGen2, gen2PollMethods, OVERTEMP_C } from '../src/monitoring';
import type { ShellyClientOptions } from '../src/client';
import type { DeviceProfile } from '../src/detect';

type RpcResponse = (methods: Array<{ id: number; method: string }>) => unknown;

interface MockDevice {
  port: number;
  rpcBatches: Array<Array<{ id: number; method: string }>>;
  close(): Promise<void>;
}

function startMockDevice(respond: RpcResponse): Promise<MockDevice> {
  const state: MockDevice = { port: 0, rpcBatches: [], close: async () => {} };
  const server = http.createServer((req, res) => {
    let rawBody = '';
    req.on('data', (c) => (rawBody += c));
    req.on('end', () => {
      if (req.url !== '/rpc' || req.method !== 'POST') {
        res.statusCode = 404;
        res.end('{}');
        return;
      }
      let body: unknown;
      try {
        body = JSON.parse(rawBody);
      } catch {
        body = undefined;
      }
      const methods = (Array.isArray(body) ? body : []) as Array<{ id: number; method: string }>;
      state.rpcBatches.push(methods);
      res.statusCode = 200;
      res.end(JSON.stringify(respond(methods)));
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

const CLASSIC_PROFILE: DeviceProfile = { gen: 2, ns: 'classic', model: 'SWN-1PM', name: 'Shelly Plus Wave', mac: '0050C1A63920', fw: '1.4.1' };
const MODERN_PROFILE: DeviceProfile = { gen: 2, ns: 'modern', model: 'Pro4Gen4', name: 'Shelly Pro 4 Gen4', mac: 'AABBCCDDEE01', fw: '2.0.5' };

/** One JSON-RPC response item. */
interface RpcItem {
  jsonrpc: string;
  id: number;
  result?: unknown;
  error?: { code: number; message: string };
}

/** Builds a full batch response for the given methods (classic-style shapes). */
function fullBatch(methods: Array<{ id: number; method: string }>): RpcItem[] {
  return methods.map((m) => {
    switch (m.method) {
      case 'Shelly.GetDeviceInfo':
      case 'Sys.GetDeviceInfo':
        return { jsonrpc: '2.0', id: m.id, result: { id: 'SWN-1PM', name: 'Shelly Plus Wave', mac: '0050C1A63920', fw_version: '1.4.1' } };
      case 'Shelly.GetStatus':
      case 'Sys.GetStatus':
        return {
          jsonrpc: '2.0',
          id: m.id,
          result: {
            sys: { uptime: 98765 },
            relay: [{ id: 0, ison: true }],
            powermeter: [{ id: 0, voltage: 230.1, current: 0.54, power: 123.4, energy: { total: 5.6 } }],
          },
        };
      case 'WiFi.GetStatus':
      case 'Wifi.GetStatus':
        return {
          jsonrpc: '2.0',
          id: m.id,
          result: { sta_ip: '192.168.1.50', status: 'connected', ssid: 'Home', channel: 6, rssi: -70, bssid: 'AA:BB:CC:DD:EE:FF' },
        };
      case 'Firmware.GetStatus':
        return { jsonrpc: '2.0', id: m.id, result: { has_update: true, new_version: '1.5.0', old_version: '1.4.1' } };
      default:
        return { jsonrpc: '2.0', id: m.id, error: { code: -32601, message: 'Method not found' } };
    }
  });
}

describe('gen2PollMethods — namespace families', () => {
  it('uses the classic family for fw 1.x devices', () => {
    expect(gen2PollMethods('classic')).toEqual(['Shelly.GetDeviceInfo', 'Shelly.GetStatus', 'WiFi.GetStatus', 'Firmware.GetStatus']);
  });

  it('uses the modern family for fw 2.x+ devices (Sys.*/Wifi.*)', () => {
    expect(gen2PollMethods('modern')).toEqual(['Sys.GetDeviceInfo', 'Sys.GetStatus', 'Wifi.GetStatus', 'Firmware.GetStatus']);
  });
});

describe('collectGen2 — classic happy path', () => {
  it('polls with ONE batched round-trip and maps every metric group', async () => {
    const dev = await startMockDevice(fullBatch);
    try {
      const r = await collectGen2(optsFor(dev.port), CLASSIC_PROFILE);

      // exactly one HTTP request, carrying all four methods in one array
      expect(dev.rpcBatches).toHaveLength(1);
      expect(dev.rpcBatches[0].map((m) => m.method)).toEqual(gen2PollMethods('classic'));

      expect(r.health).toBe('ok');
      const m = r.metrics;
      expect(m['system.swVersion']).toBe('1.4.1'); // canonical — Firmware.old_version
      expect(m['hostname']).toBe('Shelly Plus Wave');
      expect(m['shelly.model']).toBe('SWN-1PM');
      expect(m['shelly.mac']).toBe('0050C1A63920');
      expect(m['shelly.uptimeSeconds']).toBe(98765);
      // WLAN — first-class metrics incl. channel + BSSID
      expect(m['shelly.wifiRssiDbm']).toBe(-70);
      expect(m['shelly.wifiSsid']).toBe('Home');
      expect(m['shelly.wifiChannel']).toBe(6);
      expect(m['shelly.wifiBssid']).toBe('AA:BB:CC:DD:EE:FF');
      expect(m['shelly.wifiStaIp']).toBe('192.168.1.50');
      // update availability
      expect(m['shelly.fwUpdateAvailable']).toBe(1);
      // components
      expect(m['shelly.relay0On']).toBe(1);
      expect(m['shelly.powerW']).toBe(123.4);
      expect(m['shelly.energyWh']).toBe(5600); // 5.6 kWh → Wh
    } finally {
      await dev.close();
    }
  });
});

describe('collectGen2 — modern family', () => {
  it('sends Sys.*/Wifi.* methods for modern devices and maps the same model', async () => {
    const dev = await startMockDevice(fullBatch);
    try {
      const r = await collectGen2(optsFor(dev.port), MODERN_PROFILE);
      expect(dev.rpcBatches[0].map((m) => m.method)).toEqual(gen2PollMethods('modern'));
      expect(r.health).toBe('ok');
      expect(r.metrics['system.swVersion']).toBe('1.4.1');
      expect(r.metrics['shelly.wifiRssiDbm']).toBe(-70);
    } finally {
      await dev.close();
    }
  });
});

describe('collectGen2 — degradation and health', () => {
  it('omits a component whose method errored, without failing the whole poll', async () => {
    const dev = await startMockDevice((methods) =>
      methods.map((m) =>
        m.method === 'WiFi.GetStatus' || m.method === 'Wifi.GetStatus'
          ? { jsonrpc: '2.0', id: m.id, error: { code: -32601, message: 'Method not found' } }
          : fullBatch([m])[0],
      ),
    );
    try {
      const r = await collectGen2(optsFor(dev.port), CLASSIC_PROFILE);
      expect(r.health).toBe('ok'); // transport succeeded — no wifi metrics, rest intact
      expect(r.metrics['shelly.wifiRssiDbm']).toBeUndefined();
      expect(r.metrics['system.swVersion']).toBe('1.4.1');
      expect(r.metrics['shelly.uptimeSeconds']).toBe(98765);
    } finally {
      await dev.close();
    }
  });

  it('warns on overtemperature (≥ 70 °C)', async () => {
    const dev = await startMockDevice((methods) =>
      methods.map((m) => {
        const base = fullBatch([m])[0];
        if (m.method === 'Shelly.GetStatus' || m.method === 'Sys.GetStatus') {
          return { ...base, result: { sys: { uptime: 10, temperature_c: OVERTEMP_C + 5 } } };
        }
        return base;
      }),
    );
    try {
      const r = await collectGen2(optsFor(dev.port), CLASSIC_PROFILE);
      expect(r.health).toBe('warning');
      expect(r.warnings.some((w) => /overtemperature/.test(w))).toBe(true);
    } finally {
      await dev.close();
    }
  });

  it('is critical when the transport fails entirely (device down)', async () => {
    const probe = http.createServer(() => {});
    await new Promise<void>((r) => probe.listen(0, '127.0.0.1', () => r()));
    const deadPort = (probe.address() as AddressInfo).port;
    await new Promise<void>((r) => probe.close(() => r()));

    const r = await collectGen2(optsFor(deadPort), CLASSIC_PROFILE);
    expect(r.health).toBe('critical');
    expect(r.error).toMatch(/unreachable/);
    expect(r.metrics).toEqual({});
  });

  it('is critical with an auth-rejected message on HTTP 401', async () => {
    const server = http.createServer((req, res) => {
      res.statusCode = 401;
      res.end('{}');
    });
    await new Promise<void>((r) => server.listen(0, '127.0.0.1', () => r()));
    const port = (server.address() as AddressInfo).port;
    try {
      const r = await collectGen2(optsFor(port), CLASSIC_PROFILE);
      expect(r.health).toBe('critical');
      expect(r.error).toMatch(/authentication rejected/);
    } finally {
      await new Promise<void>((r) => server.close(() => r()));
    }
  });
});
