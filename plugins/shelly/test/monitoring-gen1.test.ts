/**
 * Unit tests for the Gen1 (legacy REST) monitoring collector — against an
 * in-process mock device whose /status mirrors the official Shelly Gen1 API
 * documentation example.
 */
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { collectGen1, WEAK_RSSI_DBM } from '../src/monitoring';
import type { ShellyClientOptions } from '../src/client';
import type { DeviceProfile } from '../src/detect';

interface MockDevice {
  port: number;
  statusHits: string[]; // recorded paths
  close(): Promise<void>;
}

function startMockDevice(statusBody: unknown, statusStatus = 200): Promise<MockDevice> {
  const state: MockDevice = { port: 0, statusHits: [], close: async () => {} };
  const server = http.createServer((req, res) => {
    if (req.url === '/status' && req.method === 'GET') {
      state.statusHits.push(req.url);
      res.statusCode = statusStatus;
      res.end(JSON.stringify(statusBody));
    } else {
      res.statusCode = 404;
      res.end('{}');
    }
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

const PROFILE: DeviceProfile = {
  gen: 1,
  model: 'SHPLG-1',
  name: 'Shelly Plug US',
  mac: 'BCDCB43E9A0C',
  fw: '4.3.0',
};

/** Official Gen1 /status documentation example (with a relay added). */
const DOC_STATUS = {
  wifi_sta: { connected: true, ssid: 'Home', ip: '192.168.1.50', rssi: -73 },
  meters: [{ voltage: 220, current: 1.2, power: 264, total: 1.23 }],
  update: { has_update: false, new_version: '', old_version: '4.3.0' },
  uptime: 3662, // seconds since boot (official docs)
  ram_total: 191800,
  ram_free: 125472,
  ram_lwm: 4096,
  fs_size: 1067904,
  fs_free: 823196,
  relay: [{ ison: true }, { ison: false }],
};

describe('collectGen1 — happy path', () => {
  it('maps the /status payload onto the canonical metric model (one GET per poll)', async () => {
    const dev = await startMockDevice(DOC_STATUS);
    try {
      const r = await collectGen1(optsFor(dev.port), PROFILE);
      expect(r.health).toBe('ok');
      expect(r.warnings).toEqual([]);
      expect(dev.statusHits).toEqual(['/status']); // exactly one request

      const m = r.metrics;
      expect(m['system.swVersion']).toBe('4.3.0'); // canonical, from update.old_version
      expect(m['hostname']).toBe('Shelly Plug US');
      expect(m['shelly.model']).toBe('SHPLG-1');
      expect(m['shelly.mac']).toBe('BCDCB43E9A0C');
      expect(m['shelly.uptimeSeconds']).toBe(3662);
      expect(m['shelly.ramFreeBytes']).toBe(125472);
      expect(m['shelly.ramTotalBytes']).toBe(191800);
      expect(m['shelly.fsFreeBytes']).toBe(823196);
      // WLAN — first-class metrics
      expect(m['shelly.wifiRssiDbm']).toBe(-73);
      expect(m['shelly.wifiSsid']).toBe('Home');
      expect(m['shelly.wifiStaIp']).toBe('192.168.1.50');
      // update availability
      expect(m['shelly.fwUpdateAvailable']).toBe(0);
      // model-specific extras (best effort)
      expect(m['shelly.relay0On']).toBe(1);
      expect(m['shelly.relay1On']).toBe(0);
      expect(m['shelly.powerW']).toBe(264);
      expect(m['shelly.energyWh']).toBe(1230); // 1.23 kWh → Wh
    } finally {
      await dev.close();
    }
  });

  it('falls back to the detected firmware version when /status lacks update info', async () => {
    const dev = await startMockDevice({ uptime: 10, wifi_sta: { rssi: -60 } });
    try {
      const r = await collectGen1(optsFor(dev.port), PROFILE);
      expect(r.metrics['system.swVersion']).toBe('4.3.0'); // from profile.fw
    } finally {
      await dev.close();
    }
  });
});

describe('collectGen1 — health verdicts', () => {
  it('warns on weak WLAN RSSI (≤ -85 dBm)', async () => {
    const dev = await startMockDevice({ ...DOC_STATUS, wifi_sta: { ssid: 'Home', rssi: WEAK_RSSI_DBM - 5 } });
    try {
      const r = await collectGen1(optsFor(dev.port), PROFILE);
      expect(r.health).toBe('warning');
      expect(r.warnings.some((w) => /weak WLAN RSSI/.test(w))).toBe(true);
    } finally {
      await dev.close();
    }
  });

  it('warns when free RAM is at/below the device threshold', async () => {
    const dev = await startMockDevice({ ...DOC_STATUS, ram_free: 2048 }); // below ram_lwm 4096
    try {
      const r = await collectGen1(optsFor(dev.port), PROFILE);
      expect(r.health).toBe('warning');
      expect(r.warnings.some((w) => /RAM low/.test(w))).toBe(true);
    } finally {
      await dev.close();
    }
  });

  it('warns when flash is ≥90% used', async () => {
    const dev = await startMockDevice({ ...DOC_STATUS, fs_size: 1000, fs_free: 50 });
    try {
      const r = await collectGen1(optsFor(dev.port), PROFILE);
      expect(r.health).toBe('warning');
      expect(r.warnings.some((w) => /flash nearly full/.test(w))).toBe(true);
    } finally {
      await dev.close();
    }
  });

  it('stays ok below the flash threshold', async () => {
    const dev = await startMockDevice({ ...DOC_STATUS, fs_size: 1000, fs_free: 150 }); // 85% used < 90
    try {
      const r = await collectGen1(optsFor(dev.port), PROFILE);
      expect(r.health).toBe('ok');
    } finally {
      await dev.close();
    }
  });

  it('is critical with an auth-rejected message on HTTP 401', async () => {
    const dev = await startMockDevice({}, 401);
    try {
      const r = await collectGen1(optsFor(dev.port), PROFILE);
      expect(r.health).toBe('critical');
      expect(r.error).toMatch(/authentication rejected/);
      expect(r.metrics).toEqual({});
    } finally {
      await dev.close();
    }
  });

  it('is critical with an unreachable message when the device is down', async () => {
    const probe = http.createServer(() => {});
    await new Promise<void>((r) => probe.listen(0, '127.0.0.1', () => r()));
    const deadPort = (probe.address() as AddressInfo).port;
    await new Promise<void>((r) => probe.close(() => r()));

    const r = await collectGen1(optsFor(deadPort), PROFILE);
    expect(r.health).toBe('critical');
    expect(r.error).toMatch(/unreachable/);
    expect(r.metrics).toEqual({});
  });
});
