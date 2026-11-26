/**
 * Unit tests for src/auth.ts — Gen1 HTTP Basic + Gen2+ shellyun-auth cookie
 * session manager, exercised against an in-process node:http mock device and
 * through the real client transport.
 */
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { basicAuthHeader } from '@unm/plugin-sdk';
import { rpc, type ShellyClientOptions } from '../src/client';
import {
  AuthSession,
  authSessionFor,
  clearAuthSessions,
  sessionKey,
  SHELLYUN_AUTH_COOKIE,
} from '../src/auth';

interface RecordedRequest {
  url: string;
  authorization?: string;
  cookie?: string;
  body: unknown;
}

interface MockDevice {
  port: number;
  requests: RecordedRequest[];
  /** Per-request behavior queue — shifts one entry per request. */
  behaviors: Array<(req: RecordedRequest) => BehaviorOut>;
  close(): Promise<void>;
}

type BehaviorOut = { status?: number; setCookie?: string; body?: unknown };

function startMockDevice(): Promise<MockDevice> {
  const requests: RecordedRequest[] = [];
  const behaviors: MockDevice['behaviors'] = [];
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
      const recorded: RecordedRequest = {
        url: req.url ?? '',
        authorization: req.headers.authorization,
        cookie: req.headers.cookie,
        body,
      };
      requests.push(recorded);
      const behavior = behaviors.shift() ?? ((): BehaviorOut => ({ body: {} }));
      const out = behavior(recorded);
      res.statusCode = out.status ?? 200;
      if (out.setCookie) res.setHeader('Set-Cookie', out.setCookie);
      res.end(JSON.stringify(out.body ?? {}));
    });
  });
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      resolve({
        port: (server.address() as AddressInfo).port,
        requests,
        behaviors,
        close: () => new Promise<void>((r) => server.close(() => r())),
      });
    });
  });
}

function optsFor(port: number): ShellyClientOptions {
  return { address: `http://127.0.0.1:${port}`, transport: 'http', timeoutMs: 2000 };
}

beforeEach(() => clearAuthSessions());

describe('AuthSession (unit)', () => {
  it('sends HTTP Basic when credentials are bound (Gen1 style)', () => {
    const s = new AuthSession({ username: 'admin', password: 'secret' });
    expect(s.hasCredentials).toBe(true);
    expect(s.headers().Authorization).toBe(basicAuthHeader('admin', 'secret'));
  });

  it('sends nothing when no credentials are bound (auth-disabled device)', () => {
    const s = new AuthSession(undefined);
    expect(s.hasCredentials).toBe(false);
    expect(s.headers()).toEqual({});
  });

  it('captures the shellyun-auth cookie from Set-Cookie and reuses it', () => {
    const s = new AuthSession({ username: 'admin', password: 'secret' });
    expect(s.hasCookie).toBe(false);

    s.onResponse(200, ['shellyun-auth=tok123; Path=/; HttpOnly']);
    expect(s.hasCookie).toBe(true);
    const h = s.headers();
    expect(h.Cookie).toBe('shellyun-auth=tok123');
    // Basic still rides along — the device accepts either, both is safest.
    expect(h.Authorization).toBe(basicAuthHeader('admin', 'secret'));
  });

  it('ignores unrelated cookies and keeps the last shellyun-auth value', () => {
    const s = new AuthSession({ username: 'a', password: 'b' });
    s.onResponse(200, ['other=x; Path=/']);
    expect(s.hasCookie).toBe(false);
    s.onResponse(200, [`${SHELLYUN_AUTH_COOKIE}=first`]);
    s.onResponse(200, [`${SHELLYUN_AUTH_COOKIE}=second`]);
    expect(s.headers().Cookie).toBe(`${SHELLYUN_AUTH_COOKIE}=second`);
  });

  it('invalidates the cookie on 401/403 (session restarts with fresh Basic)', () => {
    const s = new AuthSession({ username: 'a', password: 'b' });
    s.onResponse(200, [`${SHELLYUN_AUTH_COOKIE}=tok`]);
    expect(s.hasCookie).toBe(true);

    s.onResponse(401, []);
    expect(s.hasCookie).toBe(false);
    expect(s.headers().Cookie).toBeUndefined();
    expect(s.headers().Authorization).toBe(basicAuthHeader('a', 'b')); // handshake restarts
  });
});

describe('per-device session registry', () => {
  it('returns the same session for the same address+user, distinct ones otherwise', () => {
    const a1 = authSessionFor('http://dev:80', { username: 'u', password: 'p' });
    const a2 = authSessionFor('http://dev:80', { username: 'u', password: 'p' });
    expect(a2).toBe(a1);

    const b = authSessionFor('http://dev:80', { username: 'other', password: 'p' });
    expect(b).not.toBe(a1);
  });

  it('sessionKey encodes address + username (empty user for anonymous)', () => {
    expect(sessionKey('h', { username: 'u' })).toBe('h|u');
    expect(sessionKey('h', undefined)).toBe('h|');
  });

  it('clearAuthSessions drops every session', () => {
    const a = authSessionFor('http://dev:80', { username: 'u', password: 'p' });
    clearAuthSessions();
    expect(authSessionFor('http://dev:80', { username: 'u', password: 'p' })).not.toBe(a);
  });
});

describe('cookie handshake through the real transport (Gen2+)', () => {
  it('first request carries Basic only; device sets cookie; second request reuses it', async () => {
    const dev = await startMockDevice();
    try {
      // Request 1: no cookie yet → answer with Set-Cookie.
      dev.behaviors.push(() => ({ setCookie: 'shellyun-auth=handshake-tok; Path=/', body: [{ jsonrpc: '2.0', id: 1, result: { id: 'SWN-1PM' } }] }));
      // Request 2: the session must now present the captured cookie.
      dev.behaviors.push((req) => ({ body: [{ jsonrpc: '2.0', id: 1, result: { ok: true } }] }));

      const creds = { username: 'admin', password: 'pw' };
      const session = authSessionFor(`http://127.0.0.1:${dev.port}`, creds);

      const r1 = await rpc(optsFor(dev.port), [{ method: 'Shelly.GetDeviceInfo' }], session);
      expect(r1.ok).toBe(true);
      expect(session.hasCookie).toBe(true);
      expect(dev.requests[0].authorization).toBe(basicAuthHeader('admin', 'pw'));
      expect(dev.requests[0].cookie).toBeUndefined();

      const r2 = await rpc(optsFor(dev.port), [{ method: 'Shelly.GetStatus' }], session);
      expect(r2.ok).toBe(true);
      expect(dev.requests[1].cookie).toBe('shellyun-auth=handshake-tok');
    } finally {
      await dev.close();
    }
  });

  it('after a 401 the next request drops the dead cookie and re-hands-shake', async () => {
    const dev = await startMockDevice();
    try {
      dev.behaviors.push(() => ({ setCookie: 'shellyun-auth=stale; Path=/', body: [{ jsonrpc: '2.0', id: 1, result: {} }] }));
      dev.behaviors.push(() => ({ status: 401, body: {} })); // cookie rejected
      dev.behaviors.push((req) => ({ setCookie: 'shellyun-auth=fresh; Path=/', body: [{ jsonrpc: '2.0', id: 1, result: { ok: true } }] }));

      const creds = { username: 'admin', password: 'pw' };
      const session = authSessionFor(`http://127.0.0.1:${dev.port}`, creds);

      await rpc(optsFor(dev.port), [{ method: 'Shelly.GetDeviceInfo' }], session);
      expect(session.hasCookie).toBe(true);

      const mid = await rpc(optsFor(dev.port), [{ method: 'Shelly.GetStatus' }], session);
      expect(mid.ok).toBe(false);
      expect(mid.errorKind).toBe('auth-rejected');
      expect(session.hasCookie).toBe(false); // invalidated by the 401

      const after = await rpc(optsFor(dev.port), [{ method: 'Shelly.GetStatus' }], session);
      expect(after.ok).toBe(true);
      // restarted handshake: Basic present, fresh cookie captured again
      expect(dev.requests[2].authorization).toBe(basicAuthHeader('admin', 'pw'));
      expect(dev.requests[2].cookie).toBeUndefined();
      expect(session.hasCookie).toBe(true);
    } finally {
      await dev.close();
    }
  });
});
