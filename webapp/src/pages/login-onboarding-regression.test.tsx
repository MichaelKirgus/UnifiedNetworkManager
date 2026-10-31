// @vitest-environment jsdom
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, waitFor, cleanup } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import Login from './Login';
import { OnboardingRedirect } from '../components/OnboardingRedirect';

// Mock the API client at module level — Login + OnboardingRedirect touch these.
vi.mock('../api/client', () => ({
  api: {
    authFlow: vi.fn(),
    login: vi.fn(),
    completeLogin: vi.fn(),
    verify2fa: vi.fn(),
    me: vi.fn(),
  },
  ApiError: class ApiError extends Error {},
}));
import { api, type User } from '../api/client';

// Login imports the permission store for finishSignIn — keep it inert in tests.
vi.mock('../auth/permissions', () => ({
  setPermissions: vi.fn(),
  setUsername: vi.fn(),
}));

/** Full /auth/me response shape (User + effective permissions) for the mocks. */
function meResponse(username: string, onboardedAt?: string | null): User & { effectivePermissions: string[] } {
  return {
    id: `u-${username}`,
    username,
    roles: ['admin'],
    permissions: [],
    twoFactorEnabled: false,
    onboardedAt,
    effectivePermissions: ['*'],
  };
}

/**
 * Regression test for the v0.3.3 production bug: a fresh install's admin logged
 * in but was NEVER forced into the setup wizard (no password/TOTP enforcement).
 *
 * Original buggy state: OnboardingRedirect's ['me'] query was ALWAYS enabled, so
 * opening the app unauthenticated fired /auth/me without a token and cached its
 * 401 in the shared entry — and nothing refetched it after sign-in, so
 * meQuery.data stayed undefined and the mandatory wizard silently never
 * triggered. The fix is two-layered: (1) the query is gated on an active token
 * (a disabled→enabled transition refetches), and (2) finishSignIn invalidates
 * ['me'] after every sign-in path so any stale entry — error or old data — is
 * replaced. Mutation-validated against the original buggy state (ungated + no
 * invalidation): both tests fail there, pass with the fix.
 *
 * The api.me mock mirrors production: /auth/me 401s without a token. These tests
 * render Login AND OnboardingRedirect together (as App.tsx does) and assert on
 * the USER-VISIBLE outcome: the wizard must appear after sign-in.
 */
describe('Login → onboarding cache regression', () => {
  // Vitest runs without `globals` — register cleanup explicitly.
  afterEach(() => {
    cleanup();
  });

  beforeEach(() => {
    vi.clearAllMocks();
    localStorage.removeItem('accessToken');
    vi.mocked(api.authFlow).mockResolvedValue({ flow: 'password' });
    // Mirror production: /auth/me 401s without a token, and resolves with the
    // freshly seeded admin once one is present.
    vi.mocked(api.me).mockImplementation(async () => {
      if (!localStorage.getItem('accessToken')) throw new Error('API error 401');
      return meResponse('admin', null);
    });
  });

  /** Render Login + OnboardingRedirect under one QueryClient (mirrors App.tsx). */
  function renderApp(qc: QueryClient) {
    return render(
      <QueryClientProvider client={qc}>
        <MemoryRouter initialEntries={['/login']}>
          <OnboardingRedirect />
          <Routes>
            <Route path="/login" element={<Login />} />
            {/* The wizard route — its appearance IS the assertion target. */}
            <Route path="/onboarding" element={<div data-testid="wizard">setup-wizard</div>} />
            <Route path="*" element={<div data-testid="app">app</div>} />
          </Routes>
        </MemoryRouter>
      </QueryClientProvider>
    );
  }

  /** The poisoning step: the app was opened unauthenticated, /auth/me ran without
   * a token and its 401 is now cached in the shared ['me'] entry. */
  async function poisonMeCache(qc: QueryClient) {
    await qc.prefetchQuery({ queryKey: ['me'], queryFn: async () => { throw new Error('API error 401'); } });
    expect(qc.getQueryState(['me'])?.data).toBeUndefined(); // stale pre-login state
  }

  it('forces the wizard after a password-only sign-in despite a stale pre-login ["me"] cache', async () => {
    vi.mocked(api.login).mockResolvedValue({ challengeToken: 'ct-1', twoFactorRequired: false, passwordExpired: false });
    vi.mocked(api.completeLogin).mockResolvedValue({
      accessToken: 'tok-fresh',
      expiresIn: 3600,
      username: 'admin',
      roles: ['admin'],
      permissions: ['*'],
    });

    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    await poisonMeCache(qc);
    renderApp(qc);

    const user = userEvent.setup();
    // The form only renders once authFlow() resolves — wait for it.
    await user.type(await screen.findByLabelText(/username/i), 'admin');
    await user.type(screen.getByLabelText(/password/i), 'admin');
    await user.click(screen.getByRole('button', { name: /continue/i }));

    // THE regression assertion: the mandatory wizard must appear after sign-in.
    // Without finishSignIn's invalidateQueries(['me']), the stale 401 is never
    // refetched, OnboardingRedirect sees no account data and this times out —
    // exactly what happened on the fresh Truenas install.
    await waitFor(() => expect(screen.getByTestId('wizard')).toBeInTheDocument(), { timeout: 3000 });
  });

  it('forces the wizard after a TOTP sign-in despite a stale pre-login ["me"] cache', async () => {
    vi.mocked(api.login).mockResolvedValue({ challengeToken: 'ct-2', twoFactorRequired: true, passwordExpired: false });
    vi.mocked(api.verify2fa).mockResolvedValue({
      accessToken: 'tok-totp',
      expiresIn: 3600,
      username: 'admin',
      roles: ['admin'],
      permissions: ['*'],
    });

    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    await poisonMeCache(qc);
    renderApp(qc);

    const user = userEvent.setup();
    await user.type(await screen.findByLabelText(/username/i), 'admin');
    await user.type(screen.getByLabelText(/password/i), 'admin');
    await user.click(screen.getByRole('button', { name: /continue/i }));

    // Step 2 appears (TOTP required) — submit a code.
    const totp = await screen.findByLabelText(/two-factor/i);
    await user.type(totp, '123456');
    await user.click(screen.getByRole('button', { name: /verify & sign in/i }));

    await waitFor(() => expect(screen.getByTestId('wizard')).toBeInTheDocument(), { timeout: 3000 });
  });
});
