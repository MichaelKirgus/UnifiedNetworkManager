// @vitest-environment jsdom
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, waitFor, cleanup } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { OnboardingRedirect } from './OnboardingRedirect';

// The component fetches the caller's profile via api.me — mock at module level.
vi.mock('../api/client', () => ({
  api: { me: vi.fn() },
}));
import { api, type User } from '../api/client';

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

const freshAdmin = meResponse('admin', null);

function renderAt(pathname: string, initialMe?: unknown) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  if (initialMe !== undefined) qc.setQueryData(['me'], initialMe);
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={[pathname]}>
        <OnboardingRedirect />
        <Routes>
          {/* A redirect to /onboarding renders the wizard marker; staying put does not. */}
          <Route path="/onboarding" element={<div data-testid="wizard">wizard</div>} />
          <Route path="*" element={<div data-testid="app">app</div>} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>
  );
}

describe('OnboardingRedirect (component)', () => {
  // Vitest runs without `globals`, so testing-library's auto-cleanup is not
  // registered — clean up explicitly or renders accumulate across tests.
  afterEach(() => {
    cleanup();
  });

  beforeEach(() => {
    vi.clearAllMocks();
    localStorage.removeItem('accessToken');
  });

  it('does nothing without a session token — and never fetches /auth/me', async () => {
    renderAt('/devices');
    await waitFor(() => expect(screen.getByTestId('app')).toBeInTheDocument());
    // The query must be GATED on the token: pre-login, api.me must not fire at all.
    expect(api.me).not.toHaveBeenCalled();
  });

  it('redirects a freshly seeded admin after login (the critical first-run path)', async () => {
    localStorage.setItem('accessToken', 'tok');
    vi.mocked(api.me).mockResolvedValue(freshAdmin);
    renderAt('/devices');
    await waitFor(() => expect(screen.getByTestId('wizard')).toBeInTheDocument(), { timeout: 3000 });
    expect(api.me).toHaveBeenCalledTimes(1);
  });

  it('does NOT redirect an admin who already completed onboarding', async () => {
    localStorage.setItem('accessToken', 'tok');
    vi.mocked(api.me).mockResolvedValue(meResponse('admin', '2026-10-31T12:00:00.000Z'));
    renderAt('/devices');
    await waitFor(() => expect(screen.getByTestId('app')).toBeInTheDocument());
  });

  it('does NOT redirect non-admin accounts', async () => {
    localStorage.setItem('accessToken', 'tok');
    vi.mocked(api.me).mockResolvedValue(meResponse('alice'));
    renderAt('/devices');
    await waitFor(() => expect(screen.getByTestId('app')).toBeInTheDocument());
  });

  it('does NOT redirect from the login page (no loop into the wizard pre-auth)', async () => {
    localStorage.setItem('accessToken', 'tok');
    vi.mocked(api.me).mockResolvedValue(freshAdmin);
    renderAt('/login');
    await waitFor(() => expect(screen.getByTestId('app')).toBeInTheDocument());
  });

  it('recovers from a STALE pre-login cache entry: once /auth/me resolves, the redirect fires', async () => {
    // Regression guard for the v0.3.3 bug: the shared ['me'] entry can hold a
    // pre-login error/undefined while a token exists — the component must still
    // fetch (enabled on token) and redirect as soon as real data arrives.
    localStorage.setItem('accessToken', 'tok');
    vi.mocked(api.me).mockResolvedValue(freshAdmin);
    renderAt('/devices', undefined); // stale/absent cache entry
    await waitFor(() => expect(screen.getByTestId('wizard')).toBeInTheDocument(), { timeout: 3000 });
  });
});
