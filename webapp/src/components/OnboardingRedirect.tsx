import { useEffect } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { api } from '../api/client';

/** Minimal account shape the first-run redirect decision needs. */
export interface OnboardingAccount {
  username: string;
  /** Set when the setup wizard was completed or skipped (null = not yet). */
  onboardedAt?: string | null;
}

/**
 * Pure decision for the mandatory first-run wizard — extracted from App.tsx so
 * the critical behaviour is unit-testable without a router/query provider.
 * True only when: a session exists, we are not already on /onboarding (or its
 * login page), and the seeded `admin` account has not completed onboarding yet.
 */
export function shouldRedirectToOnboarding(opts: {
  tokenPresent: boolean;
  pathname: string;
  me?: OnboardingAccount | null;
}): boolean {
  if (!opts.tokenPresent) return false;
  if (opts.pathname === '/onboarding' || opts.pathname.startsWith('/login')) return false;
  const me = opts.me;
  return Boolean(me && me.username === 'admin' && !me.onboardedAt);
}

/**
 * First-run onboarding redirect: the seeded `admin` account is sent to the
 * setup wizard exactly once — when it has a session token, is not already on
 * /onboarding (or its login page), and `users.onboardedAt` is still NULL.
 * Completing or skipping the wizard stamps the flag, so this never fires again.
 */
export function OnboardingRedirect() {
  const navigate = useNavigate();
  const location = useLocation();
  // Gated on an active token: without this, the query fires on the login page
  // too (no auth header → 401 cached in the shared ['me'] entry), and after a
  // sign-in the stale error would keep `data` undefined — so the mandatory
  // first-run wizard never triggered for a freshly seeded admin.
  const meQuery = useQuery({ queryKey: ['me'], queryFn: api.me, enabled: Boolean(localStorage.getItem('accessToken')) });

  useEffect(() => {
    if (shouldRedirectToOnboarding({ tokenPresent: Boolean(localStorage.getItem('accessToken')), pathname: location.pathname, me: meQuery.data })) {
      navigate('/onboarding', { replace: true });
    }
  }, [meQuery.data, location.pathname, navigate]);

  return null;
}
