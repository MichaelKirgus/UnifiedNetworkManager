import { describe, it, expect } from 'vitest';
import { shouldRedirectToOnboarding } from './OnboardingRedirect';

/**
 * Truth table for the mandatory first-run wizard redirect — critical behaviour:
 * a freshly seeded admin (onboardedAt NULL) MUST be sent to /onboarding after
 * login. A regression here silently disables password + 2FA enforcement on
 * fresh installs (observed in production, fixed in v0.3.3).
 */
describe('shouldRedirectToOnboarding', () => {
  const base = { tokenPresent: true, pathname: '/devices' };

  it('redirects a freshly seeded admin (onboardedAt null)', () => {
    expect(shouldRedirectToOnboarding({ ...base, me: { username: 'admin', onboardedAt: null } })).toBe(true);
  });

  it('treats a missing onboardedAt field as not-yet-onboarded', () => {
    expect(shouldRedirectToOnboarding({ ...base, me: { username: 'admin' } })).toBe(true);
  });

  it('does NOT redirect once onboarding was completed (onboardedAt stamped)', () => {
    expect(
      shouldRedirectToOnboarding({ ...base, me: { username: 'admin', onboardedAt: '2026-10-31T12:00:00.000Z' } })
    ).toBe(false);
  });

  it('does NOT redirect non-admin accounts even without onboarding', () => {
    expect(shouldRedirectToOnboarding({ ...base, me: { username: 'alice', onboardedAt: null } })).toBe(false);
  });

  it('does NOT redirect while the account data is still loading (me undefined)', () => {
    expect(shouldRedirectToOnboarding({ ...base, me: undefined })).toBe(false);
  });

  it('does NOT redirect without a session token', () => {
    expect(
      shouldRedirectToOnboarding({ tokenPresent: false, pathname: '/devices', me: { username: 'admin', onboardedAt: null } })
    ).toBe(false);
  });

  it('does NOT redirect when already on /onboarding (no loop)', () => {
    expect(shouldRedirectToOnboarding({ ...base, pathname: '/onboarding', me: { username: 'admin' } })).toBe(false);
  });

  it('does NOT redirect from the login page or its sub-paths', () => {
    for (const p of ['/login', '/login?reason=disabled']) {
      expect(shouldRedirectToOnboarding({ ...base, pathname: p, me: { username: 'admin' } })).toBe(false);
    }
  });
});
