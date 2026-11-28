// NOTE: credentialPolicy imports ../db (lazy pg Pool — no connection until a
// query runs). The jest suite is for pure-utility tests and uuid is ESM-only,
// so mock the db module to keep this file importable without side effects.
jest.mock('../db', () => ({ db: {} }));

import { validatePolicyBody } from './credentialPolicy';

describe('validatePolicyBody gateAmrs', () => {
  it('accepts an interactive-only gate (unchanged behavior)', () => {
    expect(validatePolicyBody({ gateAmrs: ['totp', 'webauthn'] })).toBeNull();
  });

  it('accepts token as a gate AMR for per-user policies', () => {
    expect(validatePolicyBody({ gateAmrs: ['totp', 'token'] }, { global: false })).toBeNull();
    // Default (no opts) is the per-user path.
    expect(validatePolicyBody({ gateAmrs: ['token'] })).toBeNull();
  });

  it('rejects token in the GLOBAL policy (per-user opt-in only)', () => {
    const err = validatePolicyBody({ gateAmrs: ['totp', 'token'] }, { global: true });
    expect(err).toMatch(/per-user/);
  });

  it('still rejects unknown AMRs', () => {
    expect(validatePolicyBody({ gateAmrs: ['nope'] })).toMatch(/Invalid gateAmrs entry/);
  });

  it('rejects an empty gateAmrs (would lock out the gate entirely)', () => {
    expect(validatePolicyBody({ gateAmrs: [] })).toMatch(/at least one AMR/);
  });

  it('still validates requiredMethods independently of KNOWN_AMRS', () => {
    // 'token' is a valid AMR but NOT a second-factor method.
    expect(validatePolicyBody({ requiredMethods: ['token'] })).toMatch(/Invalid requiredMethods entry/);
  });
});
