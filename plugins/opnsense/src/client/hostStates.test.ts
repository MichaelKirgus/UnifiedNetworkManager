import { shouldSkipStateWalk, isStateWalkConsistent, isShortPageComplete, DEFAULT_STATE_WALK_MAX_STATES } from './hostStates';

describe('shouldSkipStateWalk', () => {
  it('skips when the live table exceeds the limit', () => {
    expect(shouldSkipStateWalk(284_482, 200_000)).toBe(true);
    expect(shouldSkipStateWalk(DEFAULT_STATE_WALK_MAX_STATES + 1, DEFAULT_STATE_WALK_MAX_STATES)).toBe(true);
  });

  it('walks at exactly the limit (only STRICTLY above skips)', () => {
    expect(shouldSkipStateWalk(200_000, 200_000)).toBe(false);
    expect(shouldSkipStateWalk(DEFAULT_STATE_WALK_MAX_STATES - 1, DEFAULT_STATE_WALK_MAX_STATES)).toBe(false);
  });

  it('does NOT skip when the count probe failed (null = unknown size)', () => {
    // A dead pf_states endpoint is no evidence of table size — the walk itself
    // fails harmlessly if it really is oversized.
    expect(shouldSkipStateWalk(null, 200_000)).toBe(false);
  });

  it('treats maxStates=0 as "no limit" (defensive; the option form min is 10k)', () => {
    expect(shouldSkipStateWalk(999_999, 0)).toBe(false);
  });
});

describe('isStateWalkConsistent', () => {
  it('accepts a stable table (no drift)', () => {
    expect(isStateWalkConsistent(284_000, 284_100)).toBe(true); // +0.035%
  });

  it('rejects drift above the 5% threshold', () => {
    expect(isStateWalkConsistent(284_000, 300_000)).toBe(false); // +5.6%
    expect(isStateWalkConsistent(284_000, 265_000)).toBe(false); // -6.7%
  });

  it('accepts drift exactly AT the threshold (<= not <)', () => {
    expect(isStateWalkConsistent(100_000, 105_000)).toBe(true); // +5.0%
  });

  it('treats an unverifiable total as inconsistent (conservative)', () => {
    expect(isStateWalkConsistent(null, 284_000)).toBe(false);
    expect(isStateWalkConsistent(284_000, null)).toBe(false);
    expect(isStateWalkConsistent(0, 5_000)).toBe(false); // table appeared mid-walk (reboot)
  });
});

describe('isShortPageComplete', () => {
  it('accepts a short page when the total agrees (table shrank slightly during scan)', () => {
    expect(isShortPageComplete(48_000, 47_500)).toBe(true); // total < received rows
    expect(isShortPageComplete(49_000, 51_000)).toBe(true); // +4.1% growth during scan
  });

  it('accepts a short page exactly AT the drift tolerance', () => {
    expect(isShortPageComplete(40_000, 42_000)).toBe(true); // +5.0%
  });

  it('rejects a short page when the total claims more states exist than we received', () => {
    // configd returned fewer rows than requested while claiming a bigger table:
    // unseen states would be diffed as "destroyed" → false churn spike.
    expect(isShortPageComplete(49_000, 60_000)).toBe(false);
    expect(isShortPageComplete(1_000, 50_000)).toBe(false);
  });

  it('treats a missing total as NOT complete (conservative — churn nulled)', () => {
    expect(isShortPageComplete(49_000, null)).toBe(false);
  });
});
