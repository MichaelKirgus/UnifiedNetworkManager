import { readStringArray, parseStringArrayField } from './stringArrays';

describe('readStringArray', () => {
  it('parses a stored JSON string array', () => {
    expect(readStringArray('["a","b"]')).toEqual(['a', 'b']);
  });

  it('accepts an already-parsed array', () => {
    expect(readStringArray(['a', 'b'])).toEqual(['a', 'b']);
  });

  it('returns [] for invalid JSON strings', () => {
    expect(readStringArray('not-json')).toEqual([]);
    expect(readStringArray('{"a":1}')).toEqual([]);
  });

  it('returns [] for non-array, non-string input', () => {
    expect(readStringArray(42)).toEqual([]);
    expect(readStringArray(null)).toEqual([]);
    expect(readStringArray(undefined)).toEqual([]);
  });

  it('skips non-string entries and empty/whitespace values', () => {
    expect(readStringArray('[1, "a", null, "", "   "]')).toEqual(['a']);
  });

  it('trims and dedupes entries', () => {
    expect(readStringArray('[" a ", "b", "a"]')).toEqual(['a', 'b']);
  });
});

describe('parseStringArrayField', () => {
  it('returns an error when the field is not an array', () => {
    const res = parseStringArrayField('"tags"', 'tags');
    expect(res.value).toBeUndefined();
    expect(res.error).toBe('"tags" must be an array of strings');
  });

  it('returns an error for non-string entries', () => {
    const res = parseStringArrayField(['a', 1], 'tags');
    expect(res.value).toBeUndefined();
    expect(res.error).toBe('"tags" entries must be non-empty strings');
  });

  it('returns an error for empty/whitespace-only entries', () => {
    const res = parseStringArrayField(['a', '   '], 'tags');
    expect(res.value).toBeUndefined();
    expect(res.error).toBe('"tags" entries must be non-empty strings');
  });

  it('returns the trimmed, deduped list on success', () => {
    const res = parseStringArrayField([' a ', 'b', 'a'], 'tags');
    expect(res.error).toBeUndefined();
    expect(res.value).toEqual(['a', 'b']);
  });

  it('accepts an empty array as valid (no entries to check)', () => {
    const res = parseStringArrayField([], 'tags');
    expect(res.error).toBeUndefined();
    expect(res.value).toEqual([]);
  });
});
