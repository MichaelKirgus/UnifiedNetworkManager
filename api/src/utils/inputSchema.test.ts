import { validateAgainstProperty, validateInput, isValidInput } from './inputSchema';
import type { InputSchema, InputSchemaProperty } from './inputSchema';

describe('validateAgainstProperty', () => {
  it('treats null/undefined as valid (presence is the caller\'s job)', () => {
    expect(validateAgainstProperty({ type: 'string' }, undefined, 'x')).toEqual([]);
    expect(validateAgainstProperty({ type: 'string' }, null, 'x')).toEqual([]);
  });

  it('validates string values and patterns', () => {
    expect(validateAgainstProperty({ type: 'string' }, 'abc', 'name')).toEqual([]);
    const bad = validateAgainstProperty({ type: 'string' }, 42, 'name');
    expect(bad).toHaveLength(1);
    expect(bad[0].message).toBe('expected a string');

    const pattern: InputSchemaProperty = { type: 'string', pattern: '^[a-z]+$' };
    expect(validateAgainstProperty(pattern, 'abc', 's')).toEqual([]);
    expect(validateAgainstProperty(pattern, 'ABC', 's')[0].message).toContain('pattern');
  });

  it('coerces numeric strings for number properties and enforces min/max', () => {
    expect(validateAgainstProperty({ type: 'number' }, '42', 'n')).toEqual([]);
    const withBounds: InputSchemaProperty = { type: 'number', min: 10, max: 50 };
    expect(validateAgainstProperty(withBounds, 7, 'n')[0].message).toBe('must be >= 10');
    expect(validateAgainstProperty(withBounds, 60, 'n')[0].message).toBe('must be <= 50');
    expect(validateAgainstProperty({ type: 'number' }, 'nope', 'n')[0].message).toBe('expected a number');
  });

  it('validates booleans', () => {
    expect(validateAgainstProperty({ type: 'boolean' }, true, 'b')).toEqual([]);
    expect(validateAgainstProperty({ type: 'boolean' }, 'true', 'b')[0].message).toBe('expected a boolean');
  });

  it('validates arrays with item schemas and indexed paths', () => {
    const prop: InputSchemaProperty = { type: 'array', items: { type: 'string' } };
    expect(validateAgainstProperty(prop, ['a', 'b'], 'list')).toEqual([]);
    const issues = validateAgainstProperty(prop, ['a', 1], 'list');
    expect(issues).toHaveLength(1);
    expect(issues[0].path).toBe('list[1]');
    expect(validateAgainstProperty({ type: 'array' }, 'nope', 'list')[0].message).toBe('expected an array');
  });

  it('validates nested objects with required sub-properties', () => {
    const prop: InputSchemaProperty = {
      type: 'object',
      properties: {
        host: { type: 'string', required: true },
        port: { type: 'number' },
      },
    };
    expect(validateAgainstProperty(prop, { host: 'h', port: 80 }, 'o')).toEqual([]);
    const missing = validateAgainstProperty(prop, {}, 'o');
    expect(missing).toHaveLength(1);
    expect(missing[0].path).toBe('o.host');
    expect(missing[0].message).toBe('is required');
  });

  it('enforces enums with numeric-string coercion', () => {
    const prop: InputSchemaProperty = { type: 'number', enum: [1, 2, 3] };
    expect(validateAgainstProperty(prop, 2, 'e')).toEqual([]);
    expect(validateAgainstProperty(prop, '2', 'e')).toEqual([]); // numeric-string coercion
    expect(validateAgainstProperty(prop, 9, 'e')[0].message).toBe('must be one of: 1, 2, 3');
  });
});

describe('validateInput / isValidInput', () => {
  const schema: InputSchema = {
    name: { type: 'string', required: true },
    count: { type: 'number' },
  };

  it('flags missing required properties and validates present ones', () => {
    expect(validateInput(schema, {})).toEqual([{ path: 'name', message: 'is required' }]);
    expect(validateInput(schema, { name: 'x', count: 3 })).toEqual([]);
    const issues = validateInput(schema, { name: 'x', count: 'bad' });
    expect(issues).toHaveLength(1);
    expect(issues[0].path).toBe('count');
  });

  it('isValidInput mirrors the issue list', () => {
    expect(isValidInput(schema, { name: 'x' })).toBe(true);
    expect(isValidInput(schema, {})).toBe(false);
  });
});
