import { describe, it, expect } from 'vitest';
import { parseCsv, splitCellValues, suggestHeaderMapping } from './csv';

describe('parseCsv', () => {
  it('parses a simple matrix with LF endings', () => {
    expect(parseCsv('a,b\nc,d')).toEqual([['a', 'b'], ['c', 'd']]);
  });

  it('handles CRLF endings and a leading UTF-8 BOM', () => {
    expect(parseCsv('\ufeffh1,h2\r\nv1,v2')).toEqual([['h1', 'h2'], ['v1', 'v2']]);
  });

  it('supports quoted fields with escaped quotes and embedded commas/newlines', () => {
    expect(parseCsv('"a""b",c\n"x,y",z')).toEqual([['a"b', 'c'], ['x,y', 'z']]);
  });

  it('flushes a final row without trailing newline and drops empty rows', () => {
    expect(parseCsv('a,b\n\nc,d')).toEqual([['a', 'b'], ['c', 'd']]);
    expect(parseCsv('only-one-row')).toEqual([['only-one-row']]);
  });

  it('returns [] for blank input', () => {
    expect(parseCsv('')).toEqual([]);
    expect(parseCsv('\n\n')).toEqual([]);
  });
});

describe('splitCellValues', () => {
  it('splits on commas, semicolons and whitespace', () => {
    expect(splitCellValues('10.0.0.1, 10.0.0.2;10.0.0.3')).toEqual(['10.0.0.1', '10.0.0.2', '10.0.0.3']);
    expect(splitCellValues('a\tb c')).toEqual(['a', 'b', 'c']);
  });

  it('returns [] for empty/whitespace-only input', () => {
    expect(splitCellValues('   ')).toEqual([]);
    expect(splitCellValues('')).toEqual([]);
  });
});

describe('suggestHeaderMapping', () => {
  it('maps a typical export header row to the right columns', () => {
    const m = suggestHeaderMapping(['Hostname', 'IP Address', 'MAC', 'Description']);
    expect(m.dnsNames).toBe(0);
    expect(m.address).toBe(1);
    expect(m.mac).toBe(2);
    expect(m.description).toBe(3);
  });

  it('leaves unmapped fields at -1 and does not double-claim columns', () => {
    const m = suggestHeaderMapping(['Hostname']);
    expect(m.dnsNames).toBe(0);
    expect(m.mac).toBe(-1);
    expect(m.address).toBe(-1);
  });

  it('falls back to dnsNames for a bare "Name" header', () => {
    const m = suggestHeaderMapping(['Name']);
    expect(m.dnsNames).toBe(0);
  });

  it('returns all -1 for headers that match nothing', () => {
    const m = suggestHeaderMapping(['foo', 'bar']);
    expect(Object.values(m).every((v) => v === -1)).toBe(true);
  });
});
