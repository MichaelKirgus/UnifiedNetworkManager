import { describe, it, expect } from 'vitest';
import { DEFAULT_TABLE_PAGE_SIZES, parseTablePageSizeOptions } from './useTablePageSizes';

describe('parseTablePageSizeOptions', () => {
  it('parses a clean list preserving order (first entry = initial default)', () => {
    expect(parseTablePageSizeOptions('25,50,100')).toEqual([25, 50, 100]);
  });

  it('tolerates whitespace and trailing commas', () => {
    expect(parseTablePageSizeOptions(' 10 , 20 ,30, ')).toEqual([10, 20, 30]);
  });

  it('drops duplicates while keeping first-occurrence order', () => {
    expect(parseTablePageSizeOptions('50,25,50')).toEqual([50, 25]);
  });

  it('drops invalid entries and keeps the valid ones', () => {
    expect(parseTablePageSizeOptions('25,abc,100,-3,2.5')).toEqual([25, 100]);
  });

  it('falls back to defaults for empty/garbage/non-string values', () => {
    expect(parseTablePageSizeOptions('')).toEqual(DEFAULT_TABLE_PAGE_SIZES);
    expect(parseTablePageSizeOptions(' , ')).toEqual(DEFAULT_TABLE_PAGE_SIZES);
    expect(parseTablePageSizeOptions(undefined)).toEqual(DEFAULT_TABLE_PAGE_SIZES);
    expect(parseTablePageSizeOptions(42)).toEqual(DEFAULT_TABLE_PAGE_SIZES);
  });

  it('drops out-of-range values (1..1000)', () => {
    expect(parseTablePageSizeOptions('0,1001,50')).toEqual([50]);
  });
});
