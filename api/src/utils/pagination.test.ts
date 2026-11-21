import {
  envelopePage,
  hasPaginationParams,
  limitOffset,
  parsePagination,
  parseTablePageSizeOptions,
  type ParsedPagination,
} from './pagination';

describe('parsePagination', () => {
  it('returns defaults when nothing is present', () => {
    expect(parsePagination({})).toEqual({ page: 1, pageSize: 50, all: false });
  });

  it('honors custom default/max options', () => {
    const pg = parsePagination({}, { defaultPageSize: 25, maxPageSize: 100 }) as { pageSize: number };
    expect(pg.pageSize).toBe(25);
    const clamped = parsePagination({ pageSize: 999 }, { maxPageSize: 100 }) as { pageSize: number };
    expect(clamped.pageSize).toBe(100);
  });

  it('accepts page/pageSize as numbers (OpenAPI validator coerces them)', () => {
    expect(parsePagination({ page: 3, pageSize: 25 })).toEqual({ page: 3, pageSize: 25, all: false });
  });

  it('also accepts numeric strings (pre-coercion / direct calls)', () => {
    expect(parsePagination({ page: '3', pageSize: '25' })).toEqual({ page: 3, pageSize: 25, all: false });
  });

  it('rejects non-integer or out-of-range values', () => {
    expect((parsePagination({ page: 'abc' }) as { error: string }).error).toContain('"page"');
    expect((parsePagination({ page: 0 }) as { error: string }).error).toContain('"page"');
    expect((parsePagination({ page: -2 }) as { error: string }).error).toContain('"page"');
    expect((parsePagination({ pageSize: 'x' }) as { error: string }).error).toContain('"pageSize"');
    expect((parsePagination({ pageSize: 0 }) as { error: string }).error).toContain('"pageSize"');
  });

  it('clamps oversized pageSize to the max instead of erroring', () => {
    const pg = parsePagination({ pageSize: 9999 }) as { pageSize: number };
    expect(pg.pageSize).toBe(200);
  });

  it('accepts all as a real boolean (coerced) or "true"/"false" string', () => {
    const t = parsePagination({ all: true }) as ParsedPagination;
    expect(t.all).toBe(true);
    const f = parsePagination({ all: false }) as ParsedPagination;
    expect(f.all).toBe(false);
    const ts = parsePagination({ all: 'true' } as Record<string, unknown>) as ParsedPagination;
    expect(ts.all).toBe(true);
    const fs = parsePagination({ all: 'false' } as Record<string, unknown>) as ParsedPagination;
    expect(fs.all).toBe(false);
  });

  it('rejects garbage all values', () => {
    const res = parsePagination({ all: 'banana' }) as { error: string };
    expect(res.error).toContain('"all"');
  });

  it('keeps page/pageSize valid when combined with all=true (all wins at query time)', () => {
    const pg = parsePagination({ page: 4, pageSize: 25, all: true }) as { all: boolean; page: number };
    expect(pg.all).toBe(true);
    expect(pg.page).toBe(4); // parsed fine — limitOffset() ignores it
  });
});

describe('hasPaginationParams', () => {
  it('is false for legacy calls without any pagination param', () => {
    expect(hasPaginationParams({})).toBe(false);
    expect(hasPaginationParams({ search: 'x', limit: 50 })).toBe(false);
  });

  it('is true when any of page/pageSize/all is present', () => {
    expect(hasPaginationParams({ page: 1 })).toBe(true);
    expect(hasPaginationParams({ pageSize: 25 })).toBe(true);
    expect(hasPaginationParams({ all: 'true' } as Record<string, unknown>)).toBe(true);
  });

  it('can ignore the all param for endpoints where all has another meaning', () => {
    // /notifications uses all=true to ignore personal visibility prefs — that
    // must NOT flip a legacy call into paged mode.
    expect(hasPaginationParams({ all: true }, { includeAll: false })).toBe(false);
    expect(hasPaginationParams({ page: 2, all: true }, { includeAll: false })).toBe(true);
  });
});

describe('limitOffset', () => {
  it('computes offset from the 1-based page', () => {
    expect(limitOffset({ page: 1, pageSize: 50, all: false })).toEqual({ limit: 50, offset: 0 });
    expect(limitOffset({ page: 3, pageSize: 25, all: false })).toEqual({ limit: 25, offset: 50 });
  });

  it('is null in all-mode (unbounded)', () => {
    expect(limitOffset({ page: 1, pageSize: 50, all: true })).toBeNull();
  });
});

describe('envelopePage', () => {
  it('echoes the requested page/pageSize normally', () => {
    expect(envelopePage({ page: 2, pageSize: 25, all: false }, 100)).toEqual({ page: 2, pageSize: 25 });
  });

  it('reports one page holding everything in all-mode', () => {
    expect(envelopePage({ page: 1, pageSize: 50, all: true }, 344)).toEqual({ page: 1, pageSize: 344 });
    expect(envelopePage({ page: 1, pageSize: 50, all: true }, 0)).toEqual({ page: 1, pageSize: 0 });
  });
});

describe('parseTablePageSizeOptions (global tablePageSizeOptions setting)', () => {
  it('parses a clean comma-separated list, preserving order', () => {
    expect(parseTablePageSizeOptions('25,50,100')).toEqual([25, 50, 100]);
  });

  it('tolerates whitespace around entries and trailing commas', () => {
    expect(parseTablePageSizeOptions(' 10 , 20 ,30, ')).toEqual([10, 20, 30]);
  });

  it('accepts a single value', () => {
    expect(parseTablePageSizeOptions('50')).toEqual([50]);
  });

  it('rejects an empty list', () => {
    expect(() => parseTablePageSizeOptions('')).toThrow(/at least one/);
    expect(() => parseTablePageSizeOptions(' , ')).toThrow(/at least one/);
  });

  it('rejects non-numeric entries', () => {
    expect(() => parseTablePageSizeOptions('25,abc')).toThrow(/not a positive integer/);
    expect(() => parseTablePageSizeOptions('-5')).toThrow(/not a positive integer/);
    expect(() => parseTablePageSizeOptions('2.5')).toThrow(/not a positive integer/);
  });

  it('rejects out-of-range values', () => {
    expect(() => parseTablePageSizeOptions('0')).toThrow(/between 1 and 1000/);
    expect(() => parseTablePageSizeOptions('1001')).toThrow(/between 1 and 1000/);
  });
});
