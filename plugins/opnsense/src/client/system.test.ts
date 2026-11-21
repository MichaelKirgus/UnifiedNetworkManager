import { parseBase10Bytes, opnsenseFsType, parseSystemDiskRows } from './system';

describe('parseBase10Bytes', () => {
  it('parses base-10 human strings (K=1000)', () => {
    expect(parseBase10Bytes('5.2G')).toBe(5_200_000_000);
    expect(parseBase10Bytes('800M')).toBe(800_000_000);
    expect(parseBase10Bytes('93.8K')).toBe(93_800);
    expect(parseBase10Bytes('2T')).toBe(2e12);
  });

  it('accepts raw numbers (defensive multi-shape)', () => {
    expect(parseBase10Bytes(123456)).toBe(123456);
    expect(parseBase10Bytes(1.5e9)).toBe(1_500_000_000);
  });

  it('returns null for non-sizes', () => {
    expect(parseBase10Bytes('-')).toBeNull(); // unlimited / not applicable
    expect(parseBase10Bytes(undefined)).toBeNull();
    expect(parseBase10Bytes(null)).toBeNull();
    expect(parseBase10Bytes({})).toBeNull();
    expect(parseBase10Bytes('abc')).toBeNull();
  });
});

describe('opnsenseFsType', () => {
  it('maps known types and defaults to other', () => {
    expect(opnsenseFsType('zfs')).toBe('zfs-pool'); // base mapping — dataset split happens in parseSystemDiskRows
    expect(opnsenseFsType('ext4')).toBe('ext4');
    expect(opnsenseFsType('squashfs')).toBe('squashfs');
    expect(opnsenseFsType('ufs')).toBe('other');
    expect(opnsenseFsType('msdosfs')).toBe('other');
    expect(opnsenseFsType(null)).toBe('other');
  });
});

describe('parseSystemDiskRows', () => {
  it('splits ZFS pools from datasets on a ZFS-rooted appliance (real GWBN01 payload shape)', () => {
    // The appliance runs `df -abT` server-side: every MOUNTED DATASET is its own
    // entry with type "zfs". Before the fix ALL of these were pushed as
    // top-level zfs-pool rows (the Storage page showed 11 fake pools for one box).
    const res = {
      ok: true,
      data: {
        devices: [
          { device: '/dev/gpt/efiboot0', type: 'msdosfs', blocks: '260M', used: '1.3M', available: '259M', mountpoint: '/boot/efi' },
          { device: 'zroot', type: 'zfs', blocks: '113G', used: '96K', available: '113G', mountpoint: '/zroot' },
          { device: 'zroot/ROOT/default', type: 'zfs', blocks: '114G', used: '1.3G', available: '113G', mountpoint: '/' },
          { device: 'zroot/home', type: 'zfs', blocks: '113G', used: '96K', available: '113G', mountpoint: '/home' },
          { device: 'zroot/var/log', type: 'zfs', blocks: '114G', used: '1.2G', available: '113G', mountpoint: '/var/log' },
        ],
      },
    };

    const rows = parseSystemDiskRows(res);
    expect(rows).toHaveLength(5);

    // Non-ZFS mounts are untouched (no parent, type from the mapping).
    const efi = rows.find((r) => r['name'] === '/dev/gpt/efiboot0')!;
    expect(efi['type']).toBe('other');
    expect(efi['parent']).toBeNull();

    // The slash-free name is the ONE real pool.
    const pool = rows.find((r) => r['name'] === 'zroot')!;
    expect(pool['type']).toBe('zfs-pool');
    expect(pool['parent']).toBeNull();
    expect(pool['sizeBytes']).toBe(113e9);

    // Every slashed name is a dataset nested under its pool (first path segment).
    for (const name of ['zroot/ROOT/default', 'zroot/home', 'zroot/var/log']) {
      const ds = rows.find((r) => r['name'] === name)!;
      expect(ds['type']).toBe('zfs-dataset');
      expect(ds['parent']).toBe('zroot');
    }

    // Sizes parse from base-10 human strings.
    const root = rows.find((r) => r['name'] === 'zroot/ROOT/default')!;
    expect(root['usedBytes']).toBe(1_300_000_000);
  });

  it('derives used/free when only some size fields are present', () => {
    const res = {
      ok: true,
      data: {
        devices: [
          // no `used` → derived from blocks - available
          { device: 'zroot/home', type: 'zfs', blocks: '100G', available: '90G', mountpoint: '/home' },
          // no `available` → derived from blocks - used
          { device: 'zroot/tmp', type: 'zfs', blocks: '100G', used: '5G', mountpoint: '/tmp' },
        ],
      },
    };

    const rows = parseSystemDiskRows(res);
    expect(rows[0]['usedBytes']).toBe(100e9 - 90e9);
    expect(rows[0]['freeBytes']).toBe(90e9);
    expect(rows[1]['freeBytes']).toBe(100e9 - 5e9);
    expect(rows[1]['usedBytes']).toBe(5e9);
  });

  it('accepts raw numeric size fields (defensive multi-shape)', () => {
    const res = {
      ok: true,
      data: { devices: [{ device: 'zroot', type: 'zfs', blocks: 113_000_000_000, used: 96_000, available: 112_999_904_000, mountpoint: '/zroot' }] },
    };
    const rows = parseSystemDiskRows(res);
    expect(rows[0]['sizeBytes']).toBe(113_000_000_000);
  });

  it('returns an empty array for a missing/404 response (caller omits the keys — no wipe)', () => {
    expect(parseSystemDiskRows(undefined)).toEqual([]);
    expect(parseSystemDiskRows({ ok: false })).toEqual([]);
  });

  it('returns an empty array for malformed shapes', () => {
    expect(parseSystemDiskRows({ ok: true, data: {} })).toEqual([]);
    expect(parseSystemDiskRows({ ok: true, data: { devices: 'nope' } })).toEqual([]);
    // Rows without a usable name are skipped.
    const rows = parseSystemDiskRows({ ok: true, data: { devices: [{ type: 'zfs', blocks: '1G' }, null, 42] } });
    expect(rows).toEqual([]);
  });
});
