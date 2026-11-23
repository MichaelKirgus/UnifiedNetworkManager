/**
 * Unit tests for the pure LCOS-LX firmware-file matching logic (firmwareFiles.ts).
 * No network — listFirmwareFiles() is intentionally NOT covered here.
 */

import { deviceModelDigits, findRepoFirmwareTarget, liveVersionCore, parseLxFwFileName } from './firmwareFiles';

describe('parseLxFwFileName', () => {
  it('parses the canonical LANCOM naming convention', () => {
    expect(parseLxFwFileName('LC-LX-6500-7.20.0192-RU1.upx')).toEqual({ modelDigits: '6500', version: '7.20.0192-RU1' });
  });

  it('is case-insensitive and accepts _ separators', () => {
    expect(parseLxFwFileName('lc-lx_6400_7.20.0087-rel.upx')).toEqual({ modelDigits: '6400', version: '7.20.0087-rel' });
  });

  it('accepts an uppercase .UPX extension', () => {
    expect(parseLxFwFileName('LC-LX-7500-7.20.0192-RU1.UPX')).toEqual({ modelDigits: '7500', version: '7.20.0192-RU1' });
  });

  it('rejects names that do not follow the convention', () => {
    expect(parseLxFwFileName('firmware.upx')).toBeNull();
    expect(parseLxFwFileName('LC-LX-6500-7.20.0192-RU1.zip')).toBeNull();
    expect(parseLxFwFileName('LC-LX-6500.upx')).toBeNull(); // no version part
    expect(parseLxFwFileName('')).toBeNull();
  });
});

describe('deviceModelDigits', () => {
  it('extracts the model digits from a device model string', () => {
    expect(deviceModelDigits('LC-LX-6500')).toBe('6500');
    expect(deviceModelDigits('LANCOM LC-LX-7500 (A00)')).toBe('7500');
  });

  it('returns null when no model is known', () => {
    expect(deviceModelDigits(null)).toBeNull();
    expect(deviceModelDigits(undefined)).toBeNull();
    expect(deviceModelDigits('')).toBeNull();
  });
});

describe('liveVersionCore', () => {
  it('strips the trailing build date from a live swVersion', () => {
    expect(liveVersionCore('7.20.0087Rel / 31.10.2026')).toBe('7.20.0087Rel');
  });

  it('keeps version strings without a date untouched', () => {
    expect(liveVersionCore('7.20.0192RU1')).toBe('7.20.0192RU1');
  });

  it('returns an empty string for missing input', () => {
    expect(liveVersionCore(null)).toBe('');
    expect(liveVersionCore(undefined)).toBe('');
  });
});

describe('findRepoFirmwareTarget', () => {
  const files = [
    { id: 'f-6400', name: 'LC-LX-6400-7.20.0192-RU1.upx', sizeBytes: 69_800_000 },
    { id: 'f-6500-old', name: 'LC-LX-6500-7.20.0087-Rel.upx', sizeBytes: 70_000_000 },
    { id: 'f-6500-new', name: 'LC-LX-6500-7.20.0192-RU1.upx', sizeBytes: 70_288_610 },
    { id: 'f-junk', name: 'some-random-image.upx' },
  ];

  it('offers the newest model-matching file that is newer than live', () => {
    const target = findRepoFirmwareTarget('7.20.0087Rel / 31.10.2026', 'LC-LX-6500', files);
    expect(target).toEqual({ fileId: 'f-6500-new', fileName: 'LC-LX-6500-7.20.0192-RU1.upx', version: '7.20.0192-RU1', sizeBytes: 70_288_610 });
  });

  it("only considers files of the device's own model", () => {
    // For a 6400 the 6500 images must be invisible — even though they are newer.
    expect(findRepoFirmwareTarget('7.20.0087Rel / 31.10.2026', 'LC-LX-6400', files)?.fileId).toBe('f-6400');
    // A 7500 has no matching file at all → nothing offered.
    expect(findRepoFirmwareTarget('7.20.0087Rel / 31.10.2026', 'LC-LX-7500', files)).toBeNull();
  });

  it('picks the highest version when several matching files exist', () => {
    const two = [
      { id: 'a', name: 'LC-LX-6500-7.20.0150.upx' },
      { id: 'b', name: 'LC-LX-6500-7.20.0192-RU1.upx' },
    ];
    expect(findRepoFirmwareTarget('7.20.0087Rel / 31.10.2026', 'LC-LX-6500', two)?.fileId).toBe('b');
  });

  it('does not offer a same-build file (date suffix must not fake "newer")', () => {
    const onlySame = [{ id: 's', name: 'LC-LX-6500-7.20.0087-Rel.upx' }];
    expect(findRepoFirmwareTarget('7.20.0087Rel / 31.10.2026', 'LC-LX-6500', onlySame)).toBeNull();
  });

  it('offers nothing when the device model is unknown (wrong-model images must never get an Update button)', () => {
    expect(findRepoFirmwareTarget('7.20.0087Rel / 31.10.2026', null, files)).toBeNull();
    expect(findRepoFirmwareTarget('7.20.0087Rel / 31.10.2026', undefined, files)).toBeNull();
  });

  it('offers nothing when the live version is missing', () => {
    expect(findRepoFirmwareTarget(null, 'LC-LX-6500', files)).toBeNull();
    expect(findRepoFirmwareTarget('', 'LC-LX-6500', files)).toBeNull();
  });

  it('skips malformed file names without throwing', () => {
    const mixed = [{ id: 'x', name: 'not-a-firmware.upx' }, { id: 'y', name: 'LC-LX-6500-7.20.0192-RU1.upx' }];
    expect(findRepoFirmwareTarget('7.20.0087Rel / 31.10.2026', 'LC-LX-6500', mixed)?.fileId).toBe('y');
  });
});
