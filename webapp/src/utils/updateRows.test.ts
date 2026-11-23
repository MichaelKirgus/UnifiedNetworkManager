import { describe, it, expect } from 'vitest';
import type { UpdateRow } from '../api/client';
import { updateRowsForRepoFiles } from './updateRows';

/** Minimal UpdateRow factory — only the fields the filter touches. */
function row(over: Partial<UpdateRow> & { deviceId: string; kind: UpdateRow['kind']; name: string }): UpdateRow {
  return {
    pluginId: 'p1',
    deviceName: null,
    managementAddress: null,
    siteName: null,
    currentVersion: null,
    latestVersion: null,
    rebootRequired: null,
    sizeBytes: null,
    releaseNotesUrl: null,
    releaseNotes: null,
    branch: null,
    applyActionId: null,
    collectedAt: '2026-01-01T00:00:00Z',
    ...over,
  };
}

describe('updateRowsForRepoFiles', () => {
  it('returns the rows untouched when no file ids are given (no filter)', () => {
    const rows = [row({ deviceId: 'd1', kind: 'firmware', name: 'os' })];
    expect(updateRowsForRepoFiles(rows, [])).toBe(rows);
  });

  it('keeps only rows whose applyInput.repoFileId is in the wanted set', () => {
    const a = row({ deviceId: 'd1', kind: 'firmware', name: 'os', applyActionId: 'lx.firmware.update', applyInput: { repoFileId: 'f-6500' } });
    const b = row({ deviceId: 'd2', kind: 'firmware', name: 'os', applyActionId: 'lx.firmware.update', applyInput: { repoFileId: 'f-7500' } });
    const c = row({ deviceId: 'd3', kind: 'os-package', name: 'curl', applyActionId: 'packages.update', applyInput: {} });

    expect(updateRowsForRepoFiles([a, b, c], ['f-6500']).map((r) => r.deviceId)).toEqual(['d1']);
    // Multiple wanted ids — order of the input rows is preserved.
    expect(updateRowsForRepoFiles([c, a, b], ['f-7500', 'f-6500']).map((r) => r.deviceId)).toEqual(['d1', 'd2']);
  });

  it('drops rows without an apply input or with a non-string repoFileId', () => {
    const noInput = row({ deviceId: 'd1', kind: 'firmware', name: 'os' });
    const notString = row({ deviceId: 'd2', kind: 'firmware', name: 'os', applyInput: { repoFileId: 42 } as Record<string, unknown> });
    const otherKey = row({ deviceId: 'd3', kind: 'app', name: 'x', applyInput: { file: 'f-6500' } });
    expect(updateRowsForRepoFiles([noInput, notString, otherKey], ['f-6500'])).toEqual([]);
  });

  it('ignores unknown wanted ids (no match → empty result)', () => {
    const a = row({ deviceId: 'd1', kind: 'firmware', name: 'os', applyInput: { repoFileId: 'f-6500' } });
    expect(updateRowsForRepoFiles([a], ['does-not-exist'])).toEqual([]);
  });
});
