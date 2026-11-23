import type { UpdateRow } from '../api/client';

/** Update rows whose apply input points at one of the given repo files — the
 * Files-page "Flash devices…" deep link (?file=<id>, repeatable) filters with
 * this. An empty id list means no filter (rows returned untouched). */
export function updateRowsForRepoFiles(rows: UpdateRow[], fileIds: string[]): UpdateRow[] {
  if (fileIds.length === 0) return rows;
  const wanted = new Set(fileIds);
  return rows.filter((r) => {
    const ai = r.applyInput;
    return !!ai && typeof ai['repoFileId'] === 'string' && wanted.has(ai['repoFileId']);
  });
}
