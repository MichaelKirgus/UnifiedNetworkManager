/**
 * Minimal type surface for `unzipper` (no @types package is published that
 * matches the API we use). Only what extractMember() touches.
 */
declare module 'unzipper' {
  export interface ZipFileEntry {
    path: string;
    /** 'File' for regular entries, 'Directory' for folders. */
    type: string;
    size: number;
    /** Reads the full (decompressed) entry into memory — fine for GeoIP CSVs (<100 MiB). */
    buffer(): Promise<Buffer>;
  }

  export namespace Open {
    function file(path: string): Promise<{ files: ZipFileEntry[] }>;
  }
}
