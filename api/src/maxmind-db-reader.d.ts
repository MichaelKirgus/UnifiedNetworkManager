/**
 * Minimal type surface for `maxmind-db-reader` (MaxMind's official pure-JS MMDB
 * reader — no @types package is published). Only what utils/geoIp.ts touches.
 */
declare module 'maxmind-db-reader' {
  export interface MaxmindReader {
    /** Synchronous lookup — returns the record for `ip`, or null when absent. */
    getGeoDataSync(ip: string): Record<string, unknown> | null;
    getGeoData(ip: string, callback: (err: Error | null, data: Record<string, unknown> | null) => void): void;
  }

  export default class MaxmindDBReader {
    static open(database: string, callback: (err: Error | null, reader: MaxmindReader) => void): void;
    /** Reads the whole file into memory — lookups are then synchronous. */
    static openSync(database: string): MaxmindReader;
  }
}
