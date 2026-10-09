/**
 * One address of a device (primary flag included).
 *
 * Previously re-declared verbatim in the console/filesystem/probe/state brokers,
 * workers/telemetry, and deviceIps — one owner now. The plugin-facing sites set
 * only `address` + `isPrimary`; the IP broker's UI view additionally carries the
 * secondary row id (optional, so both shapes share this single type).
 */

export interface DeviceAddressView {
  address: string;
  isPrimary: boolean;
  /** Row id of a secondary IP; null for the primary (which lives on the device). Set by the IP broker's UI view only. */
  id?: string | null;
}
