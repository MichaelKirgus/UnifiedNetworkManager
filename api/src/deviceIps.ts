import { asc, eq } from 'drizzle-orm';
import { v4 as uuidv4 } from 'uuid';
import { db } from './db';
import * as schema from './db/schema';
import { isValidAddress, addressError } from './utils/address';

/**
 * Device IP-address broker.
 *
 * A device's PRIMARY address is `devices.managementAddress` (validated to an
 * IPv4 / IPv6 literal or DNS name). This module manages the SECONDARY
 * addresses in `device_ips` — additional targets plugins may reach (a public
 * interface, a second management VLAN, …). The primary is never stored here;
 * views always present it first with `isPrimary: true`.
 */

export interface DeviceIp {
  id: string;
  deviceId: string;
  address: string;
  createdAt: string;
}

/** Address as presented to the UI (primary flag + row id for deletion). */
export interface DeviceAddressView {
  address: string;
  isPrimary: boolean;
  /** Row id of a secondary IP; null for the primary (which lives on the device). */
  id?: string | null;
}

/** Error carrying an HTTP status so routes can map it directly. */
export class IpError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

type DeviceRow = NonNullable<Awaited<ReturnType<typeof fetchDevice>>>;

async function assertDevice(deviceId: string): Promise<DeviceRow> {
  const device = await fetchDevice(deviceId);
  if (!device) throw new IpError(404, 'Device not found');
  return device;
}

async function fetchDevice(deviceId: string) {
  return db.query.devices.findFirst({
    where: (devices, { eq }) => eq(devices.id, deviceId),
  });
}

/** All secondary addresses for a device (oldest first). */
export async function listDeviceIps(deviceId: string): Promise<DeviceIp[]> {
  await assertDevice(deviceId);
  return db.query.deviceIps.findMany({
    where: (rows) => eq(rows.deviceId, deviceId),
    orderBy: [asc(schema.deviceIps.createdAt)],
  });
}

/**
 * Full address view for a device: the primary (managementAddress) first with
 * `isPrimary: true`, then all secondary addresses.
 */
export async function listDeviceAddresses(deviceId: string): Promise<DeviceAddressView[]> {
  const [device, ips] = await Promise.all([fetchDevice(deviceId), listDeviceIps(deviceId)]);
  if (!device) throw new IpError(404, 'Device not found');
  return [
    { address: device.managementAddress, isPrimary: true, id: null },
    ...ips.map((ip) => ({ address: ip.address, isPrimary: false, id: ip.id })),
  ];
}

/**
 * Adds a secondary IP to a device.
 * - Invalid format → 400 (with the validator's message).
 * - Duplicate of an existing secondary OR of the primary → 409.
 */
export async function addDeviceIp(input: {
  deviceId: string;
  address: unknown;
}): Promise<DeviceIp> {
  const { deviceId } = input;
  const device = await assertDevice(deviceId);

  if (!isValidAddress(input.address)) {
    throw new IpError(400, addressError(input.address) ?? 'Invalid address');
  }
  const address = (input.address as string).trim();

  // Case-insensitive duplicate check: hostnames are case-insensitive and the
  // DB unique index is not. Compare against the primary too — a secondary may
  // never shadow managementAddress.
  const existing = await db.query.deviceIps.findMany({
    where: (rows) => eq(rows.deviceId, deviceId),
  });
  const clash =
    device.managementAddress.trim().toLowerCase() === address.toLowerCase() ||
    existing.some((row) => row.address.trim().toLowerCase() === address.toLowerCase());
  if (clash) {
    throw new IpError(409, 'This address is already registered for the device');
  }

  const now = new Date().toISOString();
  await db.insert(schema.deviceIps).values({
    id: uuidv4(),
    deviceId,
    address,
    createdAt: now,
  });

  return (await findDeviceIp(deviceId, address))!;
}

/** Removes a secondary IP from its device. */
export async function removeDeviceIp(deviceId: string, ipId: string): Promise<void> {
  await assertDevice(deviceId);
  const row = await db.query.deviceIps.findFirst({
    where: (rows) => eq(rows.id, ipId),
  });
  if (!row || row.deviceId !== deviceId) {
    throw new IpError(404, 'Address is not registered for this device');
  }
  await db.delete(schema.deviceIps).where(eq(schema.deviceIps.id, row.id));
}

async function findDeviceIp(deviceId: string, address: string) {
  const rows = await db.query.deviceIps.findMany({
    where: (rows) => eq(rows.deviceId, deviceId),
  });
  return rows.find((row) => row.address === address);
}
