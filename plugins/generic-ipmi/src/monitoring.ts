/**
 * Monitoring collection for generic IPMI devices.
 *
 * One UNM device = one BMC (username/password over RMCP+). Each poll:
 *   1. connect() — the RAKP handshake doubles as reachability + auth probe;
 *   2. chassis status → power state (health signal);
 *   3. SDR walk + live sensor readings → ipmi.sensors table with threshold states;
 *   4. FRU read → identity enrichment (manufacturer/model/serial);
 *   5. SEL tail → ipmi.sel table (recent events, newest last);
 *   6. inventory propagation: networks[] row from the LAN channel config.
 *
 * Budget discipline: the SDR walk is the slow part (one round-trip per record +
 * one per reading). `collectInventory=false` polls skip FRU/SEL/LAN entirely and
 * OMIT those metric keys — an absent key never wipes stored rows, so metrics-only
 * polls are safe by contract. Sensor threshold violations degrade health to
 * warning/critical; a failed sub-read degrades to warning + partial data.
 */

import { Health } from '@unm/plugin-sdk';
import type { IpmiClient } from './client/ipmiClient';
import { getChassisStatus, getSensorReadings, readFru, getSelEntries, getLanConfig } from './client/ipmiCommands';
import { detectAspeedVariant, readAspeedFanState } from './client/aspeedFan';

export interface IpmiMonitoringOptions {
  /** When false (non-inventory poll), skip FRU/SEL/LAN collection and omit those keys. */
  collectInventory: boolean;
  /** When false, skip the SDR walk + sensor readings entirely (fastest poll). */
  collectSensors: boolean;
  /** When true, read the Aspeed OEM fan table (netfn 0x3a) on every poll — AST2600/AST2500 boards. */
  aspeedFan: boolean;
}

export interface IpmiMonitoringResult {
  health: Health;
  metrics: Record<string, unknown>;
  errors: string[];
}

// --- Inventory row shapes (consumed by the API's ingestInventory) -----------------

interface NetworkRow {
  name: string;
  ip: string;
  prefix: number | null;
  version: '4' | '6';
  vlanId: number | null;
  mac: string | null;
  status: string | null;
}

/** "255.255.255.0" → 24 (null when unparseable). */
function netmaskToPrefix(netmask?: string): number | null {
  if (!netmask) return null;
  const parts = netmask.split('.').map((p) => parseInt(p, 10));
  if (parts.length !== 4 || parts.some((n) => Number.isNaN(n))) return null;
  let prefix = 0;
  for (const octet of parts) {
    if (octet === 255) prefix += 8;
    else if (octet === 0) break;
    else return null; // non-contiguous — not a plain prefix
  }
  return prefix;
}

/** Collects the networks[] row from the BMC's LAN channel config. */
function networkRowsForLan(lan: { ipAddress: string; subnetMask: string; macAddress: string }): NetworkRow[] {
  const rows: NetworkRow[] = [];
  if (lan.ipAddress && /^\d+\.\d+\.\d+\.\d+$/.test(lan.ipAddress)) {
    rows.push({
      name: 'ipmi-lan',
      ip: lan.ipAddress,
      prefix: netmaskToPrefix(lan.subnetMask),
      version: '4',
      vlanId: null,
      mac: lan.macAddress ? lan.macAddress.toLowerCase() : null,
      status: 'up',
    });
  }
  return rows;
}

// --- Collection ------------------------------------------------------------------

/** Runs one full monitoring poll against a connected BMC. */
export async function collectIpmiMonitoring(client: IpmiClient, opts: IpmiMonitoringOptions): Promise<IpmiMonitoringResult> {
  const metrics: Record<string, unknown> = {};
  const errors: string[] = [];

  // --- Chassis status (always — it is the primary health signal) -------------------
  let poweredOn = false;
  try {
    const chassis = await getChassisStatus(client);
    poweredOn = chassis.poweredOn;
    metrics['ipmi.chassis'] = {
      poweredOn: chassis.poweredOn,
      powerControlLost: chassis.powerControlLost,
      restorePolicy: chassis.restorePolicy,
    };
  } catch (e) {
    errors.push(`chassis status: ${errMsg(e)}`);
  }

  // --- Sensors (SDR walk + live readings) ------------------------------------------
  let sensorStates: Array<'ok' | 'warning' | 'critical'> = [];
  if (opts.collectSensors) {
    try {
      const sensors = await getSensorReadings(client, { withReadings: true });
      metrics['ipmi.sensors'] = sensors.map((s) => ({
        id: s.id,
        type: s.type,
        reading: s.reading,
        rawReading: s.rawReading,
        unit: s.unit,
        state: s.state,
      }));
      sensorStates = sensors.map((s) => s.state);
    } catch (e) {
      errors.push(`sensor walk: ${errMsg(e)}`);
    }
  }

  // --- Aspeed OEM fan state (opt-in — AST2600/AST2500 boards, e.g. ASRock Rack) ------
  if (opts.aspeedFan) {
    try {
      const variant = await detectAspeedVariant(client);
      if (!variant) throw new Error('BMC does not answer Aspeed fan OEM commands (netfn 0x3a) — disable the aspeedFan option on non-Aspeed boards');
      const state = await readAspeedFanState(client, variant);
      // Table metric — ARRAY form (one row per channel), rendered by MetricTable.
      metrics['ipmi.fan'] = state.channels.map((c) => ({ channel: c.index, mode: c.mode, dutyPercent: c.dutyPercent }));
    } catch (e) {
      errors.push(`Aspeed fan read: ${errMsg(e)}`);
    }
  }

  // --- Inventory-only sections (omitted on metrics-only polls) ----------------------
  if (opts.collectInventory) {
    // FRU → identity enrichment. Table of rows — the webapp renders table metrics
    // as arrays of row objects, so each field becomes one {area, key, value} row.
    try {
      const fru = await readFru(client, 0);
      if (fru.length > 0) {
        const seen = new Set<string>();
        const rows: Array<{ area: string; key: string; value: string }> = [];
        for (const f of fru) {
          const k = `${f.area}.${f.key}`;
          if (seen.has(k)) continue; // first occurrence wins (chassis before board/product)
          seen.add(k);
          rows.push({ area: f.area, key: f.key, value: f.value });
        }
        metrics['ipmi.fru'] = rows;
      }
    } catch (e) {
      errors.push(`FRU read: ${errMsg(e)}`);
    }

    // SEL tail → recent events.
    try {
      const sel = await getSelEntries(client, 50);
      metrics['ipmi.sel'] = sel.map((s) => ({
        recordId: s.recordId,
        timestamp: s.timestamp || null,
        severity: s.severity,
        sensorType: s.sensorType,
        event: s.event,
      }));
    } catch (e) {
      errors.push(`SEL read: ${errMsg(e)}`);
    }

    // LAN config → networks[] inventory row.
    try {
      const lan = await getLanConfig(client, 1);
      if (lan.ipAddress) metrics['networks'] = networkRowsForLan(lan);
    } catch (e) {
      errors.push(`LAN config read: ${errMsg(e)}`);
    }
  }

  // --- Health ------------------------------------------------------------------------
  let health: Health = 'ok';
  const reasons: string[] = [];

  if (errors.length > 0 && !('ipmi.chassis' in metrics)) {
    // Chassis status failed — we can't even confirm the BMC is answering commands.
    health = 'critical';
    reasons.push(`BMC unreachable or command failure: ${errors[0]}`);
  } else if (poweredOn === false) {
    // A powered-off server is a state, not a fault — but it IS worth surfacing.
    health = 'warning';
    reasons.push('Server is powered off');
  }

  const criticalSensors = sensorStates.filter((s) => s === 'critical').length;
  const warningSensors = sensorStates.filter((s) => s === 'warning').length;
  if (criticalSensors > 0) {
    health = 'critical';
    reasons.push(`${criticalSensors} sensor(s) in critical state`);
  } else if (warningSensors > 0 && health !== 'critical') {
    health = 'warning';
    reasons.push(`${warningSensors} sensor(s) above/below non-critical threshold`);
  }

  // Partial sub-read failures degrade to warning when otherwise healthy.
  if (errors.length > 0 && health === 'ok') {
    health = 'warning';
    reasons.push(`Partial data: ${errors.join('; ')}`);
  }

  return { health, metrics, errors };
}

function errMsg(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}
