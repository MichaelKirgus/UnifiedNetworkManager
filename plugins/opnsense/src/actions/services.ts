import * as ntpd from '../client/ntpd';
import * as syslog from '../client/syslog';
import * as monit from '../client/monit';
import { ActionDescriptor } from './types';

/** NTP, syslog and monit actions. */

function dataOf(res: { ok: boolean; status: number; data: unknown }): Record<string, unknown> | undefined {
  return res.ok && res.data !== null && typeof res.data === 'object' ? (res.data as Record<string, unknown>) : undefined;
}

export const ntpdActions: ActionDescriptor[] = [
  {
    id: 'ntpd.status.read',
    label: 'Read NTP sync status',
    module: 'NTP',
    riskLevel: 'read',
    deviceCount: 1,
    inputSchema: {},
    execute: async (ctx) => {
      const res = await ntpd.getServiceStatus(ctx.client);
      return { success: res.ok, details: dataOf(res) ?? {} };
    },
  },
  {
    id: 'ntpd.settings.set',
    label: 'Update NTP settings (staged)',
    module: 'NTP',
    riskLevel: 'write',
    staged: true,
    deviceCount: 1,
    inputSchema: { settings: { type: 'object', required: true } },
    execute: async (ctx, input) => {
      const res = await ntpd.setSettings(ctx.client, (input.settings as Record<string, unknown>) ?? {});
      return { success: res.ok, applied: false, details: dataOf(res) ?? {} };
    },
  },
];

export const syslogActions: ActionDescriptor[] = [
  {
    id: 'syslog.destinations.read',
    label: 'Read syslog destinations',
    module: 'Syslog',
    riskLevel: 'read',
    deviceCount: 1,
    inputSchema: {},
    execute: async (ctx) => {
      const res = await syslog.searchDestinations(ctx.client);
      return { success: res.ok, details: dataOf(res) ?? {} };
    },
  },
  {
    id: 'syslog.destination.add',
    label: 'Add syslog destination (staged)',
    module: 'Syslog',
    riskLevel: 'write',
    staged: true,
    deviceCount: 1,
    inputSchema: { item: { type: 'object', required: true } },
    execute: async (ctx, input) => {
      const res = await syslog.addDestination(ctx.client, (input.item as Record<string, unknown>) ?? {});
      return { success: res.ok, applied: false, details: dataOf(res) ?? {} };
    },
  },
  {
    id: 'syslog.destination.delete',
    label: 'Delete syslog destination (staged)',
    module: 'Syslog',
    riskLevel: 'write',
    staged: true,
    deviceCount: 1,
    inputSchema: { uuid: { type: 'string', required: true } },
    execute: async (ctx, input) => {
      const res = await syslog.deleteDestination(ctx.client, String(input.uuid));
      return { success: res.ok, applied: false, details: dataOf(res) ?? {} };
    },
  },
  {
    id: 'syslog.reconfigure',
    label: 'Apply staged syslog changes',
    module: 'Syslog',
    riskLevel: 'write',
    deviceCount: 1,
    inputSchema: {},
    execute: async (ctx) => {
      const res = await syslog.reconfigureService(ctx.client);
      return { success: res.ok, applied: res.ok, details: dataOf(res) ?? {} };
    },
  },
];

export const monitActions: ActionDescriptor[] = [
  {
    id: 'monit.services.read',
    label: 'Read monitored services',
    module: 'Monit',
    riskLevel: 'read',
    deviceCount: 1,
    inputSchema: {},
    execute: async (ctx) => {
      const res = await monit.searchServices(ctx.client);
      return { success: res.ok, details: dataOf(res) ?? {} };
    },
  },
  {
    id: 'monit.service.add',
    label: 'Add monitored service (staged)',
    module: 'Monit',
    riskLevel: 'write',
    staged: true,
    deviceCount: 1,
    inputSchema: { item: { type: 'object', required: true } },
    execute: async (ctx, input) => {
      const res = await monit.addService(ctx.client, (input.item as Record<string, unknown>) ?? {});
      return { success: res.ok, applied: false, details: dataOf(res) ?? {} };
    },
  },
  {
    id: 'monit.service.delete',
    label: 'Delete monitored service (staged)',
    module: 'Monit',
    riskLevel: 'write',
    staged: true,
    deviceCount: 1,
    inputSchema: { uuid: { type: 'string', required: true } },
    execute: async (ctx, input) => {
      const res = await monit.deleteService(ctx.client, String(input.uuid));
      return { success: res.ok, applied: false, details: dataOf(res) ?? {} };
    },
  },
  {
    id: 'monit.reconfigure',
    label: 'Apply staged monit changes',
    module: 'Monit',
    riskLevel: 'write',
    deviceCount: 1,
    inputSchema: {},
    execute: async (ctx) => {
      const res = await monit.reconfigureService(ctx.client);
      return { success: res.ok, applied: res.ok, details: dataOf(res) ?? {} };
    },
  },
];
