/**
 * Unit tests for the Shelly planner (src/plan.ts) — fan-out, validation errors,
 * and the settle-wait + inventory-refresh tail appended after firmware updates.
 */
import { PlanningError, SYSTEM_STEP_WAIT, SYSTEM_STEP_INVENTORY_REFRESH } from '@unm/plugin-sdk';
import type { PlanRequest } from '../src/plan';
import { buildPlan } from '../src/plan';

function device(deviceId: string) {
  return { deviceId, managementAddress: `http://127.0.0.1:${Number(deviceId.slice(-4)) || 9}`, credentials: {} };
}

function reqFor(actionId: string, devices: ReturnType<typeof device>[], inputs: Record<string, unknown> = {}, deviceInputs?: Record<string, Record<string, unknown>>): PlanRequest {
  return { intent: { actionId, inputs }, devices, ...(deviceInputs ? { deviceInputs } : {}) };
}

describe('buildPlan — structural errors', () => {
  it('rejects an empty device list', () => {
    expect(() => buildPlan(reqFor('shelly.reboot', [], {}))).toThrow(PlanningError);
    expect(() => buildPlan(reqFor('shelly.reboot', [], {}))).toThrow(/at least one device/i);
  });

  it('rejects an unknown action and lists the available ones', () => {
    expect(() => buildPlan(reqFor('shelly.nuke', [device('dev-0001')], {}))).toThrow(PlanningError);
    const msg = (() => { try { buildPlan(reqFor('shelly.nuke', [device('dev-0001')], {})); return ''; } catch (e) { return (e as Error).message; } })();
    expect(msg).toContain('shelly.firmware.update');
    expect(msg).toContain('shelly.reboot');
  });

  it('rejects invalid inputs (bad stage enum)', () => {
    expect(() => buildPlan(reqFor('shelly.firmware.update', [device('dev-0001')], { stage: 'nightly' }))).toThrow(PlanningError);
    expect(() => buildPlan(reqFor('shelly.firmware.update', [device('dev-0001')], { stage: 'nightly' }))).toThrow(/stage/);
  });

  it('accepts valid inputs (stable/beta/absent)', () => {
    for (const inputs of [{}, { stage: 'stable' }, { stage: 'beta' }]) {
      const plan = buildPlan(reqFor('shelly.firmware.update', [device('dev-0001')], inputs));
      expect(plan.steps.length).toBeGreaterThan(0);
    }
  });
});

describe('buildPlan — reboot fan-out (no settle tail)', () => {
  it('emits exactly one step per device, no system steps', () => {
    const plan = buildPlan(reqFor('shelly.reboot', [device('dev-0001'), device('dev-0002')], {}));
    expect(plan.intentActionId).toBe('shelly.reboot');
    expect(plan.steps).toHaveLength(2);
    expect(plan.steps.map((s) => s.actionId)).toEqual(['shelly.reboot', 'shelly.reboot']);
    expect(plan.steps.map((s) => s.deviceId)).toEqual(['dev-0001', 'dev-0002']);
    // stepIndex is a dense 0..n-1 sequence
    expect(plan.steps.map((s) => s.stepIndex)).toEqual([0, 1]);
    expect(plan.provisionRequests).toEqual([]);
  });

  it('merges per-device input overrides onto the shared inputs', () => {
    const plan = buildPlan(reqFor('shelly.firmware.update', [device('dev-0001'), device('dev-0002')], { stage: 'stable' }, { 'dev-0002': { stage: 'beta' } }));
    const byDevice = new Map(plan.steps.filter((s) => s.actionId === 'shelly.firmware.update').map((s) => [s.deviceId, s.input]));
    expect(byDevice.get('dev-0001')).toEqual({ stage: 'stable' });
    expect(byDevice.get('dev-0002')).toEqual({ stage: 'beta' });
  });
});

describe('buildPlan — firmware update appends settle-wait + inventory refresh', () => {
  it('single device: update step, then a 120 s wait, then an inventory refresh that depends on the wait', () => {
    const plan = buildPlan(reqFor('shelly.firmware.update', [device('dev-0001')], {}));
    expect(plan.steps.map((s) => s.actionId)).toEqual(['shelly.firmware.update', SYSTEM_STEP_WAIT, SYSTEM_STEP_INVENTORY_REFRESH]);

    const [update, wait, refresh] = plan.steps;
    expect(update.deviceId).toBe('dev-0001');
    expect(wait.input).toEqual({ ms: 120_000 });
    expect(wait.bestEffort).toBe(true);
    // refresh waits for the settle to finish
    expect(refresh.dependsOn).toEqual([wait.stepIndex]);
    expect(refresh.bestEffort).toBe(true);
    // indices are dense and final
    expect(plan.steps.map((s) => s.stepIndex)).toEqual([0, 1, 2]);
  });

  it('two devices: each updated device gets its own wait + refresh pair', () => {
    const plan = buildPlan(reqFor('shelly.firmware.update', [device('dev-0001'), device('dev-0002')], {}));
    expect(plan.steps).toHaveLength(6);
    const waits = plan.steps.filter((s) => s.actionId === SYSTEM_STEP_WAIT);
    const refreshes = plan.steps.filter((s) => s.actionId === SYSTEM_STEP_INVENTORY_REFRESH);
    expect(waits.map((s) => s.deviceId)).toEqual(['dev-0001', 'dev-0002']);
    expect(refreshes.map((s) => s.deviceId)).toEqual(['dev-0001', 'dev-0002']);
    for (const w of waits) expect(w.input).toEqual({ ms: 120_000 });
    // each refresh depends on ITS OWN wait
    for (const r of refreshes) {
      const ownWait = plan.steps.find((s) => s.actionId === SYSTEM_STEP_WAIT && s.deviceId === r.deviceId)!;
      expect(r.dependsOn).toEqual([ownWait.stepIndex]);
    }
  });
});
