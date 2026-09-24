/**
 * Unit checks for the hardened computeDiff — run with: node test-diff.cjs
 */
const assert = require('assert');
const { computeDiff, markerValueOf, mergeMarkerTag, LEGACY_MARKER_VALUE } = require('./dist/src/sync.js');

const cfgBase = {
  scope: 'documented', syncTag: '', markerTag: 'unm-managed', nameTemplate: '{dns0}',
  groups: [], autoCreateGroups: true, template: '', ipMode: 'all',
  deleteOrphans: false, inactiveAsDisabled: true, adoptExisting: false,
};

const host = (id, dns, extra = {}) => ({ id, name: dns, dnsNames: [dns], friendlyName: null, tags: [], isActive: true, documented: true, addresses: [{ address: '10.0.0.1', mac: 'aa' }], ...extra });
const managed = (hostid, zbxName, unmHostId, extra = {}) => ({ hostid, zbxName, status: '0', ips: new Set(['10.0.0.1']), unmHostId, ...extra });

let n = 0;
function check(label, fn) { try { fn(); console.log(`ok ${++n} - ${label}`); } catch (e) { console.error(`FAIL ${n + 1} - ${label}: ${e.message}`); process.exitCode = 1; } }

// 1. New host → create
check('new host creates', () => {
  const r = computeDiff([host('u1', 'web-01')], [], [], cfgBase);
  assert.strictEqual(r.ops.length, 1); assert.strictEqual(r.ops[0].kind, 'create');
});

// 2. Managed by marker id → unchanged (idempotent)
check('marker-id match is a no-op when in sync', () => {
  const r = computeDiff([host('u1', 'web-01')], [managed('z1', 'web-01', 'u1')], [], cfgBase);
  assert.strictEqual(r.ops.length, 0); assert.strictEqual(r.unchanged, 1);
});

// 3. Name template changed: managed host keeps OLD name but marker id matches → update (no duplicate create)
check('template change survives via marker id', () => {
  const r = computeDiff([host('u1', 'web-02')], [managed('z1', 'web-01', 'u1')], [], cfgBase);
  assert.strictEqual(r.ops.length, 1); assert.strictEqual(r.ops[0].kind, 'update'); assert.ok(!r.ops.some(o => o.kind === 'create'));
});

// 4. Legacy host (value "managed") matched by name → update with marker re-tag
check('legacy host migrated by name', () => {
  const r = computeDiff([host('u1', 'web-01')], [managed('z1', 'web-01', null)], [], cfgBase);
  assert.strictEqual(r.ops.length, 1); assert.strictEqual(r.ops[0].kind, 'update');
  assert.ok(r.ops[0].reason.includes('marker')); assert.strictEqual(r.ops[0].zbxHostId, 'z1');
});

// 5. Legacy host NOT in scope + deleteOrphans off → kept (no op)
check('legacy orphan kept by default', () => {
  const r = computeDiff([], [managed('z9', 'gone-01', null)], [], cfgBase);
  assert.strictEqual(r.ops.length, 0);
});

// 6. Legacy orphan + deleteOrphans on → deleted (it is UNM-managed)
check('legacy orphan deleted when enabled', () => {
  const r = computeDiff([], [managed('z9', 'gone-01', null)], [], { ...cfgBase, deleteOrphans: true });
  assert.strictEqual(r.ops.length, 1); assert.strictEqual(r.ops[0].kind, 'delete'); assert.strictEqual(r.ops[0].zbxHostId, 'z9');
});

// 7. Untagged candidate + adoptExisting on → claimed (update with marker)
check('untagged host adopted when enabled', () => {
  const cand = { hostid: 'c1', zbxName: 'web-01', status: '0', ips: new Set(['10.9.9.9']) };
  const r = computeDiff([host('u1', 'web-01')], [], [cand], { ...cfgBase, adoptExisting: true });
  assert.strictEqual(r.ops.length, 1); assert.strictEqual(r.ops[0].kind, 'update');
  assert.ok(r.ops[0].reason.includes('marker')); assert.ok(r.ops[0].reason.includes('interfaces'));
});

// 8. Untagged candidate + adoptExisting off → create (Zabbix will reject the duplicate; surfaced as per-host error)
check('untagged host NOT adopted by default', () => {
  const cand = { hostid: 'c1', zbxName: 'web-01', status: '0', ips: new Set(['10.9.9.9']) };
  const r = computeDiff([host('u1', 'web-01')], [], [cand], cfgBase);
  assert.strictEqual(r.ops.length, 1); assert.strictEqual(r.ops[0].kind, 'create');
});

// 9. Untagged candidate is NEVER deleted even with deleteOrphans on
check('untagged host never deleted', () => {
  const cand = { hostid: 'c1', zbxName: 'manual-01', status: '0', ips: new Set() };
  const r = computeDiff([], [], [cand], { ...cfgBase, deleteOrphans: true });
  assert.strictEqual(r.ops.length, 0);
});

// 10. Ownership conflict: managed host's marker points at ANOTHER UNM host → conflict, no op
check('foreign-marker conflict reported, untouched', () => {
  const r = computeDiff([host('u1', 'web-01')], [managed('z1', 'web-01', 'u-other')], [], cfgBase);
  assert.strictEqual(r.ops.length, 0); assert.strictEqual(r.conflicts.length, 1);
});

// 11. Two legacy hosts share a name → conflict for the UNM host, both kept
check('duplicate legacy names conflict', () => {
  const r = computeDiff([host('u1', 'web-01')], [managed('z1', 'web-01', null), managed('z2', 'web-01', null)], [], cfgBase);
  assert.strictEqual(r.ops.length, 0); assert.strictEqual(r.conflicts.length, 1);
});

// 12. Inactive UNM host → status change on marker-matched host
check('inactive maps to disabled', () => {
  const r = computeDiff([host('u1', 'web-01', { isActive: false })], [managed('z1', 'web-01', 'u1')], [], cfgBase);
  assert.strictEqual(r.ops.length, 1); assert.ok(r.ops[0].reason.includes('status'));
});

// 13. IP change → interfaces op
check('ip set change detected', () => {
  const r = computeDiff([host('u1', 'web-01', { addresses: [{ address: '10.0.0.2', mac: 'aa' }] })], [managed('z1', 'web-01', 'u1')], [], cfgBase);
  assert.strictEqual(r.ops.length, 1); assert.ok(r.ops[0].reason.includes('interfaces'));
});

// 14. markerValueOf / mergeMarkerTag helpers
check('marker helpers behave', () => {
  assert.strictEqual(markerValueOf([{ tag: 'unm-managed', value: LEGACY_MARKER_VALUE }], 'unm-managed'), null);
  assert.strictEqual(markerValueOf([{ tag: 'unm-managed', value: 'abc-123' }], 'unm-managed'), 'abc-123');
  const merged = mergeMarkerTag([{ tag: 'env', value: 'prod' }, { tag: 'unm-managed', value: LEGACY_MARKER_VALUE }], 'unm-managed', 'u9');
  assert.deepStrictEqual(merged, [{ tag: 'unm-managed', value: 'u9' }, { tag: 'env', value: 'prod' }]);
});

// 15. Candidate name shadowed by a managed host → not adoptable (managed wins)
check('managed host shadows candidate of same name', () => {
  const cand = { hostid: 'c1', zbxName: 'web-01', status: '0', ips: new Set() };
  const r = computeDiff([host('u2', 'web-01')], [managed('z1', 'web-01', 'u1')], [cand], { ...cfgBase, adoptExisting: true });
  // u2's rendered name collides with a host owned by u1 → conflict, candidate untouched
  assert.strictEqual(r.ops.length, 0); assert.strictEqual(r.conflicts.length, 1);
});

console.log(process.exitCode ? 'SOME TESTS FAILED' : `ALL ${n} CHECKS PASSED`);
