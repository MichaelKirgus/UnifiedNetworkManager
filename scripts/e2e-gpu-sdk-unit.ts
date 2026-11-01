/**
 * Offline unit check for the shared SDK GPU module (packages/plugin-sdk/src/gpu.ts).
 * Feeds realistic multi-vendor probe-script output through collectGpuRows() with a
 * mock exec backend and asserts the merged GpuRow[] is correct — no live hardware,
 * no auth required. Run from repo root:
 *   ./node_modules/.bin/tsx scripts/e2e-gpu-sdk-unit.ts
 */

import path from 'node:path';
import { createRequire } from 'node:module';

const apiRequire = createRequire(path.resolve(process.cwd(), 'api', 'package.json'));
// Resolve the SDK through a plugin's node_modules copy (the built dist).
const sdkPath = path.resolve(process.cwd(), 'plugins/generic-ssh/node_modules/@unm/plugin-sdk');
const { collectGpuRows, parsePciGpuSection, parseNvidiaSmiSection, normalizeNvidiaSlot, detectGpuVendor } = require(sdkPath);

let failures = 0;
function check(label: string, cond: boolean, extra?: unknown): void {
  if (cond) console.log(`  PASS ${label}`);
  else { failures++; console.error(`  FAIL ${label}`, extra !== undefined ? JSON.stringify(extra).slice(0, 400) : ''); }
}

// --- Realistic probe-script stdout: one NVIDIA + one AMD + one Intel iGPU ------
const PCI = [
  'UNM_GPU_PCI:BEGIN',
  // slot|vendor|device|driver|driverVersion
  '0000:41:00.0|0x10de|0x2684|nvidia|550.90.07',   // RTX 4070 Ti Super (NVIDIA)
  '0000:c1:00.0|0x1002|0x73bf|amdgpu|6.14.0',       // RX 6800 XT (AMD)
  '0000:00:02.0|0x8086|0x9a49|i915|6.10.7',         // Intel iGPU (enabled)
  'UNM_GPU_PCI:END',
].join('\n');

const NVIDIA = [
  'UNM_GPU_NVIDIA:BEGIN',
  // pci.bus_id,name,driver_version,memory.total,memory.used,utilization.gpu,utilization.memory,temperature.gpu,power.draw,clocks.current.graphics,clocks.max.graphics
  '00000000:41:00.0, NVIDIA GeForce RTX 4070 Ti Super, 550.90.07, 12288, 3072, 64, 41, 58, 45.2, 2400, 2610',
  'UNM_GPU_NVIDIA:END',
].join('\n');

const ROCM = [
  'UNM_GPU_ROCM_NAME:BEGIN',
  'Card 0: Radeon RX 6800 XT',
  'UNM_GPU_ROCM_NAME:END',
].join('\n');

const stdout = `${PCI}\n${NVIDIA}\n${ROCM}\n`;

async function main(): Promise<void> {
  // --- Pure parser checks -----------------------------------------------------
  const pci = parsePciGpuSection(PCI);
  check('parsePciGpuSection: 3 entries', pci.length === 3, pci);
  check('parsePciGpuSection: slot format kept', pci[0].slot === '0000:41:00.0' && pci[2].slot === '0000:00:02.0');

  const nv = parseNvidiaSmiSection(NVIDIA);
  check('parseNvidiaSmiSection: normalized slot key', nv.has('0000:41:00.0'), Array.from(nv.keys()));
  check('normalizeNvidiaSlot short form', normalizeNvidiaSlot('41:00.0') === '0000:41:00.0');
  check('detectGpuVendor nvidia by id', detectGpuVendor('10de', null) === 'NVIDIA');
  check('detectGpuVendor amd by driver', detectGpuVendor(null, 'amdgpu') === 'AMD');
  check('detectGpuVendor intel by driver', detectGpuVendor(null, 'i915') === 'INTEL');

  // --- Full collectGpuRows with a mock backend ---------------------------------
  const rows = await collectGpuRows({ exec: async () => ({ code: 0, stdout, stderr: '' }) });
  check('collectGpuRows returns array', Array.isArray(rows), rows);
  if (!Array.isArray(rows)) return;
  check('collectGpuRows: 3 rows (NVIDIA+AMD+iGPU)', rows.length === 3, rows.map((r) => r.slot));

  const nvidia = rows.find((r) => r.slot === '0000:41:00.0');
  check('nvidia row vendor', nvidia?.vendor === 'NVIDIA', nvidia);
  check('nvidia row name from smi', nvidia?.name === 'NVIDIA GeForce RTX 4070 Ti Super', nvidia?.name);
  check('nvidia driverVersion merged', nvidia?.driverVersion === '550.90.07');
  check('nvidia vramBytes (MiB→bytes)', nvidia?.vramBytes === 12288 * 1048576, nvidia?.vramBytes);
  check('nvidia utilPercent merged', nvidia?.utilPercent === 64);
  check('nvidia tempCelsius merged', nvidia?.tempCelsius === 58);
  check('nvidia powerWatts merged', nvidia?.powerWatts === 45.2);
  check('nvidia coreClockMhz merged', nvidia?.coreClockMhz === 2400 && nvidia?.maxCoreClockMhz === 2610);

  const amd = rows.find((r) => r.slot === '0000:c1:00.0');
  check('amd row vendor', amd?.vendor === 'AMD', amd);
  check('amd name from rocm-smi (ordered map)', amd?.name === 'Radeon RX 6800 XT', amd?.name);
  check('amd driverVersion from sysfs module', amd?.driverVersion === '6.14.0');

  const intel = rows.find((r) => r.slot === '0000:00:02.0');
  check('intel iGPU row vendor', intel?.vendor === 'INTEL', intel);
  check('intel has no live counters (no CLI)', intel?.utilPercent == null && intel?.tempCelsius == null, intel);

  // --- Failure path: exec throws → null (caller omits key = no wipe) -----------
  const failed = await collectGpuRows({ exec: async () => { throw new Error('ssh down'); } });
  check('collectGpuRows returns null on exec failure', failed === null, failed);

  // --- No-GPU host: empty PCI section → authoritative [] ------------------------
  const none = await collectGpuRows({ exec: async () => ({ code: 0, stdout: 'UNM_GPU_PCI:BEGIN\nUNM_GPU_PCI:END\n', stderr: '' }) });
  check('collectGpuRows returns [] when no GPUs (authoritative wipe)', Array.isArray(none) && none.length === 0, none);

  console.log(`\n${failures === 0 ? 'ALL CHECKS PASSED' : `${failures} CHECK(S) FAILED`}`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => { console.error(e.message ?? e); process.exit(1); });
