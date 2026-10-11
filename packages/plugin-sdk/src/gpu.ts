/**
 * Shared GPU detection + live-metrics collection for UNM plugins.
 *
 * The ONE place that knows how to enumerate GPUs over a POSIX shell and read
 * vendor live counters, so every plugin (generic-ssh, ix-truenas, docker) emits
 * the SAME `gpus[]` metric contract:
 *
 *   gpus[] { name, vendor?, slot, driver?, driverVersion?, vramBytes?,
 *            utilPercent?, memUtilPercent?, tempCelsius?, powerWatts?,
 *            coreClockMhz?, maxCoreClockMhz?, extra? }
 *
 * Detection is PCI-based and VENDOR-NEUTRAL — it catches NVIDIA, AMD and Intel
 * (incl. enabled iGPUs) alike:
 *   - inventory: /sys/bus/pci/devices class 0x03 (Display controller), which the
 *     kernel exposes for every GPU regardless of vendor or driver state;
 *   - live metrics: `nvidia-smi --query-gpu` (NVIDIA — full counters) and
 *     `rocm-smi` (AMD — best effort); Intel iGPUs have no standard CLI, so they
 *     get inventory + driver info only.
 *
 * Everything is best-effort: a host without GPUs yields an EMPTY array
 * (authoritative wipe at ingest), a missing vendor tool degrades to the sysfs
 * fields, and a failed exec resolves to null (caller omits the key — no wipe).
 */

import type { ExecResult } from './ssh';

/** One GPU row → `metrics['gpus']` (mirrors api/src/db/schema.ts `gpus`). */
export interface GpuRow {
  /** Human-readable card name; falls back to the PCI slot when unknown. */
  name: string;
  /** NVIDIA | AMD | INTEL | UNKNOWN — vendor family, uppercase. */
  vendor?: string;
  /** PCI address (e.g. "0000:41:00.0") — the stable identity + PK part. */
  slot: string;
  /** Kernel driver bound to the device (nvidia, amdgpu, i915, xe, ...). */
  driver?: string | null;
  /** Driver version when the vendor tool reports one (e.g. "550.90.07"). */
  driverVersion?: string | null;
  /** Total VRAM in bytes (null = unknown / no dedicated memory). */
  vramBytes?: number | null;
  /** GPU core utilization % (null when the vendor tool is unavailable). */
  utilPercent?: number | null;
  /** VRAM utilization % (NVIDIA only; AMD/Intel expose no equivalent). */
  memUtilPercent?: number | null;
  /** Temperature in °C. */
  tempCelsius?: number | null;
  /** Power draw in watts. */
  powerWatts?: number | null;
  /** Current core clock in MHz (null = not reported / iGPU). */
  coreClockMhz?: number | null;
  /** Max supported core clock in MHz. */
  maxCoreClockMhz?: number | null;
  /** Plugin-specific details stored verbatim (e.g. TrueNAS available_to_host). */
  extra?: Record<string, unknown>;
}

/** Minimal exec surface — satisfied by generic-ssh's ElevatedBackend and the
 * SDK's SshClient alike, so plugins don't need to adapt their backends. */
export interface GpuExecBackend {
  exec(command: string, timeoutMs?: number): Promise<ExecResult>;
}

// --- Vendor detection -----------------------------------------------------------

/** PCI vendor IDs for the three GPU families (subset — enough for detection). */
const NVIDIA_VENDOR_ID = '10de';
const AMD_VENDOR_IDS = new Set(['1002']); // ATI/AMD
const INTEL_VENDOR_ID = '8086';

/** Well-known discrete-GPU PCI device IDs → marketing name. A small, curated
 * subset: the sysfs/lspci description is preferred when available; this table
 * only fills gaps (e.g. nvidia-smi absent but the card is present). */
const KNOWN_GPU_NAMES: Record<string, string> = {
  // NVIDIA — datacenter + common consumer
  '10de:26ba': 'NVIDIA A100',
  '10de:20b3': 'NVIDIA A100 (SXM4)',
  '10de:20f3': 'NVIDIA H100 (SXM5)',
  '10de:2329': 'NVIDIA H100 (PCIe)',
  '10de:2204': 'NVIDIA A10',
  '10de:2216': 'NVIDIA T4',
  '10de:1eb8': 'NVIDIA Tesla V100',
  '10de:1b06': 'NVIDIA GeForce RTX 3090',
  '10de:2206': 'NVIDIA GeForce RTX 3080',
  '10de:2480': 'NVIDIA GeForce RTX 4090',
  '10de:2684': 'NVIDIA GeForce RTX 4070 Ti Super',
  // AMD — common consumer/datacenter
  '1002:73bf': 'AMD Radeon RX 6800 XT',
  '1002:73bc': 'AMD Radeon RX 6800',
  '1002:73c0': 'AMD Radeon RX 6900 XT',
  '1002:744c': 'AMD Radeon Pro W6800',
};

/** Resolves the vendor family from a PCI vendor ID + bound driver name. */
export function detectGpuVendor(pciVendorId?: string | null, driver?: string | null): string {
  const vid = (pciVendorId ?? '').toLowerCase();
  const drv = (driver ?? '').toLowerCase();
  if (vid === NVIDIA_VENDOR_ID || drv.startsWith('nvidia')) return 'NVIDIA';
  if (AMD_VENDOR_IDS.has(vid) || drv === 'amdgpu' || drv === 'radeon') return 'AMD';
  if (vid === INTEL_VENDOR_ID || drv === 'i915' || drv === 'xe') return 'INTEL';
  return 'UNKNOWN';
}

/** Best-effort marketing name from a PCI id, falling back to the vendor family. */
export function gpuNameFromPci(pciVendorId?: string | null, pciDeviceId?: string | null): string {
  const key = `${(pciVendorId ?? '').toLowerCase()}:${(pciDeviceId ?? '').toLowerCase()}`;
  return KNOWN_GPU_NAMES[key] ?? '';
}

// --- PCI enumeration (sysfs) ----------------------------------------------------

/** One raw PCI display-controller entry from the shell probe. */
export interface PciGpuEntry {
  slot: string; // e.g. "0000:41:00.0"
  vendorId: string; // hex, lowercase
  deviceId: string; // hex, lowercase
  driver: string | null;
  driverVersion: string | null;
}

/** Parses the `UNM_GPU_PCI` section of buildGpuProbeScript's output into raw
 * PCI entries. Tolerant of missing/malformed lines (defensive reads). */
export function parsePciGpuSection(raw: string): PciGpuEntry[] {
  const out: PciGpuEntry[] = [];
  for (const line of raw.split('\n')) {
    const parts = line.trim().split('|');
    if (parts.length < 3) continue;
    const [slot, vendorId, deviceId] = parts.map((p) => p.trim());
    if (!/^[0-9a-f]{4}:[0-9a-f]{2}:[0-9a-f]{2}\.[0-7]$/.test(slot)) continue;
    out.push({
      slot,
      vendorId: (vendorId || '').toLowerCase(),
      deviceId: (deviceId || '').toLowerCase(),
      driver: parts[3] && parts[3].trim() !== '' ? parts[3].trim() : null,
      driverVersion: parts[4] && parts[4].trim() !== '' ? parts[4].trim() : null,
    });
  }
  return out;
}

// --- nvidia-smi parsing ---------------------------------------------------------

/** Normalizes an nvidia-smi PCI bus id ("00000000:41:00.0" or "41:00.0") to the
 * sysfs slot form ("0000:41:00.0"). */
export function normalizeNvidiaSlot(busId: string): string {
  const s = busId.trim().toLowerCase();
  // Short form "41:00.0" (some nvidia-smi builds / --query-gpu=pci.bus_id).
  if (/^[0-9a-f]{2}:[0-9a-f]{2}\.[0-7]$/.test(s)) return `0000:${s}`;
  // Full form "domain:bus.device.fn" — nvidia-smi's default pads the domain to
  // EIGHT hex digits ("00000000:41:00.0"); sysfs uses four ("0000:41:00.0").
  // Take the LAST FOUR domain digits so both collapse onto the same key (and a
  // non-zero multi-domain system keeps its real domain).
  const m = s.match(/^([0-9a-f]{1,8}):([0-9a-f]{2}):([0-9a-f]{2})\.([0-7])$/);
  if (m) return `${m[1].slice(-4)}:${m[2]}:${m[3]}.${m[4]}`;
  return s;
}

/** Parses `nvidia-smi --query-gpu=... --format=csv,noheader,nounits` output into
 * a map keyed by normalized PCI slot. Field order MUST match buildGpuProbeScript. */
/** One nvidia-smi card's parsed fields (null = not reported / [N/A]). */
export interface NvidiaSmiFields {
  name: string;
  driverVersion: string;
  vramTotalMiB: number | null;
  memUsedMiB: number | null;
  utilPercent: number | null;
  memUtilPercent: number | null;
  tempCelsius: number | null;
  powerWatts: number | null;
  coreClockMhz: number | null;
  maxCoreClockMhz: number | null;
}

export function parseNvidiaSmiSection(raw: string): Map<string, NvidiaSmiFields> {
  const out = new Map<string, NvidiaSmiFields>();
  for (const line of raw.split('\n')) {
    if (!line.trim()) continue;
    // CSV with noheader,nounits — split on commas. Names may contain commas in
    // theory but nvidia-smi does not quote them; a defensive max-split keeps the
    // trailing numeric fields intact even for odd names.
    const parts = line.split(',').map((p) => p.trim());
    if (parts.length < 10) continue;
    const slot = normalizeNvidiaSlot(parts[0]);
    const num = (s: string): number | null => {
      if (!s || s === '[N/A]' || s.toLowerCase() === 'n/a') return null;
      const n = Number(s);
      return Number.isFinite(n) ? n : null;
    };
    out.set(slot, {
      name: parts[1] && parts[1] !== '[N/A]' ? parts[1] : '',
      driverVersion: parts[2] && parts[2] !== '[N/A]' ? parts[2] : '',
      vramTotalMiB: num(parts[3]),
      memUsedMiB: num(parts[4]),
      utilPercent: num(parts[5]),
      memUtilPercent: num(parts[6]),
      tempCelsius: num(parts[7]),
      powerWatts: num(parts[8]),
      coreClockMhz: num(parts[9]),
      maxCoreClockMhz: num(parts[10] ?? ''),
    });
  }
  return out;
}

// --- rocm-smi parsing (AMD, best effort) ----------------------------------------

/** Parses `rocm-smi --showproductname` output into an ordered list of AMD card
 * names. The order matches the kernel's PCI enumeration order (same as sysfs),
 * which callers use to map back onto slots when no explicit slot is present. */
export function parseRocmProductNames(raw: string): string[] {
  const out: string[] = [];
  for (const line of raw.split('\n')) {
    // Lines look like "Card 0: Radeon RX 6800" or a bare name; capture after the colon.
    const m = line.match(/:\s*(.+)$/);
    if (m && m[1].trim() !== '') out.push(m[1].trim());
  }
  return out;
}

/** Parses `rocm-smi --showuse` output into an ordered list of GPU utilization %
 * values. Best effort — rocm-smi's format varies across ROCm versions, so a
 * missing/odd line simply yields no value for that card. */
export function parseRocmUseSection(raw: string): (number | null)[] {
  const out: (number | null)[] = [];
  for (const line of raw.split('\n')) {
    // Look for a "GPU use" percentage; tolerate "GPU use (%) : 42" or bare numbers.
    const m = line.match(/(\d{1,3})\s*%/);
    if (m) out.push(Number(m[1]));
  }
  return out;
}

// --- The combined shell probe ---------------------------------------------------

/** Builds ONE shell script that gathers everything collectGpuRows needs in a
 * single exec round-trip: PCI display-controller enumeration + nvidia-smi CSV +
 * rocm-smi product names. Section markers are parsed by the parse* helpers. */
export function buildGpuProbeScript(): string {
  return [
    'echo "UNM_GPU_PCI:BEGIN"',
    'for d in /sys/bus/pci/devices/*; do',
    '  c=$(cat "$d/class" 2>/dev/null) || continue;',
    '  case "$c" in 0x03*) ;; *) continue;; esac;',
    '  v=$(cat "$d/vendor" 2>/dev/null); dev=$(cat "$d/device" 2>/dev/null);',
    '  drv=""; if [ -e "$d/driver" ]; then drv=$(basename "$(readlink -f "$d/driver")" 2>/dev/null); fi;',
    '  dv=""; if [ -n "$drv" ] && [ -r "/sys/module/$drv/version" ]; then dv=$(cat "/sys/module/$drv/version" 2>/dev/null); fi;',
    '  echo "$(basename "$d")|$v|$dev|${drv:-}|${dv:-}";',
    'done',
    'echo "UNM_GPU_PCI:END"',
    'if command -v nvidia-smi >/dev/null 2>&1; then',
    '  echo "UNM_GPU_NVIDIA:BEGIN"',
    '  nvidia-smi --query-gpu=pci.bus_id,name,driver_version,memory.total,memory.used,utilization.gpu,utilization.memory,temperature.gpu,power.draw,clocks.current.graphics,clocks.max.graphics --format=csv,noheader,nounits 2>/dev/null || true',
    '  echo "UNM_GPU_NVIDIA:END"',
    'fi',
    'if command -v rocm-smi >/dev/null 2>&1; then',
    '  echo "UNM_GPU_ROCM_NAME:BEGIN"',
    '  rocm-smi --showproductname 2>/dev/null || true',
    '  echo "UNM_GPU_ROCM_NAME:END"',
    'fi',
  ].join('\n');
}

/** Extracts one marked section's body from a probe script's stdout. */
function extractSection(stdout: string, marker: string): string {
  const begin = `UNM_GPU_${marker}:BEGIN`;
  const end = `UNM_GPU_${marker}:END`;
  const b = stdout.indexOf(begin);
  if (b < 0) return '';
  const start = b + begin.length;
  const e = stdout.indexOf(end, start);
  return e > start ? stdout.slice(start, e) : stdout.slice(start);
}

// --- Main entry point -----------------------------------------------------------

/** Collects GPU rows for one host over a single exec round-trip. Returns:
 *   - an array (possibly EMPTY — authoritative "no GPUs") on success;
 *   - null when the exec itself failed (caller must omit the `gpus` key so no
 *     wipe happens, per the ingestion contract).
 * Live counters are merged by PCI slot from nvidia-smi / rocm-smi when present. */
export async function collectGpuRows(backend: GpuExecBackend): Promise<GpuRow[] | null> {
  let r: ExecResult;
  try {
    r = await backend.exec(buildGpuProbeScript(), 20_000);
  } catch {
    return null; // transport failure — no wipe
  }
  if (!r || typeof r.stdout !== 'string') return null;

  const pciEntries = parsePciGpuSection(extractSection(r.stdout, 'PCI'));
  const nvidia = parseNvidiaSmiSection(extractSection(r.stdout, 'NVIDIA'));
  const rocmNames = parseRocmProductNames(extractSection(r.stdout, 'ROCM_NAME'));

  // Map AMD slots (in sysfs enumeration order) onto rocm-smi's ordered names.
  const amdSlots = pciEntries.filter((e) => detectGpuVendor(e.vendorId, e.driver) === 'AMD').map((e) => e.slot);
  const rocmNameBySlot = new Map<string, string>();
  amdSlots.forEach((slot, i) => {
    if (rocmNames[i]) rocmNameBySlot.set(slot, rocmNames[i]);
  });

  const rows: GpuRow[] = [];
  for (const e of pciEntries) {
    const vendor = detectGpuVendor(e.vendorId, e.driver);
    const nv = nvidia.get(e.slot);
    // Name priority: nvidia-smi's marketing name > rocm-smi product name >
    // curated PCI table > driver+vendor fallback.
    let name = '';
    if (nv && typeof nv.name === 'string' && nv.name !== '') name = nv.name;
    else {
      const rocmName = rocmNameBySlot.get(e.slot);
      if (rocmName) name = rocmName;
      else {
        const fromPci = gpuNameFromPci(e.vendorId, e.deviceId);
        name = fromPci !== '' ? fromPci : `${vendor} GPU (${e.slot})`;
      }
    }

    const row: GpuRow = {
      name,
      vendor,
      slot: e.slot,
      driver: e.driver ?? null,
      // Driver version: nvidia-smi's is authoritative for NVIDIA; sysfs module
      // version covers amdgpu/i915/xe when present.
      driverVersion: (nv && typeof nv.driverVersion === 'string' && nv.driverVersion !== '') ? nv.driverVersion : e.driverVersion,
    };

    if (nv) {
      const vramTotalMiB = typeof nv.vramTotalMiB === 'number' ? nv.vramTotalMiB : null;
      if (vramTotalMiB !== null && vramTotalMiB > 0) row.vramBytes = Math.round(vramTotalMiB * 1024 * 1024);
      const util = typeof nv.utilPercent === 'number' ? nv.utilPercent : null;
      if (util !== null) row.utilPercent = Math.max(0, Math.min(100, Math.trunc(util)));
      const memUtil = typeof nv.memUtilPercent === 'number' ? nv.memUtilPercent : null;
      if (memUtil !== null) row.memUtilPercent = Math.max(0, Math.min(100, Math.trunc(memUtil)));
      const temp = typeof nv.tempCelsius === 'number' ? nv.tempCelsius : null;
      if (temp !== null) row.tempCelsius = Math.trunc(temp);
      const power = typeof nv.powerWatts === 'number' ? nv.powerWatts : null;
      if (power !== null && power > 0) row.powerWatts = Math.round(power * 100) / 100;
      const clock = typeof nv.coreClockMhz === 'number' ? nv.coreClockMhz : null;
      if (clock !== null) row.coreClockMhz = Math.trunc(clock);
      const maxClock = typeof nv.maxCoreClockMhz === 'number' ? nv.maxCoreClockMhz : null;
      if (maxClock !== null) row.maxCoreClockMhz = Math.trunc(maxClock);
    }

    rows.push(row);
  }
  return rows;
}
