/**
 * @unm/plugin-sdk — shared update-gathering primitives (capability 'updates').
 *
 * The Updates page is fed by ONE normalized metric key: plugins emit
 * `metrics['updates']` = UpdateRow[] during their inventory collection. This
 * module provides the row type, robust version comparison (firmware strings
 * are messy — semver, dotted numeric, calver, vendor suffixes), and a
 * package-manager adapter registry for SSH-reachable hosts so every plugin
 * composes its own gather/apply logic on shared primitives instead of
 * re-implementing parsers.
 *
 * Contract:
 *  - `name` is the stable identity of an update within (device, kind) — e.g.
 *    "os" for firmware, a package name, an app name, an image reference.
 *  - `applyActionId` + `applyInput` point at THIS plugin's action catalog:
 *    the webapp fires them through the plan workflow (2FA-gated). Omit both
 *    when there is no safe apply path — the row still shows as available,
 *    just without an Update button.
 */

// ---------------------------------------------------------------------------
// Row contract
// ---------------------------------------------------------------------------

/** Known update kinds; plugins may emit custom strings for future kinds. */
export type UpdateKind = 'firmware' | 'os-package' | 'docker-image' | 'app';

/** One available (or checked) update on one device, as emitted in metrics['updates']. */
export interface UpdateRow {
  /** Stable identity within (device, kind): "os", a package name, app name, image ref. */
  name: string;
  kind: UpdateKind | (string & {});
  currentVersion?: string | null;
  latestVersion?: string | null;
  /** True when an update is actually available (false rows are dropped by the API). */
  available: boolean;
  rebootRequired?: boolean;
  sizeBytes?: number | null;
  /** Catalog action id that applies this row (must exist in THIS plugin's catalog). */
  applyActionId?: string;
  /** Prefilled input for that action. */
  applyInput?: Record<string, unknown>;
  extra?: Record<string, unknown>;
}

// ---------------------------------------------------------------------------
// Version comparison — robust against messy firmware strings
// ---------------------------------------------------------------------------

/** Pre-release markers: a version carrying one is OLDER than the plain release. */
const PRE_RELEASE = /^(rc|beta|alpha|pre|dev|snapshot)/i;

/** Tokenize into runs of digits / letters: "4.30.0434RU7" → ["4","30","0434","RU","7"]. */
function tokenize(v: string): string[] {
  return (v.trim().match(/[0-9]+|[A-Za-z]+/g) ?? []);
}

/**
 * Compare two version strings. Returns -1 / 0 / 1.
 * Handles semver, variable-length dotted numeric ("26.7" < "26.7.1"), calver,
 * and vendor-suffixed builds ("4.30.0434RU7"). Missing trailing segments count
 * as older — except when the extra segment is a pre-release marker (RC/beta/…),
 * which counts as OLDER than the plain release.
 */
export function compareVersions(a: string, b: string): -1 | 0 | 1 {
  const ta = tokenize(a);
  const tb = tokenize(b);
  const len = Math.max(ta.length, tb.length);
  for (let i = 0; i < len; i++) {
    const sa = ta[i];
    const sb = tb[i];
    if (sa === undefined || sb === undefined) {
      // One side has extra segments. A pre-release marker makes it OLDER,
      // any other content makes it NEWER than the shorter string.
      const extra = sa ?? sb;
      const aIsExtra = sa !== undefined;
      if (PRE_RELEASE.test(extra)) return aIsExtra ? -1 : 1;
      return aIsExtra ? 1 : -1;
    }
    const na = /^\d+$/.test(sa) ? Number(sa) : null;
    const nb = /^\d+$/.test(sb) ? Number(sb) : null;
    if (na !== null && nb !== null) {
      if (na !== nb) return na < nb ? -1 : 1;
    } else if (sa.toLowerCase() !== sb.toLowerCase()) {
      return sa.toLowerCase() < sb.toLowerCase() ? -1 : 1;
    }
  }
  return 0;
}

/** True when `latest` is strictly newer than `current`. Missing either side → false. */
export function isUpdateAvailable(current?: string | null, latest?: string | null): boolean {
  if (!current || !latest) return false;
  try {
    return compareVersions(current, latest) < 0;
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// Row helpers
// ---------------------------------------------------------------------------

/** Convenience: a firmware row from current/latest strings (available computed). */
export function firmwareRow(
  currentVersion?: string | null,
  latestVersion?: string | null,
  extra?: { rebootRequired?: boolean; applyActionId?: string; applyInput?: Record<string, unknown>; note?: string },
): UpdateRow {
  return {
    name: 'os',
    kind: 'firmware',
    currentVersion: currentVersion ?? null,
    latestVersion: latestVersion ?? null,
    available: isUpdateAvailable(currentVersion, latestVersion),
    rebootRequired: extra?.rebootRequired ?? true,
    applyActionId: extra?.applyActionId,
    applyInput: extra?.applyInput,
    ...(extra?.note ? { extra: { note: extra.note } } : {}),
  };
}

// ---------------------------------------------------------------------------
// Static-catalog firmware comparison (plugins without a live update feed)
// ---------------------------------------------------------------------------

/**
 * Extracts the leading major.minor from a messy vendor firmware string.
 * Handles "7.14.0036RU1 / 30.07.2026" (LANCOM), "v3.34.0326" (LANCOM SX),
 * "SCALE 25.04.2", plain "2.18" — anything whose first two dotted numbers are
 * the release line. null when no major.minor is present.
 */
export function extractMajorMinor(v?: string | null): string | null {
  const m = (v ?? '').trim().match(/(\d+)\.(\d+)/);
  return m ? `${m[1]}.${m[2]}` : null;
}

/**
 * Picks the NEWEST catalog line strictly newer than the live version's
 * major.minor — or null when the device is already on (or beyond) every known
 * line. Catalog lines are plain "major.minor" strings from a plugin's static
 * device-models catalog; malformed entries are skipped, never thrown.
 */
export function latestCatalogLine(liveVersion: string, lines: readonly string[]): string | null {
  const cur = extractMajorMinor(liveVersion);
  if (!cur) return null;
  let best: string | null = null;
  for (const line of lines) {
    try {
      if (compareVersions(cur, line) < 0 && (best === null || compareVersions(line, best) > 0)) best = line;
    } catch {
      // skip malformed catalog entries
    }
  }
  return best;
}

/**
 * Convenience for plugins whose firmware surface is a STATIC release catalog
 * (no live update feed on the device): builds an available-without-apply
 * firmware row when the live version trails the newest known line, else null.
 * The raw live string rides in currentVersion (display) only — availability is
 * decided by major.minor comparison and FORCED true here: re-comparing the raw
 * strings would misfire on vendor prefixes ("OPNsense 26.4-amd64", "v3.34.0326")
 * whose leading non-numeric token sorts above any digit in compareVersions.
 */
export function catalogFirmwareRow(
  liveVersion: string | null | undefined,
  lines: readonly string[],
  extra?: { rebootRequired?: boolean; note?: string },
): UpdateRow | null {
  if (!liveVersion) return null;
  const latest = latestCatalogLine(liveVersion, lines);
  if (!latest) return null;
  const row = firmwareRow(liveVersion, latest, extra);
  row.available = true; // major.minor comparison already proved live < latest
  return row;
}

// ---------------------------------------------------------------------------
// SSH package-manager adapters (apt / dnf / yum / pacman / apk)
// ---------------------------------------------------------------------------

/** Minimal exec surface — generic-ssh's pooled SshBackend satisfies this directly. */
export interface UpdateExecBackend {
  exec(command: string): Promise<{ code: number; stdout: string; stderr?: string }>;
}

/** One upgradable package as reported by a package manager. */
export interface UpgradablePackage {
  name: string;
  currentVersion: string | null;
  latestVersion: string;
}

/** A package-manager adapter: knows how to detect itself, list upgrades and apply them. */
export interface PmAdapter {
  id: 'apt' | 'dnf' | 'yum' | 'pacman' | 'apk';
  /** os-release ID / ID_LIKE values this manager is expected on. */
  distros: string[];
  /** True when the tooling exists on the host (command probe). */
  detect(backend: UpdateExecBackend): Promise<boolean>;
  /** List upgradable packages; [] when none or unparseable output. */
  listUpgradable(backend: UpdateExecBackend): Promise<UpgradablePackage[]>;
  /** Shell command(s) that upgrade ONE package, or ALL when pkg is omitted. */
  upgrade(pkg?: string): string[];
}

async function commandExists(backend: UpdateExecBackend, cmd: string): Promise<boolean> {
  try {
    const r = await backend.exec(`command -v ${cmd} >/dev/null 2>&1 && echo yes || true`);
    return /yes/.test(r.stdout);
  } catch {
    return false;
  }
}

/** Parse `ID=`/`ID_LIKE=` from os-release output into a lowercase list. */
function parseOsRelease(stdout: string): string[] {
  const ids = new Set<string>();
  for (const line of stdout.split('\n')) {
    const m = line.match(/^(ID|ID_LIKE)=(.*)$/);
    if (!m) continue;
    for (const part of m[2].replace(/"/g, '').split(/\s+/)) {
      if (part) ids.add(part.toLowerCase());
    }
  }
  return [...ids];
}

/** Read /etc/os-release (or /usr/lib/os-release) from the host; [] on failure. */
export async function readOsReleaseIds(backend: UpdateExecBackend): Promise<string[]> {
  try {
    const r = await backend.exec('cat /etc/os-release 2>/dev/null || cat /usr/lib/os-release 2>/dev/null || true');
    return parseOsRelease(r.stdout);
  } catch {
    return [];
  }
}

const APT_DISTROS = ['debian', 'ubuntu', 'raspbian', 'kali', 'linuxmint', 'pop', 'elementary', 'deepin', 'neon'];
const DNF_DISTROS = ['fedora', 'rhel', 'centos', 'rocky', 'almalinux', 'amzn', 'ol', 'photon', 'openeuler'];

export const PACKAGE_MANAGER_ADAPTERS: PmAdapter[] = [
  {
    id: 'apt',
    distros: APT_DISTROS,
    detect: (b) => commandExists(b, 'apt-get'),
    listUpgradable: async (b) => {
      // "pkg/release 1.2.3 amd64 [upgradable from: 1.0.0]"
      const r = await b.exec('DEBIAN_FRONTEND=noninteractive apt list --upgradable 2>/dev/null || true');
      const out: UpgradablePackage[] = [];
      for (const line of r.stdout.split('\n')) {
        const m = line.match(/^([^\s/]+)\/[^\s]+\s+([\w.:+~-]+)\s+\S+\s+\[upgradable from:\s*([\w.:+~-]+)\]/);
        if (m && !line.startsWith('Listing...')) out.push({ name: m[1], currentVersion: m[3], latestVersion: m[2] });
      }
      return out;
    },
    upgrade: (pkg) => [
      'export DEBIAN_FRONTEND=noninteractive',
      pkg ? `apt-get install --only-upgrade -y ${pkg}` : 'apt-get upgrade -y',
    ],
  },
  {
    id: 'dnf',
    distros: DNF_DISTROS,
    detect: (b) => commandExists(b, 'dnf'),
    listUpgradable: async (b) => {
      // "name.arch version repo" — exit code 100 means updates exist.
      const r = await b.exec('dnf -q check-update 2>/dev/null || true');
      const out: UpgradablePackage[] = [];
      for (const line of r.stdout.split('\n')) {
        const m = line.match(/^([A-Za-z0-9._+-]+)\.(x86_64|noarch|i[35]86|aarch64|s390x|ppc64le|riscv64)\s+([\w.:+~-]+)\s+\S+/);
        if (m) out.push({ name: m[1], currentVersion: null, latestVersion: m[3] });
      }
      return out;
    },
    upgrade: (pkg) => [pkg ? `dnf -y upgrade ${pkg}` : 'dnf -y upgrade'],
  },
  {
    id: 'yum',
    distros: DNF_DISTROS,
    detect: async (b) => (await commandExists(b, 'dnf')) ? false : commandExists(b, 'yum'),
    listUpgradable: async (b) => {
      const r = await b.exec('yum -q check-update 2>/dev/null || true');
      const out: UpgradablePackage[] = [];
      for (const line of r.stdout.split('\n')) {
        // Newer yum: "name.arch version repo"; older: "name arch current -> latest"
        let m = line.match(/^([A-Za-z0-9._+-]+)\.(x86_64|noarch|i[35]86|aarch64|s390x|ppc64le)\s+([\w.:+~-]+)\s+\S+/);
        if (m) { out.push({ name: m[1], currentVersion: null, latestVersion: m[3] }); continue; }
        m = line.match(/^([A-Za-z0-9._+-]+)\s+(x86_64|noarch|i[35]86|aarch64)\s+[\w.:+~-]+\s*->\s*([\w.:+~-]+)/);
        if (m) out.push({ name: m[1], currentVersion: null, latestVersion: m[3] });
      }
      return out;
    },
    upgrade: (pkg) => [pkg ? `yum -y update ${pkg}` : 'yum -y update'],
  },
  {
    id: 'pacman',
    distros: ['arch', 'manjaro', 'endeavouros', 'archarm'],
    detect: (b) => commandExists(b, 'pacman'),
    listUpgradable: async (b) => {
      // "name version"
      const r = await b.exec('pacman -Qu 2>/dev/null || true');
      const out: UpgradablePackage[] = [];
      for (const line of r.stdout.split('\n')) {
        const m = line.match(/^([\w][\w.+-]*?)\s+([\w.:+~-]+)\s*$/);
        if (m) out.push({ name: m[1], currentVersion: null, latestVersion: m[2] });
      }
      return out;
    },
    upgrade: (pkg) => [pkg ? `pacman -Sy --noconfirm ${pkg}` : 'pacman -Syu --noconfirm'],
  },
  {
    id: 'apk',
    distros: ['alpine'],
    detect: (b) => commandExists(b, 'apk'),
    listUpgradable: async (b) => {
      // "name-1.30-r2 < 1.31-r0"
      const r = await b.exec("apk version -l '<' 2>/dev/null || true");
      const out: UpgradablePackage[] = [];
      for (const line of r.stdout.split('\n')) {
        const m = line.match(/^([\w][\w.+-]*?)-([\w.+:-]+)\s+<\s+([\w.+:-]+)/);
        if (m) out.push({ name: m[1], currentVersion: m[2], latestVersion: m[3] });
      }
      return out;
    },
    upgrade: (pkg) => [pkg ? `apk upgrade ${pkg}` : 'apk upgrade'],
  },
];

/**
 * Pick the adapter for this host: os-release ID/ID_LIKE match first, then a
 * command probe in registry order. Null when nothing is recognized (e.g. NixOS).
 */
export async function detectPackageManager(backend: UpdateExecBackend): Promise<PmAdapter | null> {
  const ids = await readOsReleaseIds(backend);
  if (ids.length > 0) {
    for (const adapter of PACKAGE_MANAGER_ADAPTERS) {
      if (adapter.distros.some((d) => ids.includes(d))) return adapter;
    }
  }
  for (const adapter of PACKAGE_MANAGER_ADAPTERS) {
    if (await adapter.detect(backend)) return adapter;
  }
  return null;
}

export interface SshUpdatesOptions {
  /** Catalog action id applied per package row (omit → rows without Update button). */
  applyActionId?: string;
  /** When set, each row's applyInput is `{ package: <name> }`. */
  perPackageApply?: boolean;
}

/** Result of an upgrade run. */
export interface PackageUpgradeResult {
  ok: boolean;
  stdout: string;
  stderr: string;
  /** The detected manager id (null when none was found). */
  pm: string | null;
}

/**
 * Apply a package upgrade over SSH: detect the manager, run its upgrade command
 * for one package (or all), and report success. Long-running — callers should
 * give it a generous timeout. Never throws; failures come back as ok:false.
 */
export async function runPackageUpgrade(backend: UpdateExecBackend, pkg?: string): Promise<PackageUpgradeResult> {
  const adapter = await detectPackageManager(backend);
  if (!adapter) return { ok: false, stdout: '', stderr: 'No known package manager detected on this host', pm: null };
  const script = ['set -e', ...adapter.upgrade(pkg)].join('\n');
  try {
    const r = await backend.exec(script);
    return { ok: r.code === 0, stdout: r.stdout, stderr: r.stderr ?? '', pm: adapter.id };
  } catch (err) {
    return { ok: false, stdout: '', stderr: (err as Error).message, pm: adapter.id };
  }
}

/**
 * One-call gather for SSH hosts: detect the package manager and return one
 * UpdateRow per upgradable package (kind 'os-package'). Returns [] when no
 * known PM exists or nothing is upgradable — callers should treat that as a
 * normal empty result, not an error.
 */
export async function listUpgradablePackages(backend: UpdateExecBackend, opts?: SshUpdatesOptions): Promise<UpdateRow[]> {
  const adapter = await detectPackageManager(backend);
  if (!adapter) return [];
  let pkgs: UpgradablePackage[];
  try {
    pkgs = await adapter.listUpgradable(backend);
  } catch {
    return [];
  }
  return pkgs.map((p) => ({
    name: p.name,
    kind: 'os-package' as const,
    currentVersion: p.currentVersion ?? null,
    latestVersion: p.latestVersion,
    available: true,
    rebootRequired: false,
    ...(opts?.applyActionId ? { applyActionId: opts.applyActionId } : {}),
    ...(opts?.applyActionId && opts.perPackageApply !== false ? { applyInput: { package: p.name } } : {}),
    extra: { pm: adapter.id },
  }));
}
