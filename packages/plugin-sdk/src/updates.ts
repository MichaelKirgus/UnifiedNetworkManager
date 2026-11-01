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
  /** URL where the admin can read the release notes for this update (vendor
   * changelog page, appliance docs anchor, ...). Shown as a link on the Updates page. */
  releaseNotesUrl?: string | null;
  /** Release-notes TEXT propagated directly from the device's own update feed
   * (e.g. TrueNAS `update.available_versions` carries per-release notes that its
   * web UI also shows). Rendered inline on the Updates page when present; keep
   * it short — plugins should truncate to a few KB at most. */
  releaseNotes?: string | null;
  /** The device's CURRENT update branch / channel (e.g. TrueNAS update profile
   * "GENERAL", distro codename, vendor firmware line). Shown in the Updates
   * page's Branch column so an admin can see WHICH track a row belongs to —
   * useful when a box sits on a beta/early-adopter branch and its "new version"
   * is not what a stable-track peer would get. Generic: any plugin may fill it. */
  branch?: string | null;
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
  extra?: {
    rebootRequired?: boolean;
    applyActionId?: string;
    applyInput?: Record<string, unknown>;
    note?: string;
    /** Vendor release-notes URL for the target version (shown as a link). */
    releaseNotesUrl?: string | null;
    /** Release-notes text from the device's own update feed (rendered inline). */
    releaseNotes?: string | null;
    /** The device's current update branch/channel (Updates page Branch column). */
    branch?: string | null;
  },
): UpdateRow {
  return {
    name: 'os',
    kind: 'firmware',
    currentVersion: currentVersion ?? null,
    latestVersion: latestVersion ?? null,
    available: isUpdateAvailable(currentVersion, latestVersion),
    rebootRequired: extra?.rebootRequired ?? true,
    releaseNotesUrl: extra?.releaseNotesUrl ?? null,
    releaseNotes: extra?.releaseNotes ?? null,
    branch: extra?.branch ?? null,
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
/**
 * Release-notes URL for a static-catalog firmware row. Either a fixed string,
 * or a builder that receives the SELECTED target line ("major.minor") so the
 * link points at the NEW version's notes, not the live one.
 */
export type FirmwareReleaseNotesUrl = string | null | ((targetLine: string) => string);

export function catalogFirmwareRow(
  liveVersion: string | null | undefined,
  lines: readonly string[],
  extra?: {
    rebootRequired?: boolean;
    note?: string;
    /** Vendor release-notes URL for the target version (shown as a link). */
    releaseNotesUrl?: FirmwareReleaseNotesUrl;
    /** Release-notes text from the device's own update feed (rendered inline). */
    releaseNotes?: string | null;
    /** The device's current update branch/channel (Updates page Branch column). */
    branch?: string | null;
  },
): UpdateRow | null {
  if (!liveVersion) return null;
  const latest = latestCatalogLine(liveVersion, lines);
  if (!latest) return null;
  const notesUrl = typeof extra?.releaseNotesUrl === 'function' ? extra.releaseNotesUrl(latest) : (extra?.releaseNotesUrl ?? null);
  const row = firmwareRow(liveVersion, latest, { ...extra, releaseNotesUrl: notesUrl });
  row.available = true; // major.minor comparison already proved live < latest
  return row;
}

// ---------------------------------------------------------------------------
// SSH package-manager adapters (apt / dnf / yum / pacman / apk)
// ---------------------------------------------------------------------------

/** Minimal exec surface — generic-ssh's pooled SshBackend satisfies this directly.
 *  `timeoutMs` is optional so backends without a timeout concept keep working. */
export interface UpdateExecBackend {
  exec(command: string, timeoutMs?: number): Promise<{ code: number; stdout: string; stderr?: string }>;
}

/** One upgradable package as reported by a package manager. */
export interface UpgradablePackage {
  name: string;
  currentVersion: string | null;
  latestVersion: string;
  /** True when the admin explicitly held this package (e.g. `apt-mark hold`) —
   *  bulk upgrades will NEVER install it, so it stays "upgradable" forever and
   *  must not count against post-upgrade verification. */
  held?: boolean;
  /** apt: deferred by Ubuntu's phased rollout ("deferred due to phasing") — the
   *  host is not in this version's cohort yet; `upgrade` skips it on purpose. */
  phased?: boolean;
  /** apt: dependency-kept-back (e.g. a held dependency) — `upgrade` cannot
   *  install it without also upgrading something else that is blocked. */
  keptBack?: boolean;
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
  /** Shell command(s) that upgrade EXACTLY the given packages in one invocation
   *  (one lock acquisition). Optional — managers without a clean multi-form fall
   *  back to per-package runs. Used by "update only these" bulk actions. */
  upgradeMany?(pkgs: string[]): string[];
  /** Shell command(s) for a DISTRO-LEVEL upgrade that may add/remove packages to
   *  resolve dependencies (apt `dist-upgrade`). Null when the manager has no
   *  meaningful distinction from a plain full `upgrade` (dnf/yum/pacman/apk's
   *  bulk update already resolves deps). */
  distUpgrade?(): string[] | null;
  /** Shell command(s) that HOLD one package against upgrades. Optional — only
   *  managers with an explicit hold concept implement it (apt `apt-mark hold`,
   *  dnf `dnf version lock add`). Omitted → the plugin reports "not supported". */
  holdPackage?(pkg: string): string[];
  /** Shell command(s) that release a previously held package. Optional, same
   *  availability as {@link holdPackage}. */
  unholdPackage?(pkg: string): string[];
  /** List the names of all currently held packages (one per line in stdout).
   *  Optional, same availability as {@link holdPackage}. */
  listHeld?(): string;
  /** Shell command(s) that upgrade ALL upgradable packages INCLUDING held and
   *  kept-back ones. Optional — apt: `dist-upgrade -y --allow-change-held-packages`
   *  (upgrades in place, keeps the hold flag set afterwards). Omitted → no force
   *  path for this manager. */
  upgradeForceAll?(): string[];
}

/** Runs a single-line command and returns its trimmed stdout lines (no empty). */
async function execLines(backend: UpdateExecBackend, cmd: string): Promise<string[]> {
  const r = await backend.exec(cmd);
  return r.stdout.split('\n').map((l) => l.trim()).filter(Boolean);
}

/** Holds the given packages on the host (one command per package — holds are a
 *  rare admin action, round-trips don't matter). Returns the manager id or null. */
export async function holdPackages(backend: UpdateExecBackend, pkgs: string[]): Promise<{ ok: boolean; pm: string | null; error?: string }> {
  const adapter = await detectPackageManager(backend);
  if (!adapter) return { ok: false, pm: null, error: 'No known package manager detected on this host' };
  if (!adapter.holdPackage) return { ok: false, pm: adapter.id, error: `Package holding is not supported by ${adapter.id}` };
  for (const p of pkgs) {
    try {
      const r = await backend.exec(['set -e', ...adapter.holdPackage(p)].join('\n'));
      if (r.code !== 0) return { ok: false, pm: adapter.id, error: `Holding ${p} failed: ${(r.stderr || r.stdout).slice(-300)}` };
    } catch (err) {
      return { ok: false, pm: adapter.id, error: `Holding ${p} failed: ${(err as Error).message}` };
    }
  }
  return { ok: true, pm: adapter.id };
}

/** Releases the given packages from a hold. Same contract as {@link holdPackages}. */
export async function unholdPackages(backend: UpdateExecBackend, pkgs: string[]): Promise<{ ok: boolean; pm: string | null; error?: string }> {
  const adapter = await detectPackageManager(backend);
  if (!adapter) return { ok: false, pm: null, error: 'No known package manager detected on this host' };
  if (!adapter.unholdPackage) return { ok: false, pm: adapter.id, error: `Releasing holds is not supported by ${adapter.id}` };
  for (const p of pkgs) {
    try {
      const r = await backend.exec(['set -e', ...adapter.unholdPackage(p)].join('\n'));
      if (r.code !== 0) return { ok: false, pm: adapter.id, error: `Releasing ${p} failed: ${(r.stderr || r.stdout).slice(-300)}` };
    } catch (err) {
      return { ok: false, pm: adapter.id, error: `Releasing ${p} failed: ${(err as Error).message}` };
    }
  }
  return { ok: true, pm: adapter.id };
}

/** Lists the names of all currently held packages; [] when unsupported or none. */
export async function listHeldPackages(backend: UpdateExecBackend): Promise<{ pm: string | null; supported: boolean; held: string[] }> {
  const adapter = await detectPackageManager(backend);
  if (!adapter) return { pm: null, supported: false, held: [] };
  if (!adapter.listHeld) return { pm: adapter.id, supported: false, held: [] };
  try {
    return { pm: adapter.id, supported: true, held: await execLines(backend, adapter.listHeld()) };
  } catch {
    return { pm: adapter.id, supported: true, held: [] };
  }
}

/** Upgrades ALL upgradable packages including held/kept-back ones. Returns the
 *  same result shape as {@link runPackageUpgrade}. */
export async function runForceFullUpgrade(backend: UpdateExecBackend, timeoutMs = DEFAULT_UPGRADE_TIMEOUT_MS): Promise<PackageUpgradeResult> {
  const adapter = await detectPackageManager(backend);
  if (!adapter) return { ok: false, stdout: '', stderr: 'No known package manager detected on this host', pm: null };
  if (!adapter.upgradeForceAll) return { ok: false, stdout: '', stderr: `Forcing held packages is not supported by ${adapter.id}`, pm: adapter.id };
  const script = ['set -e', ...adapter.upgradeForceAll()].join('\n');
  try {
    const r = await backend.exec(script, timeoutMs);
    return { ok: r.code === 0, stdout: r.stdout, stderr: r.stderr ?? '', pm: adapter.id };
  } catch (err) {
    return { ok: false, stdout: '', stderr: (err as Error).message, pm: adapter.id };
  }
}

/**
 * Heuristic: does upgrading this package require a reboot to take effect?
 * Kernel images/modules/headers, firmware and initramfs are the classic cases —
 * everything else (userspace libraries, daemons) restarts in place. Used to set
 * UpdateRow.rebootRequired so "update without reboot" bulk actions can skip them.
 */
export function packageRequiresReboot(name: string): boolean {
  return /(^|[\/-])(linux-(image|modules|headers|firmware)|kernel|initramfs)/i.test(name);
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
      // One round-trip: held list + upgradable table + a dry-run simulation.
      // The sim tells us which of those apt will SKIP on purpose — phased-rollout
      // deferrals and kept-back packages stay "upgradable" forever, so callers
      // must be able to tell them apart from genuinely installable updates.
      const r = await b.exec(
        [
          'echo UNM_HELD_BEGIN; apt-mark showhold 2>/dev/null || true; echo UNM_HELD_END',
          'DEBIAN_FRONTEND=noninteractive apt list --upgradable 2>/dev/null || true',
          'echo UNM_SIM_BEGIN; DEBIAN_FRONTEND=noninteractive apt-get -s upgrade 2>&1 | grep -A30 -E "deferred due to phasing|kept back" || true; echo UNM_SIM_END',
        ].join('; ')
      );
      const held = new Set<string>();
      const phased = new Set<string>();
      const keptBack = new Set<string>();
      let section: 'held' | 'phased' | 'keptBack' | null = null;
      const out: UpgradablePackage[] = [];
      for (const line of r.stdout.split('\n')) {
        if (line === 'UNM_HELD_BEGIN') { section = 'held'; continue; }
        if (line === 'UNM_HELD_END') { section = null; continue; }
        if (line === 'UNM_SIM_BEGIN') { section = null; continue; }
        if (line === 'UNM_SIM_END') { section = null; continue; }
        if (section === 'held') { const t = line.trim(); if (t) held.add(t); continue; }
        // Simulation sections: header line, then indented space-separated names.
        if (/deferred due to phasing/i.test(line)) { section = 'phased'; continue; }
        if (/kept back/i.test(line)) { section = 'keptBack'; continue; }
        const t = line.trim();
        if (section === 'phased' || section === 'keptBack') {
          // Any other header/summary line ends the package list.
          if (!t || /^The following|^\d+ upgraded/i.test(t)) { section = null; continue; }
          for (const tok of t.split(/\s+/)) (section === 'phased' ? phased : keptBack).add(tok);
          continue;
        }
        // "pkg/release 1.2.3 amd64 [upgradable from: 1.0.0]"
        const m = line.match(/^([^\s/]+)\/[^\s]+\s+([\w.:+~-]+)\s+\S+\s+\[upgradable from:\s*([\w.:+~-]+)\]/);
        if (m && !line.startsWith('Listing...')) out.push({ name: m[1], currentVersion: m[3], latestVersion: m[2] });
      }
      for (const p of out) {
        if (held.has(p.name)) p.held = true;
        if (phased.has(p.name)) p.phased = true;
        if (keptBack.has(p.name)) p.keptBack = true;
      }
      return out;
    },
    // Dpkg::Lock::Timeout makes apt WAIT for the dpkg frontend lock (up to 5 min)
    // instead of failing fast when unattended-upgrades or a cron job holds it —
    // the #1 cause of spurious "Could not get lock" failures on live servers.
    upgrade: (pkg) => [
      'export DEBIAN_FRONTEND=noninteractive',
      pkg ? `apt-get -o Dpkg::Lock::Timeout=300 install --only-upgrade -y ${pkg}` : 'apt-get -o Dpkg::Lock::Timeout=300 upgrade -y',
    ],
    // One invocation for an explicit package list — a single lock acquisition,
    // so "update only these N packages" is atomic and fast.
    upgradeMany: (pkgs) => [
      'export DEBIAN_FRONTEND=noninteractive',
      `apt-get -o Dpkg::Lock::Timeout=300 install --only-upgrade -y ${pkgs.join(' ')}`,
    ],
    // dist-upgrade resolves dependencies by ADDING/REMOVING packages — the real
    // "upgrade the whole OS" command (plain `upgrade` keeps the current set).
    distUpgrade: () => [
      'export DEBIAN_FRONTEND=noninteractive',
      'apt-get -o Dpkg::Lock::Timeout=300 dist-upgrade -y',
    ],
    // apt-mark is the admin's hold mechanism — `upgrade` skips held packages on
    // purpose, and an EXPLICIT list containing one hard-fails without this flag.
    holdPackage: (pkg) => [`apt-mark hold ${pkg}`],
    unholdPackage: (pkg) => [`apt-mark unhold ${pkg}`],
    listHeld: () => 'apt-mark showhold 2>/dev/null || true',
    // Force = dist-upgrade that also installs held packages. The hold flag stays
    // SET afterwards — forcing upgrades the version once, it does not release the pin.
    upgradeForceAll: () => [
      'export DEBIAN_FRONTEND=noninteractive',
      'apt-get -o Dpkg::Lock::Timeout=300 dist-upgrade -y --allow-change-held-packages',
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
    upgradeMany: (pkgs) => [`dnf -y upgrade ${pkgs.join(' ')}`],
    // dnf's hold mechanism is version locking (`dnf version lock add`). Locked
    // packages are skipped by `upgrade` just like apt holds. No force form — a
    // locked package must be unlocked first (packages.unhold), then upgraded.
    holdPackage: (pkg) => [`dnf -q version lock add ${pkg}`],
    unholdPackage: (pkg) => [`dnf -q version lock remove ${pkg}`],
    listHeld: () => 'dnf -q version lock list 2>/dev/null || true',
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
    upgradeMany: (pkgs) => [`yum -y update ${pkgs.join(' ')}`],
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

// ---------------------------------------------------------------------------
// Installed-package inventory (capability 'installedPackages' → CVE tracking)
// ---------------------------------------------------------------------------

/** One installed package as reported by a package manager. */
export interface InstalledPackage {
  name: string;
  /** Exact installed version (dpkg epoch/revision, apk `-rN`, rpm `epoch:ver-rel`). */
  version: string | null;
}

/** Result of an installed-package listing. */
export interface InstalledPackagesResult {
  /** The detected manager id ('apt' | 'dnf' | …); null when none was found. */
  pm: string | null;
  /** Ecosystem tag for the CVE worker — release-aware where it matters (apk →
   *  `alpine:v3.19`, because OSV.dev's Alpine source is keyed per release). */
  ecosystemTag: string | null;
  packages: InstalledPackage[];
}

/** Splits "name-version" lines where the NAME may contain dashes but the VERSION
 *  always starts with a digit (pacman `linux-firmware-20240207-1`, apk
 *  `python3-pip-2.3.1-r0`). The boundary is the first `-` immediately followed by
 *  a digit — name dashes are never followed by digits in these ecosystems. */
function splitNameVersionLines(stdout: string): InstalledPackage[] {
  const out: InstalledPackage[] = [];
  for (const line of stdout.split('\n')) {
    const m = line.trim().match(/^([^\s-][\w.+:-]*?)-(\d[\w.+:-]*)$/);
    if (m) out.push({ name: m[1], version: m[2] });
  }
  return out;
}

/** Per-manager "list ALL installed packages with exact versions" commands.
 *  Deliberately separate from listUpgradable — CVE matching needs the FULL set,
 *  not just what has an update available. */
const INSTALLED_LISTERS: Record<string, { cmd(): string; parse(stdout: string): InstalledPackage[] }> = {
  // dpkg-query is the stable machine-readable form (apt's own listing output
  // varies by locale/version). '|' can't appear in a package name.
  apt: {
    cmd: () => "dpkg-query -W -f='${Package}|${Version}\\n' 2>/dev/null || true",
    parse(stdout) {
      const out: InstalledPackage[] = [];
      for (const line of stdout.split('\n')) {
        const i = line.indexOf('|');
        if (i <= 0) continue;
        const name = line.slice(0, i).trim();
        const version = line.slice(i + 1).trim();
        if (name && version) out.push({ name, version });
      }
      return out;
    },
  },
  dnf: {
    // %{EPOCH:%{VERSION}}-%{RELEASE} → "1:2.34-5" when an epoch is set, else plain.
    cmd: () => 'rpm -q --queryformat "%{NAME}\\t%{EPOCH:%{VERSION}}-%{RELEASE}\\n" 2>/dev/null || true',
    parse(stdout) {
      const out: InstalledPackage[] = [];
      for (const line of stdout.split('\n')) {
        const i = line.indexOf('\t');
        if (i <= 0) continue;
        const name = line.slice(0, i).trim();
        const version = line.slice(i + 1).trim();
        if (name && version) out.push({ name, version });
      }
      return out;
    },
  },
  yum: { cmd: () => INSTALLED_LISTERS.dnf.cmd(), parse: (s) => INSTALLED_LISTERS.dnf.parse(s) },
  pacman: {
    // "name-version" — names may contain dashes, versions start with a digit.
    cmd: () => 'pacman -Q 2>/dev/null || true',
    parse(stdout) { return splitNameVersionLines(stdout); },
  },
  apk: {
    // "name-version-rN" — same name/version boundary rule as pacman.
    cmd: () => 'apk info -v 2>/dev/null || true',
    parse(stdout) { return splitNameVersionLines(stdout); },
  },
};

/** Reads the Alpine release line ("3.19") from /etc/alpine-release; null on failure. */
export async function readAlpineRelease(backend: UpdateExecBackend): Promise<string | null> {
  try {
    const r = await backend.exec('cat /etc/alpine-release 2>/dev/null || true');
    const m = (r.stdout ?? '').trim().match(/(\d+\.\d+)/);
    return m ? m[1] : null;
  } catch {
    return null;
  }
}

/**
 * Lists ALL installed packages with their exact versions over SSH. Uses the
 * same manager detection as the Updates page, then runs that manager's full
 * listing (dpkg-query / rpm -q / pacman -Q / apk info). Returns `pm: null` and
 * no packages when nothing is recognized (e.g. NixOS) — callers must treat
 * that as "no data" (omit the metric key), NOT as an authoritative empty list.
 * Never throws; a failed exec yields pm + empty packages so the caller can log.
 */
export async function listInstalledPackages(backend: UpdateExecBackend): Promise<InstalledPackagesResult> {
  const ids = await readOsReleaseIds(backend); // one shared round-trip (detection re-probes commands only)
  if (ids.length > 0) {
    for (const adapter of PACKAGE_MANAGER_ADAPTERS) {
      if (adapter.distros.some((d) => ids.includes(d))) return listWithAdapter(backend, adapter, ids);
    }
  }
  for (const adapter of PACKAGE_MANAGER_ADAPTERS) {
    if (await adapter.detect(backend)) return listWithAdapter(backend, adapter, ids);
  }
  return { pm: null, ecosystemTag: null, packages: [] };
}

/** Runs one manager's full listing and derives the CVE-worker ecosystem tag. */
async function listWithAdapter(
  backend: UpdateExecBackend,
  adapter: PmAdapter,
  osIds: string[],
): Promise<InstalledPackagesResult> {
  // The tag is what the API maps onto OSV.dev sources — it must be the DISTRO,
  // not the manager (apt serves both Debian and Ubuntu; OSV keys them together
  // but the tag stays honest). apk needs a RELEASE-SPECIFIC tag (alpine:v3.19):
  // OSV's Alpine source is keyed per release and plain "Alpine" matches nothing
  // for versioned queries (live-verified 2026-10).
  let ecosystemTag: string;
  if (adapter.id === 'apk') {
    const rel = await readAlpineRelease(backend);
    ecosystemTag = rel ? `alpine:v${rel}` : 'alpine';
  } else {
    ecosystemTag = osIds[0] ?? adapter.id; // most-specific ID first, manager id as last resort
  }

  try {
    const r = await backend.exec(INSTALLED_LISTERS[adapter.id].cmd());
    if (r.code !== 0) return { pm: adapter.id, ecosystemTag, packages: [] };
    // One row per name — a package can't be installed twice under one manager.
    const byName = new Map<string, InstalledPackage>();
    for (const p of INSTALLED_LISTERS[adapter.id].parse(r.stdout)) {
      if (!byName.has(p.name)) byName.set(p.name, p);
    }
    return { pm: adapter.id, ecosystemTag, packages: [...byName.values()] };
  } catch {
    return { pm: adapter.id, ecosystemTag, packages: [] };
  }
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

/** Default exec budget for an upgrade run — full OS upgrades on slow boxes can
 *  take many minutes. Callers with a tighter dispatch window should pass their own.
 *  (The old implicit default was the SSH backend's 15s exec timeout, which killed
 *  every real upgrade mid-flight.) */
export const DEFAULT_UPGRADE_TIMEOUT_MS = 9 * 60_000;

/**
 * Apply a package upgrade over SSH: detect the manager, run its upgrade command
 * for one package (or all), and report success. Long-running — `timeoutMs` must
 * cover the whole run (default 9 min; pass a larger budget under a generous
 * dispatch timeout). Never throws; failures come back as ok:false.
 */
export async function runPackageUpgrade(
  backend: UpdateExecBackend,
  pkg?: string,
  timeoutMs = DEFAULT_UPGRADE_TIMEOUT_MS,
): Promise<PackageUpgradeResult> {
  const adapter = await detectPackageManager(backend);
  if (!adapter) return { ok: false, stdout: '', stderr: 'No known package manager detected on this host', pm: null };
  const script = ['set -e', ...adapter.upgrade(pkg)].join('\n');
  try {
    const r = await backend.exec(script, timeoutMs);
    return { ok: r.code === 0, stdout: r.stdout, stderr: r.stderr ?? '', pm: adapter.id };
  } catch (err) {
    return { ok: false, stdout: '', stderr: (err as Error).message, pm: adapter.id };
  }
}

/**
 * Upgrade an EXPLICIT list of packages in one shot. Prefers the manager's
 * multi-form (`upgradeMany` — a single lock acquisition) and falls back to
 * per-package runs when it is unavailable. Used by "update only these" bulk
 * actions (e.g. everything that does not need a reboot). Never throws.
 */
export async function runPackageUpgradeList(
  backend: UpdateExecBackend,
  pkgs: string[],
  timeoutMs = DEFAULT_UPGRADE_TIMEOUT_MS,
): Promise<PackageUpgradeResult> {
  const adapter = await detectPackageManager(backend);
  if (!adapter) return { ok: false, stdout: '', stderr: 'No known package manager detected on this host', pm: null };
  if (pkgs.length === 0) return { ok: true, stdout: '', stderr: '', pm: adapter.id };

  const cmds = adapter.upgradeMany ? adapter.upgradeMany(pkgs) : pkgs.map((p) => adapter.upgrade(p)).flat();
  // Per-package fallback needs `set -e` so a failure stops the run; the multi-form
  // already carries its own flags, but set -e is harmless there too.
  const script = ['set -e', ...cmds].join('\n');
  try {
    const r = await backend.exec(script, timeoutMs);
    return { ok: r.code === 0, stdout: r.stdout, stderr: r.stderr ?? '', pm: adapter.id };
  } catch (err) {
    return { ok: false, stdout: '', stderr: (err as Error).message, pm: adapter.id };
  }
}

// ---------------------------------------------------------------------------
// Detached long-running upgrades (dist-upgrade can take minutes to HOURS — we
// must NOT hold an SSH session open for that duration; a pooled or dedicated
// connection would block every other exec on the host and risk idle drops).
// Instead: launch via nohup so the exec returns in ~1 s, then poll a status probe.
// ---------------------------------------------------------------------------

/** Marker appended to the log when a detached upgrade finishes cleanly. */
export const UPGRADE_DONE_MARKER = 'UNM_UPGRADE_DONE';
/** Exit code returned by the launcher when an upgrade is already running. */
export const DETACHED_ALREADY_RUNNING_EXIT = 97;

/**
 * Builds a standalone shell script that launches `cmdLines` DETACHED via nohup:
 * output → logFile, PID → pidFile, stdin from /dev/null. The exec returns almost
 * immediately even though the upgrade may run for hours. A concurrent launch (a
 * live PID in pidFile) is refused with exit 97 instead of double-running.
 * Safe to pass through ElevatedBackend (sudo quoting is handled by wrapSudo).
 */
export function buildDetachedUpgradeScript(cmdLines: string[], logFile: string, pidFile: string): string {
  const body = cmdLines.join('\n').replace(/'/g, "'\\''"); // single-quote-safe for the inner sh -c
  return [
    `if [ -f ${pidFile} ] && kill -0 "$(cat ${pidFile})" 2>/dev/null; then echo already-running; exit ${DETACHED_ALREADY_RUNNING_EXIT}; fi`,
    `rm -f ${logFile}`,
    `nohup sh -c 'set -e; ${body}; echo ${UPGRADE_DONE_MARKER}' > ${logFile} 2>&1 < /dev/null &`,
    `echo $! > ${pidFile}`,
    `echo launched $(cat ${pidFile})`,
  ].join('\n');
}

/** Builds the shell script that reports a previously-launched detached upgrade's state. */
export function buildUpgradeStatusScript(logFile: string, pidFile: string): string {
  return [
    `if [ -f ${pidFile} ] && kill -0 "$(cat ${pidFile})" 2>/dev/null; then echo UNM_STATE=running; else`,
    `  if grep -q ${UPGRADE_DONE_MARKER} ${logFile} 2>/dev/null; then echo UNM_STATE=done; else echo UNM_STATE=failed; fi`,
    'fi',
    'echo UNM_TAIL_BEGIN',
    `tail -n 15 ${logFile} 2>/dev/null || true`,
    'echo UNM_TAIL_END',
  ].join('\n');
}

/** Parsed state of a detached upgrade. */
export interface DetachedUpgradeStatus {
  /** running / done (clean finish) / failed (died without the DONE marker) / unknown (never launched). */
  state: 'running' | 'done' | 'failed' | 'unknown';
  /** Last lines of the log (empty when there is none yet). */
  tail: string;
}

/** Parses the output of buildUpgradeStatusScript into a structured status. */
export function parseDetachedUpgradeStatus(stdout: string): DetachedUpgradeStatus {
  const stateMatch = /UNM_STATE=(running|done|failed)/.exec(stdout);
  const state = (stateMatch?.[1] as DetachedUpgradeStatus['state']) ?? 'unknown';
  const tailMatch = /UNM_TAIL_BEGIN\n([\s\S]*?)\n?UNM_TAIL_END/.exec(stdout);
  return { state, tail: (tailMatch?.[1] ?? '').trim() };
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
    // Kernel/firmware/initramfs packages need a reboot to take effect; userspace
    // updates restart in place. Drives the "update without reboot" bulk action.
    rebootRequired: packageRequiresReboot(p.name),
    ...(opts?.applyActionId ? { applyActionId: opts.applyActionId } : {}),
    ...(opts?.applyActionId && opts.perPackageApply !== false ? { applyInput: { package: p.name } } : {}),
    extra: { pm: adapter.id, ...(p.held ? { held: true } : {}), ...(p.phased ? { phased: true } : {}), ...(p.keptBack ? { keptBack: true } : {}) },
  }));
}
