/**
 * @unm/plugin-sdk — container BOM (bill of materials) probe.
 *
 * Shared by every plugin that can exec INTO containers: the generic Docker
 * plugin (Engine API `POST /containers/{id}/exec`) and the TrueNAS plugin
 * (`docker exec` over its pooled SSH session). The goal is a fleet-wide list
 * of "which software version runs in which container" — the input for CVE
 * matching (the same `installedPackages` metric contract as host packages,
 * extended with `component: 'container'` + `componentName`).
 *
 * HOW: one POSIX-sh script runs inside each container and reports its distro
 * identity + full installed-package list in a line-based protocol. The script
 * is deliberately SINGLE-QUOTE-FREE so callers can wrap it verbatim in
 * single quotes (`sh -c '<script>'`) without any escaping — the only shell
 * metacharacters it contains are double quotes and escaped dollar signs,
 * which survive that wrapping untouched.
 *
 * Line protocol (one record per line; package names never contain '|'):
 *   ECO|<id>        os-release `ID=` lowercased ('ubuntu', 'debian', …) or 'unknown'
 *   ALPINE|<rel>    only when /etc/alpine-release exists ("3.19")
 *   PM|<pm>         detected package manager (dpkg | apk | rpm | pacman)
 *   PKG|<n>|<v>     exact name + version (dpkg/rpm — machine-readable formats)
 *   PKGRAW|<tok>    single "name-version" token (apk/pacman — split in TS with
 *                   the same boundary rule as updates.ts: first '-' followed by a digit)
 */

/** One installed package inside one container. */
export interface BomPackage {
  name: string;
  /** Exact installed version ('1.25.3-r0', '1.1.1n-0ubuntu3.9', …); null = unversioned. */
  version: string | null;
}

/** Parsed result of one container probe. `ecosystemTag` is the CVE-worker tag
 * (release-aware for Alpine, mirroring listInstalledPackages in updates.ts). */
export interface BomProbeResult {
  ecosystemTag: string | null;
  packages: BomPackage[];
}

/**
 * The in-container probe script (POSIX sh — works under dash/ash/bash).
 * NO single quotes anywhere (see module docs). Output is capped per manager
 * so a pathological image can't flood the channel. Containers without a shell
 * (scratch/distroless) produce no output at all → parseBomOutput returns null.
 */
export const BOM_PROBE_SCRIPT = [
  // os-release ID with any surrounding quotes/spaces stripped (the sed
  // expressions run inside double quotes — \" stays literal through the
  // single-quote wrapper, so the container shell hands sed a real quote char).
  'ID=$(sed -n "s/^ID=//p" /etc/os-release 2>/dev/null | sed -e "s/^[ \\" ]*//" -e "s/[ \\"]*$//" | head -n1)',
  '[ -n "$ID" ] || ID=unknown',
  'echo "ECO|$ID"',
  'if [ -r /etc/alpine-release ]; then echo "ALPINE|$(head -n1 /etc/alpine-release)"; fi',
  'if command -v dpkg-query >/dev/null 2>&1; then',
  '  echo "PM|dpkg"',
  // \${...} → the container shell passes ${Package}/${Version} through to dpkg.
  '  dpkg-query -W -f "PKG|\\${Package}|\\${Version}\\n" 2>/dev/null | head -n 4000',
  'elif command -v apk >/dev/null 2>&1; then',
  '  echo "PM|apk"',
  '  apk info -v 2>/dev/null | sed "s/^/PKGRAW|/" | head -n 4000',
  'elif command -v rpm >/dev/null 2>&1; then',
  '  echo "PM|rpm"',
  '  rpm -qa --qf "PKG|%{NAME}|\\${EPOCH:%{VERSION}}-%{RELEASE}\\n" 2>/dev/null | head -n 4000',
  'elif command -v pacman >/dev/null 2>&1; then',
  '  echo "PM|pacman"',
  '  pacman -Q 2>/dev/null | sed "s/^/PKGRAW|/" | head -n 4000',
  'fi',
].join('\n');

/** Wraps the probe script for `docker exec <id> sh -c '<script>'` — safe because
 * BOM_PROBE_SCRIPT contains no single quotes (module contract). */
export function bomExecCommand(): string {
  return `sh -c '${BOM_PROBE_SCRIPT}'`;
}

/** Splits "name-version" tokens where the NAME may contain dashes but the VERSION
 * always starts with a digit — same boundary rule as updates.ts. */
function splitNameVersionToken(tok: string): { name: string; version: string } | null {
  const m = tok.match(/^([^\s-][\w.+:-]*?)-(\d[\w.+:-]*)$/);
  return m ? { name: m[1], version: m[2] } : null;
}

/**
 * Parses one container's probe output into a BomProbeResult. Returns null when
 * the output carries no `ECO|` header — i.e. the exec produced nothing (no sh,
 * scratch/distroless image) or failed entirely. Callers must treat null as
 * "no data for this container" (keep any previous rows), NOT as an empty list.
 */
export function parseBomOutput(stdout: string): BomProbeResult | null {
  const lines = stdout.split('\n');
  let hasHeader = false;
  let ecoId = '';
  let alpineRelease: string | null = null;
  let pm = '';
  const byName = new Map<string, BomPackage>();

  for (const line of lines) {
    if (line.startsWith('ECO|')) {
      hasHeader = true;
      ecoId = line.slice(4).trim().toLowerCase();
    } else if (line.startsWith('ALPINE|')) {
      const m = line.match(/(\d+\.\d+)/);
      alpineRelease = m ? m[1] : null;
    } else if (line.startsWith('PM|')) {
      pm = line.slice(3).trim();
    } else if (line.startsWith('PKG|')) {
      const rest = line.slice(4);
      const i = rest.indexOf('|');
      if (i <= 0) continue;
      const name = rest.slice(0, i).trim();
      const version = rest.slice(i + 1).trim();
      if (name && !byName.has(name)) byName.set(name, { name, version: version !== '' ? version : null });
    } else if (line.startsWith('PKGRAW|')) {
      const tok = line.slice(7).trim();
      const split = splitNameVersionToken(tok);
      if (split && !byName.has(split.name)) byName.set(split.name, { name: split.name, version: split.version });
    }
  }

  if (!hasHeader) return null;

  // Ecosystem tag — same derivation as listInstalledPackages in updates.ts:
  // Alpine is RELEASE-SPECIFIC (OSV keys its source per release); otherwise the
  // os-release ID ('ubuntu'/'debian'/…) with the manager id as last resort.
  let ecosystemTag: string | null = null;
  if (alpineRelease) ecosystemTag = `alpine:v${alpineRelease}`;
  else if (ecoId && ecoId !== 'unknown') ecosystemTag = ecoId;
  else if (pm === 'apk') ecosystemTag = 'alpine';
  return { ecosystemTag, packages: Array.from(byName.values()) };
}
