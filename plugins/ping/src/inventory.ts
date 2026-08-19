import { execFile } from 'child_process';
import { promisify } from 'util';
import * as dns from 'dns';

const execFileAsync = promisify(execFile);

export interface TargetInventory {
  /** The host that was actually pinged. */
  target: string;
  /** Resolved IP address of the target (empty when unresolvable). */
  ip: string;
  /** MAC address from the neighbor cache (empty when unavailable, e.g. IPv6 or no ARP entry). */
  mac: string;
}

/**
 * Best-effort inventory for a pinged target:
 *   - IP via DNS lookup of the host name (literal IPs pass through),
 *   - MAC from the Linux neighbor cache (`ip neigh`). Our own ICMP echo
 *     populates the ARP/NDP entry, so this usually works right after a
 *     successful ping. Returns empty strings rather than failing — inventory
 *     is supplementary data and must never break the monitoring call.
 */
export async function collectInventory(target: string): Promise<TargetInventory> {
  let ip = '';
  try {
    const result = await dns.promises.lookup(target, { verbatim: true });
    ip = result.address;
  } catch {
    // Unresolvable name — the ping itself will report unreachable.
  }

  let mac = '';
  if (ip) {
    try {
      const { stdout } = await execFileAsync('ip', ['neigh', 'show', ip], { timeout: 3000 });
      // Line format: "<ip> dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE"
      for (const line of stdout.split('\n')) {
        const m = line.match(/lladdr\s+([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}|[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4})/);
        if (m) {
          mac = m[1].toLowerCase();
          break;
        }
      }
    } catch {
      // `ip` unavailable or no entry — leave MAC empty.
    }
  }

  return { target, ip, mac };
}
