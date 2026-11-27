/**
 * Built-in threat-intel source templates — pre-verified public IOC feeds the
 * Security page can import with one click (mirrors the automation-template
 * pattern in automations/templates.ts). The webapp renders these as a catalog;
 * picking one only PRE-FILLS the create dialog, nothing is created until the
 * user saves.
 *
 * Every URL below was verified live on 2026-11-27 (format + HTTP status).
 * Keep this list small and boring: stable, free, no-key feeds in formats the
 * worker already parses (ip-list / domain-list). Re-verify before adding.
 */

export interface ThreatIntelSourceTemplate {
  /** Stable id used as the dialog-preset key — never reuse or rename. */
  id: string;
  /** Source name pre-filled into the create dialog (unique per install). */
  name: string;
  /** One-line human description shown in the catalog card. */
  description: string;
  url: string;
  format: 'ip-list' | 'domain-list';
}

export const THREAT_INTEL_SOURCE_TEMPLATES: ThreatIntelSourceTemplate[] = [
  {
    id: 'spamhaus-drop',
    name: 'Spamhaus DROP',
    description:
      'Netblocks hijacked by criminal organizations (botnets, malware distribution). The classic baseline for inbound AND outbound blocking.',
    url: 'https://www.spamhaus.org/drop/drop.txt',
    format: 'ip-list',
  },
  {
    id: 'firehol-level3',
    name: 'FireHOL Level 3',
    description:
      'Aggressive community list: hosts involved in brute-force attacks, spyware or viruses within the last 30 days. Updated daily.',
    url: 'https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level3.netset',
    format: 'ip-list',
  },
  {
    id: 'et-block-ips',
    name: 'Emerging Threats Block IPs',
    description:
      'Community-curated CIDR blocklist (includes Spamhaus DROP). A good general-purpose baseline for home and office networks.',
    url: 'https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt',
    format: 'ip-list',
  },
  {
    id: 'et-compromised-ips',
    name: 'Emerging Threats Compromised IPs',
    description:
      'Individual IPv4 addresses of known compromised or malicious hosts (one per line). More targeted than the full blocklist.',
    url: 'https://rules.emergingthreats.net/blockrules/compromised-ips.txt',
    format: 'ip-list',
  },
  {
    id: 'blocklist-de-ssh',
    name: 'BlockList.de SSH',
    description:
      'IPs observed attempting SSH brute-force attacks. Useful when you run SSH on this network; refreshes frequently.',
    url: 'https://lists.blocklist.de/lists/ssh.txt',
    format: 'ip-list',
  },
];
