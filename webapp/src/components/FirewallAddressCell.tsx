import type { ReactNode } from 'react';
import { Users } from 'lucide-react';
import type { FirewallAddressResolution, FirewallRuleRow } from '../api/client';

/** Max subnet chips before collapsing into "+N" (the tooltip carries the rest). */
const MAX_SUBNET_CHIPS = 2;

/** Builds the hover tooltip text for a resolution — subnets, interfaces, hosts. */
function resolutionTooltip(resolution: FirewallAddressResolution): string {
  const lines: string[] = [];
  if (resolution.subnets.length > 0) lines.push(`Subnets: ${resolution.subnets.join(', ')}`);
  if (resolution.interfaces.length > 0) lines.push(`Interfaces: ${resolution.interfaces.join(', ')}`);
  for (const h of resolution.hosts.slice(0, 15)) {
    const name = h.hostname ?? h.mac;
    const ips = h.ips.length > 0 ? ` (${h.ips.join(', ')})` : '';
    const where = h.devices.length > 0 ? ` [seen on ${h.devices.join(', ')}]` : '';
    lines.push(`Host: ${name}${ips}${where}`);
  }
  if (resolution.hostCount > resolution.hosts.length) {
    lines.push(`…and ${resolution.hostCount - resolution.hosts.length} more hosts`);
  }
  for (const u of resolution.unresolved) lines.push(`Unresolved alias: ${u}`);
  return lines.join('\n');
}

/** One small colored chip. */
function Chip({ label, tone }: { label: string; tone: 'v4' | 'v6' | 'host' | 'alias' }) {
  const styles: Record<string, string> = {
    v4: 'bg-info text-info-fg',
    v6: 'bg-violet-100 text-violet-700',
    host: 'bg-success text-success-fg',
    alias: 'bg-warning text-warning-fg',
  };
  return (
    <span className={`inline-flex max-w-[160px] truncate rounded px-1.5 py-0.5 font-mono text-xs ${styles[tone]}`}>
      {label}
    </span>
  );
}

/**
 * Renders a firewall rule address with its cross-device resolution: subnet chips
 * (v4 blue / v6 violet), an emerald host-count chip, and amber chips for alias
 * tokens the inventory can't expand. The full detail lives in the hover tooltip.
 */
export function FirewallAddressCell({
  raw,
  port,
  resolution,
}: {
  /** Raw address text as configured (alias name / CIDR / IP); '' = any. */
  raw?: string;
  /** Port(s) to append when present ("443", "80-90"). */
  port?: string | null;
  resolution: FirewallAddressResolution | null | undefined;
}) {
  const addr = (raw ?? '').trim();
  const p = (port ?? '').trim();

  // No address at all — plain dash / port-only display.
  if (!addr) return <span className="font-mono text-xs">{p || '—'}</span>;

  const chips: ReactNode[] = [];
  if (resolution && resolution.subnets.length > 0) {
    for (const s of resolution.subnets.slice(0, MAX_SUBNET_CHIPS)) {
      chips.push(<Chip key={s} label={s} tone={s.includes(':') ? 'v6' : 'v4'} />);
    }
    const overflow = resolution.subnets.length - Math.min(resolution.subnets.length, MAX_SUBNET_CHIPS);
    if (overflow > 0) chips.push(<Chip key="__more" label={`+${overflow}`} tone="alias" />);
  } else {
    // No subnet match — show the raw value itself (alias name or bare IP).
    const shown = addr.length > 24 ? `${addr.slice(0, 23)}…` : addr;
    chips.push(<Chip key="__raw" label={shown} tone="alias" />);
  }

  if (resolution && resolution.hostCount > 0) {
    chips.push(
      <span
        key="__hosts"
        className="inline-flex items-center gap-1 rounded bg-success px-1.5 py-0.5 text-xs font-medium text-success-fg"
      >
        <Users size={12} aria-hidden /> {resolution.hostCount}
      </span>
    );
  }

  const tooltip = resolution ? resolutionTooltip(resolution) : addr;
  return (
    <div className="flex flex-wrap items-center gap-1" title={tooltip}>
      {chips}
      {p && <span className="font-mono text-xs text-muted-foreground">:{p}</span>}
    </div>
  );
}

/** Convenience wrapper for the Firewall table's Source/Destination columns. */
export function RuleAddressCell({ row, side }: { row: FirewallRuleRow; side: 'source' | 'dest' }) {
  const raw = side === 'source' ? row.sourceIp : row.destIp;
  const port = side === 'source' ? row.sourcePort : row.destPort;
  const resolution = side === 'source' ? row.sourceResolved : row.destResolved;
  return <FirewallAddressCell raw={raw} port={port} resolution={resolution ?? null} />;
}
