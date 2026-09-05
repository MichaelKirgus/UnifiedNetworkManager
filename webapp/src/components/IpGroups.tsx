import { Fragment } from 'react';
import type { ReactNode } from 'react';
import { ipScopeGroup, IpScopeGroup } from '../utils/address';

/**
 * One chip per scope group: "Private: 192.168.0.0/16, fdf8:f53b:86e4::/64".
 * All addresses of the same type are merged into a single compact chip — ULA
 * counts as private, GUA as public (see ipScopeGroup). Addresses that can't be
 * classified (loopback, multicast, DNS names) render as plain unlabeled chips.
 *
 * Column-width friendly: every address is whitespace-nowrap so it NEVER splits
 * across lines — wrapping only happens between addresses at the commas. Groups
 * with more than MAX_SHOWN addresses collapse their tail into a "+N" chip whose
 * tooltip lists everything, so a chip's size stays bounded no matter how many
 * members a network has or how narrow the column is.
 */

const GROUP_STYLES: Record<IpScopeGroup, string> = {
  private: 'bg-info text-info-fg',
  public: 'bg-teal-100 text-teal-800',
  'link-local': 'bg-warning text-warning-fg',
};

const GROUP_LABELS: Record<IpScopeGroup, string> = {
  private: 'Private',
  public: 'Public',
  'link-local': 'Link-Local',
};

/** Stable display order of the scope groups. */
const GROUP_ORDER: IpScopeGroup[] = ['private', 'public', 'link-local'];

/** Addresses shown per group chip before the tail collapses into "+N". */
const MAX_SHOWN = 3;

function AddressList({ list }: { list: string[] }) {
  const overflow = Math.max(0, list.length - MAX_SHOWN);
  const visible = overflow > 0 ? list.slice(0, MAX_SHOWN) : list;
  return (
    <span className="font-mono">
      {visible.map((a, i) => (
        // The comma+space lives OUTSIDE the nowrap span so a line break can
        // only occur between addresses — never inside one.
        <Fragment key={`${a}-${i}`}>
          {i > 0 && ', '}
          <span className="whitespace-nowrap">{a}</span>
        </Fragment>
      ))}
      {overflow > 0 && (
        <span title={list.join(', ')} className="ml-1 cursor-default whitespace-nowrap font-semibold opacity-70">
          +{overflow} more
        </span>
      )}
    </span>
  );
}

export function IpGroupChips({ ips }: { ips: string[] }) {
  const groups = new Map<IpScopeGroup, string[]>();
  const ungrouped: string[] = [];
  for (const ip of ips) {
    const g = ipScopeGroup(ip);
    if (!g) {
      ungrouped.push(ip);
      continue;
    }
    const list = groups.get(g);
    if (list) list.push(ip);
    else groups.set(g, [ip]);
  }

  const chips: ReactNode[] = [];
  for (const g of GROUP_ORDER) {
    const list = groups.get(g);
    if (!list || list.length === 0) continue;
    chips.push(
      <span key={g} className={`inline-flex max-w-full items-baseline gap-1 rounded px-1.5 py-0.5 text-xs ${GROUP_STYLES[g]}`}>
        <span className="shrink-0 font-semibold uppercase">{GROUP_LABELS[g]}:</span>
        <AddressList list={list} />
      </span>
    );
  }
  for (const ip of ungrouped) {
    chips.push(
      <span key={ip} className={`whitespace-nowrap rounded px-1.5 py-0.5 font-mono text-xs ${ip.includes(':') ? 'bg-purple-50 text-purple-700' : 'bg-muted text-secondary'}`}>
        {ip}
      </span>
    );
  }

  if (chips.length === 0) return <span className="text-faint">—</span>;
  return <div className="flex flex-wrap items-center gap-1">{chips}</div>;
}
