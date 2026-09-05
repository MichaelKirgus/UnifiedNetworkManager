import { useMemo } from 'react';
import clsx from 'clsx';
import { Check } from 'lucide-react';
import { StateItem, SwitchLayout, SwitchPortGroup } from '../api/client';

/**
 * VirtualSwitch — a reusable virtual switch-face renderer for state sections
 * with `kind: 'switch'`. Ports are drawn as compact cells (LED + port number +
 * one line of key info) arranged in bands that mimic a real front panel. The
 * band structure comes from the plugin's propagated `layout` (model-specific,
 * e.g. RJ45 vs SFP+ sections); when absent a generic balanced layout is used
 * (numeric port order split into N rows — like a 48-port switch in 3×16).
 *
 * Each cell is a toggle: clicking selects/deselects the port for bulk actions
 * (the parent owns `selectedKeys` and renders the action bar). Full details
 * (name, status, all fields incl. learned MACs) are available via tooltip.
 */

/** LED color for a port status string (mirrors StatusBadge semantics). */
function ledClass(status?: string | null): string {
  switch ((status ?? '').toLowerCase()) {
    case 'up':
    case 'ok':
    case 'enabled':
    case 'active':
      return 'bg-emerald-500 shadow-[0_0_6px_rgba(16,185,129,0.7)]';
    case 'down':
    case 'offline':
    case 'critical':
      return 'bg-red-500 shadow-[0_0_6px_rgba(239,68,68,0.55)]';
    case 'degraded':
    case 'warning':
      return 'bg-amber-400 shadow-[0_0_6px_rgba(251,191,36,0.6)]';
    case 'disabled':
    case 'inactive':
      return 'bg-slate-300';
    default:
      return 'bg-slate-400'; // unknown / no link info
  }
}

/** Numeric port number from an item key ('P12' → 12, '5' → 5). Name-based keys
 *  like 'em0' or 'bridge0' are NOT numeric — they keep their original order. */
function portNumber(key: string): number | null {
  const m = /^p?(\d+)$/i.exec(key.trim());
  return m ? Number(m[1]) : null;
}

/**
 * Generic fallback layout — mirrors the SDK's suggestPortLayout(): numeric keys
 * sort by port number, then the count is split into `rows` balanced bands.
 */
export function genericSwitchLayout(items: StateItem[], rows = 3): SwitchLayout {
  const ordered = [...items].sort((a, b) => {
    const na = portNumber(a.key);
    const nb = portNumber(b.key);
    if (na !== null && nb !== null) return na - nb;
    if (na !== null) return -1;
    if (nb !== null) return 1;
    return 0;
  });
  const n = ordered.length;
  if (n === 0) return { groups: [] };
  const r = Math.max(1, Math.min(rows, n));
  const base = Math.floor(n / r);
  const extra = n % r;
  const groups: SwitchPortGroup[] = [];
  let cursor = 0;
  for (let i = 0; i < r; i++) {
    const size = base + (i < extra ? 1 : 0);
    if (size === 0) continue;
    groups.push({ id: `row-${i + 1}`, portKeys: ordered.slice(cursor, cursor + size).map((it) => it.key) });
    cursor += size;
  }
  return { groups };
}

/** Short cell label — the number for numeric keys ('P12' → '12'), else the full
 *  key/title so name-based interfaces ('em0', 'bridge0') stay readable. */
function portLabel(item: StateItem): string {
  const m = /^p?(\d+)$/i.exec(item.key.trim());
  if (m) return m[1];
  return item.title;
}

/** One compact info line under the port number — speed-like field first, then VLAN/PVID. */
function infoLine(fields: StateItem['fields']): string | null {
  const keys = Object.keys(fields);
  const speedKey = keys.find((k) => /speed/i.test(k));
  const vlanKey = keys.find((k) => /(vlan|pvid)/i.test(k));
  const parts: string[] = [];
  if (speedKey && fields[speedKey] != null) parts.push(String(fields[speedKey]));
  if (vlanKey && fields[vlanKey] != null) parts.push(String(fields[vlanKey]));
  return parts.length > 0 ? parts.join(' · ') : null;
}

/** Full tooltip text — title, subtitle, status and every field (arrays joined). */
function cellTooltip(item: StateItem): string {
  const lines = [item.title];
  if (item.subtitle) lines.push(item.subtitle);
  if (item.status) lines.push(`status: ${item.status}`);
  for (const [k, v] of Object.entries(item.fields)) {
    if (v === null || v === undefined || v === '') continue;
    lines.push(`${k}: ${Array.isArray(v) ? v.join(', ') : String(v)}`);
  }
  return lines.join('\n');
}

interface VirtualSwitchProps {
  items: StateItem[];
  /** Plugin-propagated layout (bands top → bottom). Absent/empty → generic balanced rows. */
  layout?: SwitchLayout | null;
  /** Row count for the generic fallback when no layout is propagated (default 3). */
  rows?: number;
  selectedKeys: ReadonlySet<string>;
  onToggleKey: (key: string) => void;
  /** When false the face is purely informational — no checkbox overlays, clicks inert. */
  selectable?: boolean;
}

export function VirtualSwitch({ items, layout, rows = 3, selectedKeys, onToggleKey, selectable = true }: VirtualSwitchProps) {
  const byKey = useMemo(() => new Map(items.map((i) => [i.key, i])), [items]);

  // Propagated bands first; any item not referenced by a band is appended as an
  // unlabeled trailing band so nothing is ever hidden.
  const bands = useMemo<SwitchPortGroup[]>(() => {
    const base: SwitchPortGroup[] = layout && layout.groups.length > 0 ? layout.groups : genericSwitchLayout(items, rows).groups;
    const placed = new Set(base.flatMap((g) => g.portKeys));
    const orphans = items.filter((i) => !placed.has(i.key));
    return orphans.length > 0 ? [...base, { id: '_unassigned', portKeys: orphans.map((i) => i.key) }] : base;
  }, [layout, items, rows]);

  if (items.length === 0) {
    return <div className="px-4 py-3 text-xs text-faint">No ports reported.</div>;
  }

  return (
    <div className="flex flex-col gap-3 p-4">
      {bands.map((band) => (
        <div key={band.id}>
          {band.label && (
            <div className="mb-1.5 text-[11px] font-semibold uppercase tracking-wide text-faint">{band.label}</div>
          )}
          <div className="flex flex-wrap gap-1.5">
            {band.portKeys.map((key) => {
              const item = byKey.get(key);
              if (!item) return null;
              return (
                <PortCell
                  key={key}
                  item={item}
                  selected={selectedKeys.has(key)}
                  selectable={selectable}
                  onToggle={() => onToggleKey(key)}
                />
              );
            })}
          </div>
        </div>
      ))}
    </div>
  );
}

/** One port cell — LED, number, info line and (when selectable) a checkbox indicator. */
function PortCell({ item, selected, onToggle, selectable }: { item: StateItem; selected: boolean; onToggle: () => void; selectable: boolean }) {
  const info = infoLine(item.fields);
  return (
    <button
      type="button"
      onClick={selectable ? onToggle : undefined}
      title={cellTooltip(item)}
      aria-pressed={selectable ? selected : undefined}
      className={clsx(
        'relative flex h-[54px] w-[62px] shrink-0 flex-col items-center justify-center gap-1 rounded-md border transition-colors',
        selectable && selected
          ? 'border-indigo-400 bg-indigo-50 ring-1 ring-indigo-300'
          : 'border-border bg-card',
        selectable && !selected && 'hover:border-border hover:bg-background'
      )}
    >
      {selectable && (
        <span
          className={clsx(
            'absolute right-1 top-1 flex h-3.5 w-3.5 items-center justify-center rounded-sm border',
            selected ? 'border-indigo-500 bg-indigo-500 text-white' : 'border-border bg-card'
          )}
        >
          {selected && <Check className="h-2.5 w-2.5" />}
        </span>
      )}
      <span className={clsx('h-2 w-2 rounded-full', ledClass(item.status))} />
      <span className="max-w-full truncate px-1 text-[11px] font-semibold leading-none text-secondary" title={portLabel(item)}>
        {portLabel(item)}
      </span>
      {info && (
        <span className="max-w-full truncate px-1 text-[9px] leading-tight text-faint" title={info}>
          {info}
        </span>
      )}
    </button>
  );
}
