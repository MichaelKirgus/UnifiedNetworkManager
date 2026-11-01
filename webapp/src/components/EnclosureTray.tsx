import { useMemo } from 'react';
import clsx from 'clsx';
import { Check } from 'lucide-react';
import { StateItem, SwitchLayout, SwitchPortGroup } from '../api/client';
import { ledClass } from './VirtualSwitch';

/**
 * EnclosureTray — a reusable disk-tray face renderer for state sections with
 * `kind: 'enclosure'`. Each item is one drive bay (LED + slot number + one line
 * of key info) arranged in bands that mimic the front panel of each physical
 * enclosure. The band structure comes from the plugin's propagated `layout` —
 * one group per chassis, its label rendered as the tray header; items not
 * referenced by any band are appended to an "Unassigned" band so nothing is
 * ever hidden.
 *
 * Each bay cell is a toggle: clicking selects/deselects the disk for bulk
 * actions (the parent owns `selectedKeys` and renders the action bar). Full
 * details (model, serial, size, pool) are available via tooltip.
 */

/** One compact info line under the slot number — capacity first, then pool. */
function trayInfoLine(fields: StateItem['fields']): string | null {
  const parts: string[] = [];
  for (const key of Object.keys(fields)) {
    if (/size/i.test(key) && fields[key] != null) parts.push(String(fields[key]));
  }
  for (const key of Object.keys(fields)) {
    if (/pool|vdev/i.test(key) && fields[key] != null) parts.push(String(fields[key]));
  }
  return parts.length > 0 ? parts.join(' · ') : null;
}

/** Full tooltip text — title, subtitle, status and every field (arrays joined). */
function bayTooltip(item: StateItem): string {
  const lines = [item.title];
  if (item.subtitle) lines.push(item.subtitle);
  if (item.status) lines.push(`status: ${item.status}`);
  for (const [k, v] of Object.entries(item.fields)) {
    if (v === null || v === undefined || v === '') continue;
    lines.push(`${k}: ${Array.isArray(v) ? v.join(', ') : String(v)}`);
  }
  return lines.join('\n');
}

interface EnclosureTrayProps {
  items: StateItem[];
  /** Plugin-propagated layout — one group per physical enclosure (top → bottom). */
  layout?: SwitchLayout | null;
  selectedKeys: ReadonlySet<string>;
  onToggleKey: (key: string) => void;
  /** When false the tray is purely informational — no checkbox overlays, clicks inert. */
  selectable?: boolean;
}

export function EnclosureTray({ items, layout, selectedKeys, onToggleKey, selectable = true }: EnclosureTrayProps) {
  const byKey = useMemo(() => new Map(items.map((i) => [i.key, i])), [items]);

  // Propagated bands first; any item not referenced by a band is appended as an
  // "Unassigned" trailing band so nothing is ever hidden.
  const bands = useMemo<SwitchPortGroup[]>(() => {
    const base: SwitchPortGroup[] = layout && layout.groups.length > 0 ? layout.groups : [{ id: '_all', portKeys: items.map((i) => i.key) }];
    const placed = new Set(base.flatMap((g) => g.portKeys));
    const orphans = items.filter((i) => !placed.has(i.key));
    return orphans.length > 0 ? [...base, { id: '_unassigned', label: 'Unassigned', portKeys: orphans.map((i) => i.key) }] : base;
  }, [layout, items]);

  if (items.length === 0) {
    return <div className="px-4 py-3 text-xs text-faint">No drive bays reported.</div>;
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
                <BayCell
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

/** One drive-bay cell — LED, slot number, info line and (when selectable) a checkbox indicator. */
function BayCell({ item, selected, onToggle, selectable }: { item: StateItem; selected: boolean; onToggle: () => void; selectable: boolean }) {
  const info = trayInfoLine(item.fields);
  return (
    <button
      type="button"
      onClick={selectable ? onToggle : undefined}
      title={bayTooltip(item)}
      aria-pressed={selectable ? selected : undefined}
      className={clsx(
        'relative flex h-[58px] w-[76px] shrink-0 flex-col items-center justify-center gap-1 rounded-md border transition-colors',
        selectable && selected
          ? 'border-accent-hover bg-accent-indigo/60 ring-1 ring-accent-indigo-border'
          : 'border-border bg-card',
        selectable && !selected && 'hover:border-border hover:bg-background'
      )}
    >
      {selectable && (
        <span
          className={clsx(
            'absolute right-1 top-1 flex h-3.5 w-3.5 items-center justify-center rounded-sm border',
            selected ? 'border-accent-solid bg-accent-solid text-white' : 'border-border bg-card'
          )}
        >
          {selected && <Check className="h-2.5 w-2.5" />}
        </span>
      )}
      <span className={clsx('h-2 w-2 rounded-full', ledClass(item.status))} />
      <span className="max-w-full truncate px-1 text-[11px] font-semibold leading-none text-secondary" title={item.title}>
        {item.title}
      </span>
      {info && (
        <span className="max-w-full truncate px-1 text-[9px] leading-tight text-faint" title={info}>
          {info}
        </span>
      )}
    </button>
  );
}
