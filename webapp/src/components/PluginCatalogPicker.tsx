import { useMemo, useState } from 'react';
import clsx from 'clsx';
import { Check, Puzzle, Search } from 'lucide-react';
import { Plugin, pluginIconUrl } from '../api/client';

/**
 * Capabilities that make a plugin assignable to a DEVICE. A device assignment
 * means "UNM polls this appliance through the plugin" — so only plugins with a
 * device-facing data path qualify (live metrics and/or inventory). Pure service
 * plugins (secretsProvider, fileRepo, webFetch, identityProvider, logIngestion)
 * are infrastructure for UNM itself and must never appear in device pickers.
 */
export const DEVICE_ASSIGNABLE_CAPABILITIES = ['monitoring', 'inventory'] as const;

/** True when the plugin can be assigned to a device (see above). */
export function isDeviceAssignablePlugin(p: Plugin): boolean {
  return (p.capabilities ?? []).some((c) => (DEVICE_ASSIGNABLE_CAPABILITIES as readonly string[]).includes(c));
}

/** Small icon for one catalog card — the plugin's own image via the API proxy,
 * falling back to a generic puzzle glyph when none is advertised or it fails. */
function CatalogIcon({ plugin }: { plugin: Plugin }) {
  const [failed, setFailed] = useState(false);
  if (!plugin.iconUrl || failed) return <Puzzle size={18} className="mt-0.5 shrink-0 text-faint" />;
  return (
    <img
      src={pluginIconUrl(plugin.id)}
      alt=""
      onError={() => setFailed(true)}
      className="mt-0.5 h-[18px] w-[18px] shrink-0 rounded object-contain"
    />
  );
}

/**
 * Catalog-style plugin picker — the TrueNAS Apps-catalog look (search box,
 * vendor filter chips, icon + name + version + description card grid) applied
 * to UNM's own device plugins. Replaces the old flat <select> in the device
 * form: with 40+ vendor plugins a dropdown is unusable, so users browse by
 * vendor and scan descriptions instead of hunting for an exact name.
 */
export function PluginCatalogPicker({
  plugins,
  selectedId = null,
  onPick,
  takenIds = [],
}: {
  /** All discovered plugins — the picker itself hides non-assignable ones. */
  plugins: Plugin[];
  /** Currently picked plugin (highlighted + re-selectable). */
  selectedId?: string | null;
  onPick: (pluginId: string) => void;
  /** Plugin ids already used by OTHER rows — shown but disabled. */
  takenIds?: string[];
}) {
  const [search, setSearch] = useState('');
  const [vendorFilter, setVendorFilter] = useState<string | null>(null);

  // Only device-assignable plugins are offered (see DEVICE_ASSIGNABLE_CAPABILITIES).
  const assignable = useMemo(() => plugins.filter(isDeviceAssignablePlugin), [plugins]);

  // Vendor chips with counts — derived from the data so new vendor plugins
  // appear without any code change.
  const vendors = useMemo(() => {
    const counts = new Map<string, number>();
    for (const p of assignable) for (const v of p.vendors ?? []) counts.set(v, (counts.get(v) ?? 0) + 1);
    return [...counts.entries()].sort((a, b) => a[0].localeCompare(b[0]));
  }, [assignable]);

  const q = search.trim().toLowerCase();
  const visible = useMemo(
    () =>
      assignable
        .filter((p) => {
          if (vendorFilter && !(p.vendors ?? []).includes(vendorFilter)) return false;
          if (!q) return true;
          return p.name.toLowerCase().includes(q) || (p.description ?? '').toLowerCase().includes(q);
        })
        .sort((a, b) => a.name.localeCompare(b.name)),
    [assignable, vendorFilter, q]
  );

  const taken = useMemo(() => new Set(takenIds), [takenIds]);

  return (
    <div className="space-y-2">
      {/* Search — name or description */}
      <div className="relative">
        <Search size={13} className="pointer-events-none absolute left-2 top-1/2 -translate-y-1/2 text-faint" />
        <input
          type="text"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder="Search plugins by name or description…"
          className="w-full rounded-md border border-border bg-background py-1.5 pl-7 pr-2 text-sm focus:border-focus-ring"
        />
      </div>

      {/* Vendor filter chips (hidden when there is nothing to filter) */}
      {vendors.length > 1 && (
        <div className="-mx-1 flex gap-1 overflow-x-auto px-1 pb-0.5 text-xs">
          <button
            type="button"
            onClick={() => setVendorFilter(null)}
            className={clsx(
              'shrink-0 rounded-full border px-2.5 py-1 font-medium',
              vendorFilter === null ? 'border-info bg-info/40 text-secondary' : 'border-border text-muted-foreground hover:text-secondary'
            )}
          >
            All ({assignable.length})
          </button>
          {vendors.map(([v, n]) => (
            <button
              key={v}
              type="button"
              onClick={() => setVendorFilter(vendorFilter === v ? null : v)}
              className={clsx(
                'shrink-0 rounded-full border px-2.5 py-1 font-medium',
                vendorFilter === v ? 'border-info bg-info/40 text-secondary' : 'border-border text-muted-foreground hover:text-secondary'
              )}
            >
              {v} ({n})
            </button>
          ))}
        </div>
      )}

      {/* Card grid — same look as the TrueNAS app-catalog template gallery */}
      <p className="text-[11px] text-faint">
        {visible.length} of {assignable.length} plugins
      </p>
      {visible.length === 0 ? (
        <p className="py-6 text-center text-sm text-muted-foreground">No plugins match your filters.</p>
      ) : (
        <div className="grid max-h-64 grid-cols-1 gap-1.5 overflow-y-auto pr-1 sm:grid-cols-2">
          {visible.map((p) => {
            const isSelected = p.id === selectedId;
            const isTaken = !isSelected && taken.has(p.id);
            return (
              <button
                key={p.id}
                type="button"
                disabled={isTaken}
                title={isTaken ? 'Already assigned in another row' : undefined}
                onClick={() => onPick(p.id)}
                className={clsx(
                  'flex items-start gap-2 rounded-md border px-2.5 py-2 text-left',
                  isSelected ? 'border-info bg-info/40' : isTaken ? 'cursor-not-allowed border-border opacity-45' : 'border-border hover:bg-background'
                )}
              >
                <CatalogIcon plugin={p} />
                <span className="min-w-0 flex-1">
                  <span className="flex items-baseline gap-1.5">
                    <span className="truncate text-sm font-medium text-secondary">{p.name}</span>
                    <span className="shrink-0 font-mono text-[10px] text-faint">v{p.version}</span>
                  </span>
                  {p.description ? (
                    <span className="mt-0.5 line-clamp-2 block text-xs leading-snug text-muted-foreground">{p.description}</span>
                  ) : null}
                </span>
                {isSelected && <Check size={14} className="mt-1 shrink-0 text-info" />}
              </button>
            );
          })}
        </div>
      )}
    </div>
  );
}
