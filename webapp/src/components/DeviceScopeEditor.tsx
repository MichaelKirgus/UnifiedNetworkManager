import { useMemo } from 'react';
import { useQuery } from '@tanstack/react-query';
import { X } from 'lucide-react';
import { api, DeviceScope } from '../api/client';

/**
 * Editor for a device-scope object ({siteIds?, tags?, deviceIds?}). A user/role
 * may see any device matching ANY of the listed rules; an empty scope (or the
 * "Unrestricted" toggle) means full visibility. Reference data (sites, devices,
 * and the union of all device tags) is loaded here so the component is drop-in
 * for both the Users and Roles pages.
 */

interface DeviceScopeEditorProps {
  value: DeviceScope;
  onChange: (scope: DeviceScope) => void;
}

/** One "selected chips + add-dropdown" row for a single scope dimension. */
function ScopePicker({
  label,
  hint,
  selected,
  options,
  onToggle,
}: {
  label: string;
  hint?: string;
  selected: string[];
  /** id → display label for every available option. */
  options: Map<string, string>;
  onToggle: (id: string) => void;
}) {
  const remaining = [...options.entries()].filter(([id]) => !selected.includes(id));

  return (
    <div>
      <label className="mb-1 block text-sm font-medium text-secondary">{label}</label>
      {hint && <p className="mb-2 text-xs text-faint">{hint}</p>}
      <div className="flex flex-wrap items-center gap-1.5">
        {selected.map((id) => (
          <span key={id} className="inline-flex items-center gap-1 rounded-full bg-muted px-2 py-0.5 text-xs font-medium text-secondary">
            {options.get(id) ?? id}
            <button type="button" aria-label={`Remove ${options.get(id) ?? id}`} onClick={() => onToggle(id)} className="rounded p-0.5 hover:bg-border">
              <X className="h-3 w-3" />
            </button>
          </span>
        ))}
        {selected.length === 0 && <span className="text-xs text-faint">None selected</span>}
      </div>
      {remaining.length > 0 && (
        <select
          value=""
          onChange={(e) => { if (e.target.value) onToggle(e.target.value); }}
          className="mt-2 w-full rounded-md border border-border bg-card px-3 py-1.5 text-sm focus:border-slate-500 focus:outline-none"
        >
          <option value="">+ Add {label.toLowerCase()}…</option>
          {remaining.map(([id, label]) => (
            <option key={id} value={id}>{label}</option>
          ))}
        </select>
      )}
    </div>
  );
}

export function DeviceScopeEditor({ value, onChange }: DeviceScopeEditorProps) {
  const unrestricted = !value.siteIds?.length && !value.tags?.length && !value.deviceIds?.length;

  const sitesQuery = useQuery({ queryKey: ['sites'], queryFn: api.sites });
  const devicesQuery = useQuery({ queryKey: ['devices'], queryFn: api.devices });

  // Union of every tag across all devices (the only tags that can ever match).
  const allTags = useMemo(() => {
    const set = new Set<string>();
    for (const d of devicesQuery.data ?? []) for (const t of d.tags) if (t.trim()) set.add(t);
    return [...set].sort((a, b) => a.localeCompare(b));
  }, [devicesQuery.data]);

  const siteOptions = useMemo(() => {
    const m = new Map<string, string>();
    for (const s of sitesQuery.data ?? []) m.set(s.id, s.name);
    return m;
  }, [sitesQuery.data]);

  const deviceOptions = useMemo(() => {
    const m = new Map<string, string>();
    for (const d of devicesQuery.data ?? []) m.set(d.id, `${d.name} (${d.managementAddress})`);
    return m;
  }, [devicesQuery.data]);

  const tagOptions = useMemo(() => {
    const m = new Map<string, string>();
    for (const t of allTags) m.set(t, t);
    return m;
  }, [allTags]);

  function setKey(key: 'siteIds' | 'tags' | 'deviceIds', id: string) {
    const current = value[key] ?? [];
    const next = current.includes(id) ? current.filter((x) => x !== id) : [...current, id];
    onChange({ ...value, [key]: next.length > 0 ? next : undefined });
  }

  return (
    <div className="space-y-4">
      <label className="flex items-start gap-2 rounded-md border border-border bg-muted/40 p-3 text-sm">
        <input
          type="checkbox"
          checked={unrestricted}
          onChange={(e) => { if (e.target.checked) onChange({}); }}
          className="mt-0.5"
        />
        <span>
          <span className="font-medium text-secondary">Unrestricted — can access every device</span>
          <span className="block text-xs text-faint">
            Leave this on (or select no rules below) for full visibility. Selecting any rule restricts the account to matching devices only.
          </span>
        </span>
      </label>

      {!unrestricted && (
        <>
          <p className="text-xs text-faint">
            The account can see a device if it matches ANY of the rules below (union). Changes apply to existing sessions within ~5 s.
          </p>
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
            <ScopePicker label="Sites" hint="All devices assigned to these sites." selected={value.siteIds ?? []} options={siteOptions} onToggle={(id) => setKey('siteIds', id)} />
            <ScopePicker label="Tags" hint="Devices carrying any of these tags." selected={value.tags ?? []} options={tagOptions} onToggle={(id) => setKey('tags', id)} />
            <ScopePicker label="Devices" hint="Specific devices by name." selected={value.deviceIds ?? []} options={deviceOptions} onToggle={(id) => setKey('deviceIds', id)} />
          </div>
        </>
      )}
    </div>
  );
}
