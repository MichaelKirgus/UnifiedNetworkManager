import { forwardRef, useEffect, useImperativeHandle, useMemo, useRef, useState } from 'react';
import { GripVertical, Plus, Star, X } from 'lucide-react';
import clsx from 'clsx';
import { DndContext, closestCenter, PointerSensor, KeyboardSensor, useSensor, useSensors, type DragEndEvent } from '@dnd-kit/core';
import { SortableContext, verticalListSortingStrategy, useSortable, arrayMove } from '@dnd-kit/sortable';
import { CSS } from '@dnd-kit/utilities';
import { allowedSecretTypes, api, CredentialSlotDescriptor, DevicePluginAssignmentInput, Plugin, Secret } from '../api/client';

interface RowState {
  /** Stable key for drag & drop (unique per row, independent of the plugin pick). */
  id: string;
  pluginId: string;
  secretId: string;
  /** Bound extra credential slots (slot name → secrets.id). */
  slotSecrets: Record<string, string>;
}

const emptyRow = (): RowState => ({ id: crypto.randomUUID(), pluginId: '', secretId: '', slotSecrets: {} });

/** One draggable assignment row: grip handle + position badge (1 = primary) +
 * plugin/credential pickers. The whole card is the sortable element; only the
 * grip carries the drag listeners so the selects stay fully clickable. */
function SortablePluginRow({
  row,
  position,
  isPrimary,
  removable,
  availablePlugins,
  pluginMeta,
  secretsOfType,
  secretsOfSlot,
  onUpdate,
  onSlotSecret,
  onRemove,
}: {
  row: RowState;
  /** 1-based display position (position 1 is the primary plugin). */
  position: number;
  isPrimary: boolean;
  removable: boolean;
  availablePlugins: Plugin[];
  pluginMeta: Record<string, { requiredTypes: string[]; slots: CredentialSlotDescriptor[] }>;
  secretsOfType: (types: string[]) => Secret[];
  secretsOfSlot: (slot: CredentialSlotDescriptor) => Secret[];
  onUpdate: (patch: Partial<RowState>) => void;
  onSlotSecret: (slotName: string, secretId: string) => void;
  onRemove: () => void;
}) {
  const { attributes, listeners, setNodeRef, transform, transition, isDragging } = useSortable({ id: row.id });
  const meta = row.pluginId ? pluginMeta[row.pluginId] : undefined;
  // Multi-type primary support: a plugin may accept several secret types for
  // its main credential (e.g. usernamePassword OR sshKeyPair). Empty list =
  // undeclared → the picker offers every secret type.
  const requiredTypes = meta?.requiredTypes ?? [];
  const slots = meta?.slots ?? [];

  return (
    <li
      ref={setNodeRef}
      style={{ transform: CSS.Transform.toString(transform), transition }}
      className={clsx(
        'rounded-md border bg-background p-3',
        isPrimary ? 'border-primary/50' : 'border-border',
        isDragging && 'z-10 opacity-70 shadow-lg'
      )}
    >
      <div className="flex items-start gap-2">
        {/* Grip handle — the only part that starts a drag (touch-none keeps it
            usable on touch devices). */}
        <button
          type="button"
          aria-label={`Reorder plugin ${position}`}
          title="Drag to reorder — position 1 is primary"
          className="mt-0.5 cursor-grab touch-none rounded p-1 text-faint hover:bg-muted hover:text-secondary active:cursor-grabbing"
          {...attributes}
          {...listeners}
        >
          <GripVertical className="h-4 w-4" />
        </button>

        {/* Position badge — position 1 doubles as the primary indicator. */}
        <span
          title={isPrimary ? 'Primary plugin (position 1)' : `Fallback position ${position}`}
          className={clsx(
            'mt-0.5 flex h-6 w-6 shrink-0 items-center justify-center rounded-full text-xs font-bold',
            isPrimary ? 'bg-primary text-white' : 'bg-muted text-secondary'
          )}
        >
          {isPrimary ? <Star className="h-3.5 w-3.5" /> : position}
        </span>

        {/* Plugin + primary credentials share one aligned row; the remove
            control sits right-aligned on the same line. */}
        <div className="grid min-w-0 flex-1 grid-cols-1 gap-2 sm:grid-cols-[1fr_1fr_auto]">
          <div>
            <label className="mb-1 block text-xs font-medium text-secondary">Plugin</label>
            <select
              required
              className="w-full rounded-md border border-border bg-card px-2 py-1.5 text-sm"
              value={row.pluginId}
              onChange={(e) => onUpdate({ pluginId: e.target.value, secretId: '', slotSecrets: {} })}
            >
              <option value="" disabled>
                Select a plugin
              </option>
              {availablePlugins.map((p) => (
                <option key={p.id} value={p.id}>
                  {p.name} ({p.version})
                </option>
              ))}
            </select>
          </div>
          <div>
            <label className="mb-1 block text-xs font-medium text-secondary">
              Credentials{requiredTypes.length > 0 ? ` (${requiredTypes.join(' | ')})` : ''}
            </label>
            <select
              className="w-full rounded-md border border-border bg-card px-2 py-1.5 text-sm"
              value={row.secretId}
              onChange={(e) => onUpdate({ secretId: e.target.value })}
            >
              <option value="">No credentials</option>
              {secretsOfType(requiredTypes).map((s) => (
                <option key={s.id} value={s.id}>
                  {s.label || s.id} [{s.type}]
                </option>
              ))}
            </select>
          </div>
          <div className="flex items-center justify-end self-end pb-1">
            {removable && (
              <button
                type="button"
                aria-label={`Remove plugin row ${position}`}
                title="Remove this plugin"
                onClick={onRemove}
                className="rounded-md p-1.5 text-faint hover:bg-danger hover:text-danger-fg"
              >
                <X className="h-4 w-4" />
              </button>
            )}
          </div>
        </div>
      </div>

      {/* Extra credential slots — each gets its own full-width, evenly
          aligned cell in a 2-column grid (no more ragged spans). */}
      {slots.length > 0 && (
        <div className="mt-2 grid grid-cols-1 gap-2 pl-8 sm:grid-cols-2">
          {slots.map((slot) => (
            <div key={slot.name}>
              <label
                className="mb-1 block text-xs font-medium text-secondary"
                title={slot.description}
              >
                {slot.description || `Credential slot "${slot.name}"`} ({allowedSecretTypes(slot).join(' | ')})
                {!slot.required && <span className="ml-1 font-normal text-faint">optional</span>}
              </label>
              <select
                className="w-full rounded-md border border-border bg-card px-2 py-1.5 text-sm"
                value={row.slotSecrets[slot.name] ?? ''}
                onChange={(e) => onSlotSecret(slot.name, e.target.value)}
              >
                <option value="">Not set</option>
                {secretsOfSlot(slot).map((s) => (
                  <option key={s.id} value={s.id}>
                    {s.label || s.id} [{s.type}]
                  </option>
                ))}
              </select>
            </div>
          ))}
        </div>
      )}
    </li>
  );
}

/** Imperative handle so a parent with ONE central Save button can trigger the
 * builder's own (validating) submission programmatically. */
export interface PluginAssignmentBuilderHandle {
  submit: () => void;
}

/**
 * Multi-plugin assignment builder with drag & drop ordering. Each row binds one
 * plugin to a device with its own credential source (filtered by the plugin's
 * required secret type). The FIRST row is the primary plugin — drag rows via
 * their grip handle to reorder (position 0 = primary, later positions are the
 * fallback sequence for future failover logic). Adding plugins appends to the
 * end and never steals primary.
 */
export const PluginAssignmentBuilder = forwardRef<PluginAssignmentBuilderHandle, {
  plugins: Plugin[];
  secrets: Secret[];
  /** Existing assignments to prefill (e.g. when adding more to a device). */
  initial?: DevicePluginAssignmentInput[];
  /** Plugins already assigned elsewhere — hidden from the options list. */
  excludedPluginIds?: string[];
  onSubmit: (assignments: DevicePluginAssignmentInput[]) => void;
  submitLabel?: string;
  busy?: boolean;
  /** Reports the currently selected plugin ids as rows change (incl. initial).
   * Lets the parent derive vendor-specific form fields (e.g. model catalogs)
   * from exactly the plugins assigned to this device. */
  onRowsChange?: (pluginIds: string[]) => void;
  /** Reports whether any row holds a selection that differs from `initial` —
   * lets a parent with one central Save button know when assignments changed. */
  onDirtyChange?: (dirty: boolean) => void;
  /** Hide the built-in submit button so the parent can own ONE central save
   * for the whole form (device create/edit). Defaults to true (own button). */
  showSubmitButton?: boolean;
  /** When adding plugins to a device that ALREADY has assignments, new rows are
   * appended after the existing ones and never steal primary. Set this in the
   * "Add plugin" modal; leave it off for create/edit forms where row 1 = primary. */
  appendMode?: boolean;
}>(({ plugins, secrets, initial = [], excludedPluginIds = [], onSubmit, submitLabel = 'Save', busy = false, onRowsChange, onDirtyChange, showSubmitButton = true, appendMode = false }, ref) => {
  // Secret-provider plugins serve the Secrets page, not devices — they must
  // never appear in this picker (they have no device-facing capabilities).
  const availablePlugins = useMemo(
    () => plugins.filter((p) => !excludedPluginIds.includes(p.id) && !(p.capabilities ?? []).includes('secretsProvider')),
    [plugins, excludedPluginIds]
  );
  const [rows, setRows] = useState<RowState[]>(() =>
    initial.length > 0
      ? initial.map((a) => ({
          id: crypto.randomUUID(),
          pluginId: a.pluginId,
          secretId: a.secretId ?? '',
          slotSecrets: Object.fromEntries(
            Object.entries(a.extraCredentials ?? {}).filter(
              (entry): entry is [string, string] => typeof entry[1] === 'string' && entry[1] !== ''
            )
          ),
        }))
      : [emptyRow()]
  );

  // Required secret types + declared credential slots per chosen plugin (drive
  // the credentials dropdown and any per-slot pickers).
  const [pluginMeta, setPluginMeta] = useState<Record<string, { requiredTypes: string[]; slots: CredentialSlotDescriptor[] }>>({});
  useEffect(() => {
    const ids = Array.from(new Set(rows.map((r) => r.pluginId).filter(Boolean)));
    let cancelled = false;
    Promise.all(
      ids.map(async (id) => {
        try {
          const res = await api.requiredSecretType(id);
          // Multi-type list wins; fall back to the legacy single type.
          const types =
            Array.isArray(res.requiredSecretTypes) && res.requiredSecretTypes.length > 0
              ? res.requiredSecretTypes
              : res.requiredSecretType
                ? [res.requiredSecretType]
                : [];
          return [id, { requiredTypes: types, slots: res.credentialSlots ?? [] }] as const;
        } catch {
          return [id, { requiredTypes: [], slots: [] }] as const;
        }
      })
    ).then((entries) => {
      if (!cancelled) setPluginMeta(Object.fromEntries(entries));
    });
    return () => {
      cancelled = true;
    };
  }, [rows]);

  /** Secrets compatible with ANY of the given secret types (empty list = any). */
  function secretsOfType(types: string[]): Secret[] {
    if (types.length === 0) return secrets;
    return secrets.filter((s) => types.includes(s.type));
  }

  /** Secrets compatible with ANY of the slot's allowed types. */
  function secretsOfSlot(slot: CredentialSlotDescriptor): Secret[] {
    const types = allowedSecretTypes(slot);
    if (types.length === 0) return [];
    return secrets.filter((s) => types.includes(s.type));
  }

  function updateRow(id: string, patch: Partial<RowState>) {
    setRows((rs) => rs.map((r) => (r.id === id ? { ...r, ...patch } : r)));
  }

  function updateSlotSecret(id: string, slotName: string, secretId: string) {
    setRows((rs) =>
      rs.map((r) => {
        if (r.id !== id) return r;
        const next = { ...r.slotSecrets };
        if (secretId) next[slotName] = secretId;
        else delete next[slotName];
        return { ...r, slotSecrets: next };
      })
    );
  }

  // Drag & drop reordering (same @dnd-kit pattern as the nav customizer). The
  // first row is always primary — dragging a row to the top promotes it.
  const sensors = useSensors(
    useSensor(PointerSensor, { activationConstraint: { distance: 4 } }),
    useSensor(KeyboardSensor)
  );

  function handleDragEnd(event: DragEndEvent) {
    const { active, over } = event;
    if (!over || active.id === over.id) return;
    setRows((rs) => arrayMove(rs, rs.findIndex((r) => r.id === String(active.id)), rs.findIndex((r) => r.id === String(over.id))));
  }

  const usedPluginIds = useMemo(
    () => new Set(rows.map((r) => r.pluginId).filter(Boolean)),
    [rows]
  );

  // Report the selected plugin ids to the parent (initial rows included) so it
  // can derive vendor-specific fields — e.g. model catalogs — from exactly the
  // plugins assigned here. The callback is kept in a ref: only `rows` should
  // retrigger this, not a new closure on every parent render.
  const onRowsChangeRef = useRef(onRowsChange);
  onRowsChangeRef.current = onRowsChange;
  useEffect(() => {
    onRowsChangeRef.current?.(Array.from(new Set(rows.map((r) => r.pluginId).filter(Boolean))));
  }, [rows]);

  // Dirty tracking: compare the current rows against `initial` so a parent
  // with one central Save button can tell when assignments were touched.
  const onDirtyChangeRef = useRef(onDirtyChange);
  onDirtyChangeRef.current = onDirtyChange;
  useEffect(() => {
    // Key-sorted JSON so slot-map key order never causes false "dirty" states.
    const stableJson = (obj: Record<string, unknown>) =>
      JSON.stringify(Object.keys(obj).sort().reduce<Record<string, unknown>>((acc, k) => ({ ...acc, [k]: obj[k] }), {}));
    // Order matters now (position 0 = primary), so compare sequences directly.
    const rowKey = (pluginId: string, secretId: string | null, slots: Record<string, string>) =>
      `${pluginId}|${secretId ?? ''}|${stableJson(slots)}`;
    const current = rows
      .filter((r) => r.pluginId)
      .map((r) => rowKey(r.pluginId, r.secretId || null, Object.keys(r.slotSecrets).length > 0 ? r.slotSecrets : {}));
    const base = initial.map((a) => rowKey(a.pluginId, a.secretId ?? null, (a.extraCredentials ?? {}) as Record<string, string>));
    onDirtyChangeRef.current?.(current.length !== base.length || current.some((k, i) => k !== base[i]));
  }, [rows, initial]);

  function submit() {
    const valid = rows.filter((r) => r.pluginId);
    if (valid.length === 0) return;
    // The FIRST row is the primary plugin — position encodes priority/fallback.
    // In appendMode (adding to a device that already has plugins) every row is
    // appended after the existing ones and never steals primary.
    onSubmit(
      valid.map((r, i) => ({
        pluginId: r.pluginId,
        secretId: r.secretId || null,
        isPrimary: !appendMode && i === 0,
        extraCredentials:
          Object.keys(r.slotSecrets).length > 0 ? { ...r.slotSecrets } : undefined,
      }))
    );
  }

  // Expose submit() so a parent's single central Save button can trigger the
  // builder's validating submission without its own <button type="submit">.
  // No dep array on purpose — always wrap the FRESH closures (rows + onSubmit).
  useImperativeHandle(ref, () => ({ submit }));

  return (
    <form onSubmit={(e) => { e.preventDefault(); submit(); }} noValidate>
      <DndContext sensors={sensors} collisionDetection={closestCenter} onDragEnd={handleDragEnd}>
        <SortableContext items={rows.map((r) => r.id)} strategy={verticalListSortingStrategy}>
          <ul className="space-y-2">
            {rows.map((row, index) => (
              <SortablePluginRow
                key={row.id}
                row={row}
                position={index + 1}
                isPrimary={index === 0 && !appendMode}
                removable={rows.length > 1}
                availablePlugins={availablePlugins}
                pluginMeta={pluginMeta}
                secretsOfType={secretsOfType}
                secretsOfSlot={secretsOfSlot}
                onUpdate={(patch) => updateRow(row.id, patch)}
                onSlotSecret={(slotName, secretId) => updateSlotSecret(row.id, slotName, secretId)}
                onRemove={() => setRows((rs) => rs.filter((r) => r.id !== row.id))}
              />
            ))}
          </ul>
        </SortableContext>
      </DndContext>

      <div className="flex items-center justify-between">
        <button
          type="button"
          onClick={() => setRows((rs) => [...rs, emptyRow()])}
          disabled={availablePlugins.length === 0 || usedPluginIds.size >= availablePlugins.length}
          className="flex items-center gap-1.5 rounded-md border border-border px-3 py-1.5 text-sm font-medium text-secondary hover:bg-background disabled:opacity-40"
        >
          <Plus className="h-4 w-4" />
          Add plugin
        </button>
        {showSubmitButton && (
          <button
            type="submit"
            disabled={busy}
            className="flex items-center gap-1.5 rounded-md bg-primary px-4 py-2 text-sm font-semibold text-white hover:bg-primary-hover disabled:opacity-50"
          >
            {busy ? 'Saving…' : submitLabel}
          </button>
        )}
      </div>
    </form>
  );
});
