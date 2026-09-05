import { useState } from 'react';
import { useQuery, useQueryClient, useMutation } from '@tanstack/react-query';
import { ArrowDown, ArrowUp, Plus, Trash2 } from 'lucide-react';
import clsx from 'clsx';
import { Layout } from '../components/Layout';
import { api, NetworkLayer } from '../api/client';
import { can } from '../auth/permissions';

/**
 * Layers — the registry behind the topology view's horizontal bands. Seeded
 * with four built-ins (core / distribution / access / endpoint); users may add
 * custom layers and re-color/reorder any of them. Built-in ids are referenced
 * by the classification heuristic, so they cannot be deleted; custom layers
 * can, unless a device override still references one (the API answers 409).
 */

const DEFAULT_COLOR = '#8b5cf6';

export default function Layers() {
  const queryClient = useQueryClient();
  const canWrite = can('layers:write');

  const [newName, setNewName] = useState('');
  const [newColor, setNewColor] = useState(DEFAULT_COLOR);
  const [formError, setFormError] = useState<string | null>(null);

  const layersQuery = useQuery({ queryKey: ['layers'], queryFn: () => api.layers() });
  const layers = layersQuery.data ?? [];

  const invalidate = () => queryClient.invalidateQueries({ queryKey: ['layers'] });

  const createLayer = useMutation({
    mutationFn: (body: { name: string; color?: string }) => api.createLayer(body),
    onSuccess: () => {
      setNewName('');
      setFormError(null);
      invalidate();
    },
    onError: (err: unknown) => setFormError((err as Error).message),
  });

  const updateLayer = useMutation({
    mutationFn: ({ id, body }: { id: string; body: Partial<{ name: string; color: string; sort: number }> }) =>
      api.updateLayer(id, body),
    onSuccess: invalidate,
    onError: (err: unknown) => setFormError((err as Error).message),
  });

  const deleteLayer = useMutation({
    mutationFn: (id: string) => api.deleteLayer(id),
    onSuccess: invalidate,
    onError: (err: unknown) => setFormError((err as Error).message),
  });

  function handleAdd() {
    if (!newName.trim()) return;
    createLayer.mutate({ name: newName.trim(), color: newColor });
  }

  /** Swap the sort values of two adjacent rows (stable, no renumbering needed —
   * the API orders by `sort`, so exchanging the pair's values is enough). */
  function move(index: number, dir: -1 | 1) {
    const target = index + dir;
    if (target < 0 || target >= layers.length) return;
    const a = layers[index];
    const b = layers[target];
    updateLayer.mutate({ id: a.id, body: { sort: b.sort } });
    updateLayer.mutate({ id: b.id, body: { sort: a.sort } });
  }

  return (
    <Layout title="Layers">
      <div className="flex flex-col gap-4">

        {/* Add custom layer */}
        {canWrite && (
          <form
            className="flex items-center gap-2 rounded-md border border-border bg-card p-3 shadow-sm"
            onSubmit={(e) => {
              e.preventDefault();
              handleAdd();
            }}
          >
            <input
              type="color"
              value={newColor}
              onChange={(e) => setNewColor(e.target.value)}
              className="h-8 w-10 cursor-pointer rounded border border-border bg-card p-0.5"
              title="Band color"
            />
            <input
              value={newName}
              onChange={(e) => setNewName(e.target.value)}
              placeholder="New layer name (e.g. DMZ)"
              className="flex-1 rounded-md border border-border px-2 py-1.5 text-sm"
            />
            <button
              type="submit"
              disabled={!newName.trim() || createLayer.isPending}
              className="inline-flex items-center gap-1 rounded-md bg-primary px-3 py-1.5 text-xs font-medium text-white disabled:opacity-40"
            >
              <Plus className="h-3.5 w-3.5" /> Add layer
            </button>
          </form>
        )}

        {formError && (
          <div className="rounded-md border border-danger-border bg-danger px-3 py-2 text-xs text-danger-fg">{formError}</div>
        )}

        {/* Layer list */}
        <div className="overflow-hidden rounded-md border border-border bg-card shadow-sm">
          {layers.length === 0 ? (
            <div className="p-6 text-center text-sm text-faint">Loading layers…</div>
          ) : (
            <table className="w-full text-left text-sm">
              <thead className="border-b border-border bg-background text-[11px] uppercase tracking-wide text-muted-foreground">
                <tr>
                  <th className="w-16 px-3 py-2">Order</th>
                  <th className="px-3 py-2">Name</th>
                  <th className="w-24 px-3 py-2">Color</th>
                  <th className="w-20 px-3 py-2">Type</th>
                  {canWrite && <th className="w-16 px-3 py-2" />}
                </tr>
              </thead>
              <tbody>
                {layers.map((l: NetworkLayer, i) => (
                  <tr key={l.id} className="border-b border-border last:border-0">
                    <td className="px-3 py-2">
                      {canWrite ? (
                        <div className="flex items-center gap-1">
                          <button
                            onClick={() => move(i, -1)}
                            disabled={i === 0}
                            title="Move up"
                            className="rounded p-1 text-faint hover:bg-muted hover:text-secondary disabled:opacity-30"
                          >
                            <ArrowUp className="h-3.5 w-3.5" />
                          </button>
                          <span className="w-4 text-center text-xs tabular-nums text-muted-foreground">{i + 1}</span>
                          <button
                            onClick={() => move(i, 1)}
                            disabled={i === layers.length - 1}
                            title="Move down"
                            className="rounded p-1 text-faint hover:bg-muted hover:text-secondary disabled:opacity-30"
                          >
                            <ArrowDown className="h-3.5 w-3.5" />
                          </button>
                        </div>
                      ) : (
                        <span className="text-xs tabular-nums text-muted-foreground">{i + 1}</span>
                      )}
                    </td>
                    <td className="px-3 py-2">
                      {canWrite ? (
                        <input
                          key={l.id + l.name}
                          defaultValue={l.name}
                          onBlur={(e) => {
                            const v = e.target.value.trim();
                            if (v && v !== l.name) updateLayer.mutate({ id: l.id, body: { name: v } });
                          }}
                          className="w-full rounded border border-transparent px-1 py-0.5 text-sm hover:border-border focus:border-border focus:outline-none"
                        />
                      ) : (
                        <span className="font-medium text-foreground">{l.name}</span>
                      )}
                    </td>
                    <td className="px-3 py-2">
                      {canWrite ? (
                        <input
                          type="color"
                          value={l.color}
                          onChange={(e) => updateLayer.mutate({ id: l.id, body: { color: e.target.value } })}
                          className="h-7 w-10 cursor-pointer rounded border border-border bg-card p-0.5"
                        />
                      ) : (
                        <span className="inline-block h-4 w-8 rounded" style={{ backgroundColor: l.color }} />
                      )}
                    </td>
                    <td className="px-3 py-2">
                      <span
                        className={clsx(
                          'rounded px-1.5 py-0.5 text-[10px] font-medium',
                          l.isBuiltin ? 'bg-muted text-secondary' : 'bg-indigo-50 text-indigo-700'
                        )}
                      >
                        {l.isBuiltin ? 'built-in' : 'custom'}
                      </span>
                    </td>
                    {canWrite && (
                      <td className="px-3 py-2">
                        {!l.isBuiltin && (
                          <button
                            onClick={() => deleteLayer.mutate(l.id)}
                            title={`Delete layer "${l.name}"`}
                            className="rounded p-1 text-faint hover:bg-danger hover:text-danger-fg"
                          >
                            <Trash2 className="h-3.5 w-3.5" />
                          </button>
                        )}
                      </td>
                    )}
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>

        <p className="text-[11px] text-faint">
          Built-in layers cannot be deleted — the auto-classification heuristic references their ids. Custom layers are
          removed only when no device override still points at them.
        </p>
      </div>
    </Layout>
  );
}
