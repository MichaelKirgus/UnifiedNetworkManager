import { useEffect, useRef, useState } from 'react';
import clsx from 'clsx';
import { useQueryClient } from '@tanstack/react-query';
import { DndContext, closestCenter, PointerSensor, KeyboardSensor, useSensor, useSensors, type DragEndEvent } from '@dnd-kit/core';
import { SortableContext, verticalListSortingStrategy, useSortable, arrayMove } from '@dnd-kit/sortable';
import { CSS } from '@dnd-kit/utilities';
import { GripVertical, RotateCcw, X } from 'lucide-react';
import { api, type NavPreferences } from '../api/client';
import type { NavItem } from './navItems';

interface Props {
  /** Permission-visible nav items (already in the user's current order). */
  items: NavItem[];
  initialOrder: string[];
  initialHidden: string[];
  onClose: () => void;
}

/** One draggable row: drag handle + icon + label + visibility checkbox. */
function SortableRow({ item, hidden, onToggle }: { item: NavItem; hidden: boolean; onToggle: (path: string) => void }) {
  const { attributes, listeners, setNodeRef, transform, transition, isDragging } = useSortable({ id: item.to });
  const Icon = item.icon;
  return (
    <li
      ref={setNodeRef}
      style={{ transform: CSS.Transform.toString(transform), transition }}
      className={clsx(
        'flex items-center gap-2 rounded-md border border-border bg-card px-1.5 py-1',
        isDragging && 'z-10 opacity-70 shadow-lg'
      )}
    >
      <button
        type="button"
        aria-label={`Reorder ${item.label}`}
        className="cursor-grab touch-none rounded p-1 text-secondary hover:bg-muted active:cursor-grabbing"
        {...attributes}
        {...listeners}
      >
        <GripVertical className="h-4 w-4" />
      </button>
      <Icon className="h-4 w-4 shrink-0 text-secondary" />
      <span className={clsx('flex-1 truncate text-sm', hidden ? 'text-muted-foreground line-through' : 'text-foreground')}>
        {item.label}
      </span>
      <input
        type="checkbox"
        aria-label={`Show ${item.label}`}
        checked={!hidden}
        onChange={() => onToggle(item.to)}
        className="h-4 w-4 accent-[var(--color-primary)]"
      />
    </li>
  );
}

/**
 * Inline panel for reordering + hiding sidebar pages. Every change auto-saves to
 * the user's DB-backed preferences (debounced); no explicit Save button. Reset
 * restores the default order and shows every page again.
 */
export function NavCustomizer({ items, initialOrder, initialHidden, onClose }: Props) {
  const queryClient = useQueryClient();

  // Local working state — initialized from the loaded prefs (or defaults).
  const [order, setOrder] = useState<string[]>(() => initialOrder.length ? initialOrder : items.map((i) => i.to));
  const [hidden, setHidden] = useState<Set<string>>(() => new Set(initialHidden));
  const [status, setStatus] = useState<'idle' | 'saving' | 'saved' | 'error'>('idle');

  // Keep the working list in sync with the (permission-visible) item set.
  useEffect(() => {
    setOrder((prev) => {
      const known = new Set(items.map((i) => i.to));
      const kept = prev.filter((p) => known.has(p));
      const missing = items.map((i) => i.to).filter((p) => !kept.includes(p));
      return [...kept, ...missing];
    });
  }, [items]);

  // Auto-save (debounced ~300ms to coalesce rapid drags/toggles).
  const firstRun = useRef(true);
  useEffect(() => {
    if (firstRun.current) {
      firstRun.current = false;
      return;
    }
    setStatus('saving');
    const t = window.setTimeout(async () => {
      try {
        await api.setNavPrefs({ navOrder: order, hiddenPages: [...hidden] });
        queryClient.setQueryData(['navPrefs'], { navOrder: order, hiddenPages: [...hidden] } satisfies NavPreferences);
        setStatus('saved');
      } catch {
        setStatus('error');
      }
    }, 300);
    return () => window.clearTimeout(t);
  }, [order, hidden, queryClient]);

  const sensors = useSensors(
    useSensor(PointerSensor, { activationConstraint: { distance: 4 } }),
    useSensor(KeyboardSensor)
  );

  function handleDragEnd(event: DragEndEvent) {
    const { active, over } = event;
    if (over && active.id !== over.id) {
      setOrder((prev) => arrayMove(prev, prev.indexOf(String(active.id)), prev.indexOf(String(over.id))));
    }
  }

  function toggleHidden(path: string) {
    setHidden((prev) => {
      const next = new Set(prev);
      if (next.has(path)) next.delete(path);
      else next.add(path);
      return next;
    });
  }

  function reset() {
    setOrder(items.map((i) => i.to)); // default order
    setHidden(new Set()); // show everything
  }

  const statusText =
    status === 'saving' ? 'Saving…' : status === 'saved' ? 'Saved' : status === 'error' ? 'Save failed — will retry on next change' : '';

  return (
    <div className="flex max-h-[50vh] flex-col gap-2 p-3">
      <div className="flex items-center justify-between gap-2">
        <h2 className="text-sm font-semibold text-foreground">Customize navigation</h2>
        <div className="flex items-center gap-1">
          {statusText && (
            <span className={clsx('text-xs', status === 'error' ? 'text-danger' : 'text-muted-foreground')}>{statusText}</span>
          )}
          <button
            type="button"
            onClick={reset}
            title="Reset to default order and show all pages"
            className="flex items-center gap-1 rounded-md px-2 py-1 text-xs font-medium text-secondary hover:bg-muted"
          >
            <RotateCcw className="h-3.5 w-3.5" /> Reset
          </button>
          <button type="button" onClick={onClose} aria-label="Close" title="Close" className="rounded-md p-1 text-secondary hover:bg-muted">
            <X className="h-4 w-4" />
          </button>
        </div>
      </div>

      <p className="text-xs text-muted-foreground">Drag to reorder. Uncheck a page to hide it from the sidebar.</p>

      <DndContext sensors={sensors} collisionDetection={closestCenter} onDragEnd={handleDragEnd}>
        <SortableContext items={order} strategy={verticalListSortingStrategy}>
          <ul className="flex flex-col gap-1 overflow-y-auto pr-1">
            {order.map((path) => {
              const item = items.find((i) => i.to === path);
              if (!item) return null;
              return <SortableRow key={path} item={item} hidden={hidden.has(path)} onToggle={toggleHidden} />;
            })}
          </ul>
        </SortableContext>
      </DndContext>
    </div>
  );
}
