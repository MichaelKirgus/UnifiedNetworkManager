import { useEffect, useRef, useState, type PointerEvent as ReactPointerEvent, type ReactNode } from 'react';
import { ExternalLink, X } from 'lucide-react';

/**
 * Reusable draggable + resizable dialog shell. Every "big" dialog in the app
 * (console, file browser, container logs, …) renders inside this so the drag /
 * resize / viewport-clamp logic lives in exactly one place.
 *
 * - Drag: pointer-capture on the header (buttons keep their own clicks).
 * - Resize: eight edge/corner handles with native cursors; min size enforced.
 * - The panel is clamped back into the viewport when the browser window shrinks.
 * - `onOpenInWindow` optionally adds a "pop out" button that opens the same
 *   content in its own full-window tab (each dialog's page handles the rest).
 */

interface Geom { x: number; y: number; w: number; h: number }

const MIN_W = 380;
const MIN_H = 240;

const clampNum = (v: number, lo: number, hi: number): number => Math.min(Math.max(v, lo), hi);

/** Edge/corner resize handles (Tailwind ships all eight resize cursors). */
const RESIZE_HANDLES: Array<{ edge: string; cls: string }> = [
  { edge: 'n', cls: 'inset-x-3 top-0 h-1.5 cursor-n-resize' },
  { edge: 's', cls: 'inset-x-3 bottom-0 h-1.5 cursor-s-resize' },
  { edge: 'e', cls: 'top-3 bottom-3 right-0 w-1.5 cursor-e-resize' },
  { edge: 'w', cls: 'top-3 bottom-3 left-0 w-1.5 cursor-w-resize' },
  { edge: 'ne', cls: 'right-0 top-0 h-3 w-3 cursor-ne-resize' },
  { edge: 'nw', cls: 'left-0 top-0 h-3 w-3 cursor-nw-resize' },
  { edge: 'se', cls: 'bottom-0 right-0 h-3 w-3 cursor-se-resize' },
  { edge: 'sw', cls: 'bottom-0 left-0 h-3 w-3 cursor-sw-resize' },
];

export interface ResizableDialogProps {
  title: string;
  subtitle?: string;
  /** Leading icon in the header (e.g. <TerminalIcon size={16} />). */
  icon?: ReactNode;
  onClose: () => void;
  /** When provided, renders an "open in a new window" button next to close. */
  onOpenInWindow?: () => void;
  /** Extra header controls rendered before the window/close buttons (e.g. a status pill). */
  headerExtra?: ReactNode;
  /** Default panel size when opened (clamped to the viewport). */
  defaultSize?: { w: number; h: number };
  /** Override the body wrapper classes (default scrolls internally; pass
   * 'min-h-0 flex-1' for content that manages its own layout, e.g. a terminal). */
  bodyClassName?: string;
  children: ReactNode;
  /** Optional footer bar under the body (callers style their own content). */
  footer?: ReactNode;
}

export function ResizableDialog({
  title,
  subtitle,
  icon,
  onClose,
  onOpenInWindow,
  headerExtra,
  defaultSize = { w: 768, h: 520 },
  bodyClassName = 'min-h-0 flex-1 overflow-y-auto',
  children,
  footer,
}: ResizableDialogProps) {
  // Draggable + resizable geometry (centered by default).
  const [geom, setGeom] = useState<Geom>(() => {
    const vw = window.innerWidth;
    const vh = window.innerHeight;
    const w = Math.min(defaultSize.w, vw - 48);
    const h = Math.min(defaultSize.h, vh - 96);
    return { x: (vw - w) / 2, y: Math.max(16, (vh - h) / 2), w, h };
  });
  const dragRef = useRef<{ px: number; py: number; gx: number; gy: number } | null>(null);
  const resizeRef = useRef<{ edge: string; px: number; py: number; g: Geom } | null>(null);

  // Keep the panel inside the viewport when the browser window is resized.
  useEffect(() => {
    const onWindowResize = () => setGeom((g) => {
      const vw = window.innerWidth;
      const vh = window.innerHeight;
      const w = Math.min(g.w, vw - 16);
      const h = Math.min(g.h, vh - 16);
      return { ...g, w, h, x: clampNum(g.x, -(w - 96), vw - 96), y: clampNum(g.y, 0, vh - 48) };
    });
    window.addEventListener('resize', onWindowResize);
    return () => window.removeEventListener('resize', onWindowResize);
  }, []);

  // Drag — pointer capture on the header keeps tracking even outside the panel.
  const startDrag = (e: ReactPointerEvent<HTMLElement>) => {
    if ((e.target as HTMLElement).closest('button')) return; // buttons keep their own clicks
    dragRef.current = { px: e.clientX, py: e.clientY, gx: geom.x, gy: geom.y };
    e.currentTarget.setPointerCapture(e.pointerId);
  };
  const onDragMove = (e: ReactPointerEvent<HTMLElement>) => {
    const d = dragRef.current;
    if (!d) return;
    setGeom((g) => ({
      ...g,
      x: clampNum(d.gx + e.clientX - d.px, -(g.w - 96), window.innerWidth - 96),
      y: clampNum(d.gy + e.clientY - d.py, 0, window.innerHeight - 48),
    }));
  };
  const endDrag = () => { dragRef.current = null; };

  // Resize — one handler for all eight handles; the edge string drives which
  // sides move ('ne' adjusts both north and east).
  const startResize = (edge: string) => (e: ReactPointerEvent<HTMLElement>) => {
    resizeRef.current = { edge, px: e.clientX, py: e.clientY, g: geom };
    e.currentTarget.setPointerCapture(e.pointerId);
    e.stopPropagation();
  };
  const onResizeMove = (e: ReactPointerEvent<HTMLElement>) => {
    const r = resizeRef.current;
    if (!r) return;
    const dx = e.clientX - r.px;
    const dy = e.clientY - r.py;
    setGeom(() => {
      let { x, y } = r.g;
      let w = r.g.w;
      let h = r.g.h;
      if (r.edge.includes('e')) w = clampNum(r.g.w + dx, MIN_W, window.innerWidth - r.g.x);
      if (r.edge.includes('s')) h = clampNum(r.g.h + dy, MIN_H, window.innerHeight - r.g.y);
      if (r.edge.includes('w')) { const nw = clampNum(r.g.w - dx, MIN_W, r.g.x + r.g.w); x += r.g.w - nw; w = nw; }
      if (r.edge.includes('n')) { const nh = clampNum(r.g.h - dy, MIN_H, r.g.y + r.g.h); y += r.g.h - nh; h = nh; }
      return { x, y, w, h };
    });
  };
  const endResize = () => { resizeRef.current = null; };

  return (
    <div className="fixed inset-0 z-50 bg-primary/40" onClick={onClose}>
      <div
        className="absolute flex flex-col overflow-hidden rounded-md border border-border bg-card shadow-xl"
        style={{ left: geom.x, top: geom.y, width: geom.w, height: geom.h }}
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header — also the drag handle (cursor-move). */}
        <header
          className="flex cursor-move touch-none select-none items-center justify-between gap-3 border-b border-border px-4 py-3"
          onPointerDown={startDrag}
          onPointerMove={onDragMove}
          onPointerUp={endDrag}
          onPointerCancel={endDrag}
        >
          <div className="flex min-w-0 items-center gap-2.5">
            {icon && <span className="shrink-0 text-secondary">{icon}</span>}
            <div className="min-w-0">
              <h2 className="truncate text-base font-semibold text-foreground">{title}</h2>
              {subtitle && <p className="mt-0.5 truncate text-xs text-muted-foreground">{subtitle}</p>}
            </div>
          </div>
          <div className="flex shrink-0 items-center gap-2">
            {headerExtra}
            {onOpenInWindow && (
              <button type="button" aria-label={`Open ${title} in a new window`} title="Open in a new window" onClick={onOpenInWindow} className="rounded p-1 text-faint hover:bg-muted">
                <ExternalLink size={16} />
              </button>
            )}
            <button type="button" aria-label={`Close ${title}`} onClick={onClose} className="rounded p-1 text-faint hover:bg-muted">
              <X size={16} />
            </button>
          </div>
        </header>

        {/* Body — scrolls internally by default; callers can override. */}
        <div className={bodyClassName}>{children}</div>

        {footer && (
          <footer className="shrink-0 border-t border-border px-4 py-2">{footer}</footer>
        )}

        {/* Resize handles (edges + corners). */}
        {RESIZE_HANDLES.map((h) => (
          <div
            key={h.edge}
            className={`absolute touch-none ${h.cls}`}
            onPointerDown={startResize(h.edge)}
            onPointerMove={onResizeMove}
            onPointerUp={endResize}
            onPointerCancel={endResize}
          />
        ))}
      </div>
    </div>
  );
}
