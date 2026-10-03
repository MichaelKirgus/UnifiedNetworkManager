import { useState, type ReactNode } from 'react';
import { ExternalLink, X } from 'lucide-react';
import { RESIZE_HANDLES, useDragResize } from '../hooks/useDragResize';

/**
 * Reusable draggable + resizable dialog shell. Every "big" dialog in the app
 * (console, file browser, container logs, …) renders inside this so the drag /
 * resize / viewport-clamp logic lives in exactly one place (useDragResize).
 *
 * - Drag: pointer-capture on the header (buttons keep their own clicks).
 * - Resize: eight edge/corner handles with native cursors; min size enforced.
 * - The panel is clamped back into the viewport when the browser window shrinks.
 * - `onOpenInWindow` optionally adds a "pop out" button that opens the same
 *   content in its own full-window tab (each dialog's page handles the rest).
 */

const MIN_W = 380;
const MIN_H = 240;

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
  const [geom] = useState(() => {
    const vw = window.innerWidth;
    const vh = window.innerHeight;
    const w = Math.min(defaultSize.w, vw - 48);
    const h = Math.min(defaultSize.h, vh - 96);
    return { x: (vw - w) / 2, y: Math.max(16, (vh - h) / 2), w, h };
  });
  const { startDrag, onDragMove, endDrag, startResize, onResizeMove, endResize } = useDragResize({
    initialGeom: () => geom,
    minW: MIN_W,
    minH: MIN_H,
  });

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
