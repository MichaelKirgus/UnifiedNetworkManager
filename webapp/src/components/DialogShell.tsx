import { useEffect, useLayoutEffect, useRef, type ElementType, type MouseEvent as ReactMouseEvent, type FormHTMLAttributes, type ReactNode } from 'react';
import clsx from 'clsx';
import { X } from 'lucide-react';
import { RESIZE_HANDLES, useDragResize } from '../hooks/useDragResize';

/**
 * Reusable modal-dialog shell — the standard "small/medium" dialog used across
 * the app (plugin settings, action forms, schedule, clock sync, …). It exists so
 * every dialog scrolls identically when its content exceeds the viewport:
 *
 * - The overlay is `fixed inset-0`; the panel opens CENTERED and sized to its
 *   CONTENT (measured before first paint), capped by `maxWidth` / `bodyMaxHeight`.
 * - Movable + resizable like ResizableDialog — both shells share the same
 *   drag/resize/viewport-clamp logic via the useDragResize hook. Drag from the
 *   header; resize from any edge or corner (the panel keeps its size after that).
 * - The BODY scrolls internally (`overflow-y-auto`, capped by `bodyMaxHeight`)
 *   and an optional fixed footer keeps the action buttons reachable — so long
 *   forms (e.g. a plugin with many options) never get cut off.
 * - `tag` lets form-driven dialogs render the panel as a `<form>` (so Enter /
 *   submit still work); all remaining props are forwarded to that element.
 *
 * Bigger, fixed-size "window" surfaces (console, file browser, container logs)
 * use `ResizableDialog` instead — same hook, different default geometry.
 */

export interface DialogShellProps extends Omit<FormHTMLAttributes<HTMLFormElement>, 'title'> {
  /** Heading text (or node) for the dialog header. */
  title: ReactNode;
  /** Small secondary line under the title (e.g. a description or device name). */
  subtitle?: ReactNode;
  /** Leading icon in the header (e.g. <CalendarClock className="h-4 w-4 text-primary" />). */
  icon?: ReactNode;
  onClose: () => void;
  /** Optional fixed footer bar under the body (callers style their own buttons). */
  footer?: ReactNode;
  /** Panel element — 'div' by default, 'form' for submit-driven dialogs. */
  tag?: ElementType;
  /** Overlay stacking order (default z-50; pass a higher value to stack above other dialogs). */
  zIndex?: string;
  /** Max panel width (Tailwind class, e.g. 'max-w-md'; the panel hugs its content up to this — default max-w-lg). */
  maxWidth?: string;
  /** Max height of the scrolling body (CSS value, default 'min(70vh,640px)'). */
  bodyMaxHeight?: string;
  /** Extra classes for the body wrapper. */
  bodyClassName?: string;
  children: ReactNode;
}

export function DialogShell({
  title,
  subtitle,
  icon,
  onClose,
  footer,
  tag = 'div',
  zIndex = 'z-50',
  maxWidth = 'max-w-lg',
  bodyMaxHeight = 'min(70vh,640px)',
  bodyClassName,
  children,
  className,
  ...rest
}: DialogShellProps) {
  const Panel: ElementType = tag;

  // Draggable + resizable geometry. Until the first measurement below runs, the
  // panel is sized by its classes (w-full + maxWidth cap); afterwards the inline
  // style takes over so drag/resize work like in ResizableDialog.
  const { geom, setGeom, startDrag, onDragMove, endDrag, startResize, onResizeMove, endResize } = useDragResize({
    initialGeom: () => ({ x: 0, y: 0, w: 0, h: 320 }),
    minW: 280,
    minH: 140,
  });
  const panelRef = useRef<HTMLElement | null>(null);
  // Once the user resizes the panel manually, stop auto-fitting its size.
  const userAdjusted = useRef(false);

  /** The panel's natural size: header + body (capped by bodyMaxHeight) + footer. */
  function naturalSize(el: HTMLElement): { w: number; h: number } {
    const prevH = el.style.height;
    el.style.height = 'auto'; // let the content dictate — the body stays capped
    // offsetWidth/offsetHeight are border-box (Tailwind preflight), so this is
    // EXACTLY the inline height to set afterwards — no scrollbar, no clipping.
    const w = Math.min(el.offsetWidth, window.innerWidth - 32);
    const h = Math.min(el.offsetHeight, window.innerHeight - 32);
    el.style.height = prevH; // restore — the state update takes over
    return { w, h };
  }

  // Fit the panel to its natural content size once on mount (before first paint),
  // then center it. Short dialogs hug their content; long ones open at the body's
  // maxHeight cap and scroll internally.
  useLayoutEffect(() => {
    const el = panelRef.current;
    if (!el) return;
    const { w, h } = naturalSize(el);
    setGeom({ x: Math.max(16, (window.innerWidth - w) / 2), y: Math.max(16, (window.innerHeight - h) / 2), w, h });
  }, []);

  // Many dialogs load their content asynchronously (schemas, compose YAML, …)
  // — keep fitting the panel to it until the user resizes manually. Two
  // triggers: the body's box size (viewport resize changes its maxHeight cap),
  // and DOM mutations inside it (loading → form swaps). The mutation observer
  // is essential because the body's own box stays constrained by the panel's
  // fixed height, so content growth alone never resizes it.
  useEffect(() => {
    const el = panelRef.current;
    if (!el) return;
    const body = el.querySelector(':scope > div');
    if (!(body instanceof HTMLElement)) return;
    let raf = 0;
    const fit = () => {
      raf = 0;
      if (userAdjusted.current) return;
      setGeom((g) => {
        const { h } = naturalSize(el);
        if (Math.abs(h - g.h) < 1) return g;
        return { ...g, h, y: Math.max(0, Math.min(g.y, window.innerHeight - h - 16)) };
      });
    };
    const scheduleFit = () => { if (!raf) raf = requestAnimationFrame(fit); };
    const ro = new ResizeObserver(scheduleFit);
    ro.observe(body);
    const mo = new MutationObserver(scheduleFit);
    mo.observe(body, { childList: true, subtree: true });
    return () => { ro.disconnect(); mo.disconnect(); if (raf) cancelAnimationFrame(raf); };
  }, []);

  return (
    <div className={`fixed inset-0 ${zIndex} bg-primary/40`} onClick={onClose}>
      <Panel
        {...(tag === 'form' ? rest : {})}
        ref={panelRef}
        className={clsx('absolute flex w-full flex-col overflow-hidden rounded-md border border-border bg-card shadow-xl', maxWidth, className)}
        style={{ left: geom.x || undefined, top: geom.y || undefined, width: geom.w || undefined, height: geom.h }}
        onClick={(e: ReactMouseEvent<HTMLElement>) => e.stopPropagation()}
      >
        {/* Header — also the drag handle (cursor-move). */}
        <header
          className="flex shrink-0 cursor-move touch-none select-none items-center justify-between gap-3 border-b border-border px-4 py-3"
          onPointerDown={startDrag}
          onPointerMove={onDragMove}
          onPointerUp={endDrag}
          onPointerCancel={endDrag}
        >
          <div className="min-w-0">
            <h2 className="flex min-w-0 items-center gap-2 text-base font-semibold text-foreground">
              {icon}
              <span className="min-w-0 truncate">{title}</span>
            </h2>
            {subtitle && <p className="mt-0.5 text-xs text-muted-foreground">{subtitle}</p>}
          </div>
          <button type="button" aria-label="Close dialog" onClick={onClose} className="shrink-0 rounded p-1 text-faint hover:bg-muted">
            <X className="h-4 w-4" />
          </button>
        </header>

        {/* Body — scrolls internally so long content is never cut off. */}
        <div className={clsx('min-h-0 flex-1 overflow-y-auto px-4 py-3', bodyClassName)} style={{ maxHeight: bodyMaxHeight }}>{children}</div>

        {footer && (
          <footer className="shrink-0 border-t border-border px-4 py-3">{footer}</footer>
        )}

        {/* Resize handles (edges + corners). */}
        {RESIZE_HANDLES.map((h) => (
          <div
            key={h.edge}
            className={`absolute touch-none ${h.cls}`}
            onPointerDown={(e) => { userAdjusted.current = true; startResize(h.edge)(e); }}
            onPointerMove={onResizeMove}
            onPointerUp={endResize}
            onPointerCancel={endResize}
          />
        ))}
      </Panel>
    </div>
  );
}
