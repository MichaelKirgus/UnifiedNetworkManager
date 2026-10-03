import type { ElementType, MouseEvent as ReactMouseEvent, FormHTMLAttributes, ReactNode } from 'react';
import clsx from 'clsx';
import { X } from 'lucide-react';

/**
 * Reusable modal-dialog shell — the standard "small/medium" dialog used across
 * the app (plugin settings, action forms, schedule, clock sync, …). It exists so
 * every dialog scrolls identically when its content exceeds the viewport:
 *
 * - The overlay is `fixed inset-0` and centers the panel.
 * - The PANEL has a fixed header (title + close), an internally-scrolling BODY
 *   (`max-h-[min(70vh,640px)] overflow-y-auto`) and an optional fixed footer —
 *   so long forms (e.g. a plugin with many options) never get cut off and the
 *   action buttons stay reachable without scrolling.
 * - `tag` lets form-driven dialogs render the panel as a `<form>` (so Enter /
 *   submit still work); all remaining props are forwarded to that element.
 *
 * Bigger, draggable/resizable surfaces (console, file browser, container logs)
 * use `ResizableDialog` instead — same "body scrolls internally" contract.
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
  /** Max panel width (Tailwind class, default max-w-lg). */
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
  return (
    <div className={`fixed inset-0 ${zIndex} flex items-start justify-center overflow-y-auto bg-primary/40 p-6`} onClick={onClose}>
      <Panel
        {...(tag === 'form' ? rest : {})}
        className={clsx('w-full rounded-md border border-border bg-card shadow-xl', maxWidth, className)}
        onClick={(e: ReactMouseEvent<HTMLElement>) => e.stopPropagation()}
      >
        <header className="flex shrink-0 items-center justify-between gap-3 border-b border-border px-4 py-3">
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
        <div className={clsx('overflow-y-auto px-4 py-3', bodyClassName)} style={{ maxHeight: bodyMaxHeight }}>{children}</div>

        {footer && (
          <footer className="shrink-0 border-t border-border px-4 py-3">{footer}</footer>
        )}
      </Panel>
    </div>
  );
}
