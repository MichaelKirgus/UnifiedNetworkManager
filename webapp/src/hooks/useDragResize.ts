import { useEffect, useRef, useState, type PointerEvent as ReactPointerEvent } from 'react';

/** Panel geometry in viewport pixels (absolute position + size). */
export interface PanelGeom { x: number; y: number; w: number; h: number }

const clampNum = (v: number, lo: number, hi: number): number => Math.min(Math.max(v, lo), hi);

/** Edge/corner resize handles (Tailwind ships all eight resize cursors). */
export const RESIZE_HANDLES: Array<{ edge: string; cls: string }> = [
  { edge: 'n', cls: 'inset-x-3 top-0 h-1.5 cursor-n-resize' },
  { edge: 's', cls: 'inset-x-3 bottom-0 h-1.5 cursor-s-resize' },
  { edge: 'e', cls: 'top-3 bottom-3 right-0 w-1.5 cursor-e-resize' },
  { edge: 'w', cls: 'top-3 bottom-3 left-0 w-1.5 cursor-w-resize' },
  { edge: 'ne', cls: 'right-0 top-0 h-3 w-3 cursor-ne-resize' },
  { edge: 'nw', cls: 'left-0 top-0 h-3 w-3 cursor-nw-resize' },
  { edge: 'se', cls: 'bottom-0 right-0 h-3 w-3 cursor-se-resize' },
  { edge: 'sw', cls: 'bottom-0 left-0 h-3 w-3 cursor-sw-resize' },
];

export interface DragResizeOptions {
  /** Computes the initial geometry (callers center it themselves). */
  initialGeom: () => PanelGeom;
  /** Minimum width while resizing (default 320). */
  minW?: number;
  /** Minimum height while resizing (default 160). */
  minH?: number;
}

/**
 * Shared drag + resize geometry for dialog panels. Both ResizableDialog
 * (fixed-size "window" dialogs: console, file browser, container logs) and
 * DialogShell (content-sized form dialogs) use this so the pointer-capture /
 * viewport-clamp logic lives in exactly one place.
 *
 * - Drag: pointer capture on the header; buttons inside keep their own clicks.
 * - Resize: eight edge/corner handles; min size + viewport edges enforced.
 * - The panel is clamped back into the viewport when the browser window shrinks.
 */
export function useDragResize({ initialGeom, minW = 320, minH = 160 }: DragResizeOptions) {
  const [geom, setGeom] = useState<PanelGeom>(initialGeom);
  const dragRef = useRef<{ px: number; py: number; gx: number; gy: number } | null>(null);
  const resizeRef = useRef<{ edge: string; px: number; py: number; g: PanelGeom } | null>(null);

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

  // Drag — pointer capture keeps tracking even outside the panel.
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
      if (r.edge.includes('e')) w = clampNum(r.g.w + dx, minW, window.innerWidth - r.g.x);
      if (r.edge.includes('s')) h = clampNum(r.g.h + dy, minH, window.innerHeight - r.g.y);
      if (r.edge.includes('w')) { const nw = clampNum(r.g.w - dx, minW, r.g.x + r.g.w); x += r.g.w - nw; w = nw; }
      if (r.edge.includes('n')) { const nh = clampNum(r.g.h - dy, minH, r.g.y + r.g.h); y += r.g.h - nh; h = nh; }
      return { x, y, w, h };
    });
  };
  const endResize = () => { resizeRef.current = null; };

  return { geom, setGeom, startDrag, onDragMove, endDrag, startResize, onResizeMove, endResize };
}
