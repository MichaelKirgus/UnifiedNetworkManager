import { ReactNode } from 'react';
import { Sidebar } from './Sidebar';

/**
 * App shell: collapsible left sidebar + full-width content area. The content
 * pane scrolls independently so tables/forms get the maximum available space
 * (no centering cap, minimal padding).
 */
export function Layout({ children }: { children: ReactNode }) {
  return (
    <div className="flex h-screen overflow-hidden bg-slate-50">
      <Sidebar />
      <main className="min-w-0 flex-1 overflow-y-auto px-6 py-6">{children}</main>
    </div>
  );
}
