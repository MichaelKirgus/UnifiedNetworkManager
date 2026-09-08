import { ReactNode } from 'react';
import { Sidebar } from './Sidebar';
import { NotificationCenter } from './NotificationCenter';
import { PlansCenter } from './PlansCenter';
import { ThemeToggle } from './ThemeToggle';

export interface LayoutProps {
  children: ReactNode;
  /** Page title, rendered on the left of the shared top bar. */
  title?: ReactNode;
  /** Page action buttons/controls, right-aligned in the top bar (left of the bell). */
  actions?: ReactNode;
}

/**
 * App shell: collapsible left sidebar + slim top bar + full-width content area.
 * The top bar is h-14 — the same height as the sidebar brand row — and carries
 * each page's title (left) and action buttons (right), so pages don't need
 * their own header block and no vertical space is wasted on duplicated chrome.
 * The plans icon and notification bell sit far right in every view.
 */
export function Layout({ children, title, actions }: LayoutProps) {
  return (
    <div className="flex h-screen overflow-hidden bg-background">
      <Sidebar />
      <div className="flex min-w-0 flex-1 flex-col">
        {/* Top bar — page title + actions on the left/right, plans icon + bell far right. */}
        <header className="flex h-14 shrink-0 items-center gap-3 border-b border-border bg-card pl-6 pr-4">
          {title != null && (
            <h1 className="min-w-0 overflow-hidden whitespace-nowrap text-base font-semibold text-foreground">{title}</h1>
          )}
          <div className="ml-auto flex shrink-0 items-center gap-2">
            {actions}
            <ThemeToggle />
            <PlansCenter />
            <NotificationCenter />
          </div>
        </header>
        <main className="min-h-0 flex-1 overflow-y-auto px-6 py-6">{children}</main>
      </div>
    </div>
  );
}
