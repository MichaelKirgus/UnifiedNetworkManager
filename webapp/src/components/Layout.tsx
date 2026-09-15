import { ReactNode, useEffect } from 'react';
import { EyeOff } from 'lucide-react';
import { Sidebar } from './Sidebar';
import { NotificationCenter } from './NotificationCenter';
import { PlansCenter } from './PlansCenter';
import { ThemeToggle } from './ThemeToggle';
import { ExecutionModeToggle } from './ExecutionModeToggle';
import { useExecutionMode } from '../executionMode';

/** Pages whose actions flow through the plan workflow (create + execute).
 *  On every other page the top-bar Read-Only/Plan/Execute toggle renders disabled. */
const PLAN_ACTION_PATHS = ['/storage', '/shares', '/containers', '/vms'];

function isPlanActionPath(pathname: string): boolean {
  if (PLAN_ACTION_PATHS.some((p) => pathname === p || pathname.startsWith(p + '/'))) return true;
  // Per-device Config page — its state sections trigger catalog actions.
  return /^\/devices\/[^/]+\/config$/.test(pathname);
}

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
  const { mode, setApplicable } = useExecutionMode();

  // The Read-Only/Plan/Execute toggle only applies on pages whose actions flow
  // through the plan workflow — everywhere else it renders disabled.
  useEffect(() => {
    setApplicable(isPlanActionPath(window.location.pathname));
  }, [setApplicable]);

  const readOnlyBanner = mode === 'readonly' && isPlanActionPath(window.location.pathname);

  return (
    <div className="flex h-screen overflow-hidden bg-background">
      <Sidebar />
      <div className="flex min-w-0 flex-1 flex-col">
        {/* Top bar — page title + actions on the left/right, mode toggle + plans icon + bell far right. */}
        <header className="flex h-14 shrink-0 items-center gap-3 border-b border-border bg-card pl-6 pr-4">
          {title != null && (
            <h1 className="min-w-0 overflow-hidden whitespace-nowrap text-base font-semibold text-foreground">{title}</h1>
          )}
          <div className="ml-auto flex shrink-0 items-center gap-2">
            {actions}
            <ThemeToggle />
            <ExecutionModeToggle />
            <PlansCenter />
            <NotificationCenter />
          </div>
        </header>
        {readOnlyBanner && (
          <div className="flex shrink-0 items-center gap-2 border-b border-warning-border bg-warning px-6 py-1.5 text-xs font-medium text-warning-fg">
            <EyeOff className="h-3.5 w-3.5 shrink-0" />
            Read-only mode is active — no actions will be executed or saved on this page. Switch to Plan or Execute in the top bar to make changes.
          </div>
        )}
        <main className="min-h-0 flex-1 overflow-y-auto px-6 py-6">{children}</main>
      </div>
    </div>
  );
}
