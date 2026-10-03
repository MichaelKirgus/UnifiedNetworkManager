import { ReactNode, useEffect, useState } from 'react';
import { EyeOff, Hourglass } from 'lucide-react';
import { Sidebar } from './Sidebar';
import { NotificationCenter } from './NotificationCenter';
import { PlansCenter } from './PlansCenter';
import { ThemeToggle } from './ThemeToggle';
import { ExecutionModeToggle } from './ExecutionModeToggle';
import { ExtendSessionDialog } from './ExtendSessionDialog';
import { SessionChip, formatRemaining, useSessionState } from './SessionTimer';
import { useExecutionMode } from '../executionMode';

/** Pages whose actions flow through the plan workflow (create + execute).
 *  On every other page the top-bar Read-Only/Plan/Execute toggle renders disabled. */
const PLAN_ACTION_PATHS = ['/storage', '/shares', '/containers', '/vms', '/updates', '/services', '/mail'];

function isPlanActionPath(pathname: string): boolean {
  if (PLAN_ACTION_PATHS.some((p) => pathname === p || pathname.startsWith(p + '/'))) return true;
  // Per-device Config page — its state sections trigger catalog actions.
  if (/^\/devices\/[^/]+\/config$/.test(pathname)) return true;
  // Fleet rollout wizard — creates (and optionally executes) plans per plugin.
  return pathname === '/networks/rollout';
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
  const session = useSessionState();
  // The "Extend" button opens a dialog that re-proves a second factor (TOTP or
  // passkey) before the server will mint an extended token.
  const [extendOpen, setExtendOpen] = useState(false);

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
            <SessionChip expiresAt={session.expiresAt} remainingMs={session.remainingMs} warning={session.warning} />
            <ThemeToggle />
            <ExecutionModeToggle />
            <PlansCenter />
            <NotificationCenter />
          </div>
        </header>
        {session.warning && (
          <div className="flex shrink-0 items-center gap-2 border-b border-warning-border bg-warning px-6 py-1.5 text-xs font-medium text-warning-fg">
            <Hourglass className="h-3.5 w-3.5 shrink-0" />
            Your session will expire in {formatRemaining(session.remainingMs ?? 0)} — you will be signed out automatically when it ends.
            {session.extensionAllowed ? (
              <button
                type="button"
                onClick={() => setExtendOpen(true)}
                className="ml-auto rounded-md border border-warning-border bg-card px-2 py-0.5 text-xs font-semibold text-warning-fg transition-colors hover:bg-background"
              >
                Extend session
              </button>
            ) : (
              <span className="ml-auto text-[11px] opacity-80">Extension is not available for your account.</span>
            )}
          </div>
        )}
        {readOnlyBanner && (
          <div className="flex shrink-0 items-center gap-2 border-b border-warning-border bg-warning px-6 py-1.5 text-xs font-medium text-warning-fg">
            <EyeOff className="h-3.5 w-3.5 shrink-0" />
            Read-only mode is active — no actions will be executed or saved on this page. Switch to Plan or Execute in the top bar to make changes.
          </div>
        )}
        <main className="min-h-0 flex-1 overflow-y-auto px-6 py-6">{children}</main>
      </div>
      {extendOpen && (
        <ExtendSessionDialog onClose={() => setExtendOpen(false)} onSuccess={async () => { await session.refresh(); setExtendOpen(false); }} />
      )}
    </div>
  );
}
