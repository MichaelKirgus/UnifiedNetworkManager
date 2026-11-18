import type { ReactNode } from 'react';
import clsx from 'clsx';

export interface PageTab<T extends string = string> {
  id: T;
  label: string;
  /** Optional leading icon (e.g. `<MailIcon size={14} />`). */
  icon?: ReactNode;
  /** Optional count badge — rendered only when a number is provided (null/undefined hides it). */
  count?: number | null;
  /** While true, a small pulsing dot marks the tab as still loading its content. */
  loading?: boolean;
}

interface PageTabsProps<T extends string> {
  tabs: Array<PageTab<T>>;
  value: T;
  onChange: (id: T) => void;
  /** Right-aligned per-tab action buttons (create, refresh, …). */
  actions?: ReactNode;
}

/**
 * Underline-style page tab bar — the shared design for multi-section pages
 * (Mail, Security, Notifications…). The active tab gets a primary underline,
 * inactive tabs stay muted. Use `actions` for right-aligned per-tab buttons so
 * each tab's primary action sits next to its label instead of buried in content.
 */
export function PageTabs<T extends string>({ tabs, value, onChange, actions }: PageTabsProps<T>) {
  return (
    <div role="tablist" className="mb-3 flex items-center gap-1 border-b border-border">
      {tabs.map((t) => (
        <button
          key={t.id}
          type="button"
          role="tab"
          aria-selected={value === t.id}
          onClick={() => onChange(t.id)}
          className={clsx(
            'flex items-center gap-1.5 rounded-t-md px-3 py-2 text-sm font-medium',
            value === t.id ? 'border-b-2 border-primary text-foreground' : 'text-secondary hover:text-foreground',
          )}
        >
          {t.icon}
          {t.label}
          {typeof t.count === 'number' && (
            <span className="rounded-full bg-muted px-1.5 text-[10px] font-semibold leading-4 text-secondary">{t.count}</span>
          )}
          {/* Pulsing dot — this tab's content is still loading (see LoadingBar). */}
          {t.loading && (
            <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-primary" title="Loading…" aria-label="Loading" />
          )}
        </button>
      ))}
      {actions != null && actions !== false && (
        <div className="ml-auto flex items-center gap-1.5 pb-1">{actions}</div>
      )}
    </div>
  );
}
