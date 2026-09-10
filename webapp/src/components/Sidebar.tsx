import { useEffect, useMemo, useState } from 'react';
import { NavLink } from 'react-router-dom';
import clsx from 'clsx';
import { useQuery } from '@tanstack/react-query';
import { LogOut, Network, PanelLeftClose, PanelLeftOpen, SlidersHorizontal } from 'lucide-react';
import { clearPermissions, clearUsername } from '../auth/permissions';
import { api } from '../api/client';
import { MY_ACCOUNT_ITEM, orderedNavItems, BADGE_COLORS, type NavItem } from './navItems';
import { NavCustomizer } from './NavCustomizer';

const COLLAPSED_KEY = 'unm:sidebar-collapsed';

/** One sidebar row (icon + label) with an optional count badge. */
function NavRow({ item, collapsed, count }: { item: NavItem; collapsed: boolean; count?: number }) {
  const Icon = item.icon;
  return (
    <NavLink
      to={item.to}
      title={collapsed ? item.label : undefined}
      className={({ isActive }) =>
        clsx(
          'relative flex items-center gap-3 rounded-md px-2.5 py-2 text-sm font-medium transition-colors',
          collapsed && 'justify-center px-0',
          isActive ? 'bg-primary text-white' : 'text-secondary hover:bg-muted'
        )
      }
    >
      <Icon className="h-5 w-5 shrink-0" />
      {!collapsed && <span className="truncate">{item.label}</span>}
      {item.countKey && count ? (
        <span
          className={clsx(
            'absolute right-1 top-1/2 -translate-y-1/2 flex h-4 min-w-[16px] items-center justify-center rounded-full px-1 text-[10px] font-bold leading-none text-white',
            BADGE_COLORS[item.countKey]
          )}
        >
          {count > 99 ? '99+' : count}
        </span>
      ) : null}
    </NavLink>
  );
}

/**
 * Collapsible left sidebar. Expanded shows icons + labels; collapsed is an icon
 * rail (tooltips via `title`). The user's choice persists in localStorage. Nav
 * order + hidden pages are per-user prefs (DB-backed); a "Customize" button opens
 * the reorder/hide panel. Actionable items show a count badge from /counts.
 */
export function Sidebar() {
  const [collapsed, setCollapsed] = useState<boolean>(() => {
    try {
      return window.localStorage.getItem(COLLAPSED_KEY) === '1';
    } catch {
      return false;
    }
  });

  useEffect(() => {
    try {
      window.localStorage.setItem(COLLAPSED_KEY, collapsed ? '1' : '0');
    } catch {
      // Storage unavailable (private mode); preference stays in memory.
    }
  }, [collapsed]);

  const [customizing, setCustomizing] = useState(false);

  const prefsQuery = useQuery({ queryKey: ['navPrefs'], queryFn: api.getNavPrefs });
  const countsQuery = useQuery({
    queryKey: ['navCounts'],
    queryFn: api.navCounts,
    refetchInterval: 30_000,
  });

  // Permission-visible items in the user's order (the customizer lists ALL of these,
  // including hidden ones so they can be re-shown).
  const allOrderedItems = useMemo(() => orderedNavItems(prefsQuery.data), [prefsQuery.data]);

  // The sidebar itself hides pages the user has marked hidden.
  const visibleItems = useMemo(() => {
    const hidden = new Set(prefsQuery.data?.hiddenPages ?? []);
    return allOrderedItems.filter((item) => !hidden.has(item.to));
  }, [allOrderedItems, prefsQuery.data]);

  const counts = countsQuery.data ?? {};

  return (
    <aside
      className={clsx(
        'flex shrink-0 flex-col border-r border-border bg-card transition-[width] duration-200 ease-in-out',
        collapsed ? 'w-16' : 'w-56'
      )}
    >
      {/* Brand */}
      <div className={clsx('flex h-14 items-center gap-2 border-b border-border px-3', collapsed && 'justify-center px-0')}>
        <Network className="h-6 w-6 shrink-0 text-foreground" />
        {!collapsed && (
          <span className="truncate text-sm font-bold text-foreground">UnifiedNetworkManager</span>
        )}
      </div>

      {/* Navigation */}
      <nav className={clsx('flex flex-1 flex-col gap-1 overflow-y-auto p-2', collapsed && 'items-center')}>
        {visibleItems.map((item) => (
          <NavRow key={item.to} item={item} collapsed={collapsed} count={item.countKey ? counts[item.countKey] : undefined} />
        ))}
        {/* My Account is pinned last and never hidden/reordered. */}
        <NavRow item={MY_ACCOUNT_ITEM} collapsed={collapsed} />
      </nav>

      {customizing && (
        <div className="border-t border-border">
          <NavCustomizer
            items={allOrderedItems}
            initialOrder={(prefsQuery.data?.navOrder ?? []).filter((p) => allOrderedItems.some((i) => i.to === p))}
            initialHidden={prefsQuery.data?.hiddenPages ?? []}
            onClose={() => setCustomizing(false)}
          />
        </div>
      )}

      {/* Footer: customize + collapse toggle + sign out (icon-only, tooltips via title) */}
      <div className={clsx('flex gap-1 border-t border-border p-2', collapsed && 'flex-col items-center')}>
        <button
          type="button"
          aria-label="Customize navigation"
          title="Customize navigation"
          onClick={() => setCustomizing((v) => !v)}
          className={clsx(
            'flex flex-1 items-center justify-center rounded-md p-2 transition-colors',
            customizing ? 'bg-primary text-white' : 'text-secondary hover:bg-muted',
            collapsed && 'flex-none'
          )}
        >
          <SlidersHorizontal className="h-5 w-5 shrink-0" />
        </button>
        <button
          type="button"
          aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
          title={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
          onClick={() => setCollapsed((v) => !v)}
          className={clsx(
            'flex flex-1 items-center justify-center rounded-md p-2 text-secondary hover:bg-muted',
            collapsed && 'flex-none'
          )}
        >
          {collapsed ? <PanelLeftOpen className="h-5 w-5 shrink-0" /> : <PanelLeftClose className="h-5 w-5 shrink-0" />}
        </button>
        <button
          type="button"
          aria-label="Sign out"
          title="Sign out"
          onClick={() => {
            localStorage.removeItem('accessToken');
            clearPermissions();
            clearUsername();
            window.location.href = '/login';
          }}
          className={clsx(
            'flex flex-1 items-center justify-center rounded-md p-2 text-secondary hover:bg-danger hover:text-danger-fg',
            collapsed && 'flex-none'
          )}
        >
          <LogOut className="h-5 w-5 shrink-0" />
        </button>
      </div>
    </aside>
  );
}
