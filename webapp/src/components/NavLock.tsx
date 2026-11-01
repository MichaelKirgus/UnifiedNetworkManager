import { createContext, useCallback, useContext, useMemo, useState, type ReactNode } from 'react';

interface NavLockContextValue {
  /** True while a focused surface (wizard / action dialog) has paused navigation. */
  locked: boolean;
  /** Human reason shown in the sidebar hint (e.g. "Finish this wizard first"). */
  reason: string | null;
  /** Pause sidebar navigation with an optional user-facing reason. */
  lock: (reason?: string) => void;
  /** Resume navigation. Holders must not nest — see NavLockProvider note. */
  unlock: () => void;
}

const NavLockContext = createContext<NavLockContextValue>({
  locked: false,
  reason: null,
  lock: () => {},
  unlock: () => {},
});

/** Read the current navigation-lock state (used by the Sidebar). */
export function useNavLock(): NavLockContextValue {
  return useContext(NavLockContext);
}

/**
 * Tracks whether sidebar navigation is paused. Focused surfaces — multi-step
 * wizards and device-config action dialogs — call `lock()` while active so the
 * Sidebar can dim + disable its nav rows (and explain why) instead of silently
 * abandoning the user's in-progress task on a stray click.
 *
 * Holders must not NEST: each surface locks on mount / when its focused UI opens
 * and unlocks on unmount / close. In this app those surfaces are mutually
 * exclusive (a page is either a wizard or a config page with dialogs), so a
 * simple boolean + reason is sufficient — no reference counting needed.
 */
export function NavLockProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<{ locked: boolean; reason: string | null }>({ locked: false, reason: null });

  const lock = useCallback((reason?: string) => {
    setState({ locked: true, reason: reason ?? 'Finish the current task first' });
  }, []);

  const unlock = useCallback(() => {
    setState({ locked: false, reason: null });
  }, []);

  const value = useMemo<NavLockContextValue>(
    () => ({ ...state, lock, unlock }),
    [state, lock, unlock]
  );

  return <NavLockContext.Provider value={value}>{children}</NavLockContext.Provider>;
}
