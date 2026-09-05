import { useCallback, useEffect, useState } from 'react';

/**
 * Theme preferences.
 * - `preference`: 'system' (default) follows the browser's
 *   `prefers-color-scheme`; 'light'/'dark' are explicit overrides.
 * - `darkStyle`: which dark palette to use — 'black' (VS Code-like, default)
 *   or 'slate' (the original). Only meaningful when dark mode is active.
 * Both persist in localStorage and are applied pre-paint by the inline script
 * in index.html; this hook keeps <html> classes in sync afterwards (including
 * live system changes while on 'system').
 */
export type ThemePreference = 'system' | 'light' | 'dark';
export type DarkStyle = 'black' | 'slate';

const STORAGE_KEY = 'unm-theme';
const DARK_STYLE_KEY = 'unm-dark-style';

function readStored(key: string, valid: readonly string[]): string | null {
  try {
    const v = localStorage.getItem(key);
    return v && (valid as readonly string[]).includes(v) ? v : null;
  } catch {
    return null;
  }
}

function systemPrefersDark(): boolean {
  return window.matchMedia('(prefers-color-scheme: dark)').matches;
}

export function resolveTheme(pref: ThemePreference): 'light' | 'dark' {
  if (pref === 'system') return systemPrefersDark() ? 'dark' : 'light';
  return pref;
}

/** Apply both classes to <html> — the single place that knows the mapping. */
export function applyThemeClasses(pref: ThemePreference, darkStyle: DarkStyle) {
  const root = document.documentElement;
  const isDark = resolveTheme(pref) === 'dark';
  root.classList.toggle('dark', isDark);
  root.classList.remove('theme-black', 'theme-slate');
  if (isDark) root.classList.add(`theme-${darkStyle}`);
}

export function useTheme() {
  const [preference, setPreference] = useState<ThemePreference>(
    () => (readStored(STORAGE_KEY, ['system', 'light', 'dark']) as ThemePreference | null) ?? 'system'
  );
  const [style, setStyle] = useState<DarkStyle>(
    () => (readStored(DARK_STYLE_KEY, ['black', 'slate']) as DarkStyle | null) ?? 'black'
  );

  useEffect(() => {
    applyThemeClasses(preference, style);
    try {
      localStorage.setItem(STORAGE_KEY, preference);
      localStorage.setItem(DARK_STYLE_KEY, style);
    } catch {
      /* non-fatal */
    }
    // Only track OS/browser changes while in system mode.
    if (preference !== 'system') return;
    const mq = window.matchMedia('(prefers-color-scheme: dark)');
    const onChange = () => applyThemeClasses(preference, style);
    mq.addEventListener('change', onChange);
    return () => mq.removeEventListener('change', onChange);
  }, [preference, style]);

  const setTheme = useCallback((p: ThemePreference) => setPreference(p), []);
  const setDarkStyle = useCallback((s: DarkStyle) => setStyle(s), []);

  return { preference, resolved: resolveTheme(preference), darkStyle: style, setTheme, setDarkStyle };
}
