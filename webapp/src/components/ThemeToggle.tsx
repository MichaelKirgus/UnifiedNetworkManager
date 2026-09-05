import { ReactNode, useEffect, useRef, useState } from 'react';
import { Check, Monitor, Moon, Square, Sun } from 'lucide-react';
import { DarkStyle, ThemePreference, useTheme } from '../theme/useTheme';

const OPTIONS: Array<{ value: ThemePreference; label: string; icon: typeof Sun }> = [
  { value: 'system', label: 'System default', icon: Monitor },
  { value: 'light', label: 'Light', icon: Sun },
  { value: 'dark', label: 'Dark', icon: Moon },
];

const DARK_STYLES: Array<{ value: DarkStyle; label: string }> = [
  { value: 'black', label: 'Black (VS Code)' },
  { value: 'slate', label: 'Slate' },
];

function MenuRow({
  active,
  onClick,
  children,
}: {
  active: boolean;
  onClick: () => void;
  children: ReactNode;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={`flex w-full items-center gap-2 px-3 py-1.5 text-sm hover:bg-muted ${
        active ? 'text-secondary' : 'text-muted-foreground'
      }`}
    >
      {children}
      {active && <Check className="ml-auto h-3.5 w-3.5" />}
    </button>
  );
}

/**
 * Theme switcher (System / Light / Dark) with a dark-style selector
 * (Black VS Code-like default, or the original Slate). Compact menu button in
 * the top bar; the current preference's icon is shown on the trigger.
 */
export function ThemeToggle() {
  const { preference, resolved, darkStyle, setTheme, setDarkStyle } = useTheme();
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    const onDoc = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener('mousedown', onDoc);
    return () => document.removeEventListener('mousedown', onDoc);
  }, [open]);

  const current = OPTIONS.find((o) => o.value === preference) ?? OPTIONS[0];
  const CurrentIcon = current.icon;
  // Offer the style choice whenever dark mode is active or about to be.
  const showStyles = resolved === 'dark' || preference === 'dark';

  return (
    <div ref={ref} className="relative">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        title={`Theme: ${current.label}`}
        aria-label="Change theme"
        aria-expanded={open}
        className="inline-flex h-8 w-8 items-center justify-center rounded-md text-muted-foreground hover:bg-muted hover:text-secondary"
      >
        <CurrentIcon className="h-4 w-4" />
      </button>
      {open && (
        <div className="absolute right-0 z-50 mt-1.5 w-48 overflow-hidden rounded-lg border border-border bg-card py-1 shadow-lg">
          <p className="px-3 pb-1 pt-1.5 text-[11px] font-medium uppercase tracking-wide text-faint">
            Theme
          </p>
          {OPTIONS.map((o) => {
            const Icon = o.icon;
            return (
              <MenuRow
                key={o.value}
                active={preference === o.value}
                onClick={() => {
                  setTheme(o.value);
                  setOpen(false);
                }}
              >
                <Icon className="h-4 w-4" />
                {o.label}
              </MenuRow>
            );
          })}
          {showStyles && (
            <>
              <p className="mt-1 border-t border-border px-3 pb-1 pt-2 text-[11px] font-medium uppercase tracking-wide text-faint">
                Dark style
              </p>
              {DARK_STYLES.map((s) => (
                <MenuRow key={s.value} active={darkStyle === s.value} onClick={() => setDarkStyle(s.value)}>
                  <Square className="h-3.5 w-3.5" />
                  {s.label}
                </MenuRow>
              ))}
            </>
          )}
        </div>
      )}
    </div>
  );
}
