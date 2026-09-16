import { useCallback, useEffect, useState } from 'react';
import clsx from 'clsx';
import { Clock3 } from 'lucide-react';
import { api, ApiError, setAccessToken } from '../api/client';
import { clearPermissions, clearUsername } from '../auth/permissions';

/** Formats a millisecond duration compactly ("1h 04m", "58m 12s", "42 s"). */
export function formatRemaining(ms: number): string {
  const total = Math.max(0, Math.ceil(ms / 1000));
  const h = Math.floor(total / 3600);
  const m = Math.floor((total % 3600) / 60);
  const s = total % 60;
  if (h > 0) return `${h}h ${String(m).padStart(2, '0')}m`;
  if (m > 0) return `${m}m ${String(s).padStart(2, '0')}s`;
  return `${s}s`;
}

/** Drops the local session and bounces to /login with an "expired" notice. */
function signOutExpired(): void {
  localStorage.removeItem('accessToken');
  clearPermissions();
  clearUsername();
  window.location.assign('/login?reason=expired');
}

export interface SessionState {
  /** Unix epoch ms at which the session expires (null until known). */
  expiresAt: number | null;
  /** Milliseconds left in the session (null until known, clamped to >= 0). */
  remainingMs: number | null;
  /** True once the remaining time is within the configured warning lead time. */
  warning: boolean;
  /** True when the caller may extend their session at all (policy + enrolled factor). */
  extensionAllowed: boolean;
  /** Re-fetch the server-computed expiry (call after a successful extension). */
  refresh: () => Promise<void>;
}

/**
 * Session state for the app shell: fetches the SERVER-computed expiry once on
 * mount (so per-user TTL caps and later-shortened global timeouts are honored),
 * then ticks every second. Drives the top-bar countdown chip, the amber
 * "ending soon" banner, and the automatic sign-out at zero — so a timed-out
 * session navigates to /login by itself instead of waiting for a failing API
 * call to notice. Extending is NOT done here: it requires re-proving a second
 * factor (see ExtendSessionDialog), which this hook only reports as allowed.
 */
export function useSessionState(): SessionState {
  const [expiresAt, setExpiresAt] = useState<number | null>(null);
  const [warnSeconds, setWarnSeconds] = useState(0);
  const [extensionAllowed, setExtensionAllowed] = useState(false);
  const [now, setNow] = useState(() => Date.now());

  // Fetch the server-computed expiry. A 401 here means the session is already
  // gone — bounce to /login (apiFetch only auto-redirects for coded 401s; a
  // plain expired token carries no code). Re-runnable after an extension.
  const load = useCallback(async () => {
    try {
      const s = await api.sessionInfo();
      setExpiresAt(s.expiresAt);
      setWarnSeconds(s.warnSeconds);
      setExtensionAllowed(Boolean(s.extensionAllowed));
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) signOutExpired();
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  // One-second tick while a session is known.
  useEffect(() => {
    if (expiresAt === null) return;
    const t = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(t);
  }, [expiresAt]);

  const remainingMs = expiresAt !== null ? Math.max(0, expiresAt - now) : null;

  // Auto-logout the instant the session is gone — don't wait for a failing request.
  useEffect(() => {
    if (remainingMs === null || remainingMs > 0) return;
    signOutExpired();
  }, [remainingMs]);

  const warning = remainingMs !== null && warnSeconds > 0 && remainingMs <= warnSeconds * 1000;

  return { expiresAt, remainingMs, warning, extensionAllowed, refresh: load };
}

/** Top-bar countdown chip — hidden until the session expiry is known. */
export function SessionChip({
  expiresAt,
  remainingMs,
  warning,
}: {
  expiresAt: number | null;
  remainingMs: number | null;
  warning: boolean;
}) {
  if (expiresAt === null || remainingMs === null) return null;
  const at = new Date(expiresAt).toLocaleTimeString();
  return (
    <span
      title={`Session expires in ${formatRemaining(remainingMs)} (at ${at})`}
      className={clsx(
        'flex items-center gap-1 rounded-md border px-2 py-1 text-xs tabular-nums',
        warning ? 'border-warning-border bg-warning text-warning-fg' : 'border-border bg-muted/50 text-secondary'
      )}
    >
      <Clock3 className="h-3.5 w-3.5 shrink-0" />
      {formatRemaining(remainingMs)}
    </span>
  );
}
