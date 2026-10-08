import { useEffect } from 'react';
import { api } from '../api/client';

const FALLBACK_TITLE = 'UnifiedNetworkManager';

/**
 * Reflects the instance display name (global `instanceName` setting) in the
 * browser tab title. The public /auth/flow endpoint carries it so the login
 * page shows it before any credentials are entered; once a session token
 * exists, /auth/me is authoritative (an admin may have renamed the instance
 * after sign-in). Falls back to the product name when the API is unreachable
 * or the setting is empty.
 */
export function useInstanceTitle(): void {
  useEffect(() => {
    let cancelled = false;

    const apply = (name: unknown) => {
      if (cancelled) return;
      document.title = typeof name === 'string' && name.trim() !== '' ? name.trim() : FALLBACK_TITLE;
    };

    // Public read — covers the login page.
    api
      .authFlow()
      .then((res) => apply(res.instanceName))
      .catch(() => {});

    // Authenticated read — authoritative once a session token exists.
    if (localStorage.getItem('accessToken')) {
      api
        .me()
        .then((res) => apply(res.instanceName))
        .catch(() => {});
    }
  }, []);
}
