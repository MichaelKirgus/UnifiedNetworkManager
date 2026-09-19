import { createContext, useCallback, useContext, useMemo, type ReactNode } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { api, NavPreferences } from '../api/client';

/**
 * Central date/time display preferences.
 *
 * Every timestamp rendered anywhere in the webapp MUST go through one of the
 * formatters provided by `useTimeFormat()` — never a raw `toLocaleString()`.
 * The user configures these per-account on the "My Account" page (stored in
 * `user_preferences` via PUT /auth/me/preferences):
 *
 * - `timezone`: null = follow the browser's local zone; otherwise an IANA id
 *   ("Europe/Berlin", "UTC", …). All rendering is converted into this zone.
 * - `dateFormat`: which layout preset to use (locale-aware, ISO, US or EU).
 * - `showTzSuffix`: append a short zone label in parentheses after each
 *   rendered timestamp, e.g. "19.09.2026 20:55 (CEST)".
 */

export type TimeFormatPreset = 'locale' | 'iso' | 'us' | 'eu';

export interface TimePrefs {
  /** IANA timezone id; null/absent = follow the browser's local zone. */
  timezone: string | null;
  dateFormat: TimeFormatPreset;
  showTzSuffix: boolean;
}

export const DEFAULT_TIME_PREFS: TimePrefs = { timezone: null, dateFormat: 'locale', showTzSuffix: false };

/** The browser's IANA zone (falls back to UTC in exotic environments). */
function browserZone(): string {
  try {
    return Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC';
  } catch {
    return 'UTC';
  }
}

/** Resolve the effective display zone for a preference set. Invalid stored values fall back to the browser zone. */
export function resolveZone(prefs: TimePrefs): string {
  if (prefs.timezone) {
    try {
      new Intl.DateTimeFormat('en-US', { timeZone: prefs.timezone });
      return prefs.timezone;
    } catch {
      /* unknown zone — fall through to browser */
    }
  }
  return browserZone();
}

/** Short human label for a zone ("CEST", "UTC") — used as the optional suffix. */
const tzLabelCache = new Map<string, string>();
export function tzShortLabel(zone: string): string {
  const hit = tzLabelCache.get(zone);
  if (hit) return hit;
  let label = zone;
  try {
    const part = new Intl.DateTimeFormat('en-US', { timeZone: zone, timeZoneName: 'short' })
      .formatToParts(new Date())
      .find((p) => p.type === 'timeZoneName');
    if (part?.value) label = part.value;
  } catch {
    /* keep the raw id */
  }
  tzLabelCache.set(zone, label);
  return label;
}

// --- Format presets -----------------------------------------------------------
// Each preset maps to an Intl locale + options triple. 'locale' uses the
// browser's own locale (fully i18n-aware); the fixed presets pin a locale so
// the layout is stable regardless of where the user's browser runs.

interface PresetSpec {
  locale?: string; // undefined = caller's default locale
  dateTime: Intl.DateTimeFormatOptions;
  dateOnly: Intl.DateTimeFormatOptions;
  timeOnly: Intl.DateTimeFormatOptions;
}

const PRESETS: Record<TimeFormatPreset, PresetSpec> = {
  locale: {
    dateTime: { dateStyle: 'medium', timeStyle: 'short' },
    dateOnly: { dateStyle: 'medium' },
    timeOnly: { timeStyle: 'short' },
  },
  iso: {
    // en-CA renders dates as YYYY-MM-DD; the ", " between date and time is
    // post-processed to a plain space for the classic ISO-ish look.
    locale: 'en-CA',
    dateTime: { year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', hour12: false },
    dateOnly: { year: 'numeric', month: '2-digit', day: '2-digit' },
    timeOnly: { hour: '2-digit', minute: '2-digit', hour12: false },
  },
  us: {
    locale: 'en-US',
    dateTime: { month: '2-digit', day: '2-digit', year: 'numeric', hour: 'numeric', minute: '2-digit' },
    dateOnly: { month: '2-digit', day: '2-digit', year: 'numeric' },
    timeOnly: { hour: 'numeric', minute: '2-digit' },
  },
  eu: {
    locale: 'de-DE',
    dateTime: { day: '2-digit', month: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit', hour12: false },
    dateOnly: { day: '2-digit', month: '2-digit', year: 'numeric' },
    timeOnly: { hour: '2-digit', minute: '2-digit', hour12: false },
  },
};

/** Accepts anything `new Date()` accepts (ISO string, epoch ms, Date). */
export type TimeValue = string | number | Date | null | undefined;

function toDate(value: TimeValue): Date | null {
  if (value == null || value === '') return null;
  const d = value instanceof Date ? value : new Date(value);
  return Number.isNaN(d.getTime()) ? null : d;
}

// Intl formatters are comparatively expensive to construct — cache them per
// (zone, preset, kind) triple. The key space is tiny in practice.
const formatterCache = new Map<string, Intl.DateTimeFormat>();
function getFormatter(zone: string, spec: PresetSpec, options: Intl.DateTimeFormatOptions): Intl.DateTimeFormat {
  const key = `${zone}|${spec.locale ?? 'default'}|${JSON.stringify(options)}`;
  let f = formatterCache.get(key);
  if (!f) {
    f = new Intl.DateTimeFormat(spec.locale, { timeZone: zone, ...options });
    if (formatterCache.size > 256) formatterCache.clear(); // hard cap, then rebuild
    formatterCache.set(key, f);
  }
  return f;
}

function formatInZone(d: Date, prefs: TimePrefs, kind: 'dateTime' | 'dateOnly' | 'timeOnly'): string {
  const zone = resolveZone(prefs);
  const spec = PRESETS[prefs.dateFormat] ?? PRESETS.locale;
  let out = getFormatter(zone, spec, spec[kind]).format(d);
  if (prefs.dateFormat === 'iso') out = out.replace(', ', ' '); // "2026-09-19, 20:55" → "2026-09-19 20:55"
  return out;
}

function withSuffix(out: string, prefs: TimePrefs): string {
  if (!prefs.showTzSuffix || !out) return out;
  return `${out} (${tzShortLabel(resolveZone(prefs))})`;
}

/** Format a full date+time per the user's preferences. Null/invalid → "—". */
export function formatDateTime(value: TimeValue, prefs: TimePrefs): string {
  const d = toDate(value);
  if (!d) return '—';
  return withSuffix(formatInZone(d, prefs, 'dateTime'), prefs);
}

/** Format a date (no time) per the user's preferences. Null/invalid → "—". */
export function formatDate(value: TimeValue, prefs: TimePrefs): string {
  const d = toDate(value);
  if (!d) return '—';
  return withSuffix(formatInZone(d, prefs, 'dateOnly'), prefs);
}

/** Format a time of day per the user's preferences. Null/invalid → "—". */
export function formatTime(value: TimeValue, prefs: TimePrefs): string {
  const d = toDate(value);
  if (!d) return '—';
  return withSuffix(formatInZone(d, prefs, 'timeOnly'), prefs);
}

// --- React context -------------------------------------------------------------

interface TimeContextValue {
  /** The user's effective time preferences (defaults until loaded). */
  prefs: TimePrefs;
  /** Effective IANA zone currently used for rendering. */
  zone: string;
  /** Short label of the effective zone ("CEST", "UTC"). */
  tzLabel: string;
  /** Update the user's time preferences (persisted server-side, optimistic). */
  setPrefs: (patch: Partial<TimePrefs>) => void;
  // Bound formatters — use these everywhere instead of raw toLocale* calls.
  formatDateTime: (value: TimeValue) => string;
  formatDate: (value: TimeValue) => string;
  formatTime: (value: TimeValue) => string;
}

const TimeContext = createContext<TimeContextValue | null>(null);

/** Extract the time-related fields from a NavPreferences payload. */
export function extractTimePrefs(p?: Partial<NavPreferences> | undefined): TimePrefs {
  return {
    timezone: p?.timezone ?? null,
    dateFormat: (p?.dateFormat as TimeFormatPreset) || 'locale',
    showTzSuffix: Boolean(p?.showTzSuffix),
  };
}

/**
 * App-wide provider for date/time display preferences. Must be mounted inside
 * the QueryClientProvider — it shares the `['navPrefs']` query with the
 * sidebar, so there is exactly one fetch of /auth/me/preferences per session.
 */
export function TimeProvider({ children }: { children: ReactNode }) {
  const queryClient = useQueryClient();

  // Same key + fn as Sidebar's nav-prefs query → deduplicated by react-query.
  const prefsQuery = useQuery<NavPreferences>({ queryKey: ['navPrefs'], queryFn: api.getNavPrefs });

  const saveMutation = useMutation({
    // Always send the COMPLETE merged state — the PUT endpoint treats omitted
    // fields as "keep unchanged", but sending all three explicitly is simpler
    // and avoids clobbering a field that wasn't part of this patch.
    mutationFn: (next: TimePrefs) => api.setNavPrefs({ timezone: next.timezone, dateFormat: next.dateFormat, showTzSuffix: next.showTzSuffix }),
    onSuccess: () => {
      // The server echoes the stored values — refresh from it so we never
      // drift (e.g. another tab changed something in between).
      void queryClient.invalidateQueries({ queryKey: ['navPrefs'] });
    },
  });

  const prefs = useMemo(() => extractTimePrefs(prefsQuery.data), [prefsQuery.data]);
  const zone = useMemo(() => resolveZone(prefs), [prefs]);
  const tzLabel = useMemo(() => tzShortLabel(zone), [zone]);

  // Optimistic local update so the whole UI re-renders instantly.
  const setPrefs = useCallback(
    (patch: Partial<TimePrefs>) => {
      const next: TimePrefs = { ...prefs, ...Object.fromEntries(Object.entries(patch).filter(([, v]) => v !== undefined)) };
      queryClient.setQueryData<NavPreferences>(['navPrefs'], (old) => ({
        navOrder: old?.navOrder ?? [],
        hiddenPages: old?.hiddenPages ?? [],
        timezone: next.timezone,
        dateFormat: next.dateFormat,
        showTzSuffix: next.showTzSuffix,
      }));
      saveMutation.mutate(next);
    },
    [queryClient, saveMutation, prefs]
  );

  const value = useMemo<TimeContextValue>(
    () => ({
      prefs,
      zone,
      tzLabel,
      setPrefs,
      formatDateTime: (v) => formatDateTime(v, prefs),
      formatDate: (v) => formatDate(v, prefs),
      formatTime: (v) => formatTime(v, prefs),
    }),
    [prefs, zone, tzLabel, setPrefs]
  );

  return <TimeContext.Provider value={value}>{children}</TimeContext.Provider>;
}

/** Access the central date/time formatters. Must be used under <TimeProvider>. */
export function useTimeFormat(): TimeContextValue {
  const ctx = useContext(TimeContext);
  if (!ctx) {
    // Fallback (e.g. a component rendered outside the provider tree): render
    // with defaults instead of crashing — still consistent, just not user-tuned.
    return {
      prefs: DEFAULT_TIME_PREFS,
      zone: browserZone(),
      tzLabel: tzShortLabel(browserZone()),
      setPrefs: () => undefined,
      formatDateTime: (v) => formatDateTime(v, DEFAULT_TIME_PREFS),
      formatDate: (v) => formatDate(v, DEFAULT_TIME_PREFS),
      formatTime: (v) => formatTime(v, DEFAULT_TIME_PREFS),
    };
  }
  return ctx;
}
