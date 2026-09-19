import { useMemo } from 'react';
import { Clock3 } from 'lucide-react';
import { useTimeFormat, type TimeFormatPreset } from '../utils/time';

/**
 * "Date & time" self-service card for the My Account page. Lets each user pick
 * which timezone timestamps are rendered in (browser default or an explicit IANA
 * zone), which layout preset to use, and whether a short zone label is appended
 * after every timestamp. Changes apply instantly app-wide (optimistic update +
 * server persist via PUT /auth/me/preferences).
 */

const FORMAT_OPTIONS: Array<{ value: TimeFormatPreset; label: string; hint: string }> = [
  { value: 'locale', label: 'Locale default', hint: 'Follows your browser language/region' },
  { value: 'iso', label: 'ISO (2026-09-19 20:55)', hint: 'Year first, zero-padded' },
  { value: 'us', label: 'US (09/19/2026, 8:55 PM)', hint: 'Month first, 12-hour clock' },
  { value: 'eu', label: 'EU (19.09.2026 20:55)', hint: 'Day first, 24-hour clock' },
];

/** IANA zones offered in the picker — full list where the runtime supports it. */
function availableZones(): string[] {
  try {
    const anyIntl = Intl as unknown as { supportedValuesOf?: (key: string) => string[] };
    const zones = anyIntl.supportedValuesOf?.('timeZone');
    if (Array.isArray(zones) && zones.length > 0) return [...zones].sort();
  } catch {
    /* fall through to the curated list */
  }
  // Curated fallback for runtimes without Intl.supportedValuesOf.
  return [
    'UTC',
    'Europe/Berlin', 'Europe/London', 'Europe/Paris', 'Europe/Zurich', 'Europe/Vienna',
    'Europe/Madrid', 'Europe/Rome', 'Europe/Amsterdam', 'Europe/Brussels', 'Europe/Warsaw',
    'America/New_York', 'America/Chicago', 'America/Denver', 'America/Los_Angeles',
    'America/Sao_Paulo', 'Asia/Tokyo', 'Asia/Shanghai', 'Asia/Singapore', 'Australia/Sydney',
  ];
}

export function TimePreferencesCard() {
  const { prefs, zone, tzLabel, setPrefs, formatDateTime } = useTimeFormat();
  const zones = useMemo(availableZones, []);

  const previewNow = formatDateTime(new Date());

  return (
    <div className="rounded-md border border-border bg-card p-4 shadow-sm">
      <h2 className="mb-1 flex items-center gap-2 text-base font-semibold text-foreground">
        <Clock3 className="h-4 w-4 text-secondary" /> Date &amp; time display
      </h2>
      <p className="mb-4 text-xs text-faint">
        Applies to every date and time shown across the whole app — tables, logs, notifications, job history.
        Currently rendering in <span className="font-mono text-secondary">{zone}</span> ({tzLabel}).
      </p>

      <div className="grid grid-cols-1 gap-6 sm:grid-cols-2">
        {/* Timezone */}
        <div className="space-y-3">
          <label className="block text-sm font-semibold text-secondary" htmlFor="time-prefs-tz">Timezone</label>
          <select
            id="time-prefs-tz"
            value={prefs.timezone ?? 'browser'}
            onChange={(e) => {
              const v = e.target.value;
              setPrefs({ timezone: v === 'browser' ? null : v });
            }}
            className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm focus:border-focus-ring focus:outline-none"
          >
            <option value="browser">Browser default ({Intl.DateTimeFormat().resolvedOptions().timeZone || 'local'})</option>
            {zones.map((z) => (
              <option key={z} value={z}>{z}</option>
            ))}
          </select>
          <p className="text-xs text-faint">
            All timestamps are converted into this zone before rendering. "Browser default" follows the device you're signed in from.
          </p>
        </div>

        {/* Format preset */}
        <div className="space-y-3">
          <span className="block text-sm font-semibold text-secondary">Date &amp; time format</span>
          <div className="space-y-1.5" role="radiogroup" aria-label="Date and time format">
            {FORMAT_OPTIONS.map((opt) => (
              <label
                key={opt.value}
                className={`flex cursor-pointer items-center gap-2 rounded-md border px-3 py-2 text-sm transition-colors ${
                  prefs.dateFormat === opt.value ? 'border-primary bg-muted' : 'border-border hover:bg-muted/50'
                }`}
              >
                <input
                  type="radio"
                  name="time-prefs-format"
                  value={opt.value}
                  checked={prefs.dateFormat === opt.value}
                  onChange={() => setPrefs({ dateFormat: opt.value })}
                  className="accent-[var(--color-primary)]"
                />
                <span>
                  <span className="font-medium text-foreground">{opt.label}</span>
                  <span className="ml-2 hidden text-xs text-faint sm:inline">{opt.hint}</span>
                </span>
              </label>
            ))}
          </div>
        </div>
      </div>

      {/* Zone suffix toggle + live preview */}
      <div className="mt-5 flex flex-wrap items-center gap-x-8 gap-y-3 border-t border-border pt-4">
        <label className="flex cursor-pointer items-center gap-2 text-sm font-medium text-secondary">
          <input
            type="checkbox"
            checked={prefs.showTzSuffix}
            onChange={(e) => setPrefs({ showTzSuffix: e.target.checked })}
            className="accent-[var(--color-primary)]"
          />
          Append timezone label after each timestamp
        </label>
        <div className="ml-auto rounded-md bg-muted px-3 py-1.5 font-mono text-xs tabular-nums text-secondary">
          {previewNow}
        </div>
      </div>
    </div>
  );
}
