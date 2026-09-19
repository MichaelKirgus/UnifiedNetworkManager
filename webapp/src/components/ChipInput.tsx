import { KeyboardEvent, useState } from 'react';
import clsx from 'clsx';
import { X } from 'lucide-react';

interface ChipInputProps {
  values: string[];
  onChange: (values: string[]) => void;
  /** Suggested entries shown as clickable pills above the input. */
  suggestions?: string[];
  placeholder?: string;
  ariaLabel?: string;
}

/**
 * Free-form multi-value input rendered as removable chips. Enter or comma adds
 * the current text; Backspace on an empty input removes the last chip. Suggested
 * values (e.g. common device types) are offered as one-click pills — clicking a
 * selected pill removes it again. Values keep their original casing and order.
 */
export function ChipInput({ values, onChange, suggestions = [], placeholder = 'Type and press Enter…', ariaLabel }: ChipInputProps) {
  const [draft, setDraft] = useState('');

  function addValue(raw: string) {
    const v = raw.trim();
    if (v === '') return;
    // Case-insensitive dedupe — "Router" and "router" are the same tag.
    if (values.some((x) => x.toLowerCase() === v.toLowerCase())) { setDraft(''); return; }
    onChange([...values, v]);
    setDraft('');
  }

  function removeValue(v: string) {
    onChange(values.filter((x) => x !== v));
  }

  function onKeyDown(e: KeyboardEvent<HTMLInputElement>) {
    if (e.key === 'Enter' || e.key === ',') {
      e.preventDefault();
      addValue(draft);
    } else if (e.key === 'Backspace' && draft === '' && values.length > 0) {
      removeValue(values[values.length - 1]);
    }
  }

  const selectedLower = new Set(values.map((v) => v.toLowerCase()));
  // Suggestions not already selected, in the given order.
  const openSuggestions = suggestions.filter((s) => !selectedLower.has(s.toLowerCase()));

  return (
    <div>
      {openSuggestions.length > 0 && (
        <div className="mb-1.5 flex flex-wrap gap-1">
          {openSuggestions.map((s) => (
            <button
              key={s}
              type="button"
              onClick={() => addValue(s)}
              title={`Add "${s}"`}
              className="rounded-full border border-dashed border-border px-2 py-0.5 text-xs text-muted-foreground hover:border-focus-ring hover:bg-background hover:text-secondary"
            >
              + {s}
            </button>
          ))}
        </div>
      )}
      <div className="flex min-h-[38px] w-full flex-wrap items-center gap-1.5 rounded-md border border-border bg-card px-2 py-1 focus-within:border-focus-ring">
        {values.map((v) => (
          <span key={v} className="inline-flex items-center gap-1 rounded-full bg-muted px-2 py-0.5 text-xs font-medium text-secondary">
            {v}
            <button type="button" onClick={() => removeValue(v)} aria-label={`Remove ${v}`} className="text-faint hover:text-danger-fg">
              <X className="h-3 w-3" />
            </button>
          </span>
        ))}
        <input
          type="text"
          value={draft}
          onChange={(e) => setDraft(e.target.value)}
          onKeyDown={onKeyDown}
          onBlur={() => draft.trim() !== '' && addValue(draft)}
          placeholder={values.length === 0 ? placeholder : 'Add another…'}
          aria-label={ariaLabel ?? placeholder}
          className="min-w-[120px] flex-1 border-none bg-transparent py-1 text-sm focus:outline-none"
        />
      </div>
    </div>
  );
}
