import { InputSchema, InputSchemaProperty } from '../api/client';

/**
 * Renders a plugin action's `inputSchema` (the JSON-Schema subset declared in
 * the action catalog) as a controlled form. Distinct from OptionForm — it
 * works on the CATALOG's schema shape, not plugin option descriptors — but
 * follows the same styling conventions. The parent owns the values object;
 * this component only renders fields and reports changes/validation.
 */

interface SchemaFormProps {
  schema: InputSchema;
  values: Record<string, unknown>;
  onChange: (values: Record<string, unknown>) => void;
  /** Per-path validation messages (e.g. from validateSchema or the API). */
  fieldErrors?: Record<string, string>;
}

/** Mirrors the API's input-schema validator for instant client-side feedback. */
export function validateSchema(schema: InputSchema, values: Record<string, unknown>): Record<string, string> {
  const errors: Record<string, string> = {};
  for (const [key, prop] of Object.entries(schema)) {
    const v = values[key];
    if (v === undefined || v === null) {
      if (prop.required) errors[key] = 'Required';
      continue;
    }
    const issue = validateProperty(prop, v);
    if (issue) errors[key] = issue;
  }
  return errors;
}

function validateProperty(prop: InputSchemaProperty, value: unknown): string | null {
  switch (prop.type) {
    case 'string': {
      if (typeof value !== 'string') return 'Must be a string';
      if (prop.pattern) {
        try {
          if (!new RegExp(prop.pattern).test(value)) return `Does not match pattern ${prop.pattern}`;
        } catch {
          /* ignore malformed regex */
        }
      }
      return null;
    }
    case 'number': {
      const n = typeof value === 'string' ? Number(value) : value;
      if (typeof n !== 'number' || !Number.isFinite(n)) return 'Must be a number';
      if (prop.min !== undefined && n < prop.min) return `Must be >= ${prop.min}`;
      if (prop.max !== undefined && n > prop.max) return `Must be <= ${prop.max}`;
      return null;
    }
    case 'boolean': {
      if (typeof value !== 'boolean') return 'Must be a boolean';
      return null;
    }
    case 'array': {
      if (!Array.isArray(value)) return 'Must be a list';
      for (let i = 0; i < value.length; i++) {
        const issue = prop.items ? validateProperty(prop.items, value[i]) : null;
        if (issue) return `Item ${i + 1}: ${issue}`;
      }
      return null;
    }
    case 'object': {
      if (typeof value !== 'object' || Array.isArray(value)) return 'Must be an object';
      for (const [k, sub] of Object.entries(prop.properties ?? {})) {
        const child = (value as Record<string, unknown>)[k];
        if ((child === undefined || child === null) && sub.required) return `${k} is required`;
        else if (child !== undefined && child !== null) {
          const issue = validateProperty(sub, child);
          if (issue) return `${k}: ${issue}`;
        }
      }
      return null;
    }
  }
}

/** Builds the initial values object from schema defaults. */
export function defaultValues(schema: InputSchema): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [key, prop] of Object.entries(schema)) {
    if (prop.default !== undefined) out[key] = prop.default;
  }
  return out;
}

export function SchemaForm({ schema, values, onChange, fieldErrors }: SchemaFormProps) {
  const entries = Object.entries(schema);
  if (entries.length === 0) {
    return <p className="px-1 py-2 text-sm text-muted-foreground">This action takes no input.</p>;
  }

  function setTop(key: string, value: unknown) {
    onChange({ ...values, [key]: value });
  }

  return (
    <div className="space-y-4 px-1 py-2">
      {entries.map(([key, prop]) => (
        <Field key={key} name={key} prop={prop} value={values[key]} error={fieldErrors?.[key]} onValue={(v) => setTop(key, v)} />
      ))}
    </div>
  );
}

interface FieldProps {
  name: string;
  prop: InputSchemaProperty;
  value: unknown;
  error?: string;
  onValue: (value: unknown) => void;
}

function Field({ name, prop, value, error, onValue }: FieldProps) {
  const id = `schema-${name}`;
  return (
    <div>
      <label htmlFor={id} className="mb-1 flex items-center gap-2 text-sm font-medium text-secondary">
        {prop.label ?? name}
        {prop.required && <span className="text-danger-fg">*</span>}
      </label>
      {prop.description && <p className="mb-1 text-xs text-faint">{prop.description}</p>}

      {/* enum → select (any type) */}
      {prop.enum && prop.enum.length > 0 ? (
        <select id={id} value={value === undefined || value === null ? '' : String(value)}
          onChange={(e) => onValue(e.target.value === '' ? undefined : coerce(prop, e.target.value))}
          className="w-full rounded-md border border-border px-2.5 py-1.5 text-sm focus:border-focus-ring focus:ring-1 focus:ring-focus-ring">
          <option value="" disabled>— select —</option>
          {prop.enum.map((opt) => (
            <option key={String(opt)} value={String(opt)}>{String(opt)}</option>
          ))}
        </select>
      ) : prop.type === 'boolean' ? (
        <div className="flex items-center gap-2">
          <input id={id} type="checkbox" checked={value === true} onChange={(e) => onValue(e.target.checked)}
            className="h-4 w-4 rounded border-border text-foreground focus:ring-focus-ring" />
          <span className="text-sm text-muted-foreground">{value === true ? 'Enabled' : 'Disabled'}</span>
        </div>
      ) : prop.type === 'number' ? (
        <input id={id} type="number" step="any" inputMode="decimal" value={numToString(value)}
          placeholder={prop.default !== undefined ? `default: ${String(prop.default)}` : ''}
          onChange={(e) => onValue(e.target.value === '' ? undefined : Number(e.target.value))}
          className="w-full rounded-md border border-border px-2.5 py-1.5 text-sm focus:border-focus-ring focus:ring-1 focus:ring-focus-ring" />
      ) : prop.type === 'array' ? (
        <ArrayField name={name} items={prop.items ?? { type: 'string' }} value={(value as unknown[]) ?? []} onValue={onValue} />
      ) : prop.type === 'object' && prop.properties ? (
        <div className="rounded-md border border-border bg-background/60 p-3">
          {Object.entries(prop.properties).map(([subKey, subProp]) => (
            <Field key={subKey} name={`${name}.${subKey}`} prop={subProp}
              value={(value as Record<string, unknown> | undefined)?.[subKey]}
              onValue={(v) => {
                const base = (typeof value === 'object' && value !== null ? (value as Record<string, unknown>) : {}) as Record<string, unknown>;
                if (v === undefined) delete base[subKey];
                else base[subKey] = v;
                onValue(base);
              }} />
          ))}
        </div>
      ) : (
        <input id={id} type="text" value={strToString(value)}
          placeholder={prop.default !== undefined ? `default: ${String(prop.default)}` : prop.pattern ?? ''}
          onChange={(e) => onValue(e.target.value === '' ? undefined : e.target.value)}
          className="w-full rounded-md border border-border px-2.5 py-1.5 text-sm focus:border-focus-ring focus:ring-1 focus:ring-focus-ring" />
      )}
      {error && <p className="mt-1 text-xs text-danger-fg">{error}</p>}
    </div>
  );
}

function ArrayField({ name, items, value, onValue }: { name: string; items: InputSchemaProperty; value: unknown[]; onValue: (v: unknown) => void }) {
  const primitive = items.type === 'string' || items.type === 'number';
  if (!primitive) {
    // Arrays of objects are rare — fall back to a JSON editor.
    return (
      <textarea id={`schema-${name}`} rows={3} value={JSON.stringify(value, null, 2)}
        onChange={(e) => {
          try { onValue(JSON.parse(e.target.value)); } catch { /* keep last valid */ }
        }}
        className="w-full rounded-md border border-border px-2.5 py-1.5 font-mono text-xs focus:border-focus-ring focus:ring-1 focus:ring-focus-ring" />
    );
  }
  return (
    <div className="space-y-1.5">
      {value.map((item, i) => (
        <div key={i} className="flex items-center gap-2">
          <input type={items.type === 'number' ? 'number' : 'text'} step="any" value={strToString(item)}
            onChange={(e) => {
              const next = [...value];
              next[i] = items.type === 'number' ? (e.target.value === '' ? undefined : Number(e.target.value)) : e.target.value;
              onValue(next);
            }}
            className="flex-1 rounded-md border border-border px-2.5 py-1 text-sm focus:border-focus-ring focus:ring-1 focus:ring-focus-ring" />
          <button type="button" aria-label={`Remove item ${i + 1}`} title="Remove"
            onClick={() => onValue(value.filter((_, j) => j !== i))}
            className="rounded px-1.5 py-0.5 text-xs text-faint hover:bg-danger hover:text-danger-fg">✕</button>
        </div>
      ))}
      <button type="button" onClick={() => onValue([...value, items.type === 'number' ? 0 : ''])}
        className="text-xs font-medium text-muted-foreground hover:text-secondary">+ Add item</button>
    </div>
  );
}

function coerce(prop: InputSchemaProperty, raw: string): unknown {
  if (prop.type === 'number') return Number(raw);
  if (prop.enum) return prop.enum.find((e) => String(e) === raw) ?? raw;
  return raw;
}

function numToString(v: unknown): string {
  return v === undefined || v === null ? '' : String(v);
}

function strToString(v: unknown): string {
  if (v === undefined || v === null) return '';
  if (typeof v === 'object') return JSON.stringify(v);
  return String(v);
}
