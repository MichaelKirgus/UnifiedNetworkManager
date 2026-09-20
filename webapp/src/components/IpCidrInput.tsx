import { isIpLiteral } from '../utils/address';
import { ipFamily, validateIpCidr } from '../utils/hostAutofill';

/**
 * Reusable IP / CIDR input: an address field plus a prefix (CIDR) selector.
 *
 * The component detects the family of what was typed — IPv4 offers prefixes
 * 0–32, IPv6 also allows higher ones (up to 128). When no valid IP literal is
 * present yet, the prefix section is disabled; in `addressOnly` mode it stays
 * disabled permanently (the field then holds a bare address, never a CIDR).
 */

const V4_PREFIXES = Array.from({ length: 33 }, (_, i) => i); // 0..32
const V6_PREFIXES = Array.from({ length: 129 }, (_, i) => i); // 0..128

interface IpCidrInputProps {
  value: string;
  onChange: (value: string) => void;
  /** When true the field holds a bare address — the prefix selector is disabled. */
  addressOnly?: boolean;
  /** When true plain (non-IP) text is allowed — only CIDR-looking values are validated inline. */
  freeText?: boolean;
  /** Optional datalist id for known values on the address part. */
  listId?: string;
  placeholder?: string;
  title?: string;
}

export function IpCidrInput({ value, onChange, addressOnly = false, freeText = false, listId, placeholder, title }: IpCidrInputProps) {
  const trimmed = value.trim();
  const family: 'v4' | 'v6' | null = isIpLiteral(trimmed) ? ipFamily(trimmed) : null;
  const prefixEnabled = !addressOnly && family !== null;

  // The typed text already carries a "/prefix" — parse it for the selector.
  const slashIdx = trimmed.indexOf('/');
  let currentPrefix: number | null = null;
  if (slashIdx > 0) {
    const p = Number(trimmed.slice(slashIdx + 1));
    if (Number.isInteger(p)) currentPrefix = p;
  }

  function setPrefix(prefix: number) {
    const base = slashIdx > 0 ? trimmed.slice(0, slashIdx) : trimmed;
    onChange(`${base}/${prefix}`);
  }

  // Inline error: bare-address mode rejects non-IP text; free-text mode only
  // checks values that look like a CIDR (plain labels are legal there).
  let error: string | null = null;
  if (trimmed !== '') {
    if (addressOnly) error = family ? null : 'Not a valid IP address';
    else if (!freeText || trimmed.includes('/')) error = validateIpCidr(trimmed);
  }

  return (
    <div className="flex min-w-0 items-stretch gap-1">
      <input
        className={`min-w-0 flex-1 rounded-md border px-3 py-1.5 font-mono text-sm ${error ? 'border-danger' : 'border-border'}`}
        placeholder={placeholder ?? 'IPv4 or IPv6 address'}
        title={title}
        list={listId}
        value={value}
        onChange={(e) => onChange(e.target.value)}
      />
      <select
        className="w-[72px] shrink-0 rounded-md border border-border bg-background px-1 py-1.5 font-mono text-xs disabled:opacity-40"
        title={addressOnly ? 'Prefix selection is disabled — this field holds a bare address' : 'Network prefix (CIDR)'}
        value={currentPrefix ?? ''}
        disabled={!prefixEnabled}
        onChange={(e) => {
          if (e.target.value === '') onChange(slashIdx > 0 ? trimmed.slice(0, slashIdx) : trimmed); // clear the suffix
          else setPrefix(Number(e.target.value));
        }}
      >
        <option value="">
          /pfx
        </option>
        {(family === 'v6' ? V6_PREFIXES : V4_PREFIXES).map((p) => (
          <option key={p} value={p}>
            /{p}
          </option>
        ))}
      </select>
    </div>
  );
}
