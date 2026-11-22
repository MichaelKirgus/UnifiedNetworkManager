/**
 * Sigma rule parsing for log rules (docs/LOG-RULES.md §4).
 *
 * UNM implements the SINGLE-LINE subset of the Sigma format: one ingested log
 * line is matched against field conditions with boolean logic. This module is
 * PURE — no DB, no workers — so it is fully unit-testable in isolation.
 *
 * Supported (see docs/LOG-RULES.md for the full contract):
 *   - fields: message, appname, facility, hostname, srcIp, dstIp
 *     (anything else → parse error naming the offending field)
 *   - matchers: plain value (=), contains, startswith, endswith, re — a list of
 *     values is OR'd; multiple keys in one selection are AND'd (Sigma semantics).
 *     All string matching is CASE-INSENSITIVE (log-friendly default); `re`
 *     compiles as an unanchored JS regex with the i flag — Sigma/PCRE inline
 *     flags are not valid JS, so a leading (?i) group is stripped before compile
 *   - condition grammar: and / or / not + parentheses over selection names
 *   - logsource.service / logsource.product → appname scope filter
 *   - level low/medium/high/critical → info/warning/critical
 *   - UNM extension `unm.threshold {count, withinMinutes, groupBy}` (top-level)
 *     — rolling-window counters that unlock brute-force-style detection
 *
 * Deliberately REJECTED at parse time with actionable errors: aggregations
 * (count/sum/min/max), re_all/all matchers, cross-logsource correlation and any
 * field UNM does not ingest. A rule must never sit dead and silently never fire.
 */

import { parseAllDocuments } from 'yaml';

/** Parse failure with structured per-issue messages (surfaced verbatim in the UI). */
export class LogRuleParseError extends Error {
  constructor(message: string, public readonly issues: string[]) {
    super(message);
    this.name = 'LogRuleParseError';
  }
}

/** The row shape compiled rules are evaluated against (security_events columns). */
export interface LogRuleRow {
  message: string;
  appname: string | null;
  facility: string | null;
  hostname: string | null;
  srcIp: string | null;
  dstIp: string | null;
}

export type RuleSeverity = 'info' | 'warning' | 'critical';

/** UNM extension — rolling-window threshold (brute-force style detection). */
export interface LogRuleThreshold {
  count: number;
  withinMs: number;
  groupBy: 'srcIp' | 'hostname' | 'device';
}

export interface CompiledLogRule {
  /** Display name (Sigma title, or the caller-provided override). */
  name: string;
  sigmaId: string | null;
  level: RuleSeverity;
  tags: string[];
  description: string | null;
  references: string[];
  /** Lowercased appname scope from logsource.service/product — null = no scope. */
  scopeAppname: string | null;
  threshold: LogRuleThreshold | null;
  /** True when the row matches the rule's detection + condition (scope included). */
  evaluate(row: LogRuleRow): boolean;
}

const SUPPORTED_FIELDS = ['message', 'appname', 'facility', 'hostname', 'srcIp', 'dstIp'] as const;
type SupportedField = (typeof SUPPORTED_FIELDS)[number];

const LEVEL_MAP: Record<string, RuleSeverity> = { low: 'info', medium: 'warning', high: 'critical', critical: 'critical' };
const THRESHOLD_GROUP_BY = ['srcIp', 'hostname', 'device'] as const;

// ── Matchers ────────────────────────────────────────────────────────────────

type Op = 'eq' | 'contains' | 'startswith' | 'endswith' | 're';

interface Matcher {
  field: SupportedField;
  op: Op;
  /** Stringified values, OR'd (empty for re — see regexes). */
  values: string[];
  regexes?: RegExp[];
}

function rowValue(row: LogRuleRow, field: SupportedField): string | null {
  const v = row[field];
  return v === null || v === undefined ? null : String(v);
}

/** One matcher against one row. Absent (NULL) fields never match. */
export function matchersMatch(m: Matcher, row: LogRuleRow): boolean {
  const v = rowValue(row, m.field);
  if (v === null) return false;
  switch (m.op) {
    case 'eq':
      return m.values.some((x) => x.toLowerCase() === v.toLowerCase());
    case 'contains': {
      const lv = v.toLowerCase();
      return m.values.some((x) => lv.includes(x.toLowerCase()));
    }
    case 'startswith':
      return m.values.some((x) => v.toLowerCase().startsWith(x.toLowerCase()));
    case 'endswith':
      return m.values.some((x) => v.toLowerCase().endsWith(x.toLowerCase()));
    case 're':
      return (m.regexes ?? []).some((r) => r.test(v));
  }
}

/** All matchers within one selection are AND'd (Sigma semantics). */
function selectionMatches(matchers: Matcher[], row: LogRuleRow): boolean {
  return matchers.every((m) => matchersMatch(m, row));
}

// ── Condition grammar (recursive descent) ───────────────────────────────────
// expr   := term ( 'or' term )*
// term   := factor ( 'and' factor )*
// factor := 'not' factor | '(' expr ')' | selectionName

type ConditionNode =
  | { type: 'sel'; name: string }
  | { type: 'and'; children: ConditionNode[] }
  | { type: 'or'; children: ConditionNode[] }
  | { type: 'not'; child: ConditionNode };

function tokenizeCondition(s: string): string[] {
  return s.match(/[A-Za-z0-9_.\-]+|[()]/g) ?? [];
}

class ConditionParser {
  private pos = 0;
  constructor(private readonly tokens: string[], private readonly defined: Set<string>) {}

  parse(): ConditionNode {
    const node = this.parseOr();
    if (this.pos < this.tokens.length) {
      throw new LogRuleParseError(`unexpected token "${this.tokens[this.pos]}" in condition`, [
        `condition: unexpected token "${this.tokens[this.pos]}" after a complete expression`,
      ]);
    }
    return node;
  }

  private peek(): string | undefined {
    return this.tokens[this.pos];
  }

  private next(): string | undefined {
    return this.tokens[this.pos++];
  }

  private parseOr(): ConditionNode {
    const children: ConditionNode[] = [this.parseAnd()];
    while (this.peek() === 'or') {
      this.next();
      children.push(this.parseAnd());
    }
    return children.length === 1 ? children[0] : { type: 'or', children };
  }

  private parseAnd(): ConditionNode {
    const children: ConditionNode[] = [this.parseFactor()];
    while (this.peek() === 'and') {
      this.next();
      children.push(this.parseFactor());
    }
    return children.length === 1 ? children[0] : { type: 'and', children };
  }

  private parseFactor(): ConditionNode {
    const tok = this.next();
    if (tok === undefined) throw new LogRuleParseError('condition ends unexpectedly', ['condition: expression ends before it is complete']);
    if (tok === '(') {
      const inner = this.parseOr();
      if (this.next() !== ')') throw new LogRuleParseError('missing closing parenthesis in condition', ['condition: missing ")"']);
      return inner;
    }
    if (tok === 'not') return { type: 'not', child: this.parseFactor() };
    if (tok === ')' || tok === 'and' || tok === 'or') {
      throw new LogRuleParseError(`unexpected "${tok}" in condition`, [`condition: unexpected "${tok}"`]);
    }
    // A selection name.
    if (!this.defined.has(tok)) {
      throw new LogRuleParseError(
        `condition references unknown selection "${tok}"`,
        [`condition: "${tok}" is not defined in detection (known selections: ${[...this.defined].join(', ')})`]
      );
    }
    return { type: 'sel', name: tok };
  }
}

function evalCondition(node: ConditionNode, selections: Map<string, Matcher[]>, row: LogRuleRow): boolean {
  switch (node.type) {
    case 'sel':
      return selectionMatches(selections.get(node.name) ?? [], row);
    case 'and':
      return node.children.every((c) => evalCondition(c, selections, row));
    case 'or':
      return node.children.some((c) => evalCondition(c, selections, row));
    case 'not':
      return !evalCondition(node.child, selections, row);
  }
}

// ── Detection block compilation ─────────────────────────────────────────────

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

/** Coerces a scalar detection value to its string form (numbers/booleans included). */
function coerceValue(v: unknown, where: string): string {
  if (typeof v === 'string') return v;
  if (typeof v === 'number' || typeof v === 'boolean') return String(v);
  throw new LogRuleParseError(`unsupported value in ${where}`, [`${where}: values must be strings, numbers or booleans`]);
}

/** Narrows an unknown to a mapping or throws a structured parse error (CFA-visible). */
function requirePlainObject(v: unknown, where: string): Record<string, unknown> {
  if (!isPlainObject(v)) throw new LogRuleParseError(`"${where}" must be a mapping`, [`${where}: expected a mapping of key/value pairs`]);
  return v;
}

/** Compiles one detection key (field → matcher) into a Matcher. */
function compileMatcher(fieldRaw: string, value: unknown, selectionName: string): Matcher {
  if (!(SUPPORTED_FIELDS as readonly string[]).includes(fieldRaw)) {
    throw new LogRuleParseError(
      `field "${fieldRaw}" is not available in UNM log lines`,
      [`detection.${selectionName}: field "${fieldRaw}" — supported fields are: ${SUPPORTED_FIELDS.join(', ')}`]
    );
  }
  const field = fieldRaw as SupportedField;

  // Plain scalar or list of scalars → equality (OR'd).
  if (!isPlainObject(value)) {
    const values = (Array.isArray(value) ? value : [value]).map((v) => coerceValue(v, `detection.${selectionName}.${field}`));
    return { field, op: 'eq', values };
  }

  // Modifier object — exactly one known modifier.
  const keys = Object.keys(value);
  if (keys.length !== 1) {
    throw new LogRuleParseError(
      `unsupported detection syntax for ${field} in selection "${selectionName}"`,
      [`detection.${selectionName}.${field}: expected a value or exactly one modifier (${['contains', 'startswith', 'endswith', 're'].join(' | ')})`]
    );
  }
  const op = keys[0];
  if (!['contains', 'startswith', 'endswith', 're'].includes(op)) {
    throw new LogRuleParseError(
      `unsupported modifier "${op}" for ${field} in selection "${selectionName}"`,
      [`detection.${selectionName}.${field}: modifier "${op}" is not supported (supported: contains, startswith, endswith, re)`]
    );
  }

  const rawValues = Array.isArray(value[op]) ? value[op] : [value[op]];
  if (op === 're') {
    const regexes: RegExp[] = [];
    for (const p of rawValues) {
      const pat = coerceValue(p, `detection.${selectionName}.${field}.re`);
      // Sigma/PCRE inline flags are not valid JS — strip a leading (?i) group.
      // The i flag is always applied: case-insensitive matching is the
      // log-friendly default (consistent with eq/contains above).
      const jsPat = pat.replace(/^\(\?i\)/, '');
      try {
        // Unanchored search — a pattern matches anywhere in the line.
        regexes.push(new RegExp(jsPat, 'i'));
      } catch (err) {
        throw new LogRuleParseError(`invalid regular expression for ${field}`, [
          `detection.${selectionName}.${field}.re: ${(err as Error).message} (pattern: "${pat}")`,
        ]);
      }
    }
    return { field, op: 're', values: [], regexes };
  }

  const values = rawValues.map((v) => coerceValue(v, `detection.${selectionName}.${field}.${op}`));
  return { field, op: op as Op, values };
}

// ── Top-level compilation ───────────────────────────────────────────────────

export interface ParseOptions {
  /** Overrides the Sigma title as the rule name (route-provided). */
  name?: string;
}

/** Compiles a parsed YAML document object into an executable rule. Throws LogRuleParseError. */
export function compileSigmaObject(raw: unknown, opts: ParseOptions = {}): CompiledLogRule {
  const obj = requirePlainObject(raw, 'top level');

  // title / name.
  const title = typeof obj.title === 'string' ? obj.title.trim() : '';
  if (!title) throw new LogRuleParseError('"title" is required (1-200 characters)', ['"title": missing or not a string']);
  if (title.length > 200) throw new LogRuleParseError('"title" must be at most 200 characters', [`"title": ${title.length} characters — max 200`]);
  const name = opts.name?.trim() || title;

  // level.
  let level: RuleSeverity = 'warning';
  if (obj.level !== undefined) {
    const lvl = typeof obj.level === 'string' ? obj.level : '';
    if (!(lvl in LEVEL_MAP)) {
      throw new LogRuleParseError('"level" must be one of low, medium, high, critical', [`"level": "${String(obj.level)}" — expected low | medium | high | critical`]);
    }
    level = LEVEL_MAP[lvl];
  }

  // Optional metadata.
  const sigmaId = typeof obj.id === 'string' && obj.id.trim() ? obj.id.trim() : null;
  const description = typeof obj.description === 'string' && obj.description.trim() ? obj.description.trim() : null;
  const tags: string[] = Array.isArray(obj.tags) ? obj.tags.map((t) => String(t)).filter(Boolean) : [];
  const references: string[] = Array.isArray(obj.references) ? obj.references.map((r) => String(r)).filter(Boolean) : [];

  // logsource → appname scope (service or product; category has no UNM column).
  let scopeAppname: string | null = null;
  if (obj.logsource !== undefined) {
    const ls = requirePlainObject(obj.logsource, 'logsource');
    const svc = typeof ls.service === 'string' ? ls.service.trim() : '';
    const prod = typeof ls.product === 'string' ? ls.product.trim() : '';
    if (svc || prod) scopeAppname = (svc || prod).toLowerCase();
  }

  // detection.
  const detection = requirePlainObject(obj.detection, 'detection');
  const selections = new Map<string, Matcher[]>();
  for (const [selName, selValue] of Object.entries(detection)) {
    const selObj = requirePlainObject(selValue, `detection.${selName}`);
    const matchers: Matcher[] = [];
    for (const [fieldRaw, fieldValue] of Object.entries(selObj)) {
      matchers.push(compileMatcher(fieldRaw, fieldValue, selName));
    }
    if (matchers.length === 0) throw new LogRuleParseError(`selection "${selName}" is empty`, [`detection.${selName}: at least one field matcher is required`]);
    selections.set(selName, matchers);
  }

  // condition.
  const condition = typeof obj.condition === 'string' ? obj.condition.trim() : '';
  if (!condition) throw new LogRuleParseError('"condition" is required', ['"condition": missing or not a string']);
  let condNode: ConditionNode;
  try {
    condNode = new ConditionParser(tokenizeCondition(condition), new Set(selections.keys())).parse();
  } catch (err) {
    if (err instanceof LogRuleParseError) throw err;
    throw new LogRuleParseError(`invalid condition "${condition}"`, [`condition: ${(err as Error).message}`]);
  }

  // UNM extension — rolling-window threshold (documented top-level flat key "unm.threshold").
  let threshold: LogRuleThreshold | null = null;
  if (obj['unm.threshold'] !== undefined || obj.unm !== undefined) {
    if (obj['unm.threshold'] === undefined) throw new LogRuleParseError('use the top-level "unm.threshold" key', ['"unm": nested block not supported — use top-level `unm.threshold: {count, withinMinutes, groupBy}`']);
    const thObj = requirePlainObject(obj['unm.threshold'], 'unm.threshold');
    const count = Number(thObj.count);
    const withinMin = Number(thObj.withinMinutes);
    const groupBy = thObj.groupBy;
    if (!Number.isInteger(count) || count < 2) throw new LogRuleParseError('"unm.threshold.count" must be an integer >= 2', [`"unm.threshold.count": ${String(thObj.count)} — expected an integer >= 2`]);
    if (!(withinMin > 0)) throw new LogRuleParseError('"unm.threshold.withinMinutes" must be a number > 0', [`"unm.threshold.withinMinutes": ${String(thObj.withinMinutes)}`]);
    if (!(THRESHOLD_GROUP_BY as readonly string[]).includes(String(groupBy))) {
      throw new LogRuleParseError(`"unm.threshold.groupBy" must be one of: ${THRESHOLD_GROUP_BY.join(', ')}`, [`"unm.threshold.groupBy": "${String(groupBy)}"`]);
    }
    threshold = { count, withinMs: withinMin * 60_000, groupBy: groupBy as LogRuleThreshold['groupBy'] };
  }

  return {
    name,
    sigmaId,
    level,
    tags,
    description,
    references,
    scopeAppname,
    threshold,
    evaluate(row: LogRuleRow): boolean {
      // Scope first — a scoped rule never evaluates lines from other appnames.
      if (scopeAppname !== null && rowValue(row, 'appname')?.toLowerCase() !== scopeAppname) return false;
      return evalCondition(condNode, selections, row);
    },
  };
}

/** Parses exactly ONE Sigma document. Multi-document input is an error (use importAllSigmaRules). */
export function parseSigmaRule(yamlText: string, opts: ParseOptions = {}): CompiledLogRule {
  const docs = parseAllDocuments(yamlText);
  if (docs.length === 0) throw new LogRuleParseError('empty YAML document', ['no YAML content']);
  if (docs.length > 1) {
    throw new LogRuleParseError(`multi-document YAML (${docs.length} documents) is not allowed here`, [
      'this endpoint accepts exactly one rule — use POST /log-rules/import for multiple rules',
    ]);
  }
  const doc = docs[0];
  if (doc.errors.length > 0) {
    throw new LogRuleParseError('invalid YAML', doc.errors.map((e) => e.message));
  }
  return compileSigmaObject(doc.toJS(), opts);
}

/** One per-rule outcome of a multi-document import. */
export interface ImportOutcome {
  name: string | null;
  /** The document's raw YAML (re-serialized) — stored verbatim in log_rules.sigmaYaml. */
  yaml?: string;
  rule?: CompiledLogRule;
  error?: string;
}

/** Parses ALL documents in the text (import endpoint). Per-doc errors never abort the batch. */
export function importAllSigmaRules(yamlText: string): ImportOutcome[] {
  const docs = parseAllDocuments(yamlText);
  return docs.map((doc) => {
    if (doc.errors.length > 0) {
      return { name: null, error: doc.errors[0].message };
    }
    try {
      const rule = compileSigmaObject(doc.toJS());
      return { name: rule.name, yaml: doc.toString(), rule };
    } catch (err) {
      if (err instanceof LogRuleParseError) return { name: null, error: err.issues.join('; ') || err.message };
      throw err;
    }
  });
}
