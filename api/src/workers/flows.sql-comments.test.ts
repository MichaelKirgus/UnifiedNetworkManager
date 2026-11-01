/**
 * Regression guard: Postgres only knows `--` comments. A JS-style `//` comment
 * inside a SQL template literal is SILENTLY sent to the database and fails the
 * whole statement with "syntax error at or near \".\"" — tsc cannot catch it
 * (it's inside a string). This bit the hourly rollup in flows.ts for two weeks
 * (flow_agg_1h never populated; the shared lastError pinned the failure onto
 * the Flows page forever).
 *
 * The test extracts every top-level template literal from workers/flows.ts,
 * strips `${…}` interpolation regions (where JS comments ARE legal), and asserts
 * no remaining line starts with `//`.
 */

import { readFileSync } from 'node:fs';
import path from 'node:path';

/** Removes balanced `${ … }` interpolation expressions from a template body. */
function stripInterpolations(body: string): string {
  let out = '';
  let i = 0;
  while (i < body.length) {
    if (body[i] === '$' && body[i + 1] === '{') {
      // Skip the balanced brace group.
      let depth = 1;
      i += 2;
      while (i < body.length && depth > 0) {
        if (body[i] === '{') depth++;
        else if (body[i] === '}') depth--;
        i++;
      }
    } else {
      out += body[i];
      i++;
    }
  }
  return out;
}

/** Extracts top-level template literal bodies from TS source. */
function topLevelTemplateBodies(src: string): string[] {
  const bodies: string[] = [];
  let i = 0;
  while (i < src.length) {
    if (src[i] === '`') {
      const start = ++i;
      // Walk to the closing backtick, honoring escaped chars and ${…} groups.
      let j = start;
      while (j < src.length && src[j] !== '`') {
        if (src[j] === '\\') j += 2;
        else if (src[j] === '$' && src[j + 1] === '{') {
          let depth = 1;
          j += 2;
          while (j < src.length && depth > 0) {
            if (src[j] === '{') depth++;
            else if (src[j] === '}') depth--;
            j++;
          }
        } else {
          j++;
        }
      }
      bodies.push(src.slice(start, j));
      i = j + 1;
    } else {
      i++;
    }
  }
  return bodies;
}

describe('flows worker SQL template literals', () => {
  const src = readFileSync(path.join(__dirname, 'flows.ts'), 'utf8');
  // Only the templates that actually reach Postgres (the file's queries all
  // contain one of these markers).
  const sqlBodies = topLevelTemplateBodies(src).filter((b) => /INSERT INTO|SELECT |CREATE TABLE|DROP TABLE/.test(b));

  test('extracts SQL template literals', () => {
    expect(sqlBodies.length).toBeGreaterThanOrEqual(4); // drain, rollup5m select+insert, rollup1h, partitions
  });

  test.each(sqlBodies.map((b, i) => [i, b]))('template %d has no JS-style (//) comments', (_idx, body) => {
    const sql = stripInterpolations(body);
    const offenders: string[] = [];
    for (const line of sql.split('\n')) {
      if (/^\s*\/\//.test(line)) offenders.push(line.trim());
    }
    expect(offenders).toEqual([]);
  });
});
