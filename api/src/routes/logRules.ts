import { Router, Request, Response } from 'express';
import { v4 as uuidv4 } from 'uuid';
import { pool } from '../db';
import { getEffectiveSettingValue } from '../systemSettings';
import { requireAuth, requirePermission } from '../auth/middleware';
import { getLogRulesStats, invalidateLogRuleCache } from '../workers/logRules';
import { LogRuleParseError, importAllSigmaRules, parseSigmaRule } from '../logRules/sigma';

/**
 * Log rules — Sigma detection over ingested device log lines (Security page).
 *
 * Rules are rows in log_rules: built-ins seeded at boot by the worker plus user
 * rules managed here. The worker (workers/logRules.ts) scans security_events
 * with a watermark and raises 'log-rule' findings into flow_security_findings —
 * same pipeline as threat-intel hits. Reads gated on `security:read`; writes on
 * `system:write`.
 */

const router = Router();

const SEVERITIES = ['info', 'warning', 'critical'] as const;

interface RuleRow {
  id: string;
  name: string;
  source: string;
  sigmaYaml: string;
  enabled: boolean;
  severityOverride: string | null;
  lastError: string | null;
  createdAt: string;
  updatedAt: string;
}

function ruleToJson(r: RuleRow, hit?: { lastHitAt: string; occurrences: number } | null) {
  return {
    id: String(r.id),
    name: String(r.name),
    source: (['builtin', 'user'] as readonly string[]).includes(String(r.source)) ? r.source : 'user',
    sigmaYaml: String(r.sigmaYaml),
    enabled: Boolean(r.enabled),
    severityOverride: r.severityOverride && (SEVERITIES as readonly string[]).includes(String(r.severityOverride)) ? String(r.severityOverride) : null,
    lastError: r.lastError ? String(r.lastError) : null,
    createdAt: String(r.createdAt),
    updatedAt: String(r.updatedAt),
    // Open-finding stats for this rule (null = never fired / already resolved).
    lastHitAt: hit?.lastHitAt ?? null,
    occurrences: hit?.occurrences ?? 0,
  };
}

/** Open 'log-rule' findings grouped by their context.ruleId. */
async function loadRuleHits(): Promise<Map<string, { lastHitAt: string; occurrences: number }>> {
  const res = await pool.query(
    `SELECT context, "lastSeenAt", occurrences FROM flow_security_findings WHERE kind = 'log-rule' AND status = 'open'`
  );
  const map = new Map<string, { lastHitAt: string; occurrences: number }>();
  for (const r of res.rows) {
    let ruleId: unknown;
    try {
      ruleId = JSON.parse(String(r.context ?? '{}')).ruleId;
    } catch {
      continue; // context is best-effort — never fail the listing on it
    }
    if (typeof ruleId !== 'string') continue;
    const cur = map.get(ruleId);
    const lastSeenAt = String(r.lastSeenAt);
    map.set(ruleId, {
      lastHitAt: !cur || lastSeenAt > cur.lastHitAt ? lastSeenAt : cur.lastHitAt,
      occurrences: (cur?.occurrences ?? 0) + Number(r.occurrences ?? 1),
    });
  }
  return map;
}

/** GET /v1/log-rules — worker status + all rules with open-finding stats. */
router.get('/log-rules', requireAuth, requirePermission('security:read'), async (_req: Request, res: Response) => {
  try {
    const [rulesRes, hits] = await Promise.all([
      pool.query<RuleRow>(`SELECT id, name, source, "sigmaYaml", enabled, "severityOverride", "lastError", "createdAt", "updatedAt" FROM log_rules ORDER BY source DESC, name`),
      loadRuleHits(),
    ]);
    const hitRes = await pool.query(
      `SELECT count(*)::int AS n FROM flow_security_findings WHERE kind = 'log-rule' AND "firstSeenAt" >= $1`,
      [new Date(Date.now() - 86_400_000).toISOString()]
    );
    res.status(200).json({
      enabled: (await getEffectiveSettingValue('logRulesEnabled')) === true,
      worker: { ...getLogRulesStats(), hitsLast24h: Number(hitRes.rows[0]?.n ?? 0) },
      rules: rulesRes.rows.map((r) => ruleToJson(r, hits.get(String(r.id)) ?? null)),
    });
  } catch (error) {
    console.error('Error querying log rules:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

/** POST /v1/log-rules — create a user rule from one Sigma document. */
router.post('/log-rules', requireAuth, requirePermission('system:write'), async (req: Request, res: Response) => {
  try {
    const body = (req.body ?? {}) as Record<string, unknown>;
    const yamlText = typeof body.yaml === 'string' ? body.yaml : '';
    if (!yamlText.trim()) {
      res.status(400).json({ error: '"yaml" is required — one Sigma rule document' });
      return;
    }

    let parsed;
    try {
      parsed = parseSigmaRule(yamlText, typeof body.name === 'string' && body.name.trim() ? { name: body.name.trim() } : undefined);
    } catch (err) {
      if (err instanceof LogRuleParseError) {
        res.status(400).json({ error: err.message, issues: err.issues });
        return;
      }
      throw err;
    }

    const dup = await pool.query(`SELECT id FROM log_rules WHERE name = $1`, [parsed.name]);
    if (dup.rows.length > 0) {
      res.status(409).json({ error: `a rule named "${parsed.name}" already exists` });
      return;
    }

    const id = uuidv4();
    const nowIso = new Date().toISOString();
    await pool.query(
      `INSERT INTO log_rules (id, name, source, "sigmaYaml", enabled, "severityOverride", "lastError", "createdAt", "updatedAt")
       VALUES ($1, $2, 'user', $3, true, NULL, NULL, $4, $4)`,
      [id, parsed.name, yamlText.trim(), nowIso]
    );
    invalidateLogRuleCache();

    const created = await pool.query<RuleRow>(`SELECT id, name, source, "sigmaYaml", enabled, "severityOverride", "lastError", "createdAt", "updatedAt" FROM log_rules WHERE id = $1`, [id]);
    res.status(201).json(ruleToJson(created.rows[0]));
  } catch (error) {
    console.error('Error creating log rule:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

/** PATCH /v1/log-rules/:id — enable/disable, severity override; YAML replace for user rules only. */
router.patch('/log-rules/:id', requireAuth, requirePermission('system:write'), async (req: Request, res: Response) => {
  try {
    const body = (req.body ?? {}) as Record<string, unknown>;
    const pre = await pool.query<RuleRow>(`SELECT id, name, source, "sigmaYaml", enabled, "severityOverride", "lastError", "createdAt", "updatedAt" FROM log_rules WHERE id = $1`, [req.params.id]);
    if (pre.rows.length === 0) {
      res.status(404).json({ error: 'rule not found' });
      return;
    }
    const row = pre.rows[0];

    const sets: string[] = [];
    const params: unknown[] = [];
    if (body.enabled !== undefined) {
      if (typeof body.enabled !== 'boolean') {
        res.status(400).json({ error: '"enabled" must be a boolean' });
        return;
      }
      params.push(body.enabled);
      sets.push(`enabled = $${params.length}`);
    }
    if (body.severityOverride !== undefined) {
      if (body.severityOverride === null) {
        params.push(null);
        sets.push(`"severityOverride" = $${params.length}`);
      } else if (typeof body.severityOverride === 'string' && (SEVERITIES as readonly string[]).includes(body.severityOverride)) {
        params.push(body.severityOverride);
        sets.push(`"severityOverride" = $${params.length}`);
      } else {
        res.status(400).json({ error: `"severityOverride" must be null or one of: ${SEVERITIES.join(', ')}` });
        return;
      }
    }
    if (body.yaml !== undefined) {
      if (row.source === 'builtin') {
        res.status(400).json({ error: 'built-in rules are managed by UNM — disable the rule or override its severity instead' });
        return;
      }
      const yamlText = typeof body.yaml === 'string' ? body.yaml : '';
      if (!yamlText.trim()) {
        res.status(400).json({ error: '"yaml" must be a non-empty Sigma document' });
        return;
      }
      try {
        parseSigmaRule(yamlText, { name: row.name }); // validate only — the stored name stays stable
      } catch (err) {
        if (err instanceof LogRuleParseError) {
          res.status(400).json({ error: err.message, issues: err.issues });
          return;
        }
        throw err;
      }
      params.push(yamlText.trim());
      sets.push(`"sigmaYaml" = $${params.length}`);
    }
    if (sets.length === 0) {
      res.status(400).json({ error: 'no fields to update' });
      return;
    }

    params.push(new Date().toISOString());
    sets.push(`"updatedAt" = $${params.length}`);
    params.push(req.params.id);
    const upd = await pool.query<RuleRow>(
      `UPDATE log_rules SET ${sets.join(', ')} WHERE id = $${params.length} RETURNING id, name, source, "sigmaYaml", enabled, "severityOverride", "lastError", "createdAt", "updatedAt"`,
      params
    );
    invalidateLogRuleCache();
    res.status(200).json(ruleToJson(upd.rows[0]));
  } catch (error) {
    console.error('Error updating log rule:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

/** DELETE /v1/log-rules/:id — user rules only. */
router.delete('/log-rules/:id', requireAuth, requirePermission('system:write'), async (req: Request, res: Response) => {
  try {
    const del = await pool.query(`DELETE FROM log_rules WHERE id = $1 AND source = 'user'`, [req.params.id]);
    if (del.rowCount === 0) {
      // Distinguish "not found" from "built-in is protected".
      const exists = await pool.query(`SELECT id FROM log_rules WHERE id = $1`, [req.params.id]);
      res.status(exists.rows.length > 0 ? 400 : 404).json({
        error: exists.rows.length > 0 ? 'built-in rules cannot be deleted — disable them instead' : 'rule not found',
      });
      return;
    }
    invalidateLogRuleCache();
    res.status(200).json({ deleted: true });
  } catch (error) {
    console.error('Error deleting log rule:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

/** POST /v1/log-rules/import — multi-document Sigma import; per-rule results, never all-or-nothing. */
router.post('/log-rules/import', requireAuth, requirePermission('system:write'), async (req: Request, res: Response) => {
  try {
    const body = (req.body ?? {}) as Record<string, unknown>;
    const yamlText = typeof body.yaml === 'string' ? body.yaml : '';
    if (!yamlText.trim()) {
      res.status(400).json({ error: '"yaml" is required — one or more Sigma documents separated by ---' });
      return;
    }

    const outcomes = importAllSigmaRules(yamlText);
    const results: Array<{ name: string | null; status: 'created' | 'duplicate' | 'error'; error?: string }> = [];
    let imported = 0;
    for (const o of outcomes) {
      if (!o.rule) {
        results.push({ name: o.name, status: 'error', error: o.error });
        continue;
      }
      const dup = await pool.query(`SELECT id FROM log_rules WHERE name = $1`, [o.rule.name]);
      if (dup.rows.length > 0) {
        results.push({ name: o.rule.name, status: 'duplicate' });
        continue;
      }
      const nowIso = new Date().toISOString();
      await pool.query(
        `INSERT INTO log_rules (id, name, source, "sigmaYaml", enabled, "severityOverride", "lastError", "createdAt", "updatedAt")
         VALUES ($1, $2, 'user', $3, true, NULL, NULL, $4, $4)`,
        [uuidv4(), o.rule.name, (o.yaml ?? '').trim() || yamlText.trim(), nowIso]
      );
      imported++;
      results.push({ name: o.rule.name, status: 'created' });
    }

    if (imported > 0) invalidateLogRuleCache();
    res.status(201).json({ imported, total: outcomes.length, results });
  } catch (error) {
    console.error('Error importing log rules:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

export default router;
