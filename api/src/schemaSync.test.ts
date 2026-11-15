/**
 * Unit tests for the additive schema sync's pure logic (DDL parsing + statement building).
 * Fixtures are verbatim excerpts of `drizzle-kit generate` output for src/db/schema.ts.
 * The live database path is covered by dev/prod E2E (drop tables → restart api → auto-heal).
 */

import { buildAddColumn, buildIdempotentIndex, extractColumnDefs, parseMigrationSql } from './schemaSync';

const SAMPLE_SQL = [
  'CREATE TABLE "notification_rules" (',
  '        "id" text PRIMARY KEY NOT NULL,',
  '        "name" text NOT NULL,',
  '        "enabled" boolean DEFAULT true NOT NULL,',
  '        "filter" text DEFAULT \'{}\' NOT NULL,',
  '        "channelIds" text DEFAULT \'[]\' NOT NULL,',
  '        "audience" text DEFAULT \'{"type":"all"}\' NOT NULL,',
  '        "cooldownSec" integer DEFAULT 300 NOT NULL,',
  '        "createdAt" text NOT NULL',
  ');',
  '--> statement-breakpoint',
  'CREATE TABLE "threat_iocs" (',
  '        "id" text PRIMARY KEY NOT NULL,',
  '        "sourceId" text NOT NULL,',
  '        CONSTRAINT "uq_threat_iocs_source_ioc" UNIQUE("sourceId","ioc")',
  ');',
  '--> statement-breakpoint',
  'ALTER TABLE "threat_iocs" ADD CONSTRAINT "threat_iocs_sourceId_threat_intel_sources_id_fk" FOREIGN KEY ("sourceId") REFERENCES "public"."threat_intel_sources"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint',
  'CREATE INDEX "idx_notification_rules_audience" ON "notification_rules" USING btree ("audience");--> statement-breakpoint',
  'CREATE UNIQUE INDEX "uq_threat_iocs_source_ioc2" ON "threat_iocs" USING btree ("sourceId","ioc");--> statement-breakpoint',
  'SOME FUTURE STATEMENT TYPE THAT MUST BE IGNORED;',
].join('\n');

describe('parseMigrationSql', () => {
  it('classifies tables, indexes and foreign keys; ignores unknown statements', () => {
    const parsed = parseMigrationSql(SAMPLE_SQL);

    expect(parsed.tables.map((t) => t.name)).toEqual(['notification_rules', 'threat_iocs']);
    expect(parsed.indexes).toHaveLength(2);
    expect(parsed.foreignKeys).toHaveLength(1);
  });

  it('keeps the verbatim CREATE TABLE DDL for missing-table creation', () => {
    const parsed = parseMigrationSql(SAMPLE_SQL);
    const rules = parsed.tables[0];
    expect(rules.ddl.startsWith('CREATE TABLE "notification_rules" (')).toBe(true);
    expect(rules.ddl).toContain('"audience" text DEFAULT \'{"type":"all"}\' NOT NULL');
  });

  it('parses index uniqueness and target table', () => {
    const parsed = parseMigrationSql(SAMPLE_SQL);
    expect(parsed.indexes[0]).toMatchObject({ name: 'idx_notification_rules_audience', table: 'notification_rules', unique: false });
    expect(parsed.indexes[1]).toMatchObject({ name: 'uq_threat_iocs_source_ioc2', table: 'threat_iocs', unique: true });
  });

  it('parses the FK constraint name and owning table (incl. statements glued to the breakpoint marker)', () => {
    const parsed = parseMigrationSql(SAMPLE_SQL);
    expect(parsed.foreignKeys[0]).toMatchObject({
      table: 'threat_iocs',
      constraintName: 'threat_iocs_sourceId_threat_intel_sources_id_fk',
    });
  });

  it('returns empty units for empty input', () => {
    const parsed = parseMigrationSql('--> statement-breakpoint\n');
    expect(parsed).toEqual({ tables: [], indexes: [], foreignKeys: [] });
  });
});

describe('extractColumnDefs', () => {
  it('extracts one definition per column and skips table-level constraints', () => {
    const parsed = parseMigrationSql(SAMPLE_SQL);
    const rulesCols = parsed.tables[0].columns;
    expect(rulesCols).toEqual([
      '"id" text PRIMARY KEY NOT NULL',
      '"name" text NOT NULL',
      '"enabled" boolean DEFAULT true NOT NULL',
      '"filter" text DEFAULT \'{}\' NOT NULL',
      '"channelIds" text DEFAULT \'[]\' NOT NULL',
      '"audience" text DEFAULT \'{"type":"all"}\' NOT NULL',
      '"cooldownSec" integer DEFAULT 300 NOT NULL',
      '"createdAt" text NOT NULL',
    ]);

    const iocsCols = parsed.tables[1].columns;
    expect(iocsCols).toEqual(['"id" text PRIMARY KEY NOT NULL', '"sourceId" text NOT NULL']);
  });

  it('handles a composite table-level PRIMARY KEY constraint line', () => {
    const sql = 'CREATE TABLE "automation_state" (\n        "a" text NOT NULL,\n        CONSTRAINT "pkey" PRIMARY KEY("a","b")\n);';
    expect(extractColumnDefs(sql)).toEqual(['"a" text NOT NULL']);
  });

  it('returns [] when no parentheses are present', () => {
    expect(extractColumnDefs('CREATE TABLE broken')).toEqual([]);
  });
});

describe('buildAddColumn', () => {
  it('wraps a plain column definition in an idempotent ALTER TABLE', () => {
    const { sql, primaryKeyStripped } = buildAddColumn('notification_channels', '"ownerId" text');
    expect(sql).toBe('ALTER TABLE "notification_channels" ADD COLUMN IF NOT EXISTS "ownerId" text');
    expect(primaryKeyStripped).toBe(false);
  });

  it('preserves defaults and nullability in the generated statement', () => {
    const { sql } = buildAddColumn('notification_rules', '"audience" text DEFAULT \'{"type":"all"}\' NOT NULL');
    expect(sql).toBe(
      'ALTER TABLE "notification_rules" ADD COLUMN IF NOT EXISTS "audience" text DEFAULT \'{"type":"all"}\' NOT NULL'
    );
  });

  it('strips an inline PRIMARY KEY marker on a column added to an existing table', () => {
    const { sql, primaryKeyStripped } = buildAddColumn('t', '"id" text PRIMARY KEY NOT NULL');
    expect(sql).toBe('ALTER TABLE "t" ADD COLUMN IF NOT EXISTS "id" text NOT NULL');
    expect(primaryKeyStripped).toBe(true);
  });
});

describe('buildIdempotentIndex', () => {
  it('adds IF NOT EXISTS to plain indexes', () => {
    const sql = buildIdempotentIndex({
      name: 'idx_x', table: 't', unique: false,
      ddl: 'CREATE INDEX "idx_x" ON "t" USING btree ("a");',
    });
    expect(sql).toBe('CREATE INDEX IF NOT EXISTS "idx_x" ON "t" USING btree ("a");');
  });

  it('adds IF NOT EXISTS to unique indexes without breaking the UNIQUE keyword order', () => {
    const sql = buildIdempotentIndex({
      name: 'uq_x', table: 't', unique: true,
      ddl: 'CREATE UNIQUE INDEX "uq_x" ON "t" USING btree ("a","b");',
    });
    expect(sql).toBe('CREATE UNIQUE INDEX IF NOT EXISTS "uq_x" ON "t" USING btree ("a","b");');
  });
});
