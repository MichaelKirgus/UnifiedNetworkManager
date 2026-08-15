import Database from 'better-sqlite3';
import path from 'path';
import bcrypt from 'bcryptjs';
import { v4 as uuidv4 } from 'uuid';
import { generateSecret, buildOtpAuthUri } from './auth/totp';

const DB_PATH = process.env.UNM_DB_PATH ?? path.resolve(process.cwd(), 'unm.db');

export const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

export interface UserRow {
  id: string;
  username: string;
  passwordHash: string;
  totpSecret: string | null;
  roles: string; // JSON string array
  permissions: string; // JSON string array
  createdAt: string;
}

export interface DeviceRow {
  id: string;
  name: string;
  vendor: string;
  deviceType: string;
  pluginId: string;
  managementAddress: string;
  site: string | null;
  status: string;
  createdAt: string;
}

export interface PluginRow {
  id: string;
  name: string;
  version: string;
  vendors: string; // JSON string array
  capabilities: string; // JSON string array
  endpoint: string;
  authType: string;
  createdAt: string;
}

export interface ConfigJobRow {
  id: string;
  deviceId: string;
  action: string;
  status: string;
  payload: string; // JSON string
  result: string | null; // JSON string
  createdAt: string;
  finishedAt: string | null;
}

export interface TelemetryRow {
  id: string;
  deviceId: string;
  collectedAt: string;
  health: string;
  metrics: string; // JSON string
}

/**
 * Creates all tables (idempotent) and seeds a default admin user on first run.
 */
export function migrate(): void {
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      passwordHash TEXT NOT NULL,
      totpSecret TEXT,
      roles TEXT NOT NULL DEFAULT '[]',
      permissions TEXT NOT NULL DEFAULT '[]',
      createdAt TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS devices (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      vendor TEXT NOT NULL,
      deviceType TEXT NOT NULL,
      pluginId TEXT NOT NULL,
      managementAddress TEXT NOT NULL,
      site TEXT,
      status TEXT NOT NULL DEFAULT 'unknown',
      createdAt TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS plugins (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      version TEXT NOT NULL,
      vendors TEXT NOT NULL DEFAULT '[]',
      capabilities TEXT NOT NULL DEFAULT '[]',
      endpoint TEXT NOT NULL,
      authType TEXT NOT NULL DEFAULT 'none',
      createdAt TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS config_jobs (
      id TEXT PRIMARY KEY,
      deviceId TEXT NOT NULL,
      action TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'queued',
      payload TEXT NOT NULL DEFAULT '{}',
      result TEXT,
      createdAt TEXT NOT NULL,
      finishedAt TEXT
    );

    CREATE TABLE IF NOT EXISTS telemetry (
      id TEXT PRIMARY KEY,
      deviceId TEXT NOT NULL,
      collectedAt TEXT NOT NULL,
      health TEXT NOT NULL DEFAULT 'unknown',
      metrics TEXT NOT NULL DEFAULT '{}'
    );

    CREATE INDEX IF NOT EXISTS idx_telemetry_device_collected
      ON telemetry (deviceId, collectedAt DESC);

    CREATE INDEX IF NOT EXISTS idx_config_jobs_device
      ON config_jobs (deviceId, createdAt DESC);
  `);

  const existingAdmin = db.prepare('SELECT id FROM users WHERE username = ?').get('admin');
  if (!existingAdmin) {
    const passwordHash = bcrypt.hashSync('admin', 10);
    const totpSecret = generateSecret();
    db.prepare(
      `INSERT INTO users (id, username, passwordHash, totpSecret, roles, permissions, createdAt)
       VALUES (?, ?, ?, ?, ?, ?, ?)`
    ).run(
      uuidv4(),
      'admin',
      passwordHash,
      totpSecret,
      JSON.stringify(['admin']),
      JSON.stringify(['devices:read', 'devices:write', 'configs:apply', 'plugins:manage']),
      new Date().toISOString()
    );
    // eslint-disable-next-line no-console
    console.log('[db] seeded default admin user (username: admin, password: admin)');
    // eslint-disable-next-line no-console
    console.log(`[db] admin TOTP secret (dev only): ${totpSecret}`);
    // eslint-disable-next-line no-console
    console.log(`[db] admin otpauth URI (scan with an authenticator app): ${buildOtpAuthUri('admin', totpSecret)}`);
  }
}
