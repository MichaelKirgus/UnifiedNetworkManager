/**
 * @unm/plugin-sdk — shared client for UNM's central file repository.
 *
 * The file repo is a DEVICE-INDEPENDENT store owned by the UNM API: files live
 * on a volume that ONLY the API container mounts (ISOs, firmware images, config
 * backups, scripts), and their metadata (name, category, size, sha256, who
 * uploaded them, when) lives in the UNM database. Plugins NEVER touch that
 * volume — they talk to it through the API's internal plugin routes
 * (`/plugin/files/*`, gated by the shared `x-plugin-api-key`), exactly like the
 * basic-auth/secrets-provider plugins talk to `/plugin/users`. This module is
 * the ONE implementation of that contract, so no plugin re-implements repo
 * plumbing.
 *
 * The three verbs a plugin needs:
 *   - list()    — see what is in the repo (e.g. offer ISOs for VM installs)
 *   - get(id)   — fetch a file's bytes to "use" it on a device via the
 *                 plugin's OWN native transport (TrueNAS `filesystem.put` over
 *                 /_upload, an OPNsense config upload, …). The SDK never pushes
 *                 onto devices — each vendor API is different and owned by the
 *                 plugin.
 *   - upload()  — add a file to the repo (e.g. a firmware image the plugin
 *                 downloaded from a vendor feed on behalf of a device)
 *
 * Transport: raw octet-stream bodies + `x-file-name` / `x-file-category`
 * headers (no JSON envelope — multi-GB ISOs must not be base64'd or buffered).
 */

import type { Readable } from 'stream';
import axios, { AxiosInstance } from 'axios';
import { createApiClient } from './apiClient';

/** One repo file as reported by the API. */
export interface FileRepoEntry {
  /** Stable id (uuid) — reference it in plan inputs / action schemas. */
  id: string;
  /** Original file name as uploaded (e.g. "debian-12.8.0-amd64-netinst.iso"). */
  name: string;
  /** Open category set, e.g. 'iso' | 'firmware' | 'config-backup' | 'script' | 'other'. */
  category: string;
  sizeBytes: number;
  /** SHA-256 hex of the stored content (integrity + dedupe signal). */
  sha256: string;
  /** Username that uploaded the file (null for plugin uploads without a user context). */
  uploadedBy: string | null;
  /** ISO-8601 — when the file was uploaded. */
  createdAt: string;
}

/** Options for createFileRepoClient(). */
export interface FileRepoClientOptions {
  /** Base URL of the API (default UNM_API_URL env / http://localhost:3000/v1). */
  baseUrl?: string;
  /** Shared plugin API key (default PLUGIN_API_KEY env). */
  apiKey?: string;
}

/** The shared repo client — one per plugin process is fine. */
export interface FileRepoClient {
  /** Lists repo files, optionally filtered by category (newest first). */
  list(category?: string): Promise<FileRepoEntry[]>;
  /** Metadata for one file (name/category/size/sha256) — null when unknown. */
  getMeta(fileId: string): Promise<FileRepoEntry | null>;
  /** Fetches a file's raw bytes (for "use" flows that push onto a device). */
  get(fileId: string, timeoutMs?: number): Promise<Buffer>;
  /**
   * Fetches a file as a READABLE STREAM — for large files (multi-GB ISOs) that
   * must not be buffered in memory. The caller pipes it into its native device
   * transport (e.g. TrueNAS /_upload multipart). Errors reject the promise;
   * mid-stream failures surface on the returned stream's 'error' event.
   *
   * `timeoutMs` is an OPTIONAL socket-inactivity limit for this download; by
   * default there is NONE — axios applies its `timeout` as an idle timer, and a
   * slow consumer (e.g. TrueNAS writing to a degraded pool) pauses our read via
   * backpressure for longer than any sane fixed limit, which would abort the
   * stream mid-transfer. The caller's plan-step budget bounds the operation.
   */
  getStream(fileId: string, timeoutMs?: number): Promise<Readable>;
  /** Adds a file to the repo. `name` is required; category defaults to 'other'. */
  upload(
    data: Buffer | Uint8Array,
    meta: { name: string; category?: string },
    timeoutMs?: number
  ): Promise<FileRepoEntry>;
  /** Removes a file from the repo (content + metadata). */
  remove(fileId: string): Promise<void>;
  /** Records that a file was USED (audit trail — which device / for what, when). */
  recordUse(
    fileId: string,
    use: { deviceId?: string; note?: string }
  ): Promise<{ ok: boolean }>;
}

/** Builds the shared repo client on top of createApiClient(). */
export function createFileRepoClient(opts: FileRepoClientOptions = {}): FileRepoClient {
  const http: AxiosInstance = createApiClient({
    baseUrl: opts.baseUrl,
    apiKey: opts.apiKey,
    timeoutMs: 30_000,
  });

  return {
    async list(category?: string) {
      const qs = category ? `?category=${encodeURIComponent(category)}` : '';
      const res = await http.get<{ files: FileRepoEntry[] }>(`/plugin/files${qs}`);
      return Array.isArray(res.data.files) ? (res.data.files as FileRepoEntry[]) : [];
    },

    async getMeta(fileId) {
      try {
        const res = await http.get<FileRepoEntry>(`/plugin/files/${encodeURIComponent(fileId)}`);
        return res.data;
      } catch (err) {
        if (axios.isAxiosError(err) && err.response?.status === 404) return null;
        throw err;
      }
    },

    async get(fileId, timeoutMs) {
      const res = await http.get<ArrayBuffer>(
        `/plugin/files/${encodeURIComponent(fileId)}/content`,
        { responseType: 'arraybuffer', ...(timeoutMs ? { timeout: timeoutMs } : {}) }
      );
      return Buffer.from(res.data);
    },

    async getStream(fileId, timeoutMs) {
      // NO idle timeout by default — the instance's 30s `timeout` is a
      // socket-inactivity timer in axios and would abort multi-minute streams
      // whenever backpressure pauses reads (observed live: TrueNAS filesystem.put
      // writing to a degraded pool stalled >30s → "reading source: aborted").
      // timeout: 0 disables it; pass an explicit timeoutMs only when wanted.
      const res = await http.get<Readable>(
        `/plugin/files/${encodeURIComponent(fileId)}/content`,
        { responseType: 'stream', timeout: timeoutMs ?? 0 }
      );
      return res.data as Readable;
    },

    async upload(data, meta, timeoutMs) {
      if (!meta || typeof meta.name !== 'string' || meta.name.length === 0) {
        throw new Error('fileRepo.upload requires a non-empty file name');
      }
      const res = await http.post<FileRepoEntry>(
        '/plugin/files',
        data,
        {
          headers: {
            'Content-Type': 'application/octet-stream',
            'x-file-name': meta.name,
            ...(meta.category ? { 'x-file-category': meta.category } : {}),
          },
          ...(timeoutMs ? { timeout: timeoutMs } : {}),
        }
      );
      return res.data;
    },

    async remove(fileId) {
      await http.delete(`/plugin/files/${encodeURIComponent(fileId)}`);
    },

    async recordUse(fileId, use) {
      const res = await http.post<{ ok: boolean }>(
        `/plugin/files/${encodeURIComponent(fileId)}/use`,
        {
          ...(use.deviceId ? { deviceId: use.deviceId } : {}),
          ...(use.note ? { note: use.note } : {}),
        }
      );
      return res.data;
    },
  };
}
