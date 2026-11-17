# Backup & replication

The **Backups** page (gated on the `instance:backup` permission) manages UNM's own database — not device configs.

## Backups

- **Backups** are section-based gzip-compressed JSON archives (`.unmbak.gz`). Sections: `identity` (users/roles/policies), `settings`, `devices` (+plugins/secrets), `documented` (planned networks/hosts), `plans`, and `liveInventory` (regenerable telemetry — only in the *All* preset). Presets bundle sections; any combination works. Deliberately excluded from every backup: API tokens, passkeys, live telemetry/logs/events and the plugin registry cache.
- **Destinations** are per-backup: the local volume (`unm-backups` → `/data/backups`, override with `UNM_BACKUP_VOLUME`) or a registered file-repo instance (bytes content-addressed there; the backup is bound to exactly one instance — no fallback to a sibling).

## Restore

Restore is a safe merge: rows are upserted by primary key, and rows absent from the archive are never deleted. The webapp walks upload/stored → manifest preview → per-section report.

## Replication (cross-instance sync)

Replication syncs portable config (everything except `liveInventory`) one-way to/from a peer instance using a peer API token that carries `instance:backup` there. Targets support manual *Sync now* and an optional interval (leader-gated scheduler). A default exclusion list strips stack-dependent settings (`instanceName`, update feed, provider bindings, …) before sending/applying — editable per target.

**Cross-instance secret portability:** device secrets are encrypted with a key derived from `MASTER_KEY` + `CRYPTO_SALT`. For replicated/restored secrets to decrypt on the peer, both instances MUST run with identical values for both variables (set them in each stack's `.env`).

## Dev → prod recipe

1. Create an API token on **prod** with only `instance:backup` (Tokens page).
2. On **dev**, Backups → Replication → *Add target* (push, that URL + token, optional interval).
3. *Sync now*, then watch the scheduler. Verify `instanceName`/update-feed settings were NOT overwritten on prod.
