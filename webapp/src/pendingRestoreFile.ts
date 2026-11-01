/**
 * In-memory handoff for the Backups page's "Upload archive…" button.
 *
 * The picked File cannot travel through the URL (only its name can), and a
 * closed file dialog is not re-readable by script — so without this handoff
 * the restore wizard would force the user to pick the same file a second time.
 * Backups.tsx stores the File here right before navigating; BackupRestorePage
 * takes it on mount (exactly once) and stages it automatically.
 */

let pendingFile: File | null = null;

/** Stores the picked archive for the restore wizard to consume. */
export function setPendingRestoreFile(file: File): void {
  pendingFile = file;
}

/** Returns the stored archive (or null) and clears the slot — take-once semantics. */
export function takePendingRestoreFile(): File | null {
  const f = pendingFile;
  pendingFile = null;
  return f;
}
