import { useState } from 'react';
import QRCode from 'react-qr-code';
import { Check, Copy, X } from 'lucide-react';
import { TotpEnrollment } from '../api/client';

interface Props {
  /** The user this enrollment belongs to (shown in the title). */
  username: string;
  /** Enrollment payload from the API (secret + otpauth URI). */
  enrollment: TotpEnrollment;
  onClose: () => void;
}

/**
 * Modal shown after creating a user or (re-)enrolling TOTP. Renders the
 * otpauth URI as a QR code plus the raw secret so it can be typed in manually.
 * The secret is only available at this moment — closing the dialog without
 * scanning/typing it means 2FA must be re-enrolled later.
 */
export function TotpEnrollmentDialog({ username, enrollment, onClose }: Props) {
  const [copied, setCopied] = useState(false);

  async function copySecret() {
    try {
      await navigator.clipboard.writeText(enrollment.secret);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      /* clipboard unavailable — the user can select + copy manually */
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-primary/40 p-4" role="dialog" aria-modal="true">
      <div className="w-full max-w-sm rounded-lg border border-border bg-card p-6 shadow-lg">
        <div className="mb-3 flex items-center justify-between">
          <h2 className="text-base font-semibold text-foreground">Set up 2FA for {username}</h2>
          <button type="button" aria-label="Close dialog" onClick={onClose} className="rounded p-1 text-faint hover:bg-muted">
            <X className="h-4 w-4" />
          </button>
        </div>

        <p className="mb-4 text-sm text-muted-foreground">
          Scan this QR code with your authenticator app (e.g. Google Authenticator, 1Password), or enter the secret manually.
        </p>

        <div className="mb-4 flex justify-center rounded-md border border-border bg-card p-3">
          <QRCode value={enrollment.otpauthUri} size={176} />
        </div>

        <label className="mb-1 block text-sm font-medium text-secondary">Secret</label>
        <div className="flex items-center gap-2">
          <code className="flex-1 select-all rounded-md border border-border bg-background px-3 py-2 font-mono text-sm tracking-wider text-foreground">
            {enrollment.secret}
          </code>
          <button
            type="button"
            onClick={copySecret}
            className="flex items-center gap-1.5 rounded-md border border-border px-2.5 py-2 text-sm font-medium text-secondary hover:bg-muted"
          >
            {copied ? <Check className="h-4 w-4 text-green-600" /> : <Copy className="h-4 w-4" />}
            {copied ? 'Copied' : 'Copy'}
          </button>
        </div>

        <p className="mt-3 text-xs text-faint">
          Keep this secret safe — it is only shown now. After scanning, the user can sign in with their 6-digit code.
        </p>

        <div className="mt-4 flex justify-end">
          <button
            type="button"
            onClick={onClose}
            className="rounded-md bg-primary px-4 py-2 text-sm font-medium text-white hover:bg-primary-hover"
          >
            Done
          </button>
        </div>
      </div>
    </div>
  );
}
