import { useState } from 'react';
import QRCode from 'react-qr-code';
import { Check, Copy } from 'lucide-react';
import { TotpEnrollment } from '../api/client';
import { DialogShell } from './DialogShell';

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
    <DialogShell
      title={`Set up 2FA for ${username}`}
      onClose={onClose}
      maxWidth="max-w-sm"
      footer={
        <div className="flex justify-end">
          <button type="button" onClick={onClose} className="rounded-md bg-primary px-4 py-2 text-sm font-medium text-white hover:bg-primary-hover">
            Done
          </button>
        </div>
      }
    >
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
            {copied ? <Check className="h-4 w-4 text-success-fg" /> : <Copy className="h-4 w-4" />}
            {copied ? 'Copied' : 'Copy'}
          </button>
        </div>

        <p className="mt-3 text-xs text-faint">
          Keep this secret safe — it is only shown now. After scanning, the user can sign in with their 6-digit code.
        </p>
    </DialogShell>
  );
}
