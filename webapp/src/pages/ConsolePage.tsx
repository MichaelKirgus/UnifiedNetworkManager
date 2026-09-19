import { useMemo, useState } from 'react';
import { useNavigate, useParams, useSearchParams } from 'react-router-dom';
import { Terminal as TerminalIcon, X } from 'lucide-react';
import { ConsoleStatusPill, useConsoleSession, type CredentialPrompt } from '../components/ConsoleDialog';
import { CredentialPicker } from '../components/CredentialPicker';

/**
 * Standalone full-window SSH console — the destination of the dialog's "open in a
 * new window" button. Lives at `/console/:deviceId` (its own tab, no app shell) so
 * it can be tiled next to other windows like a real terminal client.
 *
 * Query params (set by the opener): `plugin`, `context` (JSON), `title`, `subtitle`.
 * The session itself is identical to the dialog's — same ticket mint + proxied WS,
 * so both surfaces can even be open at once (two independent shells).
 */
export default function ConsolePage() {
  const navigate = useNavigate();
  const { deviceId } = useParams<{ deviceId: string }>();
  const [params] = useSearchParams();

  const pluginId = params.get('plugin') ?? undefined;
  const contextKey = useMemo(() => {
    try { return JSON.stringify(JSON.parse(params.get('context') || '{}')); } catch { return '{}'; }
  }, [params]);
  const title = params.get('title') || 'Console';
  const subtitle = params.get('subtitle') || undefined;

  // Session-credential selection (same contract as the dialog): an explicit pick
  // arrives via `secret`; otherwise a 409 from mint opens the picker.
  const [chosenSecretId, setChosenSecretId] = useState<string | undefined>(params.get('secret') ?? undefined);
  const [credentialPrompt, setCredentialPrompt] = useState<CredentialPrompt | null>(null);

  const { hostRef, status, error, exitCode } = useConsoleSession(deviceId ?? '', pluginId, contextKey, chosenSecretId, (prompt) =>
    setCredentialPrompt(prompt)
  );

  /** Close the tab (works because it was script-opened via window.open); fall back to history. */
  const closeWindow = () => {
    try { window.close(); } catch { /* noop */ }
    // If the browser refused (e.g. user opened the URL manually), go back instead.
    setTimeout(() => navigate(-1), 100);
  };

  return (
    <div className="flex h-screen flex-col bg-console-bg">
      {/* Header */}
      <header className="flex items-center justify-between gap-3 border-b border-border bg-card px-4 py-2.5">
        <div className="flex min-w-0 items-center gap-2.5">
          <TerminalIcon size={16} className="shrink-0 text-secondary" />
          <div className="min-w-0">
            <h1 className="truncate text-sm font-semibold text-foreground">{title}</h1>
            {subtitle && <p className="mt-0.5 truncate text-xs text-muted-foreground">{subtitle}</p>}
          </div>
        </div>
        <div className="flex shrink-0 items-center gap-2">
          <ConsoleStatusPill status={status} exitCode={exitCode} />
          <button type="button" aria-label="Close console window" title="Close (ends the session)" onClick={closeWindow} className="rounded p-1 text-faint hover:bg-muted">
            <X size={16} />
          </button>
        </div>
      </header>

      {/* Error banner */}
      {error && (
        <div className="flex items-center justify-between gap-3 border-b border-danger-border bg-danger px-4 py-2 text-sm text-white">
          <span className="min-w-0 truncate" title={error}>{error}</span>
          <button type="button" onClick={closeWindow} className="shrink-0 rounded px-2 py-0.5 text-xs font-semibold hover:bg-white/10">Dismiss</button>
        </div>
      )}

      {/* Terminal host — xterm.js renders here; the dark theme is fixed (terminals are dark). */}
      <div className="min-h-0 flex-1 p-2">
        <div ref={hostRef} className="h-full w-full" />
      </div>

      {/* Credential picker — shown when the mint endpoint needs a choice. */}
      {credentialPrompt && (
        <CredentialPicker
          deviceId={deviceId ?? ''}
          purpose="console"
          initialCandidates={credentialPrompt.candidates}
          initialDefaultId={credentialPrompt.defaultId}
          title={`Choose an SSH credential — ${title}`}
          onPick={(secretId) => {
            setChosenSecretId(secretId);
            setCredentialPrompt(null);
          }}
          onClose={() => setCredentialPrompt(null)}
        />
      )}

      {/* Footer hint */}
      <footer className="border-t border-border bg-card px-4 py-1.5 text-[11px] text-faint">
        Interactive session over the bound SSH credential — input goes straight to the device. Closing this window ends the session.
      </footer>
    </div>
  );
}
