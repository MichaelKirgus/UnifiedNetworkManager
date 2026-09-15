import { useState, useEffect, useMemo } from 'react';
import { Pencil, Plus, RefreshCw, Save, Trash2, Wand2, X } from 'lucide-react';
import { api, Secret, SecretProvider, SecretType } from '../api/client';
import { DataTable } from '../components/DataTable';
import { Layout } from '../components/Layout';
import { can, getUsername } from '../auth/permissions';

/** Secret types that can authenticate an interactive SSH/SFTP session. */
const SESSION_CAPABLE_TYPES = new Set(['usernamePassword', 'sshKeyPair']);

export default function Secrets() {
  // The page needs secrets:read (route guard); create/delete need their own perms.
  // `secrets:self-write` opens the personal-secret area (own secrets only).
  const canWrite = can('secrets:write');
  const canSelfWrite = can('secrets:self-write');
  const canManageAny = canWrite || canSelfWrite;
  const canDelete = can('secrets:delete') || canSelfWrite;
  const [secrets, setSecrets] = useState<Secret[]>([]);
  const [providers, setProviders] = useState<SecretProvider[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [showForm, setShowForm] = useState(false);
  const [providerId, setProviderId] = useState('');
  const [type, setType] = useState('');
  const [fields, setFields] = useState<Record<string, string>>({});
  const [label, setLabel] = useState('');
  const [expiresAt, setExpiresAt] = useState('');
  // Interactive-session usage flags (opt-in per secret; only SSH-capable types).
  const [interactiveLoginAllowed, setInteractiveLoginAllowed] = useState(false);
  const [fileAccessAllowed, setFileAccessAllowed] = useState(false);
  const [generating, setGenerating] = useState(false);
  /** Non-secret material echoed back after a generate (e.g. public key line). */
  const [generatedInfo, setGeneratedInfo] = useState<{ label: string; fields: Record<string, string> } | null>(null);

  // --- Edit state (works for ALL secret types) -------------------------------
  /** The inline form works in two modes: create a new secret, or edit an
   *  existing one in place (same id — bound assignments keep working). */
  const [mode, setMode] = useState<'create' | 'edit'>('create');
  /** The secret being edited (metadata snapshot from the table row). */
  const [editing, setEditing] = useState<Secret | null>(null);
  const [savingEdit, setSavingEdit] = useState(false);



  /** Opens the inline form in create mode with a clean slate. */
  function openCreateForm() {
    setMode('create');
    setEditing(null);
    setFields({});
    setLabel('');
    setExpiresAt('');
    setInteractiveLoginAllowed(false);
    setFileAccessAllowed(false);
    setShowForm(true);
  }

  /** Opens the inline form in edit mode and loads the secret's decrypted fields. */
  async function openEdit(s: Secret) {
    setMode('edit');
    setEditing(s);
    // Point the shared form at this secret's provider + type so it renders
    // the right field schema (both are shown read-only in edit mode).
    const owner = providers.find((p) => p.id === s.providerId);
    if (owner) {
      setProviderId(owner.id);
      setType(s.type);
    }
    setLabel(s.label ?? '');
    // datetime-local needs "YYYY-MM-DDTHH:mm" — trim seconds/timezone from ISO.
    setExpiresAt(s.expiresAt ? s.expiresAt.slice(0, 16) : '');
    setInteractiveLoginAllowed(!!s.interactiveLoginAllowed);
    setFileAccessAllowed(!!s.fileAccessAllowed);
    setFields({});
    setShowForm(true);
    try {
      const data = await api.getSecret(s.id);
      // Only keep fields the type schema declares (defensive against drift).
      // If the schema is unknown (provider offline), fall back to all values.
      const declaredFields = editTypeFor(s.type)?.fields ?? null;
      const clean: Record<string, string> = {};
      for (const [k, v] of Object.entries(data.fields)) {
        if (typeof v !== 'string') continue;
        if (declaredFields && !declaredFields.some((f) => f.name === k)) continue;
        clean[k] = v;
      }
      setFields(clean);
    } catch (err) {
      alert(`Failed to load secret for editing: ${(err as Error).message}`);
      setShowForm(false);
      setEditing(null);
    }
  }

  function editTypeFor(typeName: string): SecretType | undefined {
    return providers.flatMap((p) => p.secretTypes).find((t) => t.type === typeName);
  }

  /** Closes the inline form and resets it to a clean create-mode slate. */
  function closeForm() {
    setShowForm(false);
    setMode('create');
    setEditing(null);
    setFields({});
    setLabel('');
    setExpiresAt('');
    setInteractiveLoginAllowed(false);
    setFileAccessAllowed(false);
  }

  /** Submits the inline form — creates a new secret or updates it in place
   *  (same id, so bound assignments keep working). */
  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (mode === 'edit' && editing) {
      setSavingEdit(true);
      try {
        await api.updateSecret(editing.id, {
          fields,
          label: label.trim(),
          expiresAt: expiresAt || null,
          // Only send the flags for SSH-capable types — other types can't be used
          // interactively anyway and must not gain stale flag values.
          ...(SESSION_CAPABLE_TYPES.has(editing.type) ? { interactiveLoginAllowed, fileAccessAllowed } : {}),
        });
        closeForm();
        await loadSecrets();
      } catch (err) {
        alert(`Failed to save secret: ${(err as Error).message}`);
      } finally {
        setSavingEdit(false);
      }
      return;
    }
    try {
      const response = await api.createSecret({
        type: activeType?.type ?? type,
        providerId: activeProvider?.id,
        fields,
        label,
        expiresAt: expiresAt || undefined,
        ...(SESSION_CAPABLE_TYPES.has(activeType?.type ?? type) ? { interactiveLoginAllowed, fileAccessAllowed } : {}),
      });
      closeForm();
      await loadSecrets();
    } catch (err) {
      alert(`Failed to save secret: ${(err as Error).message}`);
    }
  }

  async function loadSecrets() {
    setLoading(true);
    try {
      const [secretData, providerData] = await Promise.all([api.secrets(), api.secretProviders()]);
      setSecrets(secretData);
      setProviders(providerData);
      setError(null);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadSecrets();
  }, []);

  // Default to the first online provider + its first secret type.
  useEffect(() => {
    if (providers.length > 0 && !providerId) {
      const first = providers.find((p) => p.online) ?? providers[0];
      setProviderId(first.id);
      if (first.secretTypes.length > 0) setType(first.secretTypes[0].type);
    }
  }, [providers, providerId]);

  const activeProvider = useMemo(
    () => providers.find((p) => p.id === providerId) ?? providers[0],
    [providers, providerId]
  );

  const activeType: SecretType | undefined = useMemo(
    () => activeProvider?.secretTypes.find((t) => t.type === type) ?? activeProvider?.secretTypes[0],
    [activeProvider, type]
  );

  /** The field schema the form renders — in edit mode resolved directly by
   *  name (the owning provider may be offline/unknown, so the activeProvider
   *  fallback must not leak another provider's types into the form). */
  const formType: SecretType | undefined = useMemo(
    () => (mode === 'edit' ? editTypeFor(editing?.type ?? '') : activeType),
    [mode, editing, providers, activeType]
  );

  /** All secret types any provider marks generatable — drives the per-row regenerate action. */
  const generatableTypes = useMemo(
    () => new Set(providers.flatMap((p) => p.secretTypes.filter((t) => t.generatable).map((t) => t.type))),
    [providers]
  );

  /** Human-readable label for a secret type (from the provider schema), if known. */
  const typeLabelFor = (typeName: string): string | undefined =>
    providers.flatMap((p) => p.secretTypes).find((t) => t.type === typeName)?.label;

  /** Type chip — human label from the provider schema, indigo when generatable,
   * slate otherwise; falls back to the raw type id if no provider declares it. */
  function TypeChip({ type }: { type: string }) {
    const label = typeLabelFor(type) ?? type;
    const tone = generatableTypes.has(type)
      ? 'bg-indigo-100 text-indigo-800'
      : 'bg-muted text-secondary';
    return (
      <span
        title={label === type ? undefined : `Type id: ${type}`}
        className={`inline-flex items-center rounded-full border px-2.5 py-0.5 text-xs font-medium ${tone} ${generatableTypes.has(type) ? 'border-indigo-300' : 'border-border'}`}
      >
        {label}
      </span>
    );
  }

  function handleProviderChange(id: string) {
    setProviderId(id);
    const provider = providers.find((p) => p.id === id);
    setType(provider?.secretTypes[0]?.type ?? '');
    setFields({});
  }

  function handleTypeChange(t: string) {
    setType(t);
    setFields({});
  }

  function handleFieldChange(name: string, value: string) {
    setFields((prev) => ({ ...prev, [name]: value }));
  }

  /** Let the provider create the key material — only non-material context fields are sent. */
  async function handleGenerate() {
    if (!activeType?.generatable) return;
    setGenerating(true);
    try {
      const context: Record<string, string> = {};
      for (const f of activeType.fields ?? []) {
        if (!f.secret && fields[f.name]) context[f.name] = fields[f.name];
      }
      const result = await api.generateSecret({
        type: activeType.type,
        providerId: activeProvider?.id,
        fields: context,
        label,
        expiresAt: expiresAt || undefined,
      });
      const generatedLabel = label;
      closeForm();
      await loadSecrets();
      // Non-secret generated material (e.g. the paste-ready public key line) —
      // show it so no external tooling is needed to deploy the key.
      const pub = result.publicFields;
      if (pub && Object.keys(pub).length > 0) {
        setGeneratedInfo({ label: generatedLabel || activeType.label, fields: pub });
      }
    } catch (err) {
      alert(`Failed to generate secret: ${(err as Error).message}`);
    } finally {
      setGenerating(false);
    }
  }

  /** Re-roll key material in place — same id, so bound assignments keep working. */
  async function handleRegenerate(s: Secret) {
    if (!confirm(`Re-generate the key material for "${s.label || s.id}"?\nThe secret keeps its ID (assignments stay valid), but devices still holding the OLD key will stop authenticating.`)) return;
    try {
      await api.regenerateSecret(s.id);
      await loadSecrets();
    } catch (err) {
      alert((err as Error).message);
    }
  }

  async function handleDelete(id: string) {
    if (!confirm('Are you sure you want to delete this secret?')) return;
    try {
      await api.deleteSecret(id);
      await loadSecrets();
    } catch (err) {
      alert((err as Error).message);
    }
  }

  /** Bulk: re-roll key material for every SELECTED generatable secret in place.
   *  Same ids, so bound assignments keep working — but devices holding the old
   *  keys stop authenticating until they receive the new ones. */
  async function handleBulkRegenerate(selected: Secret[]) {
    const targets = selected.filter((s) => generatableTypes.has(s.type));
    if (targets.length === 0) {
      alert('None of the selected secrets are generatable types — there is no key material to re-roll.');
      return;
    }
    const skipped = selected.length - targets.length;
    const msg = `Re-generate the key material for ${targets.length} secret${targets.length === 1 ? '' : 's'}?\nThe secrets keep their IDs (assignments stay valid), but devices still holding the OLD keys will stop authenticating.` +
      (skipped > 0 ? `\n\n(${skipped} non-generatable selection${skipped === 1 ? '' : 's'} skipped.)` : '');
    if (!confirm(msg)) return;
    const errors: string[] = [];
    for (const s of targets) {
      try {
        await api.regenerateSecret(s.id);
      } catch (err) {
        errors.push(`${s.label ?? s.id}: ${(err as Error).message}`);
      }
    }
    await loadSecrets();
    if (errors.length > 0) alert(`Regenerated ${targets.length - errors.length} of ${targets.length}.\n${errors.join('\n')}`);
  }

  /** Bulk: delete every selected secret. No FK cascade — devices still bound to
   *  a deleted secret will fail authentication on their next poll, so the
   *  confirm warns to unbind/reassign first. */
  async function handleBulkDelete(selected: Secret[]) {
    const errors: string[] = [];
    for (const s of selected) {
      try {
        await api.deleteSecret(s.id);
      } catch (err) {
        errors.push(`${s.label ?? s.id}: ${(err as Error).message}`);
      }
    }
    await loadSecrets();
    if (errors.length > 0) alert(`Deleted ${selected.length - errors.length} of ${selected.length}.\n${errors.join('\n')}`);
  }

  async function copyText(text: string): Promise<boolean> {
    try {
      await navigator.clipboard.writeText(text);
      return true;
    } catch {
      // Clipboard API unavailable (non-secure context) — fall back to a prompt.
      window.prompt('Copy the value below:', text);
      return false;
    }
  }

  return (
    <Layout
      title="Secrets Store"
      actions={
        canManageAny && (
          <button
            onClick={() => (showForm ? closeForm() : openCreateForm())}
            className="flex items-center gap-1.5 rounded-md bg-primary px-3 py-1.5 text-sm font-semibold text-white hover:bg-primary-hover"
          >
            {showForm ? <X className="h-4 w-4" /> : <Plus className="h-4 w-4" />}
            {showForm ? 'Cancel' : 'Add Secret'}
          </button>
        )
      }
    >

      {canManageAny && showForm && (
        <div className="mb-6 rounded-md border border-border bg-card p-4 shadow-sm">
          <h2 className="mb-4 text-sm font-semibold text-foreground">{mode === 'edit' ? 'Edit Secret' : 'Create New Secret'}</h2>
          <form onSubmit={handleSubmit} className="grid grid-cols-1 gap-3 sm:grid-cols-3">
            {mode === 'edit' && (
              <p className="col-span-full -mt-2 text-xs text-muted-foreground">
                The secret keeps its ID — device assignments and plans referencing it keep working. Devices using the old
                values will use the new ones on their next poll.
              </p>
            )}
            <div>
              <label className="mb-1 block text-xs font-medium text-secondary">Provider</label>
              {mode === 'edit' ? (
                <input
                  type="text"
                  value={providers.some((p) => p.id === editing?.providerId) ? (activeProvider?.name ?? '') : 'Unknown provider'}
                  disabled
                  title="The provider that created the secret cannot be changed"
                  className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm text-muted-foreground"
                />
              ) : (
                <select
                  value={providerId}
                  onChange={(e) => handleProviderChange(e.target.value)}
                  className="w-full rounded-md border border-border px-3 py-2 text-sm"
                >
                  {providers.map((p) => (
                    <option key={p.id} value={p.id} disabled={!p.online}>
                      {p.name} {p.online ? '' : '(offline)'}
                    </option>
                  ))}
                </select>
              )}
            </div>
            <div>
              <label className="mb-1 block text-xs font-medium text-secondary">Secret Type</label>
              {mode === 'edit' ? (
                <input
                  type="text"
                  value={formType?.label ?? editing?.type ?? ''}
                  disabled
                  title="The secret type cannot be changed — create a new secret instead"
                  className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm text-muted-foreground"
                />
              ) : (
                <select
                  value={type}
                  onChange={(e) => handleTypeChange(e.target.value)}
                  className="w-full rounded-md border border-border px-3 py-2 text-sm"
                >
                  {(activeProvider?.secretTypes ?? []).map((t) => (
                    <option key={t.type} value={t.type}>
                      {t.label}
                    </option>
                  ))}
                </select>
              )}
            </div>
            <div>
              <label className="mb-1 block text-xs font-medium text-secondary">Label</label>
              <input
                type="text"
                value={label}
                onChange={(e) => setLabel(e.target.value)}
                className="w-full rounded-md border border-border px-3 py-2 text-sm"
                placeholder="e.g. OPNsense Core"
                required
              />
            </div>

            {mode === 'edit' && !formType && (
              <p className="col-span-full rounded-md border border-warning-border bg-warning px-3 py-2 text-xs text-warning-fg">
                The owning provider is not reachable right now, so the field values can't be loaded. Label and
                expiration can still be edited; try again once the provider is back online.
              </p>
            )}
            {(formType?.fields ?? []).map((f) => (
              <div key={f.name} className={f.input === 'textarea' ? 'col-span-full' : undefined}>
                <label className="mb-1 block text-xs font-medium text-secondary">
                  {f.label} {f.required ? '*' : ''}
                </label>
                {f.input === 'select' ? (
                  <select
                    value={fields[f.name] ?? ''}
                    onChange={(e) => handleFieldChange(f.name, e.target.value)}
                    className="w-full rounded-md border border-border px-3 py-2 text-sm"
                  >
                    <option value="">Select...</option>
                    {(f.options ?? []).map((opt) => (
                      <option key={opt} value={opt}>
                        {opt}
                      </option>
                    ))}
                  </select>
                ) : f.input === 'textarea' ? (
                  // Multi-line material (PEM private keys, cert bundles). A secret
                  // textarea stays a real <input type="password">-style field: the
                  // value is only ever sent to the API on submit.
                  <textarea
                    rows={6}
                    spellCheck={false}
                    value={fields[f.name] ?? ''}
                    onChange={(e) => handleFieldChange(f.name, e.target.value)}
                    className="w-full rounded-md border border-border px-3 py-2 font-mono text-xs"
                    required={f.required}
                  />
                ) : (
                  <input
                    type={f.input === 'password' ? 'password' : 'text'}
                    value={fields[f.name] ?? ''}
                    onChange={(e) => handleFieldChange(f.name, e.target.value)}
                    className="w-full rounded-md border border-border px-3 py-2 text-sm"
                    required={f.required}
                  />
                )}
              </div>
            ))}

            <div>
              <label className="mb-1 block text-xs font-medium text-secondary">Expiration Date</label>
              <input
                type="datetime-local"
                value={expiresAt}
                onChange={(e) => setExpiresAt(e.target.value)}
                className="w-full rounded-md border border-border px-3 py-2 text-sm"
              />
            </div>

            {/* Interactive-session usage flags — only meaningful for types that can
                actually authenticate over SSH (username/password or key pair). */}
            {SESSION_CAPABLE_TYPES.has(mode === 'edit' ? editing?.type ?? '' : activeType?.type ?? type) && (
              <div className="col-span-full rounded-md border border-border bg-background p-3">
                <p className="mb-2 text-xs font-semibold text-secondary">Interactive session usage</p>
                <label className="flex cursor-pointer items-start gap-2 py-1 text-sm">
                  <input
                    type="checkbox"
                    checked={interactiveLoginAllowed}
                    onChange={(e) => setInteractiveLoginAllowed(e.target.checked)}
                    className="mt-0.5"
                  />
                  <span>
                    Allow interactive SSH console logins with this credential
                    <span className="block text-xs text-muted-foreground">Users can pick this secret when opening a web shell on a device.</span>
                  </span>
                </label>
                <label className="flex cursor-pointer items-start gap-2 py-1 text-sm">
                  <input
                    type="checkbox"
                    checked={fileAccessAllowed}
                    onChange={(e) => setFileAccessAllowed(e.target.checked)}
                    className="mt-0.5"
                  />
                  <span>
                    Allow SFTP file access with this credential
                    <span className="block text-xs text-muted-foreground">Users can pick this secret when browsing a device's files.</span>
                  </span>
                </label>
              </div>
            )}
            <div className="col-span-full flex items-center justify-end gap-2">
              {mode === 'edit' ? (
                <button
                  type="submit"
                  disabled={savingEdit}
                  title="Saves in place — the secret keeps its ID, so bound assignments keep working"
                  className="flex items-center gap-1.5 rounded-md bg-primary px-4 py-2 text-sm font-medium text-white hover:bg-primary-hover disabled:cursor-not-allowed disabled:opacity-50"
                >
                  <Save className="h-4 w-4" />
                  {savingEdit ? 'Saving…' : 'Save Changes'}
                </button>
              ) : activeType?.generatable ? (
                <>
                  <button
                    type="submit"
                    title="Enter the key material yourself instead of generating it"
                    className="flex items-center gap-1.5 rounded-md border border-border bg-card px-4 py-2 text-sm font-medium text-secondary hover:bg-background"
                  >
                    <Save className="h-4 w-4" />
                    Save Manually
                  </button>
                  <button
                    type="button"
                    onClick={handleGenerate}
                    disabled={generating || !label.trim()}
                    title="The provider creates the key material for you — no manual entry needed. Context fields (e.g. username) are kept."
                    className="flex items-center gap-1.5 rounded-md bg-primary px-4 py-2 text-sm font-medium text-white hover:bg-primary-hover disabled:cursor-not-allowed disabled:opacity-50"
                  >
                    <Wand2 className="h-4 w-4" />
                    {generating ? 'Generating…' : 'Generate Key Material'}
                  </button>
                </>
              ) : (
                <button
                  type="submit"
                  className="flex items-center gap-1.5 rounded-md bg-primary px-4 py-2 text-sm font-medium text-white hover:bg-primary-hover"
                >
                  <Save className="h-4 w-4" />
                  Save Secret
                </button>
              )}
            </div>
          </form>
        </div>
      )}

      {generatedInfo && (
        <div className="mb-4 rounded-md border border-success-border bg-success p-3">
          <div className="flex items-start justify-between gap-3">
            <p className="text-sm font-medium text-emerald-900">
              Secret “{generatedInfo.label}” created — the provider generated this public material. Copy it to the device
              (e.g. append to <code className="rounded bg-success px-1">~/.ssh/authorized_keys</code>).
            </p>
            <button aria-label="Dismiss" title="Dismiss" onClick={() => setGeneratedInfo(null)} className="rounded p-1 text-success-fg hover:bg-success">
              <X className="h-4 w-4" />
            </button>
          </div>
          {Object.entries(generatedInfo.fields).map(([name, value]) => (
            <div key={name} className="mt-2 flex items-center gap-2">
              <code className="min-w-0 flex-1 overflow-x-auto whitespace-nowrap rounded bg-card px-2 py-1.5 font-mono text-xs text-foreground">{value}</code>
              <button
                onClick={() => copyText(value)}
                className="shrink-0 rounded-md border border-success-border bg-card px-2.5 py-1.5 text-xs font-medium text-success-fg hover:bg-success"
              >
                Copy
              </button>
            </div>
          ))}
        </div>
      )}

      {loading && <div className="text-center text-muted-foreground">Loading secrets...</div>}
      {error && <div className="mb-4 rounded-md border border-danger-border bg-danger px-3 py-2 text-sm text-danger-fg">{error}</div>}
      
      {!loading && !error && (
        <DataTable
          columns={[
            { header: 'Label', key: 'label', render: (s: Secret) => s.label },
            // Width fits the longest provider label ("OpenVPN Certificate Bundle (CA + cert + key)").
            { header: 'Type', key: 'type', width: 260, render: (s: Secret) => <TypeChip type={s.type} /> },
            // Which interactive session kinds this secret is enabled for.
            {
              header: 'Sessions',
              key: 'sessions',
              width: 170,
              sortable: false,
              render: (s: Secret) =>
                s.interactiveLoginAllowed || s.fileAccessAllowed ? (
                  <div className="flex flex-wrap items-center gap-1">
                    {s.interactiveLoginAllowed && (
                      <span title="May be used for interactive SSH console logins" className="rounded-full bg-sky-100 px-2 py-0.5 text-[10px] font-semibold text-sky-800">
                        SSH console
                      </span>
                    )}
                    {s.fileAccessAllowed && (
                      <span title="May be used for SFTP file-access sessions" className="rounded-full bg-emerald-100 px-2 py-0.5 text-[10px] font-semibold text-emerald-800">
                        File access
                      </span>
                    )}
                  </div>
                ) : (
                  <span className="text-xs text-faint">—</span>
                ),
            },
            { header: 'Created by user', key: 'username', render: (s: Secret) => s.username },
            // Diagnostic detail — available via the Columns picker but not worth
            // default screen space.
            { header: 'ID', key: 'id', width: 240, hiddenByDefault: true, render: (s: Secret) => s.id },
            { header: 'Created At', key: 'createdAt', sortAccessor: (s: Secret) => new Date(s.createdAt).getTime(), render: (s: Secret) => new Date(s.createdAt).toLocaleString() },
            { header: 'Expires At', key: 'expiresAt', width: 180, sortAccessor: (s: Secret) => (s.expiresAt ? new Date(s.expiresAt).getTime() : null), render: (s: Secret) => (s.expiresAt ? new Date(s.expiresAt).toLocaleString() : 'Never') },
            { 
              header: 'Actions', 
              key: 'actions',
              excludeFromExport: true,
              width: 130,
              sortable: false,
              render: (s: Secret) => {
                // Global writers manage everything; personal-area users only their own.
                const canManageRow = canWrite || (canSelfWrite && s.username === getUsername());
                return canManageRow ? (
                  <div className="flex items-center gap-1">
                    {canManageRow && (
                      <button
                        aria-label={`Edit secret ${s.label ?? s.id}`}
                        title="Edit secret fields"
                        onClick={() => openEdit(s)}
                        className="rounded-md p-1.5 text-secondary hover:bg-muted hover:text-foreground"
                      >
                        <Pencil className="h-4 w-4" />
                      </button>
                    )}
                    {canManageRow && generatableTypes.has(s.type) && (
                      <button
                        aria-label={`Regenerate key material for ${s.label ?? s.id}`}
                        title="Re-generate key material (same ID — bound assignments keep working)"
                        onClick={() => handleRegenerate(s)}
                        className="rounded-md p-1.5 text-secondary hover:bg-muted hover:text-foreground"
                      >
                        <RefreshCw className="h-4 w-4" />
                      </button>
                    )}
                    {canManageRow && (
                      <button
                        aria-label={`Delete secret ${s.label ?? s.id}`}
                        title="Delete secret"
                        onClick={() => handleDelete(s.id)}
                        className="rounded-md p-1.5 text-danger-fg hover:bg-danger hover:text-danger-fg"
                      >
                        <Trash2 className="h-4 w-4" />
                      </button>
                    )}
                  </div>
                ) : (
                  <span aria-hidden />
                );
              }
            },
          ]}
          rows={secrets}
          rowKey={(s) => s.id}
          storageKey="secrets"
          selectable={canManageAny}
          bulkActions={
            canWrite || canDelete
              ? [
                  ...(canWrite
                    ? [
                        // No declarative confirm — the handler confirms itself with a
                        // richer message (it knows how many selections are skipped).
                        { label: 'Regenerate key material', onClick: handleBulkRegenerate },
                      ]
                    : []),
                  ...(canDelete
                    ? [
                        {
                          label: 'Delete',
                          confirm: (count: number) =>
                            `Delete ${count} secret${count === 1 ? '' : 's'}?\nDevices still bound to a deleted secret will fail authentication on their next poll — unbind or reassign them first.`,
                          onClick: handleBulkDelete,
                        },
                      ]
                    : []),
                ]
              : undefined
          }
        />
      )}
    </Layout>
  );
}
