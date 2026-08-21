import { useState, useEffect, useMemo } from 'react';
import { Plus, Save, Trash2, X } from 'lucide-react';
import { api, Secret, SecretProvider, SecretType } from '../api/client';
import { DataTable } from '../components/DataTable';
import { Layout } from '../components/Layout';

export default function Secrets() {
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

  async function handleCreate(e: React.FormEvent) {
    e.preventDefault();
    try {
      const response = await api.createSecret({
        type: activeType?.type ?? type,
        providerId: activeProvider?.id,
        fields,
        label,
        expiresAt: expiresAt || undefined,
      });
      setLabel('');
      setFields({});
      setExpiresAt('');
      setShowForm(false);
      await loadSecrets();
    } catch (err) {
      alert(`Failed to save secret: ${(err as Error).message}`);
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

  return (
    <Layout>
      <div className="mb-4 flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-slate-900">Secrets Store</h1>
          <p className="text-sm text-slate-500">Manage credentials for network devices</p>
        </div>
        <button
          onClick={() => setShowForm(!showForm)}
          className="flex items-center gap-1.5 rounded-md bg-slate-900 px-3 py-1.5 text-sm font-semibold text-white hover:bg-slate-800"
        >
          {showForm ? <X className="h-4 w-4" /> : <Plus className="h-4 w-4" />}
          {showForm ? 'Cancel' : 'Add Secret'}
        </button>
      </div>

      {showForm && (
        <div className="mb-6 rounded-md border border-slate-200 bg-white p-4 shadow-sm">
          <h2 className="mb-4 text-sm font-semibold text-slate-900">Create New Secret</h2>
          <form onSubmit={handleCreate} className="grid grid-cols-1 gap-3 sm:grid-cols-3">
            <div>
              <label className="mb-1 block text-xs font-medium text-slate-700">Provider</label>
              <select
                value={providerId}
                onChange={(e) => handleProviderChange(e.target.value)}
                className="w-full rounded-md border border-slate-300 px-3 py-2 text-sm"
              >
                {providers.map((p) => (
                  <option key={p.id} value={p.id} disabled={!p.online}>
                    {p.name} {p.online ? '' : '(offline)'}
                  </option>
                ))}
              </select>
            </div>
            <div>
              <label className="mb-1 block text-xs font-medium text-slate-700">Secret Type</label>
              <select
                value={type}
                onChange={(e) => handleTypeChange(e.target.value)}
                className="w-full rounded-md border border-slate-300 px-3 py-2 text-sm"
              >
                {(activeProvider?.secretTypes ?? []).map((t) => (
                  <option key={t.type} value={t.type}>
                    {t.label}
                  </option>
                ))}
              </select>
            </div>
            <div>
              <label className="mb-1 block text-xs font-medium text-slate-700">Label</label>
              <input
                type="text"
                value={label}
                onChange={(e) => setLabel(e.target.value)}
                className="w-full rounded-md border border-slate-300 px-3 py-2 text-sm"
                placeholder="e.g. OPNsense Core"
                required
              />
            </div>

            {(activeType?.fields ?? []).map((f) => (
              <div key={f.name}>
                <label className="mb-1 block text-xs font-medium text-slate-700">
                  {f.label} {f.required ? '*' : ''}
                </label>
                {f.input === 'select' ? (
                  <select
                    value={fields[f.name] ?? ''}
                    onChange={(e) => handleFieldChange(f.name, e.target.value)}
                    className="w-full rounded-md border border-slate-300 px-3 py-2 text-sm"
                  >
                    <option value="">Select...</option>
                    {(f.options ?? []).map((opt) => (
                      <option key={opt} value={opt}>
                        {opt}
                      </option>
                    ))}
                  </select>
                ) : (
                  <input
                    type={f.input === 'password' ? 'password' : 'text'}
                    value={fields[f.name] ?? ''}
                    onChange={(e) => handleFieldChange(f.name, e.target.value)}
                    className="w-full rounded-md border border-slate-300 px-3 py-2 text-sm"
                    required={f.required}
                  />
                )}
              </div>
            ))}

            <div>
              <label className="mb-1 block text-xs font-medium text-slate-700">Expiration Date</label>
              <input
                type="datetime-local"
                value={expiresAt}
                onChange={(e) => setExpiresAt(e.target.value)}
                className="w-full rounded-md border border-slate-300 px-3 py-2 text-sm"
              />
            </div>
            <div className="col-span-full flex justify-end">
              <button
                type="submit"
                className="flex items-center gap-1.5 rounded-md bg-slate-900 px-4 py-2 text-sm font-medium text-white hover:bg-slate-800"
              >
                <Save className="h-4 w-4" />
                Save Secret
              </button>
            </div>
          </form>
        </div>
      )}

      {loading && <div className="text-center text-slate-500">Loading secrets...</div>}
      {error && <div className="mb-4 rounded-md border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-600">{error}</div>}
      
      {!loading && !error && (
        <DataTable
          columns={[
            { header: 'Label', key: 'label', render: (s: Secret) => s.label },
            { header: 'Type', key: 'type', render: (s: Secret) => s.type },
            { header: 'User', key: 'username', render: (s: Secret) => s.username },
            { header: 'ID', key: 'id', width: 240, render: (s: Secret) => s.id },
            { header: 'Created At', key: 'createdAt', sortAccessor: (s: Secret) => new Date(s.createdAt).getTime(), render: (s: Secret) => new Date(s.createdAt).toLocaleString() },
            { header: 'Expires At', key: 'expiresAt', width: 180, sortAccessor: (s: Secret) => (s.expiresAt ? new Date(s.expiresAt).getTime() : null), render: (s: Secret) => (s.expiresAt ? new Date(s.expiresAt).toLocaleString() : 'Never') },
            { 
              header: 'Actions', 
              key: 'actions',
              excludeFromExport: true,
              width: 100,
              sortable: false,
              render: (s: Secret) => (
                <button
                  aria-label={`Delete secret ${s.label ?? s.id}`}
                  title="Delete secret"
                  onClick={() => handleDelete(s.id)}
                  className="rounded-md p-1.5 text-red-600 hover:bg-red-50 hover:text-red-800"
                >
                  <Trash2 className="h-4 w-4" />
                </button>
              ) 
            },
          ]}
          rows={secrets}
          rowKey={(s) => s.id}
          storageKey="secrets"
        />
      )}
    </Layout>
  );
}
