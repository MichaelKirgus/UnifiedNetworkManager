import { useState, useEffect } from 'react';
import { api, Secret } from '../api/client';
import { DataTable } from '../components/DataTable';
import { Layout } from '../components/Layout';

export default function Secrets() {
  const [secrets, setSecrets] = useState<Secret[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [showForm, setShowForm] = useState(false);
  const [newSecret, setNewSecret] = useState({ label: '', apiKey: '', apiSecret: '', expiresAt: '' });

  async function loadSecrets() {
    setLoading(true);
    try {
      const data = await api.secrets();
      setSecrets(data);
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

  async function handleCreate(e: React.FormEvent) {
    e.preventDefault();
    try {
      console.log('Sending secret request:', newSecret);
      const response = await api.createSecret({
        apiKey: newSecret.apiKey,
        apiSecret: newSecret.apiSecret,
        label: newSecret.label,
        expiresAt: newSecret.expiresAt || undefined,
      });
      console.log('Secret created successfully:', response);
      setNewSecret({ label: '', apiKey: '', apiSecret: '', expiresAt: '' });
      setShowForm(false);
      await loadSecrets();
    } catch (err) {
      console.error('Error creating secret:', err);
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
          className="rounded-md bg-slate-900 px-3 py-1.5 text-sm font-semibold text-white hover:bg-slate-800"
        >
          {showForm ? 'Cancel' : 'Add Secret'}
        </button>
      </div>

      {showForm && (
        <div className="mb-6 rounded-md border border-slate-200 bg-white p-4 shadow-sm">
          <h2 className="mb-4 text-sm font-semibold text-slate-900">Create New Secret</h2>
          <form onSubmit={handleCreate} className="grid grid-cols-1 gap-3 sm:grid-cols-3">
            <div>
              <label className="mb-1 block text-xs font-medium text-slate-700">Label</label>
              <input
                type="text"
                value={newSecret.label}
                onChange={(e) => setNewSecret({ ...newSecret, label: e.target.value })}
                className="w-full rounded-md border border-slate-300 px-3 py-2 text-sm"
                placeholder="e.g. OPNsense Core"
                required
              />
            </div>
            <div>
              <label className="mb-1 block text-sm font-medium text-slate-700">API Key</label>
              <input
                type="text"
                value={newSecret.apiKey}
                onChange={(e) => setNewSecret({ ...newSecret, apiKey: e.target.value })}
                className="w-full rounded-md border border-slate-300 px-3 py-2 text-sm"
                required
              />
            </div>
            <div>
              <label className="mb-1 block text-sm font-medium text-slate-700">API Secret</label>
              <input
                type="password"
                value={newSecret.apiSecret}
                onChange={(e) => setNewSecret({ ...newSecret, apiSecret: e.target.value })}
                className="w-full rounded-md border border-slate-300 px-3 py-2 text-sm"
                required
              />
            </div>
            <div>
              <label className="mb-1 block text-xs font-medium text-slate-700">Expiration Date</label>
              <input
                type="datetime-local"
                value={newSecret.expiresAt}
                onChange={(e) => setNewSecret({ ...newSecret, expiresAt: e.target.value })}
                className="w-full rounded-md border border-slate-300 px-3 py-2 text-sm"
              />
            </div>
            <div className="col-span-full flex justify-end">
              <button
                type="submit"
                className="rounded-md bg-slate-900 px-4 py-2 text-sm font-medium text-white hover:bg-slate-800"
              >
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
            { header: 'User', key: 'username', render: (s: Secret) => s.username },
            { header: 'ID', key: 'id', render: (s: Secret) => s.id },
            { header: 'Created At', key: 'createdAt', render: (s: Secret) => new Date(s.createdAt).toLocaleString() },
            { header: 'Expires At', key: 'expiresAt', render: (s: Secret) => (s.expiresAt ? new Date(s.expiresAt).toLocaleString() : 'Never') },
            { 
              header: 'Actions', 
              key: 'actions',
              render: (s: Secret) => (
                <button 
                  onClick={() => handleDelete(s.id)}
                  className="text-sm font-medium text-red-600 hover:text-red-800"
                >
                  Delete
                </button>
              ) 
            },
          ]}
          rows={secrets}
          rowKey={(s) => s.id}
        />
      )}
    </Layout>
  );
}
