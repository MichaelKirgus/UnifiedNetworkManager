import { useEffect, useMemo, useState } from 'react';
import { Check, Copy, Plus, Trash2, X } from 'lucide-react';
import { api, ApiToken, PermissionCatalog } from '../api/client';
import { can } from '../auth/permissions';
import { DataTable, DataTableColumn } from '../components/DataTable';
import { Layout } from '../components/Layout';

/**
 * API tokens — long-lived bearer credentials for agents/scripts (MCP server).
 * Managing your own tokens requires the `tokens:manage` permission; users with
 * `users:read` can additionally view all tokens and `users:write` can revoke
 * any of them. The raw token value is shown exactly once at creation.
 */
export default function Tokens() {
  const [tokens, setTokens] = useState<ApiToken[]>([]);
  const [catalog, setCatalog] = useState<PermissionCatalog | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Creation form state.
  const [showForm, setShowForm] = useState(false);
  const [label, setLabel] = useState('');
  const [selectedPerms, setSelectedPerms] = useState<Set<string>>(new Set());
  const [inheritAll, setInheritAll] = useState(true);
  const [expiresAt, setExpiresAt] = useState('');

  // The just-created token (raw value shown once).
  const [createdToken, setCreatedToken] = useState<{ rawToken: string; label: string | null } | null>(null);
  const [copied, setCopied] = useState(false);

  const canSeeAll = can('users:read');
  const [seeAll, setSeeAll] = useState(false);

  async function load() {
    setLoading(true);
    try {
      const [tokenData, catalogData] = await Promise.all([api.tokens(seeAll), api.permissionCatalog()]);
      setTokens(tokenData);
      setCatalog(catalogData);
      setError(null);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [seeAll]);

  const canManageTokens = can('tokens:manage');

  const permDescriptions = useMemo(
    () => new Map((catalog?.permissions ?? []).map((p) => [p.id, p.description])),
    [catalog]
  );

  // Defense in depth — the sidebar hides this page without the permission and
  // the API still 403s; this keeps direct URL access from firing doomed calls.
  // (After all hooks — hook order must stay stable across renders.)
  if (!canManageTokens) {
    return (
      <Layout>
        <div className="mb-4">
          <h1 className="text-xl font-bold text-slate-900">API Tokens</h1>
        </div>
        <div className="rounded-md border border-slate-200 bg-white p-6 text-sm text-slate-500">
          You need the <code className="rounded bg-slate-100 px-1.5 py-0.5 text-xs">tokens:manage</code> permission to
          create and view API tokens. Ask an administrator to grant it (directly or via a role).
        </div>
      </Layout>
    );
  }

  function togglePerm(id: string) {
    setSelectedPerms((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  async function handleCreate(e: React.FormEvent) {
    e.preventDefault();
    try {
      const created = await api.createToken({
        label: label.trim() || undefined,
        permissions: inheritAll ? [] : [...selectedPerms],
        expiresAt: expiresAt ? new Date(expiresAt).toISOString() : null,
      });
      setCreatedToken({ rawToken: created.rawToken, label: created.label });
      setShowForm(false);
      setLabel('');
      setSelectedPerms(new Set());
      setInheritAll(true);
      setExpiresAt('');
      await load();
    } catch (err) {
      alert(`Failed to create token: ${(err as Error).message}`);
    }
  }

  async function handleRevoke(id: string, row: ApiToken) {
    const who = seeAll && row.username ? ` of ${row.username}` : '';
    if (!confirm(`Revoke token "${row.label ?? row.tokenPrefix}"${who}? Agents using it lose access immediately.`)) return;
    try {
      await api.deleteToken(id);
      await load();
    } catch (err) {
      alert((err as Error).message);
    }
  }

  function copyRaw() {
    if (!createdToken) return;
    navigator.clipboard.writeText(createdToken.rawToken).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  }

  const columns: DataTableColumn<ApiToken>[] = [
    {
      header: 'Label',
      key: 'label',
      width: 200,
      render: (row) => <span className="font-medium text-slate-800">{row.label || '—'}</span>,
    },
    ...(seeAll
      ? [{
          header: 'User',
          key: 'username',
          width: 140,
          render: (row: ApiToken) => <span className="text-slate-600">{row.username ?? row.userId}</span>,
        }]
      : []),
    {
      header: 'Prefix',
      key: 'tokenPrefix',
      width: 140,
      render: (row) => <code className="rounded bg-slate-100 px-1.5 py-0.5 text-xs">{row.tokenPrefix}…</code>,
    },
    {
      header: 'Permissions',
      key: 'permissions',
      width: 260,
      render: (row) =>
        row.inheritsAllPermissions || row.permissions.length === 0 ? (
          <span className="rounded-full bg-indigo-50 px-2 py-0.5 text-xs font-medium text-indigo-700">all effective</span>
        ) : (
          <div className="flex flex-wrap gap-1">
            {row.permissions.map((p) => (
              <span key={p} title={permDescriptions.get(p)} className="rounded-full bg-slate-100 px-2 py-0.5 text-xs text-slate-600">
                {p}
              </span>
            ))}
          </div>
        ),
      exportValue: (row) => (row.inheritsAllPermissions || row.permissions.length === 0 ? 'all effective' : row.permissions.join(', ')),
    },
    {
      header: 'Expires',
      key: 'expiresAt',
      width: 160,
      render: (row) => (row.expiresAt ? new Date(row.expiresAt).toLocaleString() : <span className="text-slate-400">never</span>),
    },
    {
      header: 'Last used',
      key: 'lastUsedAt',
      width: 160,
      render: (row) => (row.lastUsedAt ? new Date(row.lastUsedAt).toLocaleString() : <span className="text-slate-400">—</span>),
    },
    {
      header: 'Actions',
      key: 'actions',
      width: 80,
      sortable: false,
      filterable: false,
      excludeFromExport: true,
      render: (row) => (
        <button
          aria-label={`Revoke token ${row.label ?? row.tokenPrefix}`}
          title="Revoke token"
          onClick={() => handleRevoke(row.id, row)}
          className="rounded-md p-1.5 text-slate-400 hover:bg-red-50 hover:text-red-600"
        >
          <Trash2 className="h-4 w-4" />
        </button>
      ),
    },
  ];

  return (
    <Layout>
      <div className="mb-4 flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-slate-900">API Tokens</h1>
          <p className="text-sm text-slate-500">
            Long-lived bearer credentials for agents and scripts (e.g. the MCP server)
          </p>
        </div>
        <div className="flex items-center gap-3">
          {canSeeAll && (
            <label className="flex items-center gap-1.5 text-sm text-slate-600">
              <input type="checkbox" checked={seeAll} onChange={(e) => setSeeAll(e.target.checked)} />
              All users
            </label>
          )}
          <button
            onClick={() => setShowForm(!showForm)}
            className="flex items-center gap-1.5 rounded-md bg-slate-900 px-3 py-1.5 text-sm font-semibold text-white hover:bg-slate-800"
          >
            {showForm ? <X className="h-4 w-4" /> : <Plus className="h-4 w-4" />}
            {showForm ? 'Cancel' : 'Create Token'}
          </button>
        </div>
      </div>

      {createdToken && (
        <div className="mb-6 rounded-md border border-amber-300 bg-amber-50 p-4">
          <h2 className="text-sm font-semibold text-amber-900">
            Token created{createdToken.label ? `: ${createdToken.label}` : ''} — copy it now, it is shown only once.
          </h2>
          <div className="mt-2 flex items-center gap-2">
            <code className="flex-1 select-all break-all rounded-md border border-amber-300 bg-white px-3 py-2 text-sm">
              {createdToken.rawToken}
            </code>
            <button
              onClick={copyRaw}
              className="flex items-center gap-1.5 rounded-md border border-amber-300 bg-white px-3 py-2 text-sm font-medium text-amber-900 hover:bg-amber-100"
            >
              {copied ? <Check className="h-4 w-4 text-green-600" /> : <Copy className="h-4 w-4" />}
              {copied ? 'Copied' : 'Copy'}
            </button>
          </div>
          <p className="mt-2 text-xs text-amber-800">
            Use it as the <code>UNM_API_TOKEN</code> environment variable of the MCP server, or as a Bearer token for direct API calls.
          </p>
        </div>
      )}

      {showForm && (
        <form onSubmit={handleCreate} className="mb-6 rounded-md border border-slate-200 bg-white p-4 shadow-sm">
          <h2 className="mb-4 text-sm font-semibold text-slate-900">New API Token</h2>
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
            <div>
              <label className="mb-1 block text-xs font-medium text-slate-600">Label (purpose)</label>
              <input
                value={label}
                onChange={(e) => setLabel(e.target.value)}
                maxLength={120}
                placeholder="e.g. MCP server"
                className="w-full rounded-md border border-slate-300 px-2 py-1.5 text-sm"
              />
            </div>
            <div>
              <label className="mb-1 block text-xs font-medium text-slate-600">Expires (optional)</label>
              <input
                type="datetime-local"
                value={expiresAt}
                onChange={(e) => setExpiresAt(e.target.value)}
                className="w-full rounded-md border border-slate-300 px-2 py-1.5 text-sm"
              />
            </div>
          </div>

          <div className="mt-4">
            <label className="mb-1 flex items-center gap-1.5 text-xs font-medium text-slate-600">
              <input
                type="checkbox"
                checked={inheritAll}
                onChange={(e) => setInheritAll(e.target.checked)}
              />
              Inherit all my effective permissions (recommended for personal agents)
            </label>
            {!inheritAll && catalog && (
              <div className="mt-2 grid max-h-56 grid-cols-1 gap-1 overflow-y-auto rounded-md border border-slate-200 bg-slate-50 p-3 sm:grid-cols-2">
                {catalog.permissions.map((p) => (
                  <label key={p.id} className="flex items-start gap-2 text-sm text-slate-700" title={p.description}>
                    <input
                      type="checkbox"
                      checked={selectedPerms.has(p.id)}
                      onChange={() => togglePerm(p.id)}
                      className="mt-0.5 h-4 w-4 border-slate-300 text-slate-900 focus:ring-slate-400"
                    />
                    <span>
                      {p.id}
                      <span className="block text-xs text-slate-400">{p.description}</span>
                    </span>
                  </label>
                ))}
              </div>
            )}
          </div>

          <div className="mt-4 flex justify-end">
            <button
              type="submit"
              className="rounded-md bg-slate-900 px-4 py-2 text-sm font-semibold text-white hover:bg-slate-800"
            >
              Create Token
            </button>
          </div>
        </form>
      )}

      {error && (
        <div className="mb-4 rounded-md border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700">{error}</div>
      )}

      <DataTable
        columns={columns}
        rows={tokens}
        rowKey={(row) => row.id}
        storageKey="unm:tokens"
        emptyMessage={loading ? 'Loading…' : 'No API tokens yet — create one to connect an agent (MCP server).'}
      />
    </Layout>
  );
}
