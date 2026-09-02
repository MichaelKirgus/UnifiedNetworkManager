import { ReactNode, useMemo, useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { ArrowLeft, RefreshCw, Settings2 } from 'lucide-react';
import clsx from 'clsx';
import { Layout } from '../components/Layout';
import { StatusBadge } from '../components/StatusBadge';
import { ActionDialog } from '../components/ActionDialog';
import { api, CatalogEntry, DeviceStateResponse, StateItem, StateSection } from '../api/client';
import { can } from '../auth/permissions';

/**
 * DeviceConfig — the per-device "Config" page. Renders the DYNAMIC device-state
 * document served by an assigned plugin's GET /state endpoint (capability
 * 'deviceState'): sections of items (ports with live states + per-port MACs,
 * interfaces, ZFS pools, system info) plus context-aware action buttons. Every
 * change flows through the plan workflow — ActionDialog creates a 1-step plan
 * and executes it immediately (2FA + configs:apply apply uniformly).
 */

/** The dialog target: one catalog entry + its prefill values. */
interface DialogTarget {
  pluginId: string;
  entry: CatalogEntry;
  prefill?: Record<string, unknown>;
}

export default function DeviceConfig() {
  const { deviceId } = useParams<{ deviceId: string }>();
  const canApply = can('configs:apply');

  // The device row (for the header) + its plugin assignments.
  const devicesQuery = useQuery({ queryKey: ['devices'], queryFn: api.devices, enabled: Boolean(deviceId) });
  const device = (devicesQuery.data ?? []).find((d) => d.id === deviceId);

  // Plugins feed the capability check — only fetched when allowed.
  const pluginsQuery = useQuery({
    queryKey: ['plugins'],
    queryFn: api.plugins,
    enabled: Boolean(deviceId) && can('plugins:read'),
  });

  // Assignments whose plugin advertises 'deviceState' (the Config page's scope).
  const configAssignments = useMemo(() => {
    const capsByPlugin = new Map((pluginsQuery.data ?? []).map((p) => [p.id, p.capabilities ?? []]));
    return (device?.plugins ?? []).filter(
      (a) => a.pluginCapabilities?.includes('deviceState') || capsByPlugin.get(a.pluginId)?.includes('deviceState')
    );
  }, [device, pluginsQuery.data]);

  // Which plugin's state to show — defaults to the primary config-capable one.
  const defaultPluginId = useMemo(() => {
    if (configAssignments.length === 0) return null;
    const primary = configAssignments.find((a) => a.isPrimary);
    return (primary ?? configAssignments[0]).pluginId;
  }, [configAssignments]);

  const [selectedPluginId, setSelectedPluginId] = useState<string | null>(null);
  const activePluginId = selectedPluginId ?? defaultPluginId;

  // Live state document + the plugin's action catalog (for dialog rendering).
  const stateQuery = useQuery({
    queryKey: ['deviceState', deviceId, activePluginId],
    queryFn: () => api.deviceState(deviceId as string, activePluginId ?? undefined),
    enabled: Boolean(deviceId) && Boolean(activePluginId),
    refetchInterval: 30_000,
  });

  const actionsQuery = useQuery({
    queryKey: ['plugin-actions', activePluginId],
    queryFn: () => api.pluginActions(activePluginId as string),
    enabled: Boolean(activePluginId) && can('plugins:read'),
  });

  const [dialog, setDialog] = useState<DialogTarget | null>(null);

  if (!device) {
    return (
      <Layout>
        <div className="p-6 text-sm text-slate-500">Loading device…</div>
      </Layout>
    );
  }

  const state: DeviceStateResponse | undefined = stateQuery.data?.state;
  const catalogById = new Map((actionsQuery.data?.actions ?? []).map((a) => [a.id, a]));

  return (
    <Layout>
      <div className="mb-4 flex items-center justify-between">
        <div>
          <Link to={`/devices/${device.id}`} className="inline-flex items-center gap-1 text-xs font-medium text-slate-500 hover:text-slate-800">
            <ArrowLeft className="h-3.5 w-3.5" /> Back to {device.name}
          </Link>
          <div className="mt-1 flex items-center gap-2">
            <Settings2 className="h-5 w-5 text-slate-400" />
            <h1 className="text-xl font-bold text-slate-900">{device.name} — Config</h1>
          </div>
          <p className="mt-1 text-sm text-slate-500">
            Live device state from the plugin. Changes run immediately as plan steps — dangerous actions require an
            explicit confirmation and are recorded in the audit trail.
          </p>
        </div>

        {/* Plugin selector (only when several config-capable plugins) + refresh. */}
        <div className="flex items-center gap-2">
          {configAssignments.length > 1 && (
            <select
              value={activePluginId ?? ''}
              onChange={(e) => setSelectedPluginId(e.target.value)}
              className="rounded-md border border-slate-300 bg-white px-2 py-1.5 text-sm"
            >
              {configAssignments.map((a) => (
                <option key={a.pluginId} value={a.pluginId}>
                  {(a.pluginName ?? a.pluginId) + (a.isPrimary ? ' (primary)' : '')}
                </option>
              ))}
            </select>
          )}
          {activePluginId && (
            <button
              type="button"
              onClick={() => stateQuery.refetch()}
              disabled={stateQuery.isFetching}
              className="inline-flex items-center gap-1.5 rounded-md border border-slate-300 bg-white px-3 py-1.5 text-sm font-medium text-slate-700 hover:bg-slate-50 disabled:opacity-40"
            >
              <RefreshCw className={clsx('h-3.5 w-3.5', stateQuery.isFetching && 'animate-spin')} /> Refresh
            </button>
          )}
        </div>
      </div>

      {configAssignments.length === 0 ? (
        <div className="rounded-md border border-slate-200 bg-white p-6 text-center text-sm text-slate-500">
          No assigned plugin supports live device configuration for this device.
        </div>
      ) : stateQuery.isError ? (
        <div className="rounded-md border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700">
          {(stateQuery.error as Error).message}
        </div>
      ) : !state ? (
        <div className="p-6 text-center text-sm text-slate-400">Loading device state…</div>
      ) : (
        <div className="flex flex-col gap-4">
          {state.sections.map((section) => (
            <StateSectionCard
              key={section.id}
              section={section}
              catalogById={catalogById}
              canApply={canApply}
              onAction={(entry, prefill) => setDialog({ pluginId: activePluginId as string, entry, prefill })}
            />
          ))}
        </div>
      )}

      {dialog && (
        <ActionDialog
          deviceId={device.id}
          pluginId={dialog.pluginId}
          entry={dialog.entry}
          prefill={dialog.prefill}
          onClose={() => setDialog(null)}
        />
      )}
    </Layout>
  );
}

/** One section card: header + optional section-level actions + item table. */
function StateSectionCard({
  section,
  catalogById,
  canApply,
  onAction,
}: {
  section: StateSection;
  catalogById: Map<string, CatalogEntry>;
  canApply: boolean;
  onAction: (entry: CatalogEntry, prefill?: Record<string, unknown>) => void;
}) {
  const items = section.items ?? [];

  // Column set = union of field keys across all items (stable insertion order).
  const columns = useMemo(() => {
    const cols: string[] = [];
    for (const item of items) {
      for (const key of Object.keys(item.fields)) {
        if (!cols.includes(key)) cols.push(key);
      }
    }
    return cols;
  }, [items]);

  // Section-level actions whose catalog entry is known.
  const sectionActions = (section.actions ?? []).filter((a) => catalogById.has(a.actionId));

  return (
    <div className="overflow-hidden rounded-md border border-slate-200 bg-white shadow-sm">
      <div className="flex items-center justify-between border-b border-slate-200 bg-slate-50 px-4 py-2.5">
        <div>
          <h2 className="text-sm font-semibold text-slate-900">{section.label}</h2>
          {section.description && <p className="mt-0.5 text-xs text-slate-500">{section.description}</p>}
        </div>
        {canApply && sectionActions.length > 0 && (
          <div className="flex items-center gap-1.5">
            {sectionActions.map((ref) => {
              const entry = catalogById.get(ref.actionId)!;
              return (
                <ActionButton key={ref.actionId} entry={entry} onClick={() => onAction(entry, ref.prefill)} />
              );
            })}
          </div>
        )}
      </div>

      {items.length === 0 ? (
        <div className="px-4 py-3 text-xs text-slate-400">No items reported.</div>
      ) : (
        <table className="w-full text-left text-sm">
          <thead className="border-b border-slate-200 bg-white text-[11px] uppercase tracking-wide text-slate-500">
            <tr>
              <th className="px-4 py-2">Name</th>
              {columns.map((c) => (
                <th key={c} className="px-3 py-2 capitalize">
                  {humanize(c)}
                </th>
              ))}
              <th className="px-3 py-2">Status</th>
              {canApply && <th className="w-40 px-3 py-2 text-right">Actions</th>}
            </tr>
          </thead>
          <tbody>
            {items.map((item) => (
              <StateItemRow key={item.key} item={item} columns={columns} catalogById={catalogById} canApply={canApply} onAction={onAction} />
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

/** One row of a section table: name + fields + status badge + action buttons. */
function StateItemRow({
  item,
  columns,
  catalogById,
  canApply,
  onAction,
}: {
  item: StateItem;
  columns: string[];
  catalogById: Map<string, CatalogEntry>;
  canApply: boolean;
  onAction: (entry: CatalogEntry, prefill?: Record<string, unknown>) => void;
}) {
  const actions = (item.actions ?? []).filter((a) => catalogById.has(a.actionId));

  return (
    <tr className="border-b border-slate-100 last:border-0">
      <td className="px-4 py-2 font-medium text-slate-800">
        {item.title}
        {item.subtitle && <span className="ml-1.5 text-xs font-normal text-slate-400">{item.subtitle}</span>}
      </td>
      {columns.map((c) => (
        <td key={c} className="px-3 py-2 text-slate-600">
          {formatField(item.fields[c])}
        </td>
      ))}
      <td className="px-3 py-2">{item.status ? <StatusBadge status={item.status} /> : <span className="text-xs text-slate-400">—</span>}</td>
      {canApply && (
        <td className="px-3 py-2">
          <div className="flex flex-wrap items-center justify-end gap-1.5">
            {actions.length === 0 ? (
              <span className="text-xs text-slate-400">—</span>
            ) : (
              actions.map((ref) => {
                const entry = catalogById.get(ref.actionId)!;
                return <ActionButton key={ref.actionId} entry={entry} onClick={() => onAction(entry, ref.prefill)} />;
              })
            )}
          </div>
        </td>
      )}
    </tr>
  );
}

/** A compact action button — red-tinted for dangerous catalog entries. */
function ActionButton({ entry, onClick }: { entry: CatalogEntry; onClick: () => void }) {
  const dangerous = entry.riskLevel === 'dangerous';
  return (
    <button
      type="button"
      title={entry.description ?? entry.label}
      onClick={onClick}
      className={clsx(
        'rounded-md border px-2 py-1 text-xs font-medium',
        dangerous
          ? 'border-red-200 bg-red-50 text-red-700 hover:bg-red-100'
          : 'border-slate-300 bg-white text-slate-700 hover:bg-slate-50'
      )}
    >
      {entry.label}
    </button>
  );
}

/** camelCase field key → "Human Label" (e.g. allowedVlans → Allowed Vlans). */
function humanize(key: string): string {
  return key.replace(/([a-z0-9])([A-Z])/g, '$1 $2').replace(/^./, (c) => c.toUpperCase());
}

/** Renders a field value verbatim; null/undefined → em dash. */
function formatField(value: string | number | null | unknown[] | undefined): ReactNode {
  if (value === null || value === undefined || value === '') return <span className="text-slate-400">—</span>;
  // Arrays (e.g. per-port MAC lists) render as a wrapped chip list.
  if (Array.isArray(value)) {
    const macs = value.filter((v): v is string => typeof v === 'string');
    if (macs.length > 0) {
      return (
        <span className="flex flex-wrap gap-1">
          {macs.slice(0, 6).map((m) => (
            <span key={m} className="rounded bg-slate-100 px-1.5 py-0.5 font-mono text-[10px] text-slate-600" title={m}>
              {m}
            </span>
          ))}
          {macs.length > 6 && <span className="text-[10px] text-slate-400">+{macs.length - 6}</span>}
        </span>
      );
    }
    return <span className="text-slate-400">—</span>;
  }
  return String(value);
}
