import { useEffect, useMemo, useRef, useState } from 'react';
import { useQuery, useQueryClient, useMutation } from '@tanstack/react-query';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { ChevronDown, Copy, Eye, Pencil, Plus, Power, RefreshCw, Save, Settings2, Tag, Trash2, X } from 'lucide-react';
import { Layout } from '../components/Layout';
import { DataTable, DataTableColumn } from '../components/DataTable';
import { ChipInput } from '../components/ChipInput';
import { StatusBadge } from '../components/StatusBadge';
import { MetricCell } from '../components/MetricCell';
import { DeviceIcon } from '../components/DeviceIcon';
import { DeviceActionsCell } from '../components/DeviceActionsCell';
import { PluginAssignmentBuilder } from '../components/PluginAssignmentBuilder';
import { api, Device, DeviceCreateRequest, DeviceModelEntry, DevicePluginAssignmentInput, DevicePluginAssignment, DeviceRefreshResult, Plugin } from '../api/client';
import { OptionForm } from '../components/OptionForm';
import { can } from '../auth/permissions';
import { isValidAddress, addressError } from '../utils/address';

// Derive the list of selectable vendors from the discovered plugins so that
// adding/renaming a plugin is reflected in the GUI without code changes.
function vendorOptions(plugins: Plugin[]): string[] {
  const vendors = plugins.flatMap((p) => p.vendors ?? []);
  return Array.from(new Set(vendors)).sort();
}

/** Common device roles offered as one-click suggestions (free-form entries allowed). */
const TYPE_SUGGESTIONS = ['access point', 'controller', 'firewall', 'load balancer', 'router', 'switch', 'wireless controller'];

/** Capitalizes a stored vendor/type string for display ("opnsense" → "Opnsense"). */
function cap(s: string): string {
  return s.charAt(0).toUpperCase() + s.slice(1);
}

/** The Config page is available when ANY assigned plugin advertises the 'deviceState' capability. */
function hasDeviceConfig(device: Device, plugins?: Plugin[]): boolean {
  return (device.plugins ?? []).some((a) => {
    if (a.pluginCapabilities?.includes('deviceState')) return true;
    const p = plugins?.find((x) => x.id === a.pluginId);
    return p?.capabilities?.includes('deviceState') ?? false;
  });
}

export default function Devices() {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  // Write gating — the page itself needs devices:read (route guard), every
  // mutating action below additionally needs its own permission.
  const canWriteDevices = can('devices:write');
  const canManagePlugins = can('plugins:manage');
  const [showForm, setShowForm] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);

  // When non-null the form is in EDIT mode for that device.
  const [editingId, setEditingId] = useState<string | null>(null);
  // Original secondary IPs (with row ids) captured when entering edit mode,
  // used to diff on save (add new / remove deleted).
  const [originalSecondaryIps, setOriginalSecondaryIps] = useState<{ id: string; address: string }[]>([]);

  // Device identity fields (shared between create and edit modes). Model +
  // firmwareVersion are optional — chosen from the assigned plugins' catalogs.
  // deviceTypes is a multi-value list (a box can be router AND firewall);
  // tags are free-form user labels for future filtering / plan targeting.
  const emptyIdentity = { name: '', vendor: '', deviceTypes: ['firewall'] as string[], tags: [] as string[], managementAddress: '', siteId: '', model: '', firmwareVersion: '', layerOverride: '', pollIntervalMs: '' };
  const [identity, setIdentity] = useState(emptyIdentity);

  // Telemetry polling toggle (create + edit modes). Default enabled — disabled
  // devices are not polled; their historical data and last metrics stay preserved.
  const [enabled, setEnabled] = useState(true);

  // Plugin ids currently selected in the assignment builder (reported via
  // onRowsChange) — drives which model catalogs are offered for the vendor.
  const [selectedPluginIds, setSelectedPluginIds] = useState<string[]>([]);

  // One central Save button owns submission for the whole form: it triggers
  // the plugin-assignment builder's validating submit() via this ref and
  // persists per-plugin override edits through the OptionForm refs below.
  const builderRef = useRef<import('../components/PluginAssignmentBuilder').PluginAssignmentBuilderHandle>(null);
  const optionRefs = useRef(new Map<string, import('../components/OptionForm').OptionFormHandle>());
  const [optionDirty, setOptionDirty] = useState<Record<string, boolean>>({});
  // Per-plugin override sections are collapsed by default (5+ assigned plugins
  // would otherwise overload the form). Expanded ids live in this set.
  const [expandedOptions, setExpandedOptions] = useState<Set<string>>(new Set());

  function toggleOptionSection(pluginId: string) {
    setExpandedOptions((s) => {
      const next = new Set(s);
      if (next.has(pluginId)) next.delete(pluginId);
      else next.add(pluginId);
      return next;
    });
  }

  // Secondary IPs (creation list or existing secondaries in edit mode).
  const [additionalIps, setAdditionalIps] = useState<string[]>([]);
  const [newIpInput, setNewIpInput] = useState('');
  const [ipError, setIpError] = useState<string | null>(null);

  // Existing plugin assignments captured when entering edit mode.
  const [initialAssignments, setInitialAssignments] = useState<DevicePluginAssignment[]>([]);

  const devicesQuery = useQuery({ queryKey: ['devices'], queryFn: api.devices, refetchInterval: 30_000 });
  // Reference data for the create/edit form — only fetched when the user may
  // actually write (the API gates these on plugins:read / secrets:read /
  // sites:read). Read-only users get a placeholder icon and empty pickers.
  const pluginsQuery = useQuery({ queryKey: ['plugins'], queryFn: api.plugins, enabled: canWriteDevices && can('plugins:read') });
  const secretsQuery = useQuery({ queryKey: ['secrets'], queryFn: api.secrets, enabled: canWriteDevices && can('secrets:read') });
  // Site picker options (the Sites page owns creation; this is read-only here).
  const sitesQuery = useQuery({ queryKey: ['sites'], queryFn: api.sites, enabled: can('sites:read') && canWriteDevices });
  // Layer registry — drives the manual topology-layer override select.
  const layersQuery = useQuery({ queryKey: ['layers'], queryFn: () => api.layers() });

  // Clone handoff from DeviceDetail (?edit=<id>): once the device list has
  // loaded, open the edit form pre-filled with that (cloned) device so the
  // user can change the IP or other settings before saving.
  const [searchParams, setSearchParams] = useSearchParams();
  useEffect(() => {
    const editId = searchParams.get('edit');
    if (!editId || !devicesQuery.data) return;
    const target = devicesQuery.data.find((d) => d.id === editId);
    if (target) {
      openEdit(target);
      setSearchParams({}, { replace: true });
    }
  }, [searchParams, devicesQuery.data]); // eslint-disable-line react-hooks/exhaustive-deps

  // Model catalog for the selected vendor, merged across ALL plugins currently
  // assigned in the form (a device can have several — e.g. LANCOM + SNMP).
  // Empty when no assigned plugin advertises models for this vendor (e.g. ICMP),
  // in which case the form shows no model fields at all.
  const modelEntries = useMemo<DeviceModelEntry[]>(() => {
    if (!identity.vendor) return [];
    const byKey = new Map<string, DeviceModelEntry>();
    for (const id of selectedPluginIds) {
      const plugin = (pluginsQuery.data ?? []).find((p) => p.id === id);
      for (const entry of plugin?.deviceModels ?? []) {
        if (entry.vendor !== identity.vendor) continue;
        // First catalog wins per model name — firmware lists are merged.
        const existing = byKey.get(entry.model.toLowerCase());
        if (!existing) byKey.set(entry.model.toLowerCase(), { ...entry });
        else if (entry.firmwareVersions?.length) {
          const merged = new Set([...(existing.firmwareVersions ?? []), ...entry.firmwareVersions]);
          existing.firmwareVersions = Array.from(merged);
        }
      }
    }
    return Array.from(byKey.values()).sort((a, b) => a.model.localeCompare(b.model));
  }, [identity.vendor, selectedPluginIds, pluginsQuery.data]);

  // Firmware options for the currently selected model (empty = no dropdown).
  const firmwareOptions = useMemo(() => {
    if (!identity.model) return [];
    return modelEntries.find((m) => m.model === identity.model)?.firmwareVersions ?? [];
  }, [identity.model, modelEntries]);

  // The device's primary plugin as a full Plugin row (icon + model catalog).
  // Assignments only carry the id — resolve against the plugins list.
  function primaryPluginOf(device: Device): Plugin | null {
    const assignments = device.plugins ?? [];
    const primary = assignments.find((a) => a.isPrimary) ?? assignments[0];
    if (!primary) return null;
    return (pluginsQuery.data ?? []).find((p) => p.id === primary.pluginId) ?? null;
  }

  const createDevice = useMutation({
    mutationFn: (body: DeviceCreateRequest) => api.createDevice(body),
    onSuccess: () => resetForm(),
    onError: (err: unknown) => setFormError((err as Error).message),
  });

  const deleteDevice = useMutation({
    mutationFn: (id: string) => api.deleteDevice(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['devices'] });
      // The device's config-job history is deleted server-side too.
      queryClient.invalidateQueries({ queryKey: ['configJobs'] });
    },
    onError: (err: Error) => setFormError(err.message),
  });

  function handleDelete(row: Device) {
    if (!window.confirm(`Delete device "${row.name}"?\nIts plugin assignments, secondary IPs and telemetry history are removed. Plans referencing it must be deleted first.`)) return;
    deleteDevice.mutate(row.id);
  }

  // Clone reuses ALL settings (plugins + credentials, secondary IPs,
  // per-device overrides). On success the edit form opens pre-filled with the
  // clone so the user can change the IP or other settings before saving.
  const cloneDevice = useMutation({
    mutationFn: (id: string) => api.cloneDevice(id),
    onSuccess: (cloned) => {
      queryClient.invalidateQueries({ queryKey: ['devices'] });
      openEdit(cloned);
    },
    onError: (err: Error) => setFormError(err.message),
  });

  function handleClone(row: Device) {
    if (!window.confirm(`Clone device "${row.name}"?\nAll plugin assignments, credentials, secondary IPs and per-device settings are reused. The edit form opens so you can change the IP or other settings.`)) return;
    cloneDevice.mutate(row.id);
  }

  // Bulk delete (selection bar). Devices referenced by plans fail with 409 —
  // the rest still go through, so report per-device outcomes.
  const bulkDeleteDevices = useMutation({
    mutationFn: async (rows: Device[]) => {
      const blockedByPlans: string[] = [];
      const otherErrors: string[] = [];
      for (const row of rows) {
        try {
          await api.deleteDevice(row.id);
        } catch (err) {
          if ((err as { status?: number }).status === 409) blockedByPlans.push(row.name);
          else otherErrors.push(`${row.name}: ${(err as Error).message}`);
        }
      }
      return { total: rows.length, blockedByPlans, otherErrors };
    },
    onSuccess: ({ total, blockedByPlans, otherErrors }) => {
      queryClient.invalidateQueries({ queryKey: ['devices'] });
      // Deleted devices' config-job history is removed server-side too.
      queryClient.invalidateQueries({ queryKey: ['configJobs'] });
      if (blockedByPlans.length > 0 || otherErrors.length > 0) {
        const parts = [
          `Deleted ${total - blockedByPlans.length - otherErrors.length} of ${total} device(s).`,
          ...blockedByPlans.length > 0 ? [`Not deleted — still referenced by plans (delete those plans first):\n${blockedByPlans.join(', ')}`] : [],
          ...otherErrors.length > 0 ? [`Other errors:\n${otherErrors.join('\n')}`] : [],
        ];
        window.alert(parts.filter(Boolean).join('\n\n'));
      }
    },
  });

  // Force an immediate re-poll of one or more devices — bypasses the
  // staggered windows and refreshes BOTH live metrics and inventory now.
  // Diagnostic path for "is this device reachable right now?"; the regular
  // poll deadlines stay untouched server-side.
  const refreshDevices = useMutation({
    mutationFn: (ids: string[]) => api.refreshDevices(ids),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['devices'] });
      // Inventory tables were re-ingested — refresh the cross-device views too.
      for (const key of ['networks', 'hosts', 'tunnels', 'routes', 'firewall-rules', 'wifi', 'storage', 'containers', 'vms']) {
        queryClient.invalidateQueries({ queryKey: [key] });
      }
    },
  });

  /** Reports per-device refresh problems (unreachable plugins, disabled devices). */
  function reportRefreshResults(results: DeviceRefreshResult[]) {
    const problems = results.filter((r) => !r.ok);
    if (problems.length === 0) return; // all good — no noise
    const lines = problems.map((r) => {
      const label = r.name || r.deviceId;
      if (r.error) return `${label}: ${r.error}`;
      const bad = r.results.filter((x) => !x.reachable);
      if (bad.length === 0) return `${label}: no plugin reachable`;
      return `${label}: ${bad.map((x) => x.error ?? 'unreachable').join('; ')}`;
    });
    window.alert(`Refresh finished with problems:\n${lines.join('\n')}`);
  }

  function handleRefresh(row: Device) {
    refreshDevices.mutate([row.id], { onSuccess: (data) => reportRefreshResults(data.results) });
  }

  const updateDevice = useMutation({
    mutationFn: async (assignments?: DevicePluginAssignmentInput[]) => {
      // PATCH identity fields (model/firmwareVersion may be cleared with null).
      await api.updateDevice(editingId!, {
        name: identity.name.trim(),
        vendor: identity.vendor,
        deviceTypes: identity.deviceTypes.length > 0 ? identity.deviceTypes : ['firewall'],
        tags: identity.tags,
        managementAddress: identity.managementAddress.trim(),
        siteId: identity.siteId || null,
        model: identity.model.trim() || null,
        firmwareVersion: identity.firmwareVersion.trim() || null,
        layerOverride: identity.layerOverride || null,
        pollIntervalMs: identity.pollIntervalMs ? Number(identity.pollIntervalMs) : null,
        enabled,
      });
      // Diff secondary IPs: add new, remove deleted.
      const toAdd = additionalIps.filter((ip) => !originalSecondaryIps.some((o) => o.address === ip));
      const toRemove = originalSecondaryIps.filter((o) => !additionalIps.includes(o.address));
      for (const ip of toAdd) await api.addDeviceIp(editingId!, ip);
      for (const row of toRemove) await api.removeDeviceIp(editingId!, row.id);

      // Diff plugin assignments: add new, remove deleted, update changed. The
      // builder reports rows in their drag & drop order — position 0 is the
      // primary plugin (the rest are the fallback sequence).
      if (assignments) {
        const desiredIds = new Set(assignments.map((a) => a.pluginId));
        const removed = initialAssignments.filter((a) => !desiredIds.has(a.pluginId));

        // `now` mirrors the server's dense order as we mutate it, so at the end
        // we can tell whether one reorder call is still needed.
        let now: string[] = initialAssignments.map((a) => a.pluginId);
        for (const r of removed) {
          await api.removeDevicePlugin(editingId!, r.pluginId);
          now = now.filter((id) => id !== r.pluginId); // server re-densifies the rest
        }

        const existingById = new Map(initialAssignments.map((a) => [a.pluginId, a]));
        for (const a of assignments) {
          const prev = existingById.get(a.pluginId);
          if (!prev) {
            // New plugin: isPrimary=true lands it at position 0 (shifting the
            // rest down), otherwise it appends to the end.
            await api.addDevicePlugin(editingId!, a);
            now = a.isPrimary ? [a.pluginId, ...now] : [...now, a.pluginId];
          } else {
            // Already assigned — persist credential / slot changes only (the
            // primary flag is derived from position and fixed by the reorder).
            const secretChanged = (a.secretId ?? null) !== (prev.secretId ?? null);
            const slotsChanged = JSON.stringify(a.extraCredentials ?? {}) !== JSON.stringify(prev.extraCredentials ?? {});
            if (secretChanged || slotsChanged) {
              await api.updateDevicePlugin(editingId!, a.pluginId, {
                ...(secretChanged ? { secretId: a.secretId ?? null } : {}),
                ...(slotsChanged ? { extraCredentials: a.extraCredentials ?? {} } : {}),
              });
            }
          }
        }

        // One reorder call when the drag & drop sequence differs from what's stored.
        const desired = assignments.map((a) => a.pluginId);
        if (desired.join('\u0000') !== now.join('\u0000')) {
          await api.reorderDevicePlugins(editingId!, desired);
        }
      }
    },
    onSuccess: () => resetForm(),
    onError: (err: unknown) => setFormError((err as Error).message),
  });

  function resetForm() {
    queryClient.invalidateQueries({ queryKey: ['devices'] });
    setShowForm(false);
    setEditingId(null);
    setIdentity(emptyIdentity);
    setEnabled(true);
    setSelectedPluginIds([]);
    setAdditionalIps([]);
    setOriginalSecondaryIps([]);
    setInitialAssignments([]);
    setNewIpInput('');
    setIpError(null);
    setFormError(null);
    setExpandedOptions(new Set());
    setOptionDirty({});
  }

  function handleSubmit(assignments: DevicePluginAssignmentInput[]) {
    if (editingId) {
      updateDevice.mutate(assignments);
    } else {
      createDevice.mutate({
        ...identity,
        siteId: identity.siteId || null,
        ips: additionalIps.length > 0 ? additionalIps : undefined,
        plugins: assignments,
        model: identity.model.trim() || null,
        firmwareVersion: identity.firmwareVersion.trim() || null,
        layerOverride: identity.layerOverride || null,
        pollIntervalMs: identity.pollIntervalMs ? Number(identity.pollIntervalMs) : null,
        enabled,
      });
    }
  }

  /** Adds a secondary IP to the creation list (validated inline). */
  function addSecondaryIp() {
    const v = newIpInput.trim();
    if (!v) return;
    if (!isValidAddress(v)) { setIpError(addressError(v)); return; }
    if (additionalIps.some((ip) => ip.toLowerCase() === v.toLowerCase())) {
      setIpError('This address is already in the list.');
      return;
    }
    setAdditionalIps([...additionalIps, v]);
    setNewIpInput('');
    setIpError(null);
  }

  /** Prefills the inline form with a device's values and switches to edit mode. */
  function openEdit(device: Device) {
    // Fall back to the legacy single type for devices created before multi-type.
    const types = device.deviceTypes?.length > 0 ? device.deviceTypes : [device.deviceType ?? 'firewall'];
    setIdentity({
      name: device.name,
      vendor: device.vendor,
      deviceTypes: types,
      tags: device.tags ?? [],
      managementAddress: device.managementAddress,
      siteId: device.siteId ?? '',
      model: device.model ?? '',
      firmwareVersion: device.firmwareVersion ?? '',
      layerOverride: device.layerOverride ?? '',
      pollIntervalMs: device.pollIntervalMs != null ? String(device.pollIntervalMs) : '',
    });
    setEnabled(device.enabled !== false);
    const secondaries = (device.ips ?? []).filter((ip) => !ip.isPrimary);
    setAdditionalIps(secondaries.map((s) => s.address));
    setOriginalSecondaryIps(
      secondaries.filter((s): s is typeof s & { id: string } => s.id != null).map((s) => ({ id: s.id as string, address: s.address }))
    );
    setInitialAssignments(device.plugins ?? []);
    setNewIpInput('');
    setIpError(null);
    setFormError(null);
    setEditingId(device.id);
    setShowForm(true);
  }

  const columns: DataTableColumn<Device>[] = [
    {
      // Icon from the primary plugin (or the selected model's icon) — quick visual recognition.
      header: '',
      key: 'icon',
      width: 36,
      sortable: false,
      excludeFromExport: true,
      render: (row) => <DeviceIcon plugin={primaryPluginOf(row)} model={row.model} />,
    },
    { header: 'Name', key: 'name' },
    {
      // Stored lowercase (from plugin catalogs) — display capitalized.
      header: 'Vendor',
      key: 'vendor',
      render: (row) => cap(row.vendor),
    },
    {
      // A device can fulfill several roles at once (e.g. router + firewall).
      header: 'Types',
      key: 'deviceTypes',
      width: 200,
      exportValue: (row) => row.deviceTypes.join(', '),
      render: (row) => {
        const types = row.deviceTypes ?? [];
        if (types.length === 0) return <span className="text-faint">—</span>;
        return (
          <div className="flex flex-wrap gap-1">
            {types.map((t) => (
              <span key={t} className="inline-flex items-center rounded-full bg-muted px-2 py-0.5 text-xs font-medium capitalize text-secondary">
                {t}
              </span>
            ))}
          </div>
        );
      },
    },
    {
      // Free-form user tags — future filter / plan targeting.
      header: 'Tags',
      key: 'tags',
      width: 180,
      exportValue: (row) => row.tags.join(', '),
      render: (row) => {
        const tags = row.tags ?? [];
        if (tags.length === 0) return <span className="text-faint">—</span>;
        return (
          <div className="flex flex-wrap gap-1">
            {tags.map((t) => (
              <span key={t} className="inline-flex items-center gap-1 rounded-full bg-accent-indigo/60 px-2 py-0.5 text-xs font-medium text-accent-indigo-fg">
                <Tag className="h-3 w-3" />
                {t}
              </span>
            ))}
          </div>
        );
      },
    },
    {
      // Detected from the plugins' latest telemetry (primary plugin first) —
      // distinct from the user-selected `firmwareVersion` identity field.
      header: 'Software version',
      key: 'detectedFirmwareVersion',
      width: 170,
      render: (row) => row.detectedFirmwareVersion ?? <span className="text-faint">—</span>,
    },
    {
      header: 'Serial number',
      key: 'serialNumber',
      width: 150,
      render: (row) => row.serialNumber ? <span className="font-mono text-xs">{row.serialNumber}</span> : <span className="text-faint">—</span>,
    },
    { header: 'Site', key: 'siteName', render: (row) => row.siteName ?? <span className="text-faint">—</span> },
    {
      // Manual topology-layer override — most devices stay on "Auto" (the
      // plugin suggestion / heuristic decides); a badge shows the pinned layer.
      header: 'Layer',
      key: 'layerOverride',
      width: 120,
      exportValue: (row) => row.layerOverride ?? 'auto',
      render: (row) => {
        const l = (layersQuery.data ?? []).find((x) => x.id === row.layerOverride);
        if (!l) return <span className="text-xs text-faint">Auto</span>;
        return (
          <span
            className="inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-[10px] font-bold uppercase tracking-wide"
            style={{ color: l.color, backgroundColor: `${l.color}1a` }}
          >
            {l.name}
          </span>
        );
      },
    },
    {
      header: 'IP',
      key: 'managementAddress',
      width: 160,
      sortable: true,
      sortAccessor: (row) => row.managementAddress,
      render: (row) => {
        const secondaryCount = (row.ips ?? []).filter((ip) => !ip.isPrimary).length;
        return (
          <span className="font-mono text-xs">
            {row.managementAddress}
            {secondaryCount > 0 && (
              <span className="ml-1 rounded-full bg-muted px-1.5 py-0.5 text-[10px] font-medium text-secondary">+{secondaryCount}</span>
            )}
          </span>
        );
      },
    },
    {
      header: 'Plugins',
      key: 'plugins',
      width: 200,
      sortable: false,
      render: (row) => {
        const plugins = row.plugins ?? [];
        if (plugins.length === 0) return <span className="text-faint">—</span>;
        return (
          <div className="flex flex-wrap gap-1">
            {plugins.map((p) => (
              <span
                key={p.id}
                title={`${p.pluginName ?? p.pluginId}${p.isPrimary ? ' (primary)' : ''}`}
                className={`inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium ${
                  p.isPrimary ? 'bg-primary text-white' : 'bg-muted text-secondary'
                }`}
              >
                {p.pluginName ?? p.pluginId}
              </span>
            ))}
          </div>
        );
      },
    },
    {
      header: 'Status',
      key: 'status',
      render: (row) => (
        <span className="inline-flex items-center gap-1.5">
          <StatusBadge status={row.status} />
          {row.enabled === false && (
            <span
              title="Telemetry polling disabled — historical data and last metrics are preserved"
              className="rounded-full bg-muted px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-secondary"
            >
              disabled
            </span>
          )}
        </span>
      ),
    },
    {
      header: 'Metrics',
      key: 'metrics',
      // 3 MetricCells per line at their 120px minimum + two 20px gaps = 400.
      width: 400,
      sortable: false,
      render: (row) => {
        const metrics = row.summaryMetrics ?? [];
        if (metrics.length === 0) return <span className="text-faint">—</span>;
        return (
          <div className="flex flex-wrap items-center gap-x-5 gap-y-2">
            {metrics.map((m, i) => (
              <MetricCell key={`${m.key}-${i}`} metric={m} />
            ))}
          </div>
        );
      },
    },
    {
      // Quick actions propagated by the assigned plugins (web UI, shell, files,
      // risk-gated catalog actions). Hidden on first render — enable via the
      // Columns picker; the plugin list drives what each row offers.
      header: 'Device Actions',
      key: 'deviceActions',
      excludeFromExport: true,
      width: 150,
      sortable: false,
      hiddenByDefault: true,
      render: (row) => <DeviceActionsCell device={row} />,
    },
    {
      header: 'Management Actions',
      key: 'actions',
      excludeFromExport: true,
      width: 210,
      sortable: false,
      render: (row) => (
        <div className="flex items-center gap-1">
          <button
            aria-label={`View ${row.name}`}
            title="View details"
            className="rounded-md p-1.5 text-secondary hover:bg-muted hover:text-foreground"
            onClick={() => navigate(`/devices/${row.id}`)}
          >
            <Eye className="h-4 w-4" />
          </button>
          {hasDeviceConfig(row, pluginsQuery.data) && (
            <button
              aria-label={`Configure ${row.name}`}
              title="Open config page"
              className="rounded-md p-1.5 text-secondary hover:bg-muted hover:text-foreground"
              onClick={() => navigate(`/devices/${row.id}/config`)}
            >
              <Settings2 className="h-4 w-4" />
            </button>
          )}
          {canWriteDevices && (
            <>
              <button
                aria-label={`Refresh ${row.name}`}
                title="Force refresh — re-poll metrics + inventory now (diagnostics)"
                className="rounded-md p-1.5 text-secondary hover:bg-muted hover:text-foreground disabled:opacity-40"
                onClick={() => handleRefresh(row)}
                disabled={refreshDevices.isPending && refreshDevices.variables?.includes(row.id)}
              >
                <RefreshCw className={`h-4 w-4 ${refreshDevices.isPending && refreshDevices.variables?.includes(row.id) ? 'animate-spin' : ''}`} />
              </button>
              <button
                aria-label={`Edit ${row.name}`}
                title="Edit device"
                className="rounded-md p-1.5 text-secondary hover:bg-muted hover:text-foreground"
                onClick={() => openEdit(row)}
              >
                <Pencil className="h-4 w-4" />
              </button>
              <button
                aria-label={`Clone ${row.name}`}
                title="Clone device (reuses all settings)"
                className="rounded-md p-1.5 text-secondary hover:bg-muted hover:text-foreground"
                onClick={() => handleClone(row)}
              >
                <Copy className="h-4 w-4" />
              </button>
            </>
          )}
          {canWriteDevices && (
            <button
              aria-label={`Delete ${row.name}`}
              title="Delete device"
              className="rounded-md p-1.5 text-secondary hover:bg-danger hover:text-danger-fg"
              onClick={() => handleDelete(row)}
            >
              <Trash2 className="h-4 w-4" />
            </button>
          )}
        </div>
      ),
    },
  ];

  return (
    <Layout
      title="Devices"
      actions={
        canWriteDevices && (
          <button
            className="flex items-center gap-1.5 rounded-md bg-primary px-3 py-1.5 text-sm font-semibold text-white hover:bg-primary-hover"
            onClick={() => { setShowForm((v) => !v); if (showForm) resetForm(); }}
          >
            {showForm ? <X className="h-4 w-4" /> : <Plus className="h-4 w-4" />}
            {showForm ? 'Cancel' : editingId ? 'Edit Device' : 'Register Device'}
          </button>
        )
      }
    >

      {deleteDevice.error && (
        <div className="mb-4 rounded-md border border-danger-border bg-danger px-3 py-2 text-sm text-danger-fg">
          {(deleteDevice.error as Error).message}
        </div>
      )}

      {showForm && (
        <div
          className="mb-6 grid grid-cols-1 gap-3 rounded-md border border-border bg-card p-4 shadow-sm sm:grid-cols-2"
        >
          <h2 className="col-span-full text-sm font-semibold uppercase tracking-wide text-muted-foreground">
            {editingId ? `Edit device` : 'Register device'}
          </h2>
          {formError && (
            <div className="col-span-full rounded-md border border-danger-border bg-danger px-3 py-2 text-sm text-danger-fg">
              {formError}
            </div>
          )}
          <div>
            <label className="mb-1 block text-sm font-medium text-secondary">Name</label>
            <input
              required
              className="w-full rounded-md border border-border px-3 py-2 text-sm"
              value={identity.name}
              onChange={(e) => setIdentity({ ...identity, name: e.target.value })}
            />
          </div>
          <div>
            <label className="mb-1 block text-sm font-medium text-secondary">Vendor</label>
            <select
              required
              className="w-full rounded-md border border-border px-3 py-2 text-sm"
              value={identity.vendor}
              // Changing the vendor invalidates any model/firmware selection.
              onChange={(e) => setIdentity({ ...identity, vendor: e.target.value, model: '', firmwareVersion: '' })}
            >
              <option value="" disabled>
                Select a vendor
              </option>
              {vendorOptions(pluginsQuery.data ?? []).map((vendor) => (
                <option key={vendor} value={vendor}>
                  {vendor}
                </option>
              ))}
            </select>
          </div>
          <div>
            <label className="mb-1 block text-sm font-medium text-secondary">Device types</label>
            <ChipInput
              values={identity.deviceTypes}
              onChange={(deviceTypes) => setIdentity({ ...identity, deviceTypes })}
              suggestions={TYPE_SUGGESTIONS}
              placeholder="e.g. router, firewall — press Enter"
              ariaLabel="Device types"
            />
            <p className="mt-1 text-xs text-faint">A device can have several roles (e.g. a routed switch is both).</p>
          </div>
          <div>
            <label className="mb-1 block text-sm font-medium text-secondary">Tags</label>
            <ChipInput
              values={identity.tags}
              onChange={(tags) => setIdentity({ ...identity, tags })}
              placeholder="e.g. dmz, lab — press Enter"
              ariaLabel="Device tags"
            />
            <p className="mt-1 text-xs text-faint">Optional free-form labels for filtering and targeted changes.</p>
          </div>

          {/* Model + Firmware — only offered when an assigned plugin advertises a
              catalog for the selected vendor (vendor-specific plugins do; generic
              ones like ICMP don't). Both optional. */}
          {modelEntries.length > 0 && (
            <>
              <div>
                <label className="mb-1 block text-sm font-medium text-secondary">Model</label>
                <select
                  className="w-full rounded-md border border-border px-3 py-2 text-sm"
                  value={identity.model}
                  onChange={(e) => {
                    const nextModel = e.target.value;
                    // When a model with a plugin-suggested default layer is picked
                    // and the override is still "Auto", prefill that suggestion —
                    // it stays fully overridable in the Layer select below.
                    const suggested = modelEntries.find((m) => m.model === nextModel)?.defaultLayerId;
                    setIdentity({
                      ...identity,
                      model: nextModel,
                      firmwareVersion: '',
                      layerOverride: identity.layerOverride === '' && suggested ? suggested : identity.layerOverride,
                    });
                  }}
                >
                  <option value="">— not specified —</option>
                  {modelEntries.map((m) => (
                    <option key={m.model} value={m.model}>
                      {m.model}
                    </option>
                  ))}
                </select>
                <p className="mt-1 text-xs text-faint">Optional — enables firmware-specific data collection.</p>
              </div>
              {firmwareOptions.length > 0 && (
                <div>
                  <label className="mb-1 block text-sm font-medium text-secondary">Firmware version</label>
                  <select
                    className="w-full rounded-md border border-border px-3 py-2 text-sm"
                    value={identity.firmwareVersion}
                    onChange={(e) => setIdentity({ ...identity, firmwareVersion: e.target.value })}
                  >
                    <option value="">— not specified —</option>
                    {firmwareOptions.map((v) => (
                      <option key={v} value={v}>
                        {v}
                      </option>
                    ))}
                  </select>
                </div>
              )}
            </>
          )}
          {/* Manual topology-layer override — "Auto" lets the plugin suggestion /
              heuristic decide; picking a layer pins this device to that band. */}
          <div>
            <label className="mb-1 block text-sm font-medium text-secondary">Topology layer</label>
            <select
              className="w-full rounded-md border border-border px-3 py-2 text-sm"
              value={identity.layerOverride}
              onChange={(e) => setIdentity({ ...identity, layerOverride: e.target.value })}
            >
              <option value="">Auto (plugin suggestion / heuristic)</option>
              {(layersQuery.data ?? []).map((l) => (
                <option key={l.id} value={l.id}>
                  {l.name}
                </option>
              ))}
            </select>
            <p className="mt-1 text-xs text-faint">Which horizontal band the topology view draws this device in.</p>
          </div>
          <div>
            <label className="mb-1 block text-sm font-medium text-secondary">Primary IP / Address</label>
            <input
              required
              className={`w-full rounded-md border px-3 py-2 text-sm ${
                identity.managementAddress.trim() && !isValidAddress(identity.managementAddress)
                  ? 'border-danger-border'
                  : 'border-border'
              }`}
              value={identity.managementAddress}
              onChange={(e) => setIdentity({ ...identity, managementAddress: e.target.value })}
              placeholder="10.0.0.1 or gw.local"
            />
            {identity.managementAddress.trim() && !isValidAddress(identity.managementAddress) && (
              <p className="mt-1 text-xs text-danger-fg">{addressError(identity.managementAddress)}</p>
            )}
          </div>
          <div>
            <label className="mb-1 block text-sm font-medium text-secondary">Site</label>
            <select
              className="w-full rounded-md border border-border px-3 py-2 text-sm"
              value={identity.siteId}
              onChange={(e) => setIdentity({ ...identity, siteId: e.target.value })}
            >
              <option value="">— unassigned —</option>
              {(sitesQuery.data ?? []).map((s) => (
                <option key={s.id} value={s.id}>
                  {s.name}
                  {s.country ? ` (${s.country})` : ''}
                </option>
              ))}
            </select>
          </div>

          {/* Per-device metrics poll window — overrides the plugin/system default. */}
          <div>
            <label className="mb-1 block text-sm font-medium text-secondary">Metrics poll interval (seconds, optional)</label>
            <input
              type="number"
              min={5}
              max={3600}
              step={5}
              className="w-full rounded-md border border-border px-3 py-2 text-sm"
              value={identity.pollIntervalMs}
              onChange={(e) => setIdentity({ ...identity, pollIntervalMs: e.target.value })}
              placeholder="inherit default"
            />
            <p className="mt-1 text-xs text-faint">
              How often this device's metrics are collected. Leave empty to inherit the plugin or system default.
            </p>
          </div>

          <div className="col-span-full flex items-center gap-2">
            <input
              id="device-enabled"
              type="checkbox"
              checked={enabled}
              onChange={(e) => setEnabled(e.target.checked)}
              className="h-4 w-4 rounded border-border"
            />
            <label htmlFor="device-enabled" className="text-sm font-medium text-secondary">
              Enabled (poll telemetry)
            </label>
            <span className="text-xs text-faint">
              Disabled devices are not polled — their historical data and last metrics stay preserved.
            </span>
          </div>

          <div className="col-span-full">
            <label className="mb-1 block text-sm font-medium text-secondary">Additional IPs (optional)</label>
            <div className="flex gap-2">
              <input
                className={`w-full rounded-md border px-3 py-2 text-sm ${ipError ? 'border-danger-border' : 'border-border'}`}
                value={newIpInput}
                onChange={(e) => { setNewIpInput(e.target.value); setIpError(null); }}
                onKeyDown={(e) => { if (e.key === 'Enter') { e.preventDefault(); addSecondaryIp(); } }}
                placeholder="10.0.0.2 or 2001:db8::1"
              />
              <button
                type="button"
                onClick={addSecondaryIp}
                className="rounded-md border border-border px-3 py-2 text-sm font-medium text-secondary hover:bg-background"
              >
                Add
              </button>
            </div>
            {ipError && <p className="mt-1 text-xs text-danger-fg">{ipError}</p>}
            {additionalIps.length > 0 && (
              <div className="mt-2 flex flex-wrap gap-1">
                {additionalIps.map((ip) => (
                  <span key={ip} className="inline-flex items-center gap-1 rounded-full bg-muted px-2 py-0.5 text-xs font-medium text-secondary">
                    {ip}
                    <button
                      type="button"
                      aria-label={`Remove ${ip}`}
                      onClick={() => setAdditionalIps(additionalIps.filter((x) => x !== ip))}
                      className="text-faint hover:text-danger-fg"
                    >
                      <X className="h-3 w-3" />
                    </button>
                  </span>
                ))}
              </div>
            )}
          </div>

          <div className="col-span-full">
            <label className="mb-1 block text-sm font-medium text-secondary">
              Plugins (each with its own credentials — the first becomes primary)
            </label>
            {/* No built-in submit button here — the single central Save bar at
                the bottom of this form owns submission for everything above. */}
            <PluginAssignmentBuilder
              ref={builderRef}
              plugins={pluginsQuery.data ?? []}
              secrets={secretsQuery.data ?? []}
              initial={editingId ? initialAssignments.map((a) => ({ pluginId: a.pluginId, secretId: a.secretId ?? null, isPrimary: a.isPrimary, extraCredentials: a.extraCredentials })) : undefined}
              onRowsChange={setSelectedPluginIds}
              showSubmitButton={false}
              onSubmit={(assignments) => {
                if (!identity.name.trim() || !identity.vendor || !identity.managementAddress.trim()) {
                  setFormError('Please fill in name, vendor and primary IP before saving.');
                  return;
                }
                if (!isValidAddress(identity.managementAddress)) {
                  setFormError(`Primary IP: ${addressError(identity.managementAddress)}`);
                  return;
                }
                handleSubmit(assignments);
              }}
            />
          </div>

          {/* Per-plugin parameters — editable in edit mode only. Collapsed by
              default so several assigned plugins don't overload the form; a
              "modified" dot marks sections holding unsaved override edits. The
              OptionForm stays MOUNTED (hidden) while collapsed so its state is
              preserved and the central Save can still flush pending edits. */}
          {editingId && initialAssignments.length > 0 && (
            <div className="col-span-full space-y-2">
              <h3 className="text-xs font-semibold uppercase tracking-wide text-faint">Plugin settings (per-device overrides)</h3>
              {initialAssignments.map((a) => {
                const expanded = expandedOptions.has(a.pluginId);
                return (
                  <div key={a.pluginId} className="rounded-md border border-border bg-card">
                    <div className="flex w-full items-center gap-2 px-3 py-2">
                      <button
                        type="button"
                        onClick={() => toggleOptionSection(a.pluginId)}
                        aria-expanded={expanded}
                        title={expanded ? 'Collapse' : 'Expand'}
                        className="flex flex-1 items-center gap-2 text-left hover:bg-muted/50 rounded-md px-1 py-0.5 -mx-1"
                      >
                        <ChevronDown className={`h-4 w-4 shrink-0 text-faint transition-transform ${expanded ? '' : '-rotate-90'}`} />
                        <span className="text-sm font-medium text-secondary">{a.pluginName ?? a.pluginId}</span>
                        {optionDirty[a.pluginId] && (
                          <span
                            title="Unsaved changes in this section"
                            className="h-2 w-2 shrink-0 rounded-full bg-status-warn"
                          />
                        )}
                      </button>
                      {expanded && (
                        <button
                          type="button"
                          onClick={() => optionRefs.current.get(a.pluginId)?.reset()}
                          className="shrink-0 text-xs font-medium text-faint hover:text-secondary"
                        >
                          Reset to inherited
                        </button>
                      )}
                    </div>
                    <div className={expanded ? 'border-t border-border px-3 pb-1 pt-2' : 'hidden'}>
                      <OptionForm
                        ref={(h) => { if (h) optionRefs.current.set(a.pluginId, h); else optionRefs.current.delete(a.pluginId); }}
                        pluginId={a.pluginId}
                        deviceId={editingId!}
                        hideFooter
                        onDirtyChange={(d) => setOptionDirty((m) => ({ ...m, [a.pluginId]: d }))}
                        onSaved={() => queryClient.invalidateQueries({ queryKey: ['devices'] })}
                      />
                    </div>
                  </div>
                );
              })}
            </div>
          )}

          {/* ONE central save bar for the whole form (identity + IPs + plugins
              + per-plugin overrides) — no other Save buttons on this page. */}
          <div className="col-span-full flex items-center justify-end gap-2 border-t border-border pt-3">
            <button
              type="button"
              onClick={resetForm}
              disabled={createDevice.isPending || updateDevice.isPending}
              className="rounded-md border border-border px-4 py-2 text-sm font-medium text-secondary hover:bg-background disabled:opacity-50"
            >
              Cancel
            </button>
            <button
              type="button"
              onClick={async () => {
                // Flush per-plugin override edits first (only sections that are
                // actually dirty — unmodified ones keep inheriting globally).
                const dirtyIds = Object.keys(optionDirty).filter((id) => optionDirty[id]);
                for (const id of dirtyIds) {
                  const ok = await optionRefs.current.get(id)?.save();
                  if (!ok) {
                    // Validation failed — expand the section so errors are visible.
                    setExpandedOptions(new Set([id]));
                    return;
                  }
                }
                builderRef.current?.submit();
              }}
              disabled={createDevice.isPending || updateDevice.isPending}
              className="flex items-center gap-1.5 rounded-md bg-primary px-4 py-2 text-sm font-semibold text-white hover:bg-primary-hover disabled:opacity-50"
            >
              <Save className="h-4 w-4" />
              {createDevice.isPending || updateDevice.isPending ? 'Saving…' : editingId ? 'Save Changes' : 'Create Device'}
            </button>
          </div>
        </div>
      )}

      {devicesQuery.isLoading && <p className="text-sm text-muted-foreground">Loading devices...</p>}
      {devicesQuery.isError && (
        <p className="text-sm text-danger-fg">Failed to load devices: {(devicesQuery.error as Error).message}</p>
      )}
      {devicesQuery.data && (
        <DataTable
          columns={columns}
          rows={devicesQuery.data}
          rowKey={(row) => row.id}
          storageKey="devices"
          autoRefresh={{ intervalMs: 30_000, queries: [devicesQuery] }}
          emptyMessage="No devices registered yet."
          selectable={canWriteDevices}
          bulkActions={canWriteDevices ? [
            {
              label: 'Disable selected',
              confirm: (count) =>
                `Stop polling ${count} device(s)?\nTheir historical data and last metrics are preserved — re-enable any time to resume polling.`,
              onClick: async (rows) => {
                const { errors } = await api.setDevicesEnabled(rows.map((r) => r.id), false);
                queryClient.invalidateQueries({ queryKey: ['devices'] });
                if (errors.length > 0) window.alert(`Some devices could not be disabled:\n${errors.join('\n')}`);
              },
            },
            {
              label: 'Enable selected',
              confirm: (count) => `Resume polling ${count} device(s)?`,
              onClick: async (rows) => {
                const { errors } = await api.setDevicesEnabled(rows.map((r) => r.id), true);
                queryClient.invalidateQueries({ queryKey: ['devices'] });
                if (errors.length > 0) window.alert(`Some devices could not be enabled:\n${errors.join('\n')}`);
              },
            },
            {
              label: 'Refresh selected',
              confirm: (count) =>
                `Force an immediate re-poll of ${count} device(s)?\nLive metrics AND inventory are refreshed now; the regular poll schedule is unaffected.`,
              onClick: async (rows) => {
                try {
                  const data = await refreshDevices.mutateAsync(rows.map((r) => r.id));
                  reportRefreshResults(data.results);
                } catch (err) {
                  window.alert(`Refresh failed: ${(err as Error).message}`);
                }
              },
            },
            {
              label: 'Delete selected',
              confirm: (count) =>
                `Delete ${count} device(s)?\nTheir plugin assignments, secondary IPs and telemetry history are removed. Devices referenced by plans cannot be deleted — delete those plans first.`,
              onClick: (rows) => bulkDeleteDevices.mutate(rows),
            },
          ] : undefined}
        />
      )}

    </Layout>
  );
}
