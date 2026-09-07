import { useEffect, useMemo, useRef, useState } from 'react';
import { AlertTriangle, Boxes, ChevronDown, CopyPlus, Container as ContainerIcon, FileCode2, Image as ImageIcon, Loader2, Plus, Search, X } from 'lucide-react';
import clsx from 'clsx';
import { SchemaForm, validateSchema } from './SchemaForm';
import { api, ContainerRow, InputSchema } from '../api/client';

/**
 * CreateAppDialog — creates a NEW app on one device. GENERIC by design: the set
 * of modes is derived from what the device's plugin ADVERTISES in its action
 * catalog (no per-backend UI code):
 *   - 'catalog'  → TrueNAS app store (catalog.templates.list + containers.install)
 *   - 'compose'  → custom compose stack (containers.install mode=custom on TrueNAS,
 *                  containers.deploy-compose via SSH on a Docker host)
 *   - 'image'    → single image run (containers.run-image — Engine API only, no SSH)
 *
 * Two SOURCES: "new" (blank) or "duplicate existing" — pick any app already on the
 * device and pre-fill from it. Prefill is generic too: TrueNAS custom apps hand
 * over their compose YAML; TrueNAS catalog apps re-open their template with saved
 * values merged in; Docker single-container apps prefill image + ports + volumes.
 * Submission flows through the page's plan workflow (2FA-gated, audited).
 */

/** One creation mode offered by a candidate device. */
export type AppMode = 'catalog' | 'compose' | 'image';

const MODE_META: Record<AppMode, { label: string; icon: typeof Boxes }> = {
  catalog: { label: 'App store', icon: Boxes },
  compose: { label: 'Compose stack', icon: FileCode2 },
  image: { label: 'Run image', icon: ImageIcon },
};

/** One device that can create apps, resolved from its plugin catalogs. */
export interface CreateAppCandidate {
  deviceId: string;
  deviceName: string;
  managementAddress?: string;
  pluginId: string;
  pluginName?: string;
  /** Available modes in display order (derived from the action catalog). */
  modes: AppMode[];
  /** The install action id per mode. */
  actions: Partial<Record<AppMode, string>>;
}

/** One catalog template as returned by `catalog.templates.list`. */
interface CatalogTemplate {
  name: string;
  title?: string;
  description?: string;
  iconUrl?: string;
  latestVersion?: string;
  categories?: string[];
  tags?: string[];
  recommended?: boolean;
}

/** One template's config schema as returned by `template.details.read`. */
interface TemplateDetails {
  fields: InputSchema;
  values: Record<string, unknown>;
  /** Section layout from the plugin (TrueNAS question groups). Optional — older plugins omit it. */
  groups?: { title: string; fields: string[] }[];
  title?: string;
  description?: string;
  humanVersion?: string;
}

interface PortMapping {
  hostPort: number | '';
  containerPort: number | '';
  protocol: 'tcp' | 'udp';
}

interface EnvEntry {
  key: string;
  value: string;
}

interface VolumeEntry {
  source: string;
  target: string;
  mode: 'ro' | 'rw';
}

type CatalogSort = 'recommended' | 'name';
/** Where the new app's config comes from. */
type SourceMode = 'new' | 'duplicate';

interface CreateAppDialogProps {
  candidates: CreateAppCandidate[];
  /** Inventory rows (all devices) — used to offer existing apps as clone sources. */
  apps?: ContainerRow[];
  /** Submits the install through the page's plan workflow (handles 2FA + tracking). */
  onSubmit: (candidate: CreateAppCandidate, mode: AppMode, input: Record<string, unknown>) => void;
  onClose: () => void;
}

/** Sanitizes a user-typed app name into TrueNAS/Docker slug form. */
function slugify(s: string): string {
  return s.toLowerCase().replace(/[^a-z0-9-]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 40);
}

export function CreateAppDialog({ candidates, apps = [], onSubmit, onClose }: CreateAppDialogProps) {
  const [deviceIdx, setDeviceIdx] = useState(() => Math.max(0, candidates.findIndex((c) => c.modes.includes('catalog'))));
  const candidate = candidates[deviceIdx];
  const modes = candidate?.modes ?? [];

  // Start on the first available mode; catalog is preferred when present.
  const [mode, setMode] = useState<AppMode>(() => (candidate?.modes.includes('catalog') ? 'catalog' : candidate?.modes[0] ?? 'compose'));

  // --- Source: new vs duplicate-existing ----------------------------------------
  const [sourceMode, setSourceMode] = useState<SourceMode>('new');
  /** Key of the chosen clone source app (`deviceId|name`), or null. */
  const [cloneAppKey, setCloneAppKey] = useState<string | null>(null);
  const [cloneNotice, setCloneNotice] = useState<string | null>(null);
  const [cloning, setCloning] = useState(false);
  /** Saved values to merge over a catalog template's defaults after it loads. */
  const clonePendingValues = useRef<{ name: string; values: Record<string, unknown> } | null>(null);

  // --- Catalog state -----------------------------------------------------------
  const [trains, setTrains] = useState<string[]>([]);
  const [train, setTrain] = useState('stable');
  const [templates, setTemplates] = useState<CatalogTemplate[] | null>(null);
  const [catalogError, setCatalogError] = useState<string | null>(null);
  const [search, setSearch] = useState('');
  const [category, setCategory] = useState<string | null>(null);
  const [sortMode, setSortMode] = useState<CatalogSort>('recommended');
  const [selectedTpl, setSelectedTpl] = useState<string | null>(null);
  const [details, setDetails] = useState<TemplateDetails | null>(null);
  const [detailsLoading, setDetailsLoading] = useState(false);

  // --- Config-form state (grouped sections) -------------------------------------
  /** Section titles open by default — required/first sections stay visible. */
  const [openSections, setOpenSections] = useState<Record<string, boolean>>({});
  const [formSearch, setFormSearch] = useState('');

  // --- Compose state -------------------------------------------------------------
  const [composeString, setComposeString] = useState('');

  // --- Image-run state ------------------------------------------------------------
  const [imageRef, setImageRef] = useState('');
  const [ports, setPorts] = useState<PortMapping[]>([]);
  const [envs, setEnvs] = useState<EnvEntry[]>([]);
  const [volumes, setVolumes] = useState<VolumeEntry[]>([]);
  const [network, setNetwork] = useState('');

  // --- Shared form state -----------------------------------------------------------
  const [name, setName] = useState('');
  const [formValues, setFormValues] = useState<Record<string, unknown>>({});
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({});
  const [submitError, setSubmitError] = useState<string | null>(null);
  const [pending, setPending] = useState(false);

  // Apps on the selected device — clone sources.
  const deviceApps = useMemo(
    () => (candidate ? apps.filter((a) => a.deviceId === candidate.deviceId).sort((x, y) => x.name.localeCompare(y.name)) : []),
    [apps, candidate?.deviceId],
  );

  // Reset device-dependent state when the selected device changes.
  useEffect(() => {
    setSelectedTpl(null);
    setDetails(null);
    setName('');
    setFormValues({});
    setFieldErrors({});
    setSubmitError(null);
    setCloneAppKey(null);
    setCloneNotice(null);
    clonePendingValues.current = null;
    const c = candidates[deviceIdx];
    if (c) setMode(c.modes.includes('catalog') ? 'catalog' : c.modes[0] ?? 'compose');
  }, [deviceIdx, candidates]);

  // Load the template gallery for the selected device + train.
  useEffect(() => {
    let cancelled = false;
    if (mode !== 'catalog' || !candidate) return;
    setTemplates(null);
    setCatalogError(null);
    (async () => {
      try {
        const res = await api.executePluginAction(candidate.pluginId, {
          deviceId: candidate.deviceId,
          actionId: 'catalog.templates.list',
          input: { train },
        });
        if (cancelled) return;
        const t = res.details?.['templates'];
        setTemplates(Array.isArray(t) ? (t as CatalogTemplate[]) : []);
        const tr = res.details?.['trains'];
        if (Array.isArray(tr)) setTrains(tr.filter((x): x is string => typeof x === 'string'));
      } catch (err) {
        if (!cancelled) setCatalogError(err instanceof Error ? err.message : String(err));
      }
    })();
    return () => { cancelled = true; };
  }, [candidate?.deviceId, candidate?.pluginId, train, mode]);

  // Load the selected template's config schema + defaults.
  useEffect(() => {
    let cancelled = false;
    if (mode !== 'catalog' || !selectedTpl || !candidate) return;
    setDetailsLoading(true);
    (async () => {
      try {
        const res = await api.executePluginAction(candidate.pluginId, {
          deviceId: candidate.deviceId,
          actionId: 'template.details.read',
          input: { name: selectedTpl, train },
        });
        if (cancelled) return;
        const fields = (res.details?.['fields'] ?? {}) as InputSchema;
        const values = (res.details?.['values'] ?? {}) as Record<string, unknown>;
        const groups = res.details?.['groups'];
        setDetails({
          fields,
          values,
          groups: Array.isArray(groups) ? (groups as TemplateDetails['groups']) : undefined,
          title: typeof res.details?.['title'] === 'string' ? (res.details['title'] as string) : undefined,
          description: typeof res.details?.['description'] === 'string' ? (res.details['description'] as string) : undefined,
          humanVersion: typeof res.details?.['humanVersion'] === 'string' ? (res.details['humanVersion'] as string) : undefined,
        });
        // Pre-fill with the appliance's own defaults — the source of truth.
        setFormValues(values);
        // Clone flow: merge the SAVED values of the duplicated app over the
        // template defaults so only what changed differs from the original.
        const cp = clonePendingValues.current;
        if (cp && cp.name === selectedTpl) {
          setFormValues({ ...values, ...cp.values });
          clonePendingValues.current = null;
        }
      } catch (err) {
        if (!cancelled) setSubmitError(err instanceof Error ? err.message : String(err));
      } finally {
        if (!cancelled) setDetailsLoading(false);
      }
    })();
    return () => { cancelled = true; };
  }, [selectedTpl, train, mode, candidate?.deviceId, candidate?.pluginId]);

  // Section open/close defaults: sections with required fields (and the first
  // section) start expanded; everything else collapsed. Recomputed per template.
  useEffect(() => {
    if (!details) return;
    const layout = formLayout(details);
    const init: Record<string, boolean> = {};
    layout.forEach((sec, i) => {
      const hasRequired = sec.fields.some((k) => details!.fields[k]?.required === true);
      init[sec.title] = hasRequired || i === 0;
    });
    setOpenSections(init);
    setFormSearch('');
  }, [details]);

  // --- Duplicate/clone prefill -----------------------------------------------------
  // When a clone source app is chosen, read its config and pre-fill the matching
  // mode. TrueNAS custom → compose YAML; TrueNAS catalog → re-open template with
  // saved values; Docker single-container → image + ports + volumes.
  useEffect(() => {
    let cancelled = false;
    if (sourceMode !== 'duplicate' || !cloneAppKey || !candidate) return;
    const app = deviceApps.find((a) => `${a.deviceId}|${a.name}` === cloneAppKey);
    if (!app) return;

    setCloning(true);
    setCloneNotice(null);
    (async () => {
      try {
        // Docker host — no compose-YAML access over the Engine API. Single-container
        // apps prefill from inventory data; multi-service projects can't be cloned.
        if (!candidate.modes.includes('catalog')) {
          const count = Number((app.extra?.['containerCount'] as unknown) ?? 1);
          if (count > 1) {
            setCloneNotice(
              `“${app.name}” is a multi-container compose project — its YAML isn't exposed over the Docker Engine API, so it can't be cloned here. Copy its compose file from the host instead.`,
            );
            return;
          }
          // Single container → prefill the Run-image tab from inventory data.
          if (!candidate.modes.includes('image')) {
            setCloneNotice(`“${app.name}” can't be cloned here — this device's plugin doesn't offer a run-image action.`);
            return;
          }
          setMode('image');
          if (app.image) setImageRef(app.image);
          const pm = app.extra?.['portMappings'];
          if (Array.isArray(pm)) {
            setPorts((pm as Record<string, unknown>[]).map((p) => ({ hostPort: Number(p.hostPort), containerPort: Number(p.containerPort), protocol: p.protocol === 'udp' ? 'udp' : 'tcp' })));
          } else {
            setPorts([]);
          }
          const vm = app.extra?.['volumeMounts'];
          if (Array.isArray(vm)) {
            setVolumes((vm as Record<string, unknown>[]).map((v) => ({ source: String(v.source ?? ''), target: typeof v.target === 'string' ? v.target : '', mode: v.mode === 'ro' ? 'ro' : 'rw' })));
          } else {
            setVolumes([]);
          }
          setEnvs([]); // env isn't carried in inventory rows — left blank on purpose
          setNetwork('');
          return;
        }

        // TrueNAS — read the app's config (custom YAML or catalog identity+values).
        const res = await api.executePluginAction(candidate.pluginId, {
          deviceId: candidate.deviceId,
          actionId: 'compose.config.read',
          input: { name: app.name },
        });
        if (cancelled) return;
        const d = res.details ?? {};
        const isCatalog = d['customApp'] === false || typeof d['catalogApp'] === 'string';
        if (isCatalog && typeof d['catalogApp'] === 'string') {
          // Catalog app → re-open its template, merge saved values over defaults.
          clonePendingValues.current = { name: d['catalogApp'], values: (d['values'] as Record<string, unknown>) ?? {} };
          if (typeof d['train'] === 'string' && d['train']) setTrain(d['train']);
          setSelectedTpl(d['catalogApp']); // triggers the details-load effect above
        } else {
          // Custom app → hand over its compose YAML.
          const yaml = typeof d['yaml'] === 'string' ? (d['yaml'] as string) : '';
          if (!yaml.trim()) {
            setCloneNotice(`No editable config found for “${app.name}”.`);
            return;
          }
          setMode('compose');
          setComposeString(yaml);
        }
      } catch (err) {
        if (!cancelled) setCloneNotice(err instanceof Error ? err.message : String(err));
      } finally {
        if (!cancelled) setCloning(false);
      }
    })();
    return () => { cancelled = true; };
  }, [sourceMode, cloneAppKey, candidate?.deviceId, deviceApps]);

  // --- Catalog filtering + sorting -------------------------------------------------
  const categories = useMemo(() => {
    if (!templates) return [];
    const counts = new Map<string, number>();
    for (const t of templates) for (const c of t.categories ?? []) counts.set(c, (counts.get(c) ?? 0) + 1);
    return [...counts.entries()].sort((a, b) => a[0].localeCompare(b[0]));
  }, [templates]);

  const visibleTemplates = useMemo(() => {
    if (!templates) return null;
    let out = templates;
    if (category) out = out.filter((t) => (t.categories ?? []).includes(category));
    const q = search.trim().toLowerCase();
    if (q) {
      out = out.filter(
        (t) =>
          t.name.toLowerCase().includes(q) ||
          (t.title ?? '').toLowerCase().includes(q) ||
          (t.description ?? '').toLowerCase().includes(q) ||
          (t.categories ?? []).some((c) => c.toLowerCase().includes(q)) ||
          (t.tags ?? []).some((tag) => tag.toLowerCase().includes(q)),
      );
    }
    const sorted = [...out];
    if (sortMode === 'name') {
      sorted.sort((a, b) => (a.title ?? a.name).localeCompare(b.title ?? b.name));
    } else {
      // Recommended first, then alphabetical — keeps the gallery stable.
      sorted.sort((a, b) => Number(b.recommended === true) - Number(a.recommended === true) || (a.title ?? a.name).localeCompare(b.title ?? b.name));
    }
    return sorted;
  }, [templates, category, search, sortMode]);

  function selectTemplate(t: CatalogTemplate) {
    setSelectedTpl(t.name);
    setName(slugify(t.title?.replace(/[^a-z0-9]+/gi, ' ') || t.name));
  }

  /** Switching source mode resets the prefilled config so nothing leaks across. */
  function changeSourceMode(next: SourceMode) {
    setSourceMode(next);
    setCloneAppKey(null);
    setCloneNotice(null);
    clonePendingValues.current = null;
    if (next === 'new') {
      setSelectedTpl(null);
      setDetails(null);
      setFormValues({});
      setComposeString('');
      setImageRef('');
      setPorts([]);
      setEnvs([]);
      setVolumes([]);
      setNetwork('');
    }
  }

  async function handleSubmit() {
    if (!candidate) return;
    setSubmitError(null);
    const slug = slugify(name);
    if (slug === '') {
      setSubmitError('App name is required.');
      return;
    }
    let input: Record<string, unknown>;
    if (mode === 'catalog') {
      if (!selectedTpl) {
        setSubmitError('Pick a template from the gallery first.');
        return;
      }
      const errors = validateSchema(details?.fields ?? {}, formValues);
      if (Object.keys(errors).length > 0) {
        setFieldErrors(errors);
        // Expand every section that has an error so it's visible.
        setOpenSections((prev) => {
          const next = { ...prev };
          for (const sec of formLayout(details ?? { fields: {}, values: {} })) {
            if (sec.fields.some((k) => errors[k])) next[sec.title] = true;
          }
          return next;
        });
        return;
      }
      input = { name: slug, mode: 'catalog', catalogApp: selectedTpl, train, config: formValues };
    } else if (mode === 'compose') {
      if (composeString.trim() === '') {
        setSubmitError('Compose YAML is required.');
        return;
      }
      // TrueNAS containers.install takes mode=custom + composeString; the Docker
      // plugin's deploy-compose takes name + composeString directly.
      const actionId = candidate.actions['compose'];
      input = actionId === 'containers.deploy-compose' ? { name: slug, composeString } : { name: slug, mode: 'custom', composeString };
    } else {
      // image mode
      if (imageRef.trim() === '') {
        setSubmitError('Image reference is required.');
        return;
      }
      const portList = ports
        .filter((p) => p.hostPort !== '' && p.containerPort !== '')
        .map((p) => ({ hostPort: Number(p.hostPort), containerPort: Number(p.containerPort), protocol: p.protocol }));
      const envObj: Record<string, string> = {};
      for (const e of envs) if (e.key.trim() !== '') envObj[e.key.trim()] = e.value;
      const volList = volumes
        .filter((v) => v.source.trim() !== '')
        .map((v) => ({ source: v.source.trim(), ...(v.target.trim() ? { target: v.target.trim() } : {}), mode: v.mode }));
      input = {
        name: slug,
        image: imageRef.trim(),
        ...(portList.length > 0 ? { ports: portList } : {}),
        ...(Object.keys(envObj).length > 0 ? { env: envObj } : {}),
        ...(volList.length > 0 ? { volumes: volList } : {}),
        ...(network.trim() !== '' ? { network: network.trim() } : {}),
      };
    }
    setPending(true);
    try {
      // The page creates + executes the plan (2FA-gated). A 401 is swallowed by
      // the page (it opens its reauth flow and retries) — so resolution means
      // "done or handed off", rejection means a real error to show here.
      await onSubmit(candidate, mode, input);
      onClose();
    } catch (err) {
      setSubmitError(err instanceof Error ? err.message : String(err));
      setPending(false);
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto bg-primary/40 p-6" onClick={onClose}>
      {/* Flex column: fixed header + scrollable body + fixed footer, so long
          config forms never push the action buttons off-screen. */}
      <div className="mt-8 flex max-h-[calc(100vh-4rem)] w-full max-w-2xl flex-col rounded-md border border-border bg-card shadow-xl" onClick={(e) => e.stopPropagation()}>
        <header className="flex items-center justify-between border-b border-border px-4 py-3">
          <div>
            <h2 className="text-base font-semibold text-foreground">Create app</h2>
            <p className="mt-0.5 text-xs text-muted-foreground">
              Installs a new app on the selected device — runs through the plan workflow (2FA-gated).
            </p>
          </div>
          <button type="button" aria-label="Close dialog" onClick={onClose} className="rounded p-1 text-faint hover:bg-muted">
            <X className="h-4 w-4" />
          </button>
        </header>

        <div className="min-h-0 flex-1 space-y-3 overflow-y-auto p-4">
          {/* Device picker — only devices whose plugin advertises an install action. */}
          {candidates.length > 1 && (
            <label className="block text-sm font-medium text-secondary">
              Target device
              <select
                value={deviceIdx}
                onChange={(e) => setDeviceIdx(Number(e.target.value))}
                className="mt-1 w-full rounded-md border border-border bg-background px-2.5 py-1.5 text-sm focus:border-slate-400"
              >
                {candidates.map((c, i) => (
                  <option key={`${c.deviceId}|${c.pluginId}`} value={i}>
                    {c.deviceName} ({c.managementAddress ?? '?'}) — {c.modes.map((m) => MODE_META[m].label).join(' / ')}
                  </option>
                ))}
              </select>
            </label>
          )}

          {/* Source: start blank or duplicate an existing app on this device. */}
          <div className="space-y-2">
            <div className="flex gap-1 rounded-md border border-border bg-background p-0.5 text-sm">
              {(['new', 'duplicate'] as const).map((sm) => (
                <button
                  key={sm}
                  type="button"
                  onClick={() => changeSourceMode(sm)}
                  className={clsx(
                    'flex flex-1 items-center justify-center gap-1.5 rounded px-3 py-1.5 font-medium',
                    sourceMode === sm ? 'bg-card text-foreground shadow-sm' : 'text-muted-foreground hover:text-secondary',
                  )}
                >
                  {sm === 'new' ? <Plus size={14} /> : <CopyPlus size={14} />}
                  {sm === 'new' ? 'New app' : 'Duplicate existing'}
                </button>
              ))}
            </div>

            {sourceMode === 'duplicate' && (
              deviceApps.length > 0 ? (
                <label className="block text-sm font-medium text-secondary">
                  Use as template
                  <select
                    value={cloneAppKey ?? ''}
                    onChange={(e) => setCloneAppKey(e.target.value || null)}
                    className="mt-1 w-full rounded-md border border-border bg-background px-2.5 py-1.5 text-sm focus:border-slate-400"
                  >
                    <option value="">— pick an app on this device —</option>
                    {deviceApps.map((a) => (
                      <option key={`${a.deviceId}|${a.name}`} value={`${a.deviceId}|${a.name}`}>
                        {a.name} ({a.state.toLowerCase()}){typeof a.extra?.['containerCount'] === 'number' && Number(a.extra['containerCount']) > 1 ? ` · ${Number(a.extra['containerCount'])} containers` : ''}
                      </option>
                    ))}
                  </select>
                </label>
              ) : (
                <p className="rounded-md border border-border bg-background/60 px-3 py-2 text-xs text-muted-foreground">
                  No apps are reported on this device yet — nothing to duplicate.
                </p>
              )
            )}

            {cloning && (
              <p className="flex items-center gap-2 text-xs text-muted-foreground">
                <Loader2 size={13} className="animate-spin" /> Reading the selected app's configuration…
              </p>
            )}
            {cloneNotice && !cloning && (
              <p className="flex items-start gap-2 rounded-md border border-border bg-background/60 px-3 py-2 text-xs text-muted-foreground">
                <AlertTriangle size={14} className="mt-0.5 shrink-0" /> {cloneNotice}
              </p>
            )}
          </div>

          {/* Mode tabs — exactly the modes this device's plugin advertises. */}
          {modes.length > 1 && (
            <div className="flex gap-1 rounded-md border border-border bg-background p-0.5 text-sm">
              {modes.map((m) => {
                const Icon = MODE_META[m].icon;
                return (
                  <button
                    key={m}
                    type="button"
                    onClick={() => setMode(m)}
                    className={clsx(
                      'flex flex-1 items-center justify-center gap-1.5 rounded px-3 py-1.5 font-medium',
                      mode === m ? 'bg-card text-foreground shadow-sm' : 'text-muted-foreground hover:text-secondary',
                    )}
                  >
                    <Icon size={14} />
                    {MODE_META[m].label}
                  </button>
                );
              })}
            </div>
          )}

          {/* App name — shared by all modes. */}
          <label className="block text-sm font-medium text-secondary">
            App name
            <input
              type="text"
              value={name}
              onChange={(e) => setName(slugify(e.target.value))}
              placeholder="lowercase-slug (enforced by the backend)"
              className="mt-1 w-full rounded-md border border-border bg-background px-2.5 py-1.5 font-mono text-sm focus:border-slate-400"
            />
          </label>

          {mode === 'catalog' && candidate ? (
            <div className="space-y-3">
              {/* Train selector + search + sort */}
              <div className="flex items-center gap-2">
                {trains.length > 1 && (
                  <select
                    value={train}
                    onChange={(e) => setTrain(e.target.value)}
                    aria-label="Catalog train"
                    className="rounded-md border border-border bg-background px-2 py-1.5 text-xs focus:border-slate-400"
                  >
                    {trains.map((t) => <option key={t} value={t}>{t}</option>)}
                  </select>
                )}
                <div className="relative flex-1">
                  <Search size={13} className="pointer-events-none absolute left-2 top-1/2 -translate-y-1/2 text-faint" />
                  <input
                    type="text"
                    value={search}
                    onChange={(e) => setSearch(e.target.value)}
                    placeholder="Search templates by name, description or tag…"
                    className="w-full rounded-md border border-border bg-background py-1.5 pl-7 pr-2 text-sm focus:border-slate-400"
                  />
                </div>
                <select
                  value={sortMode}
                  onChange={(e) => setSortMode(e.target.value as CatalogSort)}
                  aria-label="Sort templates"
                  className="rounded-md border border-border bg-background px-2 py-1.5 text-xs focus:border-slate-400"
                >
                  <option value="recommended">Recommended</option>
                  <option value="name">Name A–Z</option>
                </select>
              </div>

              {/* Category filter chips */}
              {categories.length > 1 && (
                <div className="-mx-1 flex gap-1 overflow-x-auto px-1 pb-0.5 text-xs">
                  <button
                    type="button"
                    onClick={() => setCategory(null)}
                    className={clsx(
                      'shrink-0 rounded-full border px-2.5 py-1 font-medium',
                      category === null ? 'border-info bg-info/40 text-secondary' : 'border-border text-muted-foreground hover:text-secondary',
                    )}
                  >
                    All ({templates?.length ?? 0})
                  </button>
                  {categories.map(([c, n]) => (
                    <button
                      key={c}
                      type="button"
                      onClick={() => setCategory(category === c ? null : c)}
                      className={clsx(
                        'shrink-0 rounded-full border px-2.5 py-1 font-medium',
                        category === c ? 'border-info bg-info/40 text-secondary' : 'border-border text-muted-foreground hover:text-secondary',
                      )}
                    >
                      {c} ({n})
                    </button>
                  ))}
                </div>
              )}

              {/* Template gallery */}
              {catalogError && (
                <p className="rounded-md border border-danger-border bg-danger px-3 py-2 text-xs text-danger-fg">{catalogError}</p>
              )}
              {!templates && !catalogError && (
                <p className="flex items-center gap-2 py-6 text-sm text-muted-foreground">
                  <Loader2 size={14} className="animate-spin" /> Loading templates…
                </p>
              )}
              {templates && visibleTemplates && visibleTemplates.length === 0 && (
                <p className="py-6 text-center text-sm text-muted-foreground">No templates match your filters.</p>
              )}
              {visibleTemplates && visibleTemplates.length > 0 && (
                <>
                  <p className="text-[11px] text-faint">{visibleTemplates.length} of {templates?.length ?? 0} templates</p>
                  <div className="grid max-h-64 grid-cols-1 gap-1.5 overflow-y-auto pr-1 sm:grid-cols-2">
                    {visibleTemplates.map((t) => (
                      <button
                        key={t.name}
                        type="button"
                        onClick={() => selectTemplate(t)}
                        className={clsx(
                          'flex items-start gap-2 rounded-md border px-2.5 py-2 text-left',
                          selectedTpl === t.name ? 'border-info bg-info/40' : 'border-border hover:bg-background',
                        )}
                      >
                        {t.iconUrl ? (
                          <img src={t.iconUrl} alt="" className="mt-0.5 h-6 w-6 shrink-0 rounded object-contain" onError={(e) => { (e.target as HTMLImageElement).style.display = 'none'; }} />
                        ) : (
                          <Boxes size={18} className="mt-0.5 shrink-0 text-faint" />
                        )}
                        <span className="min-w-0 flex-1">
                          <span className="flex items-baseline gap-1.5">
                            <span className="truncate text-sm font-medium text-secondary">{t.title || t.name}</span>
                            {t.latestVersion && (
                              <span className="shrink-0 font-mono text-[10px] text-faint">v{t.latestVersion}</span>
                            )}
                          </span>
                          {t.description ? (
                            <span className="mt-0.5 line-clamp-2 block text-xs leading-snug text-muted-foreground">{t.description}</span>
                          ) : null}
                        </span>
                      </button>
                    ))}
                  </div>
                </>
              )}

              {/* Selected template's config form — grouped, collapsible sections */}
              {selectedTpl && detailsLoading && (
                <p className="flex items-center gap-2 text-sm text-muted-foreground">
                  <Loader2 size={14} className="animate-spin" /> Loading configuration…
                </p>
              )}
              {selectedTpl && !detailsLoading && details && (
                <ConfigForm
                  details={details}
                  values={formValues}
                  onChange={(v) => setFormValues(v)}
                  fieldErrors={fieldErrors}
                  openSections={openSections}
                  onToggleSection={(title, open) => setOpenSections((prev) => ({ ...prev, [title]: open }))}
                  formSearch={formSearch}
                  onFormSearch={setFormSearch}
                />
              )}
            </div>
          ) : mode === 'compose' ? (
            /* Compose stack tab */
            <label className="block text-sm font-medium text-secondary">
              Docker Compose YAML
              <textarea
                value={composeString}
                onChange={(e) => setComposeString(e.target.value)}
                rows={12}
                spellCheck={false}
                placeholder={'services:\n  my-service:\n    image: nginx:latest\n    ports:\n      - "8080:80"'}
                className="mt-1 w-full rounded-md border border-border bg-background px-2.5 py-1.5 font-mono text-xs focus:border-slate-400"
              />
            </label>
          ) : (
            /* Run-image tab — Engine API only, no SSH needed */
            <div className="space-y-3">
              <label className="block text-sm font-medium text-secondary">
                Image reference
                <input
                  type="text"
                  value={imageRef}
                  onChange={(e) => setImageRef(e.target.value)}
                  placeholder="nginx:latest  ·  ghcr.io/org/app:v1.2.3"
                  className="mt-1 w-full rounded-md border border-border bg-background px-2.5 py-1.5 font-mono text-sm focus:border-slate-400"
                />
              </label>

              {/* Port mappings */}
              <div>
                <div className="mb-1 flex items-center justify-between">
                  <span className="text-sm font-medium text-secondary">Port mappings</span>
                  <button type="button" onClick={() => setPorts((p) => [...p, { hostPort: '', containerPort: '', protocol: 'tcp' }])} className="inline-flex items-center gap-1 text-xs font-medium text-muted-foreground hover:text-secondary">
                    <Plus size={12} /> Add port
                  </button>
                </div>
                {ports.length === 0 && <p className="text-xs text-faint">No ports exposed (optional).</p>}
                <div className="space-y-1.5">
                  {ports.map((p, i) => (
                    <div key={i} className="flex items-center gap-2">
                      <input type="number" min={1} max={65535} value={String(p.hostPort)} placeholder="host"
                        onChange={(e) => setPorts((prev) => prev.map((x, j) => (j === i ? { ...x, hostPort: e.target.value === '' ? '' : Number(e.target.value) } : x)))}
                        className="w-24 rounded-md border border-border bg-background px-2 py-1 font-mono text-xs focus:border-slate-400" />
                      <span className="text-faint">→</span>
                      <input type="number" min={1} max={65535} value={String(p.containerPort)} placeholder="container"
                        onChange={(e) => setPorts((prev) => prev.map((x, j) => (j === i ? { ...x, containerPort: e.target.value === '' ? '' : Number(e.target.value) } : x)))}
                        className="w-24 rounded-md border border-border bg-background px-2 py-1 font-mono text-xs focus:border-slate-400" />
                      <select value={p.protocol} onChange={(e) => setPorts((prev) => prev.map((x, j) => (j === i ? { ...x, protocol: e.target.value as 'tcp' | 'udp' } : x)))}
                        className="rounded-md border border-border bg-background px-1.5 py-1 text-xs focus:border-slate-400">
                        <option value="tcp">tcp</option>
                        <option value="udp">udp</option>
                      </select>
                      <button type="button" aria-label="Remove port mapping" onClick={() => setPorts((prev) => prev.filter((_, j) => j !== i))} className="rounded px-1.5 py-0.5 text-xs text-faint hover:bg-danger hover:text-danger-fg">✕</button>
                    </div>
                  ))}
                </div>
              </div>

              {/* Volume mounts */}
              <div>
                <div className="mb-1 flex items-center justify-between">
                  <span className="text-sm font-medium text-secondary">Volume mounts</span>
                  <button type="button" onClick={() => setVolumes((v) => [...v, { source: '', target: '', mode: 'rw' }])} className="inline-flex items-center gap-1 text-xs font-medium text-muted-foreground hover:text-secondary">
                    <Plus size={12} /> Add mount
                  </button>
                </div>
                {volumes.length === 0 && <p className="text-xs text-faint">No volume mounts (optional). Host path or named volume → container path.</p>}
                <div className="space-y-1.5">
                  {volumes.map((v, i) => (
                    <div key={i} className="flex items-center gap-2">
                      <input type="text" value={v.source} placeholder="/host/path or volname"
                        onChange={(e) => setVolumes((prev) => prev.map((x, j) => (j === i ? { ...x, source: e.target.value } : x)))}
                        className="w-40 rounded-md border border-border bg-background px-2 py-1 font-mono text-xs focus:border-slate-400" />
                      <span className="text-faint">→</span>
                      <input type="text" value={v.target} placeholder="/container/path (default: same)"
                        onChange={(e) => setVolumes((prev) => prev.map((x, j) => (j === i ? { ...x, target: e.target.value } : x)))}
                        className="flex-1 rounded-md border border-border bg-background px-2 py-1 font-mono text-xs focus:border-slate-400" />
                      <select value={v.mode} onChange={(e) => setVolumes((prev) => prev.map((x, j) => (j === i ? { ...x, mode: e.target.value as 'ro' | 'rw' } : x)))}
                        className="rounded-md border border-border bg-background px-1.5 py-1 text-xs focus:border-slate-400">
                        <option value="rw">rw</option>
                        <option value="ro">ro</option>
                      </select>
                      <button type="button" aria-label="Remove volume mount" onClick={() => setVolumes((prev) => prev.filter((_, j) => j !== i))} className="rounded px-1.5 py-0.5 text-xs text-faint hover:bg-danger hover:text-danger-fg">✕</button>
                    </div>
                  ))}
                </div>
              </div>

              {/* Environment variables */}
              <div>
                <div className="mb-1 flex items-center justify-between">
                  <span className="text-sm font-medium text-secondary">Environment variables</span>
                  <button type="button" onClick={() => setEnvs((e) => [...e, { key: '', value: '' }])} className="inline-flex items-center gap-1 text-xs font-medium text-muted-foreground hover:text-secondary">
                    <Plus size={12} /> Add variable
                  </button>
                </div>
                {envs.length === 0 && <p className="text-xs text-faint">No environment variables (optional).</p>}
                <div className="space-y-1.5">
                  {envs.map((e, i) => (
                    <div key={i} className="flex items-center gap-2">
                      <input type="text" value={e.key} placeholder="KEY"
                        onChange={(ev) => setEnvs((prev) => prev.map((x, j) => (j === i ? { ...x, key: ev.target.value } : x)))}
                        className="w-40 rounded-md border border-border bg-background px-2 py-1 font-mono text-xs focus:border-slate-400" />
                      <input type="text" value={e.value} placeholder="value"
                        onChange={(ev) => setEnvs((prev) => prev.map((x, j) => (j === i ? { ...x, value: ev.target.value } : x)))}
                        className="flex-1 rounded-md border border-border bg-background px-2 py-1 font-mono text-xs focus:border-slate-400" />
                      <button type="button" aria-label="Remove variable" onClick={() => setEnvs((prev) => prev.filter((_, j) => j !== i))} className="rounded px-1.5 py-0.5 text-xs text-faint hover:bg-danger hover:text-danger-fg">✕</button>
                    </div>
                  ))}
                </div>
              </div>

              {/* Network */}
              <label className="block text-sm font-medium text-secondary">
                Network
                <input
                  type="text"
                  value={network}
                  onChange={(e) => setNetwork(e.target.value)}
                  placeholder="default (bridge) — or a custom docker network name"
                  className="mt-1 w-full rounded-md border border-border bg-background px-2.5 py-1.5 font-mono text-sm focus:border-slate-400"
                />
              </label>

              <p className="flex items-center gap-1.5 rounded-md border border-border bg-background/60 px-3 py-2 text-xs text-muted-foreground">
                <ContainerIcon size={13} className="shrink-0" />
                Runs as a standalone container (docker run equivalent) — no SSH needed, works over the Docker socket / TCP.
              </p>
            </div>
          )}

          {submitError && (
            <p className="flex items-start gap-2 rounded-md border border-danger-border bg-danger px-3 py-2 text-xs text-danger-fg">
              <AlertTriangle size={14} className="mt-0.5 shrink-0" /> {submitError}
            </p>
          )}
        </div>

        {/* Fixed footer — always visible, even for long config forms. */}
        <footer className="flex items-center justify-end gap-2 border-t border-border px-4 py-3">
          <button type="button" onClick={onClose} className="rounded-md px-3 py-1.5 text-sm font-medium text-muted-foreground hover:bg-muted">
            Cancel
          </button>
          <button
            type="button"
            disabled={pending || !candidate}
            onClick={() => void handleSubmit()}
            className="inline-flex items-center gap-2 rounded-md bg-primary px-4 py-1.5 text-sm font-medium text-primary-fg hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-50"
          >
            {pending && <Loader2 size={14} className="animate-spin" />}
            Create app
          </button>
        </footer>
      </div>
    </div>
  );
}

/** Resolves the section layout for a template's form — plugin-provided groups,
 *  or one flat "Configuration" section when the plugin didn't send any. */
function formLayout(details: TemplateDetails): { title: string; fields: string[] }[] {
  const allKeys = Object.keys(details.fields);
  if (details.groups && details.groups.length > 0) {
    // Keep only keys that still exist in the schema; append any ungrouped strays.
    const seen = new Set<string>();
    const out: { title: string; fields: string[] }[] = [];
    for (const g of details.groups) {
      const fs = g.fields.filter((k) => details.fields[k] && !seen.has(k));
      if (fs.length === 0) continue;
      for (const k of fs) seen.add(k);
      out.push({ title: g.title, fields: fs });
    }
    const strays = allKeys.filter((k) => !seen.has(k));
    if (strays.length > 0) out.push({ title: 'Other', fields: strays });
    return out;
  }
  return [{ title: 'Configuration', fields: allKeys }];
}

/** The grouped, collapsible config form for a selected catalog template. */
function ConfigForm({
  details,
  values,
  onChange,
  fieldErrors,
  openSections,
  onToggleSection,
  formSearch,
  onFormSearch,
}: {
  details: TemplateDetails;
  values: Record<string, unknown>;
  onChange: (v: Record<string, unknown>) => void;
  fieldErrors: Record<string, string>;
  openSections: Record<string, boolean>;
  onToggleSection: (title: string, open: boolean) => void;
  formSearch: string;
  onFormSearch: (s: string) => void;
}) {
  const layout = formLayout(details);
  const q = formSearch.trim().toLowerCase();

  /** Fields of a section after applying the in-form search. */
  function visibleFields(section: { title: string; fields: string[] }): string[] {
    if (!q) return section.fields;
    return section.fields.filter((k) => {
      const prop = details.fields[k];
      const label = String(prop?.label ?? k).toLowerCase();
      return label.includes(q) || k.toLowerCase().includes(q);
    });
  }

  const totalVisible = layout.reduce((n, s) => n + visibleFields(s).length, 0);

  return (
    <div className="space-y-2 rounded-md border border-border bg-background/50 p-3">
      {/* Template context */}
      {(details.title || details.description) && (
        <p className="text-xs text-muted-foreground">
          {details.title ? <span className="font-medium text-secondary">{details.title}</span> : null}
          {details.humanVersion ? <span className="ml-1.5 font-mono text-[10px] text-faint">v{details.humanVersion}</span> : null}
          {details.description ? <span className="mt-0.5 block leading-snug">{details.description}</span> : null}
        </p>
      )}

      {/* In-form field search — useful when a template has 30+ questions */}
      {layout.length > 1 && (
        <div className="relative">
          <Search size={12} className="pointer-events-none absolute left-2 top-1/2 -translate-y-1/2 text-faint" />
          <input
            type="text"
            value={formSearch}
            onChange={(e) => onFormSearch(e.target.value)}
            placeholder={`Find a setting… (${layout.reduce((n, s) => n + s.fields.length, 0)} fields)`}
            className="w-full rounded-md border border-border bg-background py-1 pl-6 pr-2 text-xs focus:border-slate-400"
          />
        </div>
      )}

      {q && totalVisible === 0 && (
        <p className="py-2 text-center text-xs text-muted-foreground">No settings match “{formSearch.trim()}”.</p>
      )}

      {layout.map((section) => {
        const fields = visibleFields(section);
        if (q && fields.length === 0) return null; // hidden while searching
        const open = q ? true : (openSections[section.title] ?? false); // search forces expand
        const requiredCount = section.fields.filter((k) => details.fields[k]?.required === true).length;
        return (
          <section key={section.title} className="rounded-md border border-border bg-background/40">
            <button
              type="button"
              onClick={() => onToggleSection(section.title, !open)}
              aria-expanded={open}
              className="flex w-full items-center justify-between gap-2 rounded-t-md px-3 py-2 text-left hover:bg-muted/50"
            >
              <span className="text-sm font-medium text-secondary">
                {section.title}
                <span className="ml-1.5 text-[11px] font-normal text-faint">{fields.length}{requiredCount > 0 ? ` · ${requiredCount} required` : ''}</span>
              </span>
              <ChevronDown size={14} className={clsx('shrink-0 text-faint transition-transform', open && 'rotate-180')} />
            </button>
            {open && (
              <div className="border-t border-border px-3 py-2">
                <SchemaForm
                  schema={Object.fromEntries(fields.map((k) => [k, details.fields[k]]))}
                  values={values}
                  onChange={onChange}
                  fieldErrors={fieldErrors}
                />
              </div>
            )}
          </section>
        );
      })}
    </div>
  );
}
