import { useState } from 'react';
import { Plugin, pluginIconUrl } from '../api/client';

/** Resolves the best icon for a device: the matching model's icon when the
 * device has a model set and its plugin catalog carries one for it, otherwise
 * the plugin's own icon. Returns null when nothing is advertised. */
function resolveIconSrc(plugin: Plugin | null | undefined, model?: string | null): string | null {
  if (!plugin) return null;
  const models = plugin.deviceModels ?? [];
  if (model) {
    const entry = models.find((m) => m.model.toLowerCase() === model.toLowerCase());
    if (entry?.iconPath) return pluginIconUrl(plugin.id, entry.iconPath);
  }
  return plugin.iconUrl ? pluginIconUrl(plugin.id) : null;
}

/** Small icon for a device — the matching model's icon when available, else
 * the primary plugin's icon. Always renders a fixed-size box (transparent when
 * no icon is advertised or it fails to load) so table columns stay aligned. */
export function DeviceIcon({
  plugin,
  model,
  size = 'sm',
}: {
  /** The device's PRIMARY plugin (icons are per-plugin; secondary plugins don't contribute). */
  plugin?: Plugin | null;
  /** The device's selected hardware model (enables the per-model icon). */
  model?: string | null;
  size?: 'sm' | 'lg';
}) {
  const [failed, setFailed] = useState(false);
  const src = failed ? null : resolveIconSrc(plugin, model);
  const px = size === 'lg' ? 32 : 20;

  if (!src) {
    return <span aria-hidden className="inline-block shrink-0 rounded bg-muted" style={{ width: px, height: px }} />;
  }
  return (
    <img
      src={src}
      alt=""
      title={plugin?.name ?? undefined}
      onError={() => setFailed(true)}
      className="inline-block shrink-0 rounded object-contain"
      style={{ width: px, height: px }}
    />
  );
}
