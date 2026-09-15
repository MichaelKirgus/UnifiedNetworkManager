import type { ComponentType } from 'react';
import {
  Activity,
  BellRing,
  Box,
  Cable,
  KeyRound,
  Laptop,
  ListChecks,
  MapPin,
  Network,
  Puzzle,
  GitGraph,
  Layers as LayersIcon,
  Route as RouteIcon,
  ScrollText,
  HardDrive,
  Share2,
  Monitor,
  Server,
  Waypoints,
  KeySquare,
  Shield,
  ShieldHalf,
  ShieldCheck,
  FileKey2,
  Settings2,
  UserRound,
  Users as UsersIcon,
  Wifi as WifiIcon,
  Clock,
} from 'lucide-react';
import { can } from '../auth/permissions';
import type { NavCountKey } from '../api/client';

/** One sidebar entry. `countKey` opts the item into a nav-badge count (see /counts). */
export interface NavItem {
  to: string;
  label: string;
  icon: ComponentType<{ className?: string }>;
  /** Permission(s) the page's route guard enforces (any one suffices) — keep in
   *  sync with PAGE_PERMISSIONS. */
  requiresPermission?: string | string[];
  /** When set, the item shows a badge from `NavCounts[countKey]` (only if > 0). */
  countKey?: NavCountKey;
}

// Every entry carries the read permission its page's route guard enforces — keep in
// sync with PAGE_PERMISSIONS in App.tsx. Entries without a permission are visible to
// every signed-in user. This array is the SINGLE SOURCE OF TRUTH for what exists;
// per-user prefs (order/hidden) only annotate it, so adding a page needs no migration.
export const NAV_ITEMS: NavItem[] = [
  { to: '/devices', label: 'Devices', icon: Server, requiresPermission: 'devices:read' },
  // Cross-device inventory views (populated by the telemetry worker).
  { to: '/networks', label: 'Networks', icon: Network, requiresPermission: 'networks:read' },
  { to: '/hosts', label: 'Hosts', icon: Laptop, requiresPermission: 'hosts:read' },
  // Cable stands in for a tunnel link (lucide's `Tunnel` icon is not in the installed version).
  { to: '/tunnels', label: 'Tunnels', icon: Cable, requiresPermission: 'tunnels:read' },
  // Firewall rules across devices (filter + NAT kinds) — ShieldHalf reads as a
  // protective barrier and is distinct from the Roles (Shield) entry.
  { to: '/firewall', label: 'Firewall', icon: ShieldHalf, requiresPermission: 'firewall:read' },
  // TLS certs + SSH host keys across devices (expiry/chain validation). The
  // badge counts endpoints that are NOT healthy right now — expired leaf or
  // issuer, chain-invalid, or presenting a different key than trusted.
  { to: '/certificates', label: 'Certificates', icon: FileKey2, requiresPermission: 'certificates:read', countKey: 'certificates' },
  // Waypoints — Route is already used by the Plans item.
  { to: '/routes', label: 'Routes', icon: Waypoints, requiresPermission: 'routes:read' },
  // Structured log entries shipped by plugins (gated — logs can carry critical details).
  { to: '/logs', label: 'Logs', icon: ScrollText, requiresPermission: 'logs:read' },
  // Notification center — full history + filters (the bell lives in the top bar).
  { to: '/notifications', label: 'Notifications', icon: BellRing, requiresPermission: 'notifications:read', countKey: 'notifications' },
  { to: '/wifi', label: 'WiFi', icon: WifiIcon, requiresPermission: 'wifi:read' },
  // Cross-device storage inventory (filesystems/pools/datasets + physical disks).
  { to: '/storage', label: 'Storage', icon: HardDrive, requiresPermission: 'storage:read' },
  // Cross-device file-share exports (SMB/CIFS, NFS, iSCSI, NVMe-oF) + live client sessions.
  { to: '/shares', label: 'Shares', icon: Share2, requiresPermission: 'shares:read' },
  // Cross-device container/App workloads (TrueNAS SCALE Apps — docker under the hood).
  { to: '/containers', label: 'Containers', icon: Box, requiresPermission: 'containers:read' },
  // Cross-device clock overview — each device's local time + drift vs UNM's own clock.
  { to: '/time', label: 'Time', icon: Clock, requiresPermission: 'time:read' },
  // Cross-device virtual machines (TrueNAS SCALE VMs today; generic key for future hypervisor plugins).
  { to: '/vms', label: 'VMs', icon: Monitor, requiresPermission: 'vms:read' },
  // Physical + logical network graph (inferred cables + per-VLAN segments).
  { to: '/topology', label: 'Topology', icon: GitGraph, requiresPermission: 'topology:read' },
  // Layer registry — the topology view's horizontal bands (open to all users).
  { to: '/layers', label: 'Layers', icon: LayersIcon },
  { to: '/sites', label: 'Sites', icon: MapPin, requiresPermission: 'sites:read' },
  // Global readers OR personal-area users (own secrets) may open the page.
  { to: '/secrets', label: 'Secrets', icon: KeyRound, requiresPermission: ['secrets:read', 'secrets:self-write'] },
  // Config jobs still queued/running surface as a badge (actionable).
  { to: '/config-jobs', label: 'Config Jobs', icon: ListChecks, requiresPermission: 'config-jobs:read', countKey: 'configJobs' },
  // Multi-device execution plans (create/execute additionally require configs:apply + 2FA).
  { to: '/plans', label: 'Plans', icon: RouteIcon, requiresPermission: 'plans:read', countKey: 'plans' },
  { to: '/plugins', label: 'Plugins', icon: Puzzle },
  // Only visible to users who may read user accounts/permissions.
  { to: '/users', label: 'Users', icon: UsersIcon, requiresPermission: 'users:read' },
  // Role management (create/edit/delete roles + permission bundles).
  { to: '/roles', label: 'Roles', icon: Shield, requiresPermission: 'users:write' },
  // Credential policies (2FA requirements + gate AMRs) — readable by everyone,
  // editing is gated in-page on auth:policies:write.
  { to: '/credential-policies', label: 'Credential Policies', icon: ShieldCheck },
  // Long-lived API tokens for agents/scripts (MCP server).
  { to: '/tokens', label: 'Tokens', icon: KeySquare, requiresPermission: 'tokens:manage' },
  // Worker/HA monitoring + runtime tuning (gated — exposes internal topology).
  { to: '/workers', label: 'Workers & HA', icon: Activity, requiresPermission: 'system:read' },
  // Central system settings (app-wide knobs) — gated like the Workers page.
  { to: '/settings', label: 'Settings', icon: Settings2, requiresPermission: 'system:read' },
];

// Self-service portal — visible to every signed-in user; credential sections inside are
// gated on `users:self-credentials`. Pinned last and never reorderable/hideable.
export const MY_ACCOUNT_ITEM: NavItem = { to: '/my-account', label: 'My Account', icon: UserRound };

/** Distinct badge color per count key (matches the top-bar bell/plans accents). */
export const BADGE_COLORS: Record<NavCountKey, string> = {
  notifications: 'bg-red-500',
  configJobs: 'bg-amber-500',
  plans: 'bg-blue-500',
  certificates: 'bg-red-500',
};

/**
 * Permission-visible nav items in the user's chosen order. Items present in
 * `navOrder` come first (in that sequence); the rest keep their default relative
 * order (stable sort). Hidden pages are NOT filtered here — callers decide, so the
 * customizer can still list + re-show them. My Account is excluded (pinned separately).
 */
export function orderedNavItems(prefs?: { navOrder?: string[] }): NavItem[] {
  const visible = NAV_ITEMS.filter(
    (item) =>
      !item.requiresPermission ||
      (Array.isArray(item.requiresPermission) ? item.requiresPermission.some((p) => can(p)) : can(item.requiresPermission))
  );
  const order = prefs?.navOrder ?? [];
  const rank = new Map<string, number>(order.map((path, idx) => [path, idx]));
  return [...visible].sort((a, b) => {
    const ra = rank.has(a.to) ? (rank.get(a.to) as number) : Number.MAX_SAFE_INTEGER;
    const rb = rank.has(b.to) ? (rank.get(b.to) as number) : Number.MAX_SAFE_INTEGER;
    return ra - rb; // stable: equal ranks keep their original relative order
  });
}
