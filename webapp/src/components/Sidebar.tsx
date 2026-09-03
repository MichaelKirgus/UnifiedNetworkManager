import { useEffect, useState } from 'react';
import { NavLink } from 'react-router-dom';
import clsx from 'clsx';
import {
  Activity,
  Cable,
  KeyRound,
  Laptop,
  ListChecks,
  LogOut,
  MapPin,
  Network,
  PanelLeftClose,
  PanelLeftOpen,
  Puzzle,
  GitGraph,
  Layers as LayersIcon,
  Route as RouteIcon,
  ScrollText,
  HardDrive,
  Server,
  Waypoints,
  KeySquare,
  Shield,
  ShieldCheck,
  UserRound,
  Users as UsersIcon,
  Wifi as WifiIcon,
} from 'lucide-react';
import { can, clearPermissions, clearUsername } from '../auth/permissions';

// Every entry carries the read permission its page's route guard enforces —
// keep in sync with PAGE_PERMISSIONS in App.tsx. Entries without a permission
// (Layers) are visible to every signed-in user.
const NAV_ITEMS = [
  { to: '/devices', label: 'Devices', icon: Server, requiresPermission: 'devices:read' },
  // Cross-device inventory views (populated by the telemetry worker).
  { to: '/networks', label: 'Networks', icon: Network, requiresPermission: 'networks:read' },
  { to: '/hosts', label: 'Hosts', icon: Laptop, requiresPermission: 'hosts:read' },
  // Cable stands in for a tunnel link (lucide's `Tunnel` icon is not in the installed version).
  { to: '/tunnels', label: 'Tunnels', icon: Cable, requiresPermission: 'tunnels:read' },
  // Waypoints — Route is already used by the Plans item.
  { to: '/routes', label: 'Routes', icon: Waypoints, requiresPermission: 'routes:read' },
  // Structured log entries shipped by plugins (gated — logs can carry critical details).
  { to: '/logs', label: 'Logs', icon: ScrollText, requiresPermission: 'logs:read' },
  { to: '/wifi', label: 'WiFi', icon: WifiIcon, requiresPermission: 'wifi:read' },
  // Cross-device storage inventory (filesystems/pools/datasets + physical disks).
  { to: '/storage', label: 'Storage', icon: HardDrive, requiresPermission: 'storage:read' },
  // Physical + logical network graph (inferred cables + per-VLAN segments).
  { to: '/topology', label: 'Topology', icon: GitGraph, requiresPermission: 'topology:read' },
  // Layer registry — the topology view's horizontal bands (open to all users).
  { to: '/layers', label: 'Layers', icon: LayersIcon },
  { to: '/sites', label: 'Sites', icon: MapPin, requiresPermission: 'sites:read' },
  { to: '/secrets', label: 'Secrets', icon: KeyRound, requiresPermission: 'secrets:read' },
  { to: '/config-jobs', label: 'Config Jobs', icon: ListChecks, requiresPermission: 'config-jobs:read' },
  // Multi-device execution plans (create/execute additionally require configs:apply + 2FA).
  { to: '/plans', label: 'Plans', icon: RouteIcon, requiresPermission: 'plans:read' },
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
];

// Self-service portal — visible to every signed-in user; credential sections
// inside are gated on `users:self-credentials`.
const MY_ACCOUNT_ITEM = { to: '/my-account', label: 'My Account', icon: UserRound };

const COLLAPSED_KEY = 'unm:sidebar-collapsed';

/**
 * Collapsible left sidebar. Expanded shows icons + labels; collapsed is an
 * icon rail (tooltips via `title`). The user's choice persists in localStorage.
 */
export function Sidebar() {
  const [collapsed, setCollapsed] = useState<boolean>(() => {
    try {
      return window.localStorage.getItem(COLLAPSED_KEY) === '1';
    } catch {
      return false;
    }
  });

  useEffect(() => {
    try {
      window.localStorage.setItem(COLLAPSED_KEY, collapsed ? '1' : '0');
    } catch {
      // Storage unavailable (private mode); preference stays in memory.
    }
  }, [collapsed]);

  return (
    <aside
      className={clsx(
        'flex shrink-0 flex-col border-r border-slate-200 bg-white transition-[width] duration-200 ease-in-out',
        collapsed ? 'w-16' : 'w-56'
      )}
    >
      {/* Brand */}
      <div className={clsx('flex h-14 items-center gap-2 border-b border-slate-200 px-3', collapsed && 'justify-center px-0')}>
        <Network className="h-6 w-6 shrink-0 text-slate-900" />
        {!collapsed && (
          <span className="truncate text-sm font-bold text-slate-900">UnifiedNetworkManager</span>
        )}
      </div>

      {/* Navigation */}
      <nav className={clsx('flex flex-1 flex-col gap-1 p-2', collapsed && 'items-center')}>
        {[...NAV_ITEMS.filter((item) => !item.requiresPermission || can(item.requiresPermission)), MY_ACCOUNT_ITEM].map(
          (item) => (
            <NavLink
              key={item.to}
              to={item.to}
              title={collapsed ? item.label : undefined}
              className={({ isActive }) =>
                clsx(
                  'flex items-center gap-3 rounded-md px-2.5 py-2 text-sm font-medium transition-colors',
                  collapsed && 'justify-center px-0',
                  isActive ? 'bg-slate-900 text-white' : 'text-slate-600 hover:bg-slate-100'
                )
              }
            >
              <item.icon className="h-5 w-5 shrink-0" />
              {!collapsed && <span className="truncate">{item.label}</span>}
            </NavLink>
          )
        )}
      </nav>

      {/* Footer: collapse toggle + sign out */}
      <div className={clsx('flex gap-1 border-t border-slate-200 p-2', collapsed && 'flex-col items-center')}>
        <button
          type="button"
          aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
          title={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
          onClick={() => setCollapsed((v) => !v)}
          className={clsx(
            'flex items-center gap-2 rounded-md px-2.5 py-2 text-sm font-medium text-slate-600 hover:bg-slate-100',
            collapsed && 'justify-center px-0'
          )}
        >
          {collapsed ? <PanelLeftOpen className="h-5 w-5 shrink-0" /> : <PanelLeftClose className="h-5 w-5 shrink-0" />}
          {!collapsed && <span>Collapse</span>}
        </button>
        <button
          type="button"
          aria-label="Sign out"
          title="Sign out"
          onClick={() => {
            localStorage.removeItem('accessToken');
            clearPermissions();
            clearUsername();
            window.location.href = '/login';
          }}
          className={clsx(
            'flex items-center gap-2 rounded-md px-2.5 py-2 text-sm font-medium text-slate-600 hover:bg-red-50 hover:text-red-700',
            collapsed && 'justify-center px-0'
          )}
        >
          <LogOut className="h-5 w-5 shrink-0" />
          {!collapsed && <span>Sign out</span>}
        </button>
      </div>
    </aside>
  );
}
