import { Navigate, Route, Routes } from 'react-router-dom';
import { ReactNode } from 'react';
import Login from './pages/Login';
import Devices from './pages/Devices';
import DeviceDetail from './pages/DeviceDetail';
import DeviceConfig from './pages/DeviceConfig';
import Secrets from './pages/Secrets';
import ConfigJobs from './pages/ConfigJobs';
import Plans from './pages/Plans';
import PlanDetail from './pages/PlanDetail';
import Plugins from './pages/Plugins';
import Sites from './pages/Sites';
import Layers from './pages/Layers';
import Networks from './pages/Networks';
import NetworkRolloutPage from './pages/NetworkRolloutPage';
import Hosts from './pages/Hosts';
import DocumentedHosts from './pages/DocumentedHosts';
import DocumentedNetworks from './pages/DocumentedNetworks';
import DocumentedNetworkImportPage from './pages/DocumentedNetworkImportPage';
import Tunnels from './pages/Tunnels';
import Services from './pages/Services';
import Mail from './pages/Mail';
import Firewall from './pages/Firewall';
import Certificates from './pages/Certificates';
import RoutesPage from './pages/Routes';
import Logs from './pages/Logs';
import Notifications from './pages/Notifications';
import Wifi from './pages/Wifi';
import Storage from './pages/Storage';
import Shares from './pages/Shares';
import Containers from './pages/Containers';
import Time from './pages/Time';
import ContainerLogsPage from './pages/ContainerLogsPage';
import ConsolePage from './pages/ConsolePage';
import FileBrowserPage from './pages/FileBrowserPage';
import Files from './pages/Files';
import Vms from './pages/Vms';
import Updates from './pages/Updates';
import Security from './pages/Security';
import Topology from './pages/Topology';
import Users from './pages/Users';
import Roles from './pages/Roles';
import Tokens from './pages/Tokens';
import Workers from './pages/Workers';
import Settings from './pages/Settings';
import CredentialPolicies from './pages/CredentialPolicies';
import MyAccount from './pages/MyAccount';
import { can } from './auth/permissions';

/**
 * Read permission each page requires. Single source of truth for the route
 * guards below AND the default-redirect priority — keep in sync with the
 * sidebar's `requiresPermission` entries (components/Sidebar.tsx).
 */
const PAGE_PERMISSIONS: Array<{ path: string; permission?: string | string[] }> = [
  { path: '/devices', permission: 'devices:read' },
  { path: '/networks', permission: 'networks:read' },
  // Full-page rollout wizard — same read perm as the Networks page it lives on.
  { path: '/networks/rollout', permission: 'networks:read' },
  { path: '/hosts', permission: 'hosts:read' },
  { path: '/documented-hosts', permission: 'documented-hosts:read' },
  { path: '/documented-networks', permission: 'documented-networks:read' },
  // Full-page "import from live inventory" wizard — mutates documented rows, so it
  // is gated on the write perm (the endpoint requires documented-networks:write).
  { path: '/documented-networks/import-from-inventory', permission: 'documented-networks:write' },
  { path: '/tunnels', permission: 'tunnels:read' },
  // Cross-device service inventory (systemd/OpenRC/runit/SysVinit/rc/middleware).
  { path: '/services', permission: 'services:read' },
  // Cross-device mail inventory — domains, mailboxes and aliases (mailcow).
  { path: '/mail', permission: 'mail:read' },
  { path: '/firewall', permission: 'firewall:read' },
  { path: '/certificates', permission: 'certificates:read' },
  { path: '/routes', permission: 'routes:read' },
  { path: '/logs', permission: 'logs:read' },
  // Notification center — full history + filters (the bell is visible to everyone
  // with the read permission; it lives in the app shell, not the sidebar).
  { path: '/notifications', permission: 'notifications:read' },
  { path: '/wifi', permission: 'wifi:read' },
  { path: '/storage', permission: 'storage:read' },
  { path: '/shares', permission: 'shares:read' },
  { path: '/containers', permission: 'containers:read' },
  // Cross-device clock overview — each device's local time + drift vs UNM.
  { path: '/time', permission: 'time:read' },
  { path: '/vms', permission: 'vms:read' },
  // Central file repository — device-independent store of ISOs/firmware/config
  // backups/scripts (volume mounted on the API only; metadata in Postgres).
  { path: '/files', permission: 'files:read' },
  // Cross-device update center (firmware/packages/images) + stack self-update card.
  { path: '/updates', permission: 'updates:read' },
  // Cross-device security findings — unsuccessful logins, file integrity, rate limiting.
  { path: '/security', permission: 'security:read' },
  { path: '/topology', permission: 'topology:read' },
  // Layers is open to every authenticated user (no read permission).
  { path: '/layers' },
  // Credential policies are readable by everyone; editing is gated server-side
  // on auth:policies:write (the page renders read-only without it).
  { path: '/credential-policies' },
  { path: '/sites', permission: 'sites:read' },
  // Global readers OR personal-area users (own secrets) may open the page.
  { path: '/secrets', permission: ['secrets:read', 'secrets:self-write'] },
  { path: '/config-jobs', permission: 'config-jobs:read' },
  { path: '/plans', permission: 'plans:read' },
  { path: '/plugins', permission: 'plugins:read' },
  { path: '/users', permission: 'users:read' },
  { path: '/roles', permission: 'users:write' },
  { path: '/tokens', permission: 'tokens:manage' },
  { path: '/workers', permission: 'system:read' },
  // Central system settings (app-wide knobs) — gated like the Workers page.
  { path: '/settings', permission: 'system:read' },
];

/** Auth + page-read-permission guard (the sidebar hides what this blocks).
 *  `permission` may be an array — ANY of the listed permissions suffices. */
function Page({ permission, children }: { permission?: string | string[]; children: ReactNode }) {
  const token = localStorage.getItem('accessToken');
  if (!token) return <Navigate to="/login" replace />;
  if (permission && !(Array.isArray(permission) ? permission.some((p) => can(p)) : can(permission))) {
    return <Navigate to="/" replace />;
  }
  return <>{children}</>;
}

/** Landing redirect — first page the user may read, else My Account. */
function HomeRedirect() {
  const target = PAGE_PERMISSIONS.find((p) =>
    !p.permission || (Array.isArray(p.permission) ? p.permission.some((x) => can(x)) : can(p.permission as string))
  )?.path ?? '/my-account';
  return <Navigate to={target} replace />;
}

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<Login />} />
      <Route path="/devices" element={<Page permission="devices:read"><Devices /></Page>} />
      <Route path="/secrets" element={<Page permission={['secrets:read', 'secrets:self-write']}><Secrets /></Page>} />
      {/* Device detail is part of the Devices page (same read permission). */}
      <Route path="/devices/:deviceId" element={<Page permission="devices:read"><DeviceDetail /></Page>} />
      {/* Per-device Config page — dynamic plugin state + actions via plans. */}
      <Route path="/devices/:deviceId/config" element={<Page permission="devices:read"><DeviceConfig /></Page>} />
      <Route path="/config-jobs" element={<Page permission="config-jobs:read"><ConfigJobs /></Page>} />
      <Route path="/plans" element={<Page permission="plans:read"><Plans /></Page>} />
      <Route path="/plans/:id" element={<Page permission="plans:read"><PlanDetail /></Page>} />
      <Route path="/plugins" element={<Page permission="plugins:read"><Plugins /></Page>} />
      <Route path="/sites" element={<Page permission="sites:read"><Sites /></Page>} />
      <Route path="/networks" element={<Page permission="networks:read"><Networks /></Page>} />
      {/* Full-page rollout wizard (replaces the old dialog) — same read perm as /networks. */}
      <Route path="/networks/rollout" element={<Page permission="networks:read"><NetworkRolloutPage /></Page>} />
      <Route path="/hosts" element={<Page permission="hosts:read"><Hosts /></Page>} />
      {/* User-maintained host documentation (permanent inventory + CSV import). */}
      <Route path="/documented-hosts" element={<Page permission="documented-hosts:read"><DocumentedHosts /></Page>} />
      <Route path="/documented-networks" element={<Page permission="documented-networks:read"><DocumentedNetworks /></Page>} />
      {/* Full-page "import from live inventory" wizard (replaces the old modal) — write-gated. */}
      <Route path="/documented-networks/import-from-inventory" element={<Page permission="documented-networks:write"><DocumentedNetworkImportPage /></Page>} />
      <Route path="/tunnels" element={<Page permission="tunnels:read"><Tunnels /></Page>} />
      {/* Cross-device service inventory (OPNsense rc, TrueNAS middleware, Linux inits). */}
      <Route path="/services" element={<Page permission="services:read"><Services /></Page>} />
      <Route path="/mail" element={<Page permission="mail:read"><Mail /></Page>} />
      <Route path="/firewall" element={<Page permission="firewall:read"><Firewall /></Page>} />
      <Route path="/certificates" element={<Page permission="certificates:read"><Certificates /></Page>} />
      <Route path="/routes" element={<Page permission="routes:read"><RoutesPage /></Page>} />
      <Route path="/logs" element={<Page permission="logs:read"><Logs /></Page>} />
      {/* Notification center — full history with filters + visibility settings. */}
      <Route path="/notifications" element={<Page permission="notifications:read"><Notifications /></Page>} />
      <Route path="/wifi" element={<Page permission="wifi:read"><Wifi /></Page>} />
      <Route path="/storage" element={<Page permission="storage:read"><Storage /></Page>} />
      {/* Cross-device file-share exports (SMB/NFS/iSCSI/NVMe-oF) + live sessions. */}
      <Route path="/shares" element={<Page permission="shares:read"><Shares /></Page>} />
      {/* Cross-device container/App workloads (TrueNAS SCALE Apps). */}
      <Route path="/containers" element={<Page permission="containers:read"><Containers /></Page>} />
      <Route path="/time" element={<Page permission="time:read"><Time /></Page>} />
      {/* Standalone SSH console window — popped out of the ConsoleDialog; needs devices:write
          because minting a console ticket is gated on it server-side. */}
      <Route path="/console/:deviceId" element={<Page permission="devices:write"><ConsolePage /></Page>} />
      {/* Standalone file browser — popped out of the FileBrowserDialog; mirrors the
          filesystem broker's devices:write gate (all ops are write-capable). */}
      <Route path="/file-browser/:deviceId" element={<Page permission="devices:write"><FileBrowserPage /></Page>} />
      {/* Standalone container logs — popped out of the LogsDialog; mirrors the
          containers.logs.read execute endpoint's containers:read gate. */}
      <Route path="/container-logs/:deviceId" element={<Page permission="containers:read"><ContainerLogsPage /></Page>} />
      {/* Cross-device virtual machines (TrueNAS SCALE VMs today; generic key for future hypervisor plugins). */}
      <Route path="/vms" element={<Page permission="vms:read"><Vms /></Page>} />
      {/* Central file repository — device-independent store of ISOs/firmware/config backups/scripts. */}
      <Route path="/files" element={<Page permission="files:read"><Files /></Page>} />
      {/* Cross-device update center — available updates + stack self-update card. */}
      <Route path="/updates" element={<Page permission="updates:read"><Updates /></Page>} />
      {/* Cross-device security findings — unsuccessful logins, file integrity, rate limiting. */}
      <Route path="/security" element={<Page permission="security:read"><Security /></Page>} />
      {/* Physical + logical network graph (inferred cables, per-VLAN segments). */}
      <Route path="/topology" element={<Page permission="topology:read"><Topology /></Page>} />
      {/* Network layer registry — open to every authenticated user. */}
      <Route path="/layers" element={<Page><Layers /></Page>} />
      {/* Credential policies — readable by everyone, editing gated in-page. */}
      <Route path="/credential-policies" element={<Page><CredentialPolicies /></Page>} />
      <Route path="/users" element={<Page permission="users:read"><Users /></Page>} />
      <Route path="/roles" element={<Page permission="users:write"><Roles /></Page>} />
      <Route path="/tokens" element={<Page permission="tokens:manage"><Tokens /></Page>} />
      {/* Workers/HA monitoring — gated by system:read (nav item hidden without it). */}
      <Route path="/workers" element={<Page permission="system:read"><Workers /></Page>} />
      {/* Central system settings (app-wide knobs) — gated like the Workers page. */}
      <Route path="/settings" element={<Page permission="system:read"><Settings /></Page>} />
      <Route path="/my-account" element={<Page><MyAccount /></Page>} />
      <Route path="/" element={<HomeRedirect />} />
      <Route path="*" element={<HomeRedirect />} />
    </Routes>
  );
}
