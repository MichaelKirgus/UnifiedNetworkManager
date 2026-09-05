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
import Hosts from './pages/Hosts';
import Tunnels from './pages/Tunnels';
import Firewall from './pages/Firewall';
import RoutesPage from './pages/Routes';
import Logs from './pages/Logs';
import Notifications from './pages/Notifications';
import Wifi from './pages/Wifi';
import Storage from './pages/Storage';
import Containers from './pages/Containers';
import Vms from './pages/Vms';
import Topology from './pages/Topology';
import Users from './pages/Users';
import Roles from './pages/Roles';
import Tokens from './pages/Tokens';
import Workers from './pages/Workers';
import CredentialPolicies from './pages/CredentialPolicies';
import MyAccount from './pages/MyAccount';
import { can } from './auth/permissions';

/**
 * Read permission each page requires. Single source of truth for the route
 * guards below AND the default-redirect priority — keep in sync with the
 * sidebar's `requiresPermission` entries (components/Sidebar.tsx).
 */
const PAGE_PERMISSIONS: Array<{ path: string; permission?: string }> = [
  { path: '/devices', permission: 'devices:read' },
  { path: '/networks', permission: 'networks:read' },
  { path: '/hosts', permission: 'hosts:read' },
  { path: '/tunnels', permission: 'tunnels:read' },
  { path: '/firewall', permission: 'firewall:read' },
  { path: '/routes', permission: 'routes:read' },
  { path: '/logs', permission: 'logs:read' },
  // Notification center — full history + filters (the bell is visible to everyone
  // with the read permission; it lives in the app shell, not the sidebar).
  { path: '/notifications', permission: 'notifications:read' },
  { path: '/wifi', permission: 'wifi:read' },
  { path: '/storage', permission: 'storage:read' },
  { path: '/containers', permission: 'containers:read' },
  { path: '/vms', permission: 'vms:read' },
  { path: '/topology', permission: 'topology:read' },
  // Layers is open to every authenticated user (no read permission).
  { path: '/layers' },
  // Credential policies are readable by everyone; editing is gated server-side
  // on auth:policies:write (the page renders read-only without it).
  { path: '/credential-policies' },
  { path: '/sites', permission: 'sites:read' },
  { path: '/secrets', permission: 'secrets:read' },
  { path: '/config-jobs', permission: 'config-jobs:read' },
  { path: '/plans', permission: 'plans:read' },
  { path: '/plugins', permission: 'plugins:read' },
  { path: '/users', permission: 'users:read' },
  { path: '/roles', permission: 'users:write' },
  { path: '/tokens', permission: 'tokens:manage' },
  { path: '/workers', permission: 'system:read' },
];

/** Auth + page-read-permission guard (the sidebar hides what this blocks). */
function Page({ permission, children }: { permission?: string; children: ReactNode }) {
  const token = localStorage.getItem('accessToken');
  if (!token) return <Navigate to="/login" replace />;
  if (permission && !can(permission)) return <Navigate to="/" replace />;
  return <>{children}</>;
}

/** Landing redirect — first page the user may read, else My Account. */
function HomeRedirect() {
  const target = PAGE_PERMISSIONS.find((p) => !p.permission || can(p.permission))?.path ?? '/my-account';
  return <Navigate to={target} replace />;
}

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<Login />} />
      <Route path="/devices" element={<Page permission="devices:read"><Devices /></Page>} />
      <Route path="/secrets" element={<Page permission="secrets:read"><Secrets /></Page>} />
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
      <Route path="/hosts" element={<Page permission="hosts:read"><Hosts /></Page>} />
      <Route path="/tunnels" element={<Page permission="tunnels:read"><Tunnels /></Page>} />
      <Route path="/firewall" element={<Page permission="firewall:read"><Firewall /></Page>} />
      <Route path="/routes" element={<Page permission="routes:read"><RoutesPage /></Page>} />
      <Route path="/logs" element={<Page permission="logs:read"><Logs /></Page>} />
      {/* Notification center — full history with filters + visibility settings. */}
      <Route path="/notifications" element={<Page permission="notifications:read"><Notifications /></Page>} />
      <Route path="/wifi" element={<Page permission="wifi:read"><Wifi /></Page>} />
      <Route path="/storage" element={<Page permission="storage:read"><Storage /></Page>} />
      {/* Cross-device container/App workloads (TrueNAS SCALE Apps). */}
      <Route path="/containers" element={<Page permission="containers:read"><Containers /></Page>} />
      {/* Cross-device virtual machines (TrueNAS SCALE VMs today; generic key for future hypervisor plugins). */}
      <Route path="/vms" element={<Page permission="vms:read"><Vms /></Page>} />
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
      <Route path="/my-account" element={<Page><MyAccount /></Page>} />
      <Route path="/" element={<HomeRedirect />} />
      <Route path="*" element={<HomeRedirect />} />
    </Routes>
  );
}
