import { Navigate, Route, Routes } from 'react-router-dom';
import { ReactNode } from 'react';
import Login from './pages/Login';
import Devices from './pages/Devices';
import DeviceDetail from './pages/DeviceDetail';
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
import RoutesPage from './pages/Routes';
import Logs from './pages/Logs';
import Wifi from './pages/Wifi';
import Topology from './pages/Topology';
import Users from './pages/Users';
import Roles from './pages/Roles';
import Tokens from './pages/Tokens';
import Workers from './pages/Workers';
import MyAccount from './pages/MyAccount';

function RequireAuth({ children }: { children: ReactNode }) {
  const token = localStorage.getItem('accessToken');
  if (!token) {
    return <Navigate to="/login" replace />;
  }
  return <>{children}</>;
}

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<Login />} />
      <Route
        path="/devices"
        element={
          <RequireAuth>
            <Devices />
          </RequireAuth>
        }
      />
      <Route
        path="/secrets"
        element={
          <RequireAuth>
            <Secrets />
          </RequireAuth>
        }
      />
      <Route
        path="/devices/:deviceId"
        element={
          <RequireAuth>
            <DeviceDetail />
          </RequireAuth>
        }
      />
      <Route
        path="/config-jobs"
        element={
          <RequireAuth>
            <ConfigJobs />
          </RequireAuth>
        }
      />
      <Route
        path="/plans"
        element={
          <RequireAuth>
            <Plans />
          </RequireAuth>
        }
      />
      <Route
        path="/plans/:id"
        element={
          <RequireAuth>
            <PlanDetail />
          </RequireAuth>
        }
      />
      <Route
        path="/plugins"
        element={
          <RequireAuth>
            <Plugins />
          </RequireAuth>
        }
      />
      <Route
        path="/sites"
        element={
          <RequireAuth>
            <Sites />
          </RequireAuth>
        }
      />
      <Route
        path="/networks"
        element={
          <RequireAuth>
            <Networks />
          </RequireAuth>
        }
      />
      <Route
        path="/hosts"
        element={
          <RequireAuth>
            <Hosts />
          </RequireAuth>
        }
      />
      <Route
        path="/tunnels"
        element={
          <RequireAuth>
            <Tunnels />
          </RequireAuth>
        }
      />
      <Route
        path="/routes"
        element={
          <RequireAuth>
            <RoutesPage />
          </RequireAuth>
        }
      />
      <Route
        path="/logs"
        element={
          <RequireAuth>
            <Logs />
          </RequireAuth>
        }
      />
      <Route
        path="/wifi"
        element={
          <RequireAuth>
            <Wifi />
          </RequireAuth>
        }
      />
      {/* Physical + logical network graph (inferred cables, per-VLAN segments). */}
      <Route
        path="/topology"
        element={
          <RequireAuth>
            <Topology />
          </RequireAuth>
        }
      />
      {/* Network layer registry — the topology view's horizontal bands. */}
      <Route
        path="/layers"
        element={
          <RequireAuth>
            <Layers />
          </RequireAuth>
        }
      />
      <Route
        path="/users"
        element={
          <RequireAuth>
            <Users />
          </RequireAuth>
        }
      />
      <Route
        path="/roles"
        element={
          <RequireAuth>
            <Roles />
          </RequireAuth>
        }
      />
      <Route
        path="/tokens"
        element={
          <RequireAuth>
            <Tokens />
          </RequireAuth>
        }
      />
      {/* Workers/HA monitoring — gated by system:read (nav item hidden without it). */}
      <Route
        path="/workers"
        element={
          <RequireAuth>
            <Workers />
          </RequireAuth>
        }
      />
      <Route
        path="/my-account"
        element={
          <RequireAuth>
            <MyAccount />
          </RequireAuth>
        }
      />
      <Route path="/" element={<Navigate to="/devices" replace />} />
      <Route path="*" element={<Navigate to="/devices" replace />} />
    </Routes>
  );
}
