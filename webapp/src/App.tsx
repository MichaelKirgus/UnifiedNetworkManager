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
import Networks from './pages/Networks';
import Hosts from './pages/Hosts';
import Users from './pages/Users';
import Roles from './pages/Roles';
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
