import { Navigate, Route, Routes } from 'react-router-dom';
import { ReactNode } from 'react';
import Login from './pages/Login';
import Devices from './pages/Devices';
import DeviceDetail from './pages/DeviceDetail';
import ConfigJobs from './pages/ConfigJobs';
import Plugins from './pages/Plugins';

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
        path="/plugins"
        element={
          <RequireAuth>
            <Plugins />
          </RequireAuth>
        }
      />
      <Route path="/" element={<Navigate to="/devices" replace />} />
      <Route path="*" element={<Navigate to="/devices" replace />} />
    </Routes>
  );
}
