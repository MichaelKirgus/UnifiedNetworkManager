import { useParams, Link } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend } from 'recharts';
import { Layout } from '../components/Layout';
import { StatusBadge } from '../components/StatusBadge';
import { api } from '../api/client';

export default function DeviceDetail() {
  const { deviceId } = useParams<{ deviceId: string }>();

  const monitoringQuery = useQuery({
    queryKey: ['monitoring', deviceId],
    queryFn: () => api.monitoring(deviceId as string),
    enabled: Boolean(deviceId),
    refetchInterval: 15_000,
  });

  const metricsEntries = monitoringQuery.data ? Object.entries(monitoringQuery.data.metrics) : [];
  const chartData = metricsEntries.map(([key, value]) => ({ name: key, value }));

  return (
    <Layout>
      <div className="mb-4">
        <Link to="/devices" className="text-sm text-slate-500 hover:underline">
          &larr; Back to devices
        </Link>
      </div>

      <h1 className="mb-1 text-xl font-bold text-slate-900">Device: {deviceId}</h1>

      {monitoringQuery.isLoading && <p className="text-sm text-slate-500">Loading telemetry...</p>}
      {monitoringQuery.isError && (
        <p className="text-sm text-red-600">Failed to load telemetry: {(monitoringQuery.error as Error).message}</p>
      )}

      {monitoringQuery.data && (
        <div className="space-y-6">
          <div className="flex items-center gap-4 rounded-md border border-slate-200 bg-white p-4 shadow-sm">
            <div>
              <p className="text-xs uppercase text-slate-400">Health</p>
              <StatusBadge status={monitoringQuery.data.health} />
            </div>
            <div>
              <p className="text-xs uppercase text-slate-400">Collected At</p>
              <p className="text-sm text-slate-700">{new Date(monitoringQuery.data.collectedAt).toLocaleString()}</p>
            </div>
          </div>

          <div className="rounded-md border border-slate-200 bg-white p-4 shadow-sm">
            <h2 className="mb-3 text-sm font-semibold text-slate-700">Metrics</h2>
            {chartData.length === 0 ? (
              <p className="text-sm text-slate-500">No metrics reported for this device yet.</p>
            ) : (
              <ResponsiveContainer width="100%" height={320}>
                <LineChart data={chartData}>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis dataKey="name" tick={{ fontSize: 12 }} interval={0} angle={-20} textAnchor="end" height={70} />
                  <YAxis />
                  <Tooltip />
                  <Legend />
                  <Line type="monotone" dataKey="value" stroke="#0f172a" strokeWidth={2} dot={{ r: 3 }} />
                </LineChart>
              </ResponsiveContainer>
            )}
          </div>
        </div>
      )}
    </Layout>
  );
}
