import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import * as OpenApiValidator from 'express-openapi-validator';
import { loadOpenApiSpec, resolveOpenApiPath } from './openapi';
import { initDb, backfillSecrets, backfillAdminPermissions, backfillDeviceSites, backfillAdminRole } from './db';
import authRouter from './routes/auth';
import devicesRouter from './routes/devices';
import pluginsRouter from './routes/plugins';
import secretsRouter from './routes/secrets';
import sitesRouter from './routes/sites';
import layersRouter from './routes/layers';
import usersRouter from './routes/users';
import credentialPoliciesRouter from './routes/credentialPolicies';
import rolesRouter from './routes/roles';
import tokensRouter from './routes/tokens';
import { internalRouter } from './routes/internal';
import configJobsRouter, { configJobsListRouter } from './routes/configJobs';
import plansRouter from './routes/plans';
import networksRouter from './routes/networks';
import topologyRouter from './routes/topology';
import logsRouter from './routes/logs';
import notificationsRouter from './routes/notifications';
import systemRouter from './routes/system';
import { startNotificationsWorker } from './workers/notifications';
import { startTelemetryWorker } from './workers/telemetry';
import { startTelemetryRetentionWorker } from './workers/telemetryRetention';
import { startPluginDiscovery } from './plugins/discovery';
import { startConfigJobWorker } from './workers/configJob';
import { startPlanExecutorWorker } from './workers/planExecutor';
import { startLogRetentionWorker } from './workers/logRetention';
import { startPluginMetricsWorker } from './workers/pluginMetrics';
import { LEADER_KEYS, runAsLeader } from './workers/leader';
import { initWorker } from './workers/stats';
import { attachConsoleProxy } from './consoleProxy';

const PORT = Number(process.env.PORT ?? 3000);
const API_PREFIX = '/v1';

// General limiter applied to every /v1 route to guard database-backed
// handlers against abuse/brute force.
const generalLimiter = rateLimit({
  windowMs: 60_000,
  limit: 300,
  standardHeaders: true,
  legacyHeaders: false,
});

// Tighter limiter for the authentication endpoints, matching the OpenAPI
// spec's documented `429 Too many login attempts` response for /auth/login.
const authLimiter = rateLimit({
  windowMs: 60_000,
  limit: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many login attempts' },
});

async function main(): Promise<void> {
  await initDb();
  await backfillAdminRole();
  await backfillAdminPermissions();
  await backfillDeviceSites();
  await backfillSecrets();

  const spec = loadOpenApiSpec();
  const specPath = resolveOpenApiPath();

  const app = express();
  app.use(helmet());
  app.use(cors());
  // Filesystem writes (POST /devices/:id/filesystem op=write) carry base64 file
  // contents — allow up to ~10 MiB of inbound JSON so a user can upload files that size.
  app.use(express.json({ limit: '12mb' }));

  app.get('/healthz', (_req, res) => {
    res.status(200).json({ status: 'ok' });
  });

  const api = express.Router();
  api.use(generalLimiter);

  // Routes not defined in the OpenAPI spec must be mounted ahead of the
  // validator, since the validator 404s any undocumented path. The internal
  // plugin routes are namespaced under /plugin/* (user data included) so they
  // never shadow public paths like POST /users — see routes/internal.ts.
  api.use(configJobsListRouter);
  api.use(internalRouter());

  api.use(
    OpenApiValidator.middleware({
      apiSpec: spec as never,
      validateRequests: true,
      validateResponses: false,
    })
  );

  api.use('/auth', authLimiter);
  api.use(authRouter);
  api.use(devicesRouter);
  api.use(pluginsRouter);
  api.use('/secrets', secretsRouter);
  api.use(sitesRouter);
  // Network layer registry (topology bands) — self-defining /layers paths.
  api.use(layersRouter);
  api.use(usersRouter);
  // Credential policies (2FA requirements + gate AMRs) — self-defining paths
  // (/auth/policies/global, /users/:id/policy).
  api.use(credentialPoliciesRouter);
  api.use(rolesRouter);
  // API tokens (self-service + admin) — long-lived bearer credentials for agents.
  api.use(tokensRouter);
  api.use(configJobsRouter);
  // Cross-device inventory views (/networks, /hosts) — self-defining paths.
  api.use(networksRouter);
  // Physical + logical topology graph for the Topology page (self-defining path).
  api.use(topologyRouter);
  // Plugin log entries (global view + per-device section in DeviceDetail).
  api.use(logsRouter);
  // Notification center (bell badge, panel, full page with filters + prefs).
  api.use(notificationsRouter);
  // System/HA observability + runtime tuning (/system/status, /system/settings).
  api.use(systemRouter);
  // The plans router defines its own /plans/... paths (like the devices router),
  // so it is mounted without an extra prefix.
  api.use(plansRouter);

  // OpenAPI validation error handler.
  api.use(
    (
      err: { status?: number; message?: string; errors?: unknown },
      _req: express.Request,
      res: express.Response,
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      _next: express.NextFunction
    ) => {
      res.status(err.status ?? 500).json({
        error: err.message ?? 'Internal server error',
        details: err.errors,
      });
    }
  );

  app.use(API_PREFIX, api);

  // Start background workers ONLY after the port is bound. Starting them before
  // (or regardless of) a successful listen lets orphaned instances that fail to
  // bind (EADDRINUSE) keep polling and writing conflicting status updates —
  // which manifests as device status flapping between online/degraded.
  //
  // HA: every worker below is gated by Postgres advisory-lock leader election
  // (workers/leader.ts). With N API replicas, exactly ONE runs each loop; the
  // others stay standby and serve HTTP only. The config-job worker is NOT
  // gated — it drains this instance's own in-process queue, so every replica
  // must run one to process jobs its routes enqueued.
  const workerStops: Array<() => Promise<void>> = [];
  const httpServer = app.listen(PORT, () => {
    // eslint-disable-next-line no-console
    console.log(`[api] UnifiedNetworkManager API listening on port ${PORT}`);
    // eslint-disable-next-line no-console
    console.log(`[api] OpenAPI spec loaded from ${specPath}`);

    // SSH console (capability 'sshConsole'): WS upgrades bypass express entirely, so
    // the proxy attaches to the raw HTTP server — it pipes browser ⇄ plugin /console
    // verbatim using single-use tickets minted by POST /devices/:id/console.
    attachConsoleProxy(httpServer);

    startConfigJobWorker();

    void runAsLeader(LEADER_KEYS.telemetry, 'telemetry', () => startTelemetryWorker()).then((stop) => workerStops.push(stop));
    void runAsLeader(LEADER_KEYS.planExecutor, 'planExecutor', () => startPlanExecutorWorker()).then((stop) => workerStops.push(stop));
    void runAsLeader(LEADER_KEYS.retention, 'retention', () => {
      const stopLogs = startLogRetentionWorker();
      return () => stopLogs();
    }).then((stop) => workerStops.push(stop));
    void runAsLeader(LEADER_KEYS.telemetryRetention, 'telemetryRetention', () => {
      const timer = startTelemetryRetentionWorker();
      return () => clearInterval(timer);
    }).then((stop) => workerStops.push(stop));
    void runAsLeader(LEADER_KEYS.pluginMetrics, 'pluginMetrics', () => startPluginMetricsWorker()).then((stop) => workerStops.push(stop));
    // Notification maintenance: auto-resolve recovered device states + retention.
    void runAsLeader(LEADER_KEYS.notifications, 'notifications', () => startNotificationsWorker()).then((stop) => workerStops.push(stop));

    // Discover plugins via mDNS/DNS-SD, with HTTP polling as a fallback for
    // Docker bridge networks where multicast is isolated. Leader-gated: the
    // upserts are idempotent but N replicas would N× the /discover traffic and
    // log noise; one discoverer keeps lastSeenAt fresh for everyone (it writes
    // to Postgres, which all replicas read).
    const pollEndpoints = (process.env.PLUGIN_POLL_ENDPOINTS ?? '')
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean);
    initWorker('discovery', LEADER_KEYS.discovery);
    void runAsLeader(LEADER_KEYS.discovery, 'discovery', () => {
      const stopDiscovery = startPluginDiscovery({
        pollEndpoints,
        pollIntervalMs: Number(process.env.PLUGIN_POLL_INTERVAL_MS ?? 60_000),
      });
      return stopDiscovery;
    }).then((stop) => workerStops.push(stop));
  });

  // Graceful shutdown: step down from leadership so a standby takes over
  // immediately (rolling deploys) instead of waiting for the lock to be
  // released by process death.
  let shuttingDown = false;
  const stopAllWorkers = async (): Promise<void> => {
    if (shuttingDown) return;
    shuttingDown = true;
    await Promise.allSettled(workerStops.map((stop) => stop()));
    process.exit(0);
  };
  process.on('SIGTERM', () => void stopAllWorkers());
  process.on('SIGINT', () => void stopAllWorkers());
}

main().catch((err) => {
  // eslint-disable-next-line no-console
  console.error('[api] fatal startup error:', err);
  process.exit(1);
});
