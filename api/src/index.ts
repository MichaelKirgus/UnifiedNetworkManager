import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import * as OpenApiValidator from 'express-openapi-validator';
import { loadOpenApiSpec, resolveOpenApiPath } from './openapi';
import { initDb, backfillSecrets, backfillAdminPermissions, backfillDeviceSites, backfillAdminRole, backfillInteractiveLoginPermission, backfillDeviceAllPermission } from './db';
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
import flowsRouter from './routes/flows';
import geoipRouter from './routes/geoip';
import mailRouter from './routes/mail';
import documentedHostsRouter from './routes/documentedHosts';
import documentedNetworksRouter from './routes/documentedNetworks';
import updatesRouter from './routes/updates';
import securityChecksRouter from './routes/securityChecks';
import topologyRouter from './routes/topology';
import logsRouter from './routes/logs';
import notificationsRouter from './routes/notifications';
import systemRouter from './routes/system';
import settingsRouter from './routes/settings';
import caRouter from './routes/ca';
import countsRouter from './routes/counts';
import { filesRouter, internalFileRepoRouter } from './routes/files';
import { startNotificationsWorker } from './workers/notifications';
import { startTelemetryWorker } from './workers/telemetry';
import { startTelemetryRetentionWorker } from './workers/telemetryRetention';
import { startFirewallEventRetentionWorker } from './workers/firewallEventRetention';
import { startHostStateRetentionWorker } from './workers/hostStateRetention';
import { startPluginDiscovery } from './plugins/discovery';
import { startConfigJobWorker } from './workers/configJob';
import { startPlanExecutorWorker } from './workers/planExecutor';
import { startPlanSchedulerWorker } from './workers/planScheduler';
import { startLogRetentionWorker } from './workers/logRetention';
import { startPluginMetricsWorker } from './workers/pluginMetrics';
import { startNtpReferencesWorker } from './workers/ntpReferences';
import { startGeoIpWorker } from './workers/geoip';
import { startFlowsWorker } from './workers/flows';
import { startInactiveUsersWorker } from './workers/inactiveUsers';
import { LEADER_KEYS, runAsLeader } from './workers/leader';
import { initWorker } from './workers/stats';
import { attachConsoleProxy } from './consoleProxy';
import { setPluginTransports } from './utils/pluginHttp';
import { startApiMtls } from './ca/apiMtls';
import { apiVersion } from './version';
import { db } from './db';

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
  // New permission: keep every pre-existing user able to sign in until an
  // admin explicitly locks them down (service-only accounts).
  await backfillInteractiveLoginPermission();
  // Device-level access control: keep everyone unrestricted until an admin
  // configures scope rules + removes the bypass for a specific account/role.
  await backfillDeviceAllPermission();
  await backfillDeviceSites();
  await backfillSecrets();

  // mTLS (Stage 1): seed the per-endpoint transport registry from the last
  // discovery state so outbound calls pick https+client-cert for plugins that
  // are already mTLS-live — before the first discovery cycle runs.
  try {
    const pluginRows = await db.query.plugins.findMany();
    setPluginTransports(pluginRows.map((p) => ({ endpoint: p.endpoint, tlsLive: p.tlsLive })));
  } catch (err) {
    console.warn('[api] could not seed plugin transport registry:', (err as Error).message);
  }

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

  // Stack identity for the webapp's sidebar (product name + version + build tag).
  // The build tag is baked into the image at CI build time (UNM_BUILD_TAG env,
  // set from the branch/release by docker-publish.yml) and empty for local/dev.
  const infoRouter = express.Router();
  infoRouter.get('/info', (_req, res) => {
    res.status(200).json({
      name: 'UnifiedNetworkManager',
      version: apiVersion(),
      buildTag: process.env.UNM_BUILD_TAG?.trim() || null,
    });
  });

  // Routes not defined in the OpenAPI spec must be mounted ahead of the
  // validator, since the validator 404s any undocumented path. The internal
  // plugin routes are namespaced under /plugin/* (user data included) so they
  // never shadow public paths like POST /users — see routes/internal.ts.
  api.use(infoRouter);
  api.use(configJobsListRouter);
  api.use(internalRouter());
  // Central file repository — internal plugin routes (/plugin/files/*, gated by
  // x-plugin-api-key). Mounted before the OpenAPI validator like the other
  // /plugin/* paths: plugins do repo CRUD here and NEVER touch the volume.
  api.use(internalFileRepoRouter);

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
  // Traffic visibility (Flows page): top talkers, internet egress, device
  // pairs, timeseries + collector stats. All aggregate-table reads only.
  api.use(flowsRouter);
  // GeoIP database status + manual refresh (Settings page "GeoIP" category).
  api.use(geoipRouter);
  // Cross-device mail inventory (/mail/domains, /mail/mailboxes, /mail/aliases).
  api.use(mailRouter);
  // User-maintained host documentation (/documented-hosts + CSV import).
  api.use(documentedHostsRouter);
  // User-maintained network documentation (/documented-networks + CSV import).
  api.use(documentedNetworksRouter);
  // Cross-device update center (/updates: device updates + stack self-update card).
  api.use(updatesRouter);
  // Cross-device security findings (Security page) — actionable checks only.
  api.use(securityChecksRouter);
  // Physical + logical topology graph for the Topology page (self-defining path).
  api.use(topologyRouter);
  // Plugin log entries (global view + per-device section in DeviceDetail).
  api.use(logsRouter);
  // Notification center (bell badge, panel, full page with filters + prefs).
  api.use(notificationsRouter);
  // System/HA observability + runtime tuning (/system/status, /system/settings).
  api.use(systemRouter);
  // Central system settings (the Settings page) — app-wide knobs.
  api.use(settingsRouter);
  // Certificate Authority management (/ca/status, /ca/certificates, /ca/revoke).
  api.use(caRouter);
  // Aggregated nav-badge counts for the sidebar (permission-aware).
  api.use(countsRouter);
  // Central file repository (/files: list/upload/download/delete + usage audit).
  api.use(filesRouter);
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

    // mTLS (Stage 1): enroll the API itself against UNM's step-ca (identity
    // "api") and open a TLS listener on :8443 serving the same app. Gated by
    // UNM_TLS=1 (off by default — plain-HTTP fleets stay untouched). Non-fatal:
    // while the CA is down the API keeps serving plain HTTP on :3000 and talks
    // to plugins over http; enrollment retries every 30s in the background.
    if (process.env.UNM_TLS === '1') {
      void startApiMtls(app, {
        onServer: (server) => attachConsoleProxy(server),
      }).catch((err) => console.warn(`[api] mTLS not live yet: ${(err as Error).message}`));
    } else {
      console.log('[api] UNM_TLS not set — skipping API self-enrollment (plain HTTP only)');
    }

    startConfigJobWorker();

    void runAsLeader(LEADER_KEYS.telemetry, 'telemetry', () => startTelemetryWorker()).then((stop) => workerStops.push(stop));
    void runAsLeader(LEADER_KEYS.planExecutor, 'planExecutor', () => startPlanExecutorWorker()).then((stop) => workerStops.push(stop));
    // Scheduled plans: flips due 'scheduled' plans to executing (leader-gated).
    void runAsLeader(LEADER_KEYS.planScheduler, 'planScheduler', () => startPlanSchedulerWorker()).then((stop) => workerStops.push(stop));
    void runAsLeader(LEADER_KEYS.retention, 'retention', () => {
      const stopLogs = startLogRetentionWorker();
      return () => stopLogs();
    }).then((stop) => workerStops.push(stop));
    void runAsLeader(LEADER_KEYS.telemetryRetention, 'telemetryRetention', () => {
      const timer = startTelemetryRetentionWorker();
      return () => clearInterval(timer);
    }).then((stop) => workerStops.push(stop));
    // Firewall event-log retention (append-only log pushed via /plugin/firewall-events).
    void runAsLeader(LEADER_KEYS.firewallEventRetention, 'firewallEventRetention', () => {
      const timer = startFirewallEventRetentionWorker();
      return () => clearInterval(timer);
    }).then((stop) => workerStops.push(stop));
    // Per-host state snapshot retention (append-only log pushed via /plugin/host-states).
    void runAsLeader(LEADER_KEYS.hostStateRetention, 'hostStateRetention', () => {
      const timer = startHostStateRetentionWorker();
      return () => clearInterval(timer);
    }).then((stop) => workerStops.push(stop));
    void runAsLeader(LEADER_KEYS.pluginMetrics, 'pluginMetrics', () => startPluginMetricsWorker()).then((stop) => workerStops.push(stop));
    // Public NTP reference polling (Time page "Time base" card — fleet time-base check).
    void runAsLeader(LEADER_KEYS.ntpReferences, 'ntpReferences', () => startNtpReferencesWorker()).then((stop) => workerStops.push(stop));
    // Notification maintenance: auto-resolve recovered device states + retention.
    void runAsLeader(LEADER_KEYS.notifications, 'notifications', () => startNotificationsWorker()).then((stop) => workerStops.push(stop));
    // Inactivity auto-disable (credential policy inactiveDisableAfterDays).
    void runAsLeader(LEADER_KEYS.inactiveUsers, 'inactiveUsers', () => startInactiveUsersWorker()).then((stop) => workerStops.push(stop));
    // Flow data: drains the POST /plugin/flows queue into flow_micro and runs
    // the 5m/hourly rollups + partition maintenance (sFlow/NetFlow feature).
    void runAsLeader(LEADER_KEYS.flows, 'flows', () => startFlowsWorker()).then((stop) => workerStops.push(stop));

    // GeoIP database refresh (leader-gated; cadence from geoipFetchIntervalHours).
    void runAsLeader(LEADER_KEYS.geoip, 'geoip', () => startGeoIpWorker()).then((stop) => workerStops.push(stop));

    // CA config rendering: the API owns ca.json (rendered from global settings)
    // on the shared volume; the CA service SIGHUPs itself when it changes.
    // The CA container may not have bootstrapped its PKI yet at our first write,
    // so retry until it succeeds — after that, setting changes re-render via
    // their onChange hooks (systemSettings.ts).
    let caRenderWarned = false;
    const renderCaConfig = async (): Promise<boolean> => {
      try {
        const { changed } = await require('./ca/stepCaConfig').writeStepCaConfig();
        if (changed) console.log('[api] rendered CA config from global settings');
        return true;
      } catch (err) {
        // Volume not mounted / PKI not bootstrapped yet — retry on next beat.
        const e = err as { message?: string };
        if (!caRenderWarned) {
          caRenderWarned = true;
          console.log(`[api] CA config render deferred (CA service not ready?): ${e.message}`);
        }
        return false;
      }
    };
    void (async () => {
      for (;;) {
        if (await renderCaConfig()) break;
        await new Promise((r) => setTimeout(r, 15_000));
      }
    })();

    // Discover plugins. Primary path: plugins SELF-REGISTER (POST /plugin/register,
    // SDK startRegistration) and land in the plugins table — no UNM-side catalog
    // of plugin endpoints exists anymore. The discovery worker re-reads that
    // table every cycle (registeredEndpoints) and polls each endpoint for
    // liveness + descriptor refresh; mDNS is a second path on networks where
    // multicast reaches. PLUGIN_POLL_ENDPOINTS remains only as an optional
    // legacy fallback for topologies where a plugin cannot reach the API at all.
    const staticPollEndpoints = (process.env.PLUGIN_POLL_ENDPOINTS ?? '')
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean);
    initWorker('discovery', LEADER_KEYS.discovery);
    void runAsLeader(LEADER_KEYS.discovery, 'discovery', () => {
      const stopDiscovery = startPluginDiscovery({
        pollEndpoints: staticPollEndpoints,
        seededEndpoints: require('./plugins/discovery').registeredEndpoints,
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
