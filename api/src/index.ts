import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import * as OpenApiValidator from 'express-openapi-validator';
import { loadOpenApiSpec, resolveOpenApiPath } from './openapi';
import { initDb } from './db';
import authRouter from './routes/auth';
import devicesRouter from './routes/devices';
import pluginsRouter from './routes/plugins';
import { internalRouter } from './routes/internal';
import configJobsRouter, { configJobsListRouter } from './routes/configJobs';
import { startTelemetryWorker } from './workers/telemetry';
import { startConfigJobWorker } from './workers/configJob';

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

  const spec = loadOpenApiSpec();
  const specPath = resolveOpenApiPath();

  const app = express();
  app.use(helmet());
  app.use(cors());
  app.use(express.json());

  app.get('/healthz', (_req, res) => {
    res.status(200).json({ status: 'ok' });
  });

  const api = express.Router();
  api.use(generalLimiter);

  // Convenience endpoint (not defined in the OpenAPI spec) must be mounted
  // ahead of the validator, since the validator 404s any undocumented path.
  api.use(configJobsListRouter);

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
  api.use(internalRouter());
  api.use(configJobsRouter);

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

  app.listen(PORT, () => {
    // eslint-disable-next-line no-console
    console.log(`[api] UnifiedNetworkManager API listening on port ${PORT}`);
    // eslint-disable-next-line no-console
    console.log(`[api] OpenAPI spec loaded from ${specPath}`);
  });

  startTelemetryWorker();
  startConfigJobWorker();
}

main().catch((err) => {
  // eslint-disable-next-line no-console
  console.error('[api] fatal startup error:', err);
  process.exit(1);
});
