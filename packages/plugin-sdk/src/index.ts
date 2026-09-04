/**
 * @unm/plugin-sdk — shared SDK for UnifiedNetworkManager plugins.
 *
 * Single entry point: contract types + runtime helpers. See docs/PLUGIN-DEVELOPMENT.md
 * for the full developer guide and plugins/_template for a copy-paste starting point.
 */

export * from './types';
export { resolvePluginIdentity, DEFAULT_PLUGIN_PORT } from './identity';
export type { PluginIdentity, PluginIdentityInput } from './identity';
export { createPluginServer, buildDiscoverPayload, requirePluginKey, stateHandler } from './server';
export type { PluginServerOptions, PluginServer, DiscoveryExtras } from './server';
export { readSettings, clampInt, hostFromAddress, pickString, pickNumber } from './settings';
export { suggestPortLayout, portNumberFromKey } from './portLayout';
export { INVENTORY_INTERVAL_MS, errorDescriptor, modelFirmwareDescriptors, gaugeMetric, textMetric, tableMetric } from './metrics';
export { validateInput, isValidInput, createRegistry } from './actions';
export type { ValidationIssue, ActionDescriptor, ActionRegistry } from './actions';
export { PlanningError, STEP_TOKEN_PATTERN, shiftStepTokens, finalizePlan } from './planning';
export type { FinalizePlanOptions } from './planning';
export { CounterTracker } from './rates';
export type { CounterTrackerOptions } from './rates';
export { TtlCache } from './ttlCache';
export type { TtlCacheOptions } from './ttlCache';
export { createApiClient, isNotFound } from './apiClient';
export type { ApiClientOptions } from './apiClient';
export { createPluginLogger, LOG_LEVELS } from './logging';
export type { PluginLogger, PluginLoggerOptions, PluginLogEntry, LogLevel, LogCallOptions } from './logging';
export { createNotifier, NOTIFICATION_SEVERITIES } from './notifications';
export type { PluginNotifier, NotifierOptions, PluginNotification, NotificationSeverity } from './notifications';
export { createSelfMetrics } from './selfMetrics';
export type { PluginSelfMetrics, SelfMetricsOptions, SelfMetricsLoggerLike } from './selfMetrics';// SSH access for plugins (shared transport + credential resolution). See ssh.ts.
export { SshClient, createSshPool, resolveSshCredentials, normalizeFingerprint, fingerprintMatches, computeFingerprint } from './ssh';
export type { SshCredentials, SshClientOptions, ExecResult, SshPool, SshPoolOptions, SshFingerprint } from './ssh';
export { SshError, SshAuthError, SshHostKeyError, SshTimeoutError } from './ssh';