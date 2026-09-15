/**
 * @unm/plugin-sdk — shared SDK for UnifiedNetworkManager plugins.
 *
 * Single entry point: contract types + runtime helpers. See docs/PLUGIN-DEVELOPMENT.md
 * for the full developer guide and plugins/_template for a copy-paste starting point.
 */

export * from './types';
export { resolvePluginIdentity, DEFAULT_PLUGIN_PORT } from './identity';
export type { PluginIdentity, PluginIdentityInput } from './identity';
export { createPluginServer, buildDiscoverPayload, requirePluginKey, stateHandler, probeHandler, filesystemHandler } from './server';
export type { PluginServerOptions, PluginServer, DiscoveryExtras } from './server';
// Interactive SSH console (capability 'sshConsole'): PTY sessions + pool (terminal.ts)
// and the WebSocket bridge helper plugins pass to createPluginServer (consoleWs.ts).
export { SshTerminalSession, SshTerminalConnection, createTerminalPool } from './terminal';
export type { TerminalCredentials, TerminalPtyOptions, TerminalConnectionOptions, TerminalPool, TerminalPoolOptions } from './terminal';
export { makeConsoleUpgrade } from './consoleWs';
export type { ConsoleEndpointOptions, ConsoleUpgradeHandler } from './consoleWs';
export { readSettings, readGlobalSettings, clampInt, hostFromAddress, pickString, pickNumber, pickBool, normalizeMac, resolveUserPass } from './settings';
export type { UserPassCreds, ResolveUserPassResult } from './settings';
// Outbound device-HTTP shared layer (endpoint resolution + TLS/error primitives). See http.ts.
export { withPort, resolveEndpointCandidates, toWsUrl, insecureHttpsAgent, isNetworkLevelError, basicAuthHeader } from './http';
export type { DeviceApiResult, EndpointTransport, EndpointPorts, EndpointOptions } from './http';
export { suggestPortLayout, portNumberFromKey } from './portLayout';
export { INVENTORY_INTERVAL_MS, errorDescriptor, modelFirmwareDescriptors, gaugeMetric, textMetric, tableMetric } from './metrics';
export { validateInput, isValidInput, createRegistry } from './actions';
export type { ValidationIssue, ActionDescriptor, ActionRegistry } from './actions';
export { PlanningError, STEP_TOKEN_PATTERN, shiftStepTokens, finalizePlan } from './planning';
export { pollUntil, stateEquals } from './verification';
export type { PollUntilOptions, PollUntilResult } from './verification';
export type { FinalizePlanOptions } from './planning';
export { CounterTracker } from './rates';
export type { CounterTrackerOptions } from './rates';
export { TtlCache } from './ttlCache';
export type { TtlCacheOptions } from './ttlCache';
export { createApiClient, isNotFound } from './apiClient';
export type { ApiClientOptions } from './apiClient';
export { createPluginLogger, warnOnce, LOG_LEVELS } from './logging';
export type { PluginLogger, PluginLoggerOptions, PluginLogEntry, LogLevel, LogCallOptions } from './logging';
export { createNotifier, NOTIFICATION_SEVERITIES } from './notifications';
export type { PluginNotifier, NotifierOptions, PluginNotification, NotificationSeverity } from './notifications';
export { createSelfMetrics } from './selfMetrics';
export type { PluginSelfMetrics, SelfMetricsOptions, SelfMetricsLoggerLike } from './selfMetrics';
// Device clock / timezone contract for the Time page (see deviceTime.ts).
export { parseDeviceTimeToEpochMs, buildDeviceTimeInfo, ianaZoneToOffsetMinutes, parseLooseDeviceDatetime, tzAbbrToOffsetMinutes, TZ_ABBR_OFFSET_MINUTES } from './deviceTime';
export type { DeviceTimeInfo, LooseDeviceDatetime } from './deviceTime';// SSH access for plugins (shared transport + credential resolution). See ssh.ts.
export { SshClient, createSshPool, resolveSshCredentials, normalizeFingerprint, fingerprintMatches, computeFingerprint, normalizePrivateKey } from './ssh';
export type { SshCredentials, SshClientOptions, ExecResult, SshPool, SshPoolOptions, SshFingerprint } from './ssh';
export { SshError, SshAuthError, SshHostKeyError, SshTimeoutError } from './ssh';
// SFTP file-system access for plugins (shared transport + path safety). See sftp.ts.
export { SftpSession, createSftpPool, resolvePath, SftpPathError } from './sftp';
export type { SftpCredentials, SftpSessionOptions, SftpPool, SftpPoolOptions, FsEntry, FsListResult, FsStat } from './sftp';// Certificate collection + chain validation for the Certificates page. See certificates.ts.
export { parseCertificate, validateChain, probeTlsEndpoint, probeSshHostKey, collectDeviceCertificates, collectCertificatesForBaseUrl, parseProbeTarget } from './certificates';
export type { CertificateInfo, RawCertificate, CertificateRow, TlsProbeOptions, TlsProbeResult, SshProbeOptions, SshProbeResult, DeviceCertOptions, ChainValidation } from './certificates';
// Certificate/host-key PINNING — refuse connections whose key differs from UNM's inventory. See pinning.ts.
export { pinningContextFromRequest, knownFingerprint, verifyTlsFingerprint, verifyEndpointForRequest, endpointUsesTls, createPinningGuard, rememberPinningContext, currentPinningContextFor, dynamicSshHostVerifier, makeSshHostVerifier, resolveSshPinnedFingerprint, normalizeCertFingerprint, certFingerprintMatches, endpointKey, recordObservedFingerprint, observedFingerprintFor, sshPinningErrorMessage, CertificatePinningError, resolveHttpsPort, resolveHttpPort, resolveSshPort } from './pinning';
export type { PinningMode, KnownCertificate, PinningContext, TlsPreflightOptions, TlsPreflightResult, EndpointCheckOptions, PinningGuard, PinningGuardOptions, PinningPorts } from './pinning';