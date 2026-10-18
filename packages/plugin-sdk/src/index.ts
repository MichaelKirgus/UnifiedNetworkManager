/**
 * @unm/plugin-sdk — shared SDK for UnifiedNetworkManager plugins.
 *
 * Single entry point: contract types + runtime helpers. See docs/PLUGIN-DEVELOPMENT.md
 * for the full developer guide and plugins/_template for a copy-paste starting point.
 */

export * from './types';
export { resolvePluginIdentity, DEFAULT_PLUGIN_PORT } from './identity';
export type { PluginIdentity, PluginIdentityInput } from './identity';
export { createPluginServer, buildDiscoverPayload, requirePluginKey, stateHandler, probeHandler, filesystemHandler, quickActionHandler } from './server';
export type { TlsEnrollHandle } from './server';
export type { PluginServerOptions, PluginServer, DiscoveryExtras } from './server';
// Push-based self-registration with the UNM API (POST /plugin/register) — the
// primary discovery mechanism; no pre-configured endpoint list needed. See register.ts.
export { startRegistration, registerWithApi } from './register';
export type { RegisterOptions } from './register';
// Interactive SSH console (capability 'sshConsole'): PTY sessions + pool (terminal.ts)
// and the WebSocket bridge helper plugins pass to createPluginServer (consoleWs.ts).
export { SshTerminalSession, SshTerminalConnection, createTerminalPool } from './terminal';
export type { TerminalCredentials, TerminalPtyOptions, TerminalConnectionOptions, TerminalPool, TerminalPoolOptions } from './terminal';
export { makeConsoleUpgrade } from './consoleWs';
export type { ConsoleEndpointOptions, ConsoleUpgradeHandler } from './consoleWs';
export { readSettings, readGlobalSettings, clampInt, hostFromAddress, pickString, pickNumber, pickBool, normalizeMac, resolveUserPass } from './settings';
export type { UserPassCreds, ResolveUserPassResult } from './settings';
// IP address math — the ONE place that parses IPv4/IPv6 literals and does CIDR
// containment / network-address / scope (loopback, link-local, private,
// multicast, public) classification. Pure + browser-safe; the webapp keeps a
// documented mirror at webapp/src/utils/ip.ts. See ip.ts.
export { stripZoneId, ipFamily, ipv4ToInt, ipv4FromInt, ipv6ToWords, ipv6FromWords, ipv6ToBigInt, ipv6FromBigInt, splitCidr, ipInCidr, cidrsOverlap, v4PrefixMatch, v6PrefixMatch, subnetOf, isPrivateIpv4, isLoopbackIpv4, isLinkLocalIpv4, isMulticastIpv4, isReservedIpv4, isUlaIpv6, isLoopbackIpv6, isLinkLocalIpv6, isMulticastIpv6, isDocumentationIpv6, isPublicIpv4, isPublicIpv6, ipScope, nextFreeAddressInCidr } from './ip';
export type { IpScope } from './ip';
// Outbound device-HTTP shared layer (endpoint resolution + TLS/error primitives). See http.ts.
export { withPort, resolveEndpointCandidates, toWsUrl, buildWebUiUrl, insecureHttpsAgent, isNetworkLevelError, isTransientTransportError, basicAuthHeader } from './http';
export type { DeviceApiResult, EndpointTransport, EndpointPorts, EndpointOptions, WebUiUrlOptions } from './http';
export { suggestPortLayout, portNumberFromKey } from './portLayout';
export { INVENTORY_INTERVAL_MS, errorDescriptor, modelFirmwareDescriptors, gaugeMetric, textMetric, tableMetric } from './metrics';
export { validateInput, isValidInput, createRegistry } from './actions';
export type { ValidationIssue, ActionDescriptor, ActionRegistry } from './actions';
export { PlanningError, STEP_TOKEN_PATTERN, shiftStepTokens, finalizePlan, SYSTEM_STEP_WAIT, SYSTEM_STEP_INVENTORY_REFRESH, isSystemStepAction, appendSettleAndRefresh } from './planning';
// Canonical fleet intents (cross-vendor network rollout contract). See intents.ts.
export { INTENT_NETWORK_CREATE, INTENT_NETWORK_DELETE, CANONICAL_INTENTS, isCanonicalIntent, NETWORK_CREATE_SCHEMA, NETWORK_DELETE_SCHEMA, CANONICAL_INTENT_SCHEMAS } from './intents';
export type { PreflightConfidence, PreflightValue, PreflightResult, PreflightRequest, PreflightPort, PreflightInterfaceOption, PreflightCapabilities } from './intents';
// L2 topology abstraction (interface layering: ports → bundles/bridges). See intents.ts.
export { INTENT_L2_TOPOLOGY_READ, suggestL2AttachPoint, suggestL2VlanPorts, portTrunkStatus } from './intents';
export type { L2PhysicalPort, L2Bridge, L2Bundle, L2Topology } from './intents';
// Device support metadata + effective-capability evaluation (license/help/docs,
// supported-device matrix with feature/slot/firmware gating). See deviceSupport.ts.
export { DETECTED_FEATURES_METRIC_KEY, matchSupportProfile, describeProfile, evaluateDeviceSupport } from './deviceSupport';
export type { PluginLicense, SupportCondition, SupportCapabilityGrant, SupportIntentGrant, DeviceSupportProfile, DeviceSupport, CapabilityEvaluation, DeviceSupportContext, DeviceSupportEvaluation } from './deviceSupport';
export { pollUntil, stateEquals } from './verification';
export type { PollUntilOptions, PollUntilResult } from './verification';
export type { FinalizePlanOptions } from './planning';
export { CounterTracker } from './rates';
export type { CounterTrackerOptions } from './rates';
export { TtlCache } from './ttlCache';
export type { TtlCacheOptions } from './ttlCache';
export { createApiClient, isNotFound } from './apiClient';
export type { ApiClientOptions } from './apiClient';
// Central file repository client (capability 'fileRepo'): the ONE implementation of
// the API's /plugin/files/* contract — list/get/upload/remove/recordUse. See fileRepo.ts.
export { createFileRepoClient } from './fileRepo';
export type { FileRepoEntry, FileRepoClient, FileRepoClientOptions } from './fileRepo';
// Shared config-backup naming convention (all vendors store backups in the same
// <device>__config-backup-<UTC-timestamp>.<ext> pattern). See configBackup.ts.
export { configBackupFileName, sanitizeBackupDevicePart, backupTimestamp } from './configBackup';
export type { ConfigBackupNameOptions } from './configBackup';
export { createPluginLogger, warnOnce, LOG_LEVELS } from './logging';
export type { PluginLogger, PluginLoggerOptions, PluginLogEntry, LogLevel, LogCallOptions } from './logging';
export { createNotifier, NOTIFICATION_SEVERITIES } from './notifications';
export type { PluginNotifier, NotifierOptions, PluginNotification, NotificationSeverity } from './notifications';
export { createSelfMetrics } from './selfMetrics';
export type { PluginSelfMetrics, SelfMetricsOptions, SelfMetricsLoggerLike } from './selfMetrics';
// Device clock / timezone contract for the Time page (see deviceTime.ts).
export { parseDeviceTimeToEpochMs, buildDeviceTimeInfo, ianaZoneToOffsetMinutes, parseLooseDeviceDatetime, tzAbbrToOffsetMinutes, TZ_ABBR_OFFSET_MINUTES } from './deviceTime';
export type { DeviceTimeInfo, LooseDeviceDatetime } from './deviceTime';
// NTP/SNTP client (RFC 1305/4330) — query a device's time service for the
// instant it serves. See ntp.ts.
export { queryNtp } from './ntp';
export type { NtpQueryResult } from './ntp';
// Update gathering (capability 'updates'): row contract + version comparison +
// SSH package-manager adapters. See updates.ts.
export { compareVersions, isUpdateAvailable, firmwareRow, extractMajorMinor, latestCatalogLine, catalogFirmwareRow, PACKAGE_MANAGER_ADAPTERS, detectPackageManager, readOsReleaseIds, listUpgradablePackages, listInstalledPackages, readAlpineRelease, runPackageUpgrade, runPackageUpgradeList, holdPackages, unholdPackages, listHeldPackages, runForceFullUpgrade, packageRequiresReboot, buildDetachedUpgradeScript, buildUpgradeStatusScript, parseDetachedUpgradeStatus, UPGRADE_DONE_MARKER, DETACHED_ALREADY_RUNNING_EXIT } from './updates';
export type { InstalledPackage, InstalledPackagesResult } from './updates';
export type { UpdateKind, UpdateRow, UpdateExecBackend, UpgradablePackage, PmAdapter, SshUpdatesOptions, PackageUpgradeResult, DetachedUpgradeStatus } from './updates';
// Security checks (capability 'securityChecks'): row contract for the cross-device
// Security page. See security.ts.
export type { SecurityCheckKind, SecurityCheckRow } from './security';
// GPU detection + live metrics (generic `gpus[]` metric): PCI enumeration over
// sysfs + nvidia-smi / rocm-smi parsers — vendor-neutral (NVIDIA/AMD/Intel). See gpu.ts.
export { collectGpuRows, buildGpuProbeScript, parsePciGpuSection, parseNvidiaSmiSection, normalizeNvidiaSlot, detectGpuVendor, gpuNameFromPci } from './gpu';
export type { GpuRow, GpuExecBackend, PciGpuEntry } from './gpu';
// Generic plugin state store — persistent opaque JSON blobs in the UNM database
// across polls/restarts (baselines, counters, TOFU fingerprints). See stateStore.ts.
export { createPluginStateStore } from './stateStore';
export type { PluginStateStore, PluginStateEntry, PluginStateRow, PluginStateStoreOptions } from './stateStore';
// SSH access for plugins (shared transport + credential resolution). See ssh.ts.
export { SshClient, createSshPool, resolveSshCredentials, resolveSlotFields, resolveRootSlotCredentials, wrapSudo, probePrivilege, shQuote, normalizeFingerprint, fingerprintMatches, computeFingerprint, normalizePrivateKey } from './ssh';
export type { SshCredentials, SshClientOptions, ExecResult, SshPool, SshPoolOptions, SshFingerprint, SudoExecBackend, PrivilegeMode, PrivilegeProbe } from './ssh';
export { SshError, SshAuthError, SshHostKeyError, SshTimeoutError } from './ssh';
// SFTP file-system access for plugins (shared transport + path safety). See sftp.ts.
export { SftpSession, createSftpPool, resolvePath, SftpPathError } from './sftp';
export type { SftpCredentials, SftpSessionOptions, SftpPool, SftpPoolOptions, FsEntry, FsListResult, FsStat } from './sftp';// Certificate collection + chain validation for the Certificates page. See certificates.ts.
export { parseCertificate, validateChain, probeTlsEndpoint, probeSshHostKey, collectDeviceCertificates, collectCertificatesForBaseUrl, parseProbeTarget } from './certificates';
export type { CertificateInfo, RawCertificate, CertificateRow, TlsProbeOptions, TlsProbeResult, SshProbeOptions, SshProbeResult, DeviceCertOptions, ChainValidation } from './certificates';
// Service-inventory contract for the Services page (see services.ts).
export { SERVICE_STATUSES } from './services';
export type { ServiceType, ServiceStatus, ServiceRow } from './services';
// Certificate/host-key PINNING — refuse connections whose key differs from UNM's inventory. See pinning.ts.
export { pinningContextFromRequest, knownFingerprint, verifyTlsFingerprint, verifyEndpointForRequest, endpointUsesTls, createPinningGuard, rememberPinningContext, currentPinningContextFor, dynamicSshHostVerifier, makeSshHostVerifier, resolveSshPinnedFingerprint, normalizeCertFingerprint, certFingerprintMatches, endpointKey, recordObservedFingerprint, observedFingerprintFor, sshPinningErrorMessage, CertificatePinningError, resolveHttpsPort, resolveHttpPort, resolveSshPort } from './pinning';
export type { PinningMode, KnownCertificate, PinningContext, TlsPreflightOptions, TlsPreflightResult, EndpointCheckOptions, PinningGuard, PinningGuardOptions, PinningPorts } from './pinning';
// mTLS (Stage 1): minimal RFC 8555 ACME client for UNM's step-ca + the
// enrollment/cert-lifecycle helper. See acmeClient.ts / tlsIdentity.ts.
export { AcmeClient, AcmeError, buildCsr, derToRawSig, jwkThumbprint } from './acmeClient';
export type { AcmeDirectory, AcmeChallenge, AcmeAuthorization, AcmeOrder, AcmeClientOptions } from './acmeClient';
export { ensureTlsIdentity, scheduleTlsRenewal, describeTlsCert, describeLeaf } from './tlsIdentity';
export type { TlsIdentity, TlsIdentityOptions, TlsCertInfo } from './tlsIdentity';
// Client-only mTLS enrollment (services that present a leaf but never serve TLS). See clientMtls.ts.
export { startClientMtls } from './clientMtls';
export type { ClientMtlsHandle, ClientMtlsOptions } from './clientMtls';