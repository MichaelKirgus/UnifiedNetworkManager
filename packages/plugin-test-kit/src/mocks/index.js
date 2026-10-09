/** @unm/plugin-test-kit — shared mock appliances (re-export barrel). */

export { startHttpMock } from './httpMock.js';
export { startNtpMock } from './ntpMock.js';
export { startDockerDaemonMock } from './dockerMock.js';
// Phase 2 — plain-HTTP appliance mocks for the REST-based plugins.
export {
  startOpnsenseMock,
  startMailcowMock,
  startZabbixMock,
  startFboxMock,
  startOpenwrtMock,
  startRouterOsMock,
} from './applianceHttp.js';
// Phase 2 — TrueNAS JSON-RPC-over-WebSocket appliance.
export { startTruenasMock } from './truenasMock.js';
// Phase 3 — in-process SSH appliance (ssh2 Server) for the SSH-collecting plugins.
export { startSshMock } from './sshMock.js';
// Phase 3 — pure-JS SNMP v2c agent (RFC 3416 wire format) for the LANCOM plugins.
export { startSnmpMock } from './snmpMock.js';
