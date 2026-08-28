/**
 * Minimal type declarations for the `net-snmp` npm package (pure JS, ships no
 * types). Covers exactly what @unm/snmp-client uses: sessions (get/set/walk/
 * subtree), varbind helpers, protocol constants — plus the Agent API used by
 * smoke-test.ts. Keep in sync with net-snmp@3.x.
 */
declare module 'net-snmp' {
  export interface VarBind {
    oid: string; // dotted OID, no leading dot
    type: number; // one of ObjectType.*
    value: unknown; // number | string | Buffer | boolean | null — see ObjectType
  }

  export interface SessionOptions {
    port?: number;
    retries?: number;
    /** Per-request timeout in ms (grows by `backoff` per retry). */
    timeout?: number;
    backoff?: number;
    transport?: string;
    version?: number; // Version1 | Version2c — createSession defaults to v1!
    idBitsSize?: number;
    context?: string;
    sourceAddress?: string;
    sourcePort?: number;
    engineID?: string | Buffer;
    debug?: boolean;
  }

  /**
   * v3 USM user. authKey/privKey hold PASSPHRASES, not keys — the library
   * derives the localized keys itself (RFC 3414 A.2.1), same as `snmpwalk -A/-X`.
   */
  export interface V3User {
    name: string;
    level: number; // SecurityLevel.*
    authProtocol?: number; // AuthProtocols.*
    authKey?: string;
    privProtocol?: number; // PrivProtocols.*
    privKey?: string;
  }

  export class Session {
    get(oids: string[], cb: (err: Error | null, varbinds?: VarBind[]) => void): this;
    getNext(oids: string[], cb: (err: Error | null, varbinds?: VarBind[]) => void): this;
    getBulk(
      oids: string[],
      nonRepeaters: number,
      maxRepetitions: number,
      cb: (err: Error | null, varbinds?: unknown) => void
    ): this;
    set(varbinds: { oid: string; type: number; value: unknown }[], cb: (err: Error | null, varbinds?: VarBind[]) => void): this;
    /** Walks to EndOfMibView — does NOT stop at subtree boundaries. Prefer subtree(). */
    walk(oid: string, maxRepetitions?: number, feedCb?: (varbinds: VarBind[]) => boolean, doneCb?: (err?: Error | null) => void): this;
    /** Walks only the subtree under `oid` (snmpwalk CLI semantics). feedCb gets a varbind array per batch; return true to stop early. */
    subtree(oid: string, maxRepetitions?: number, feedCb?: (varbinds: VarBind[]) => boolean, doneCb?: (err?: Error | null) => void): this;
    /** Closes the UDP socket and cancels in-flight requests. */
    close(): this;
  }

  export function createSession(target: string, community: string, options?: SessionOptions): Session;
  export function createV3Session(target: string, user: V3User, options?: SessionOptions): Session;

  /** True for NoSuchObject / NoSuchInstance / EndOfMibView varbinds. */
  export function isVarbindError(vb: VarBind): boolean;
  /** Human-readable error text for an error varbind (e.g. "NoSuchObject: oid"). */
  export function varbindError(vb: VarBind): string;

  export const Version1: number;
  export const Version2c: number;
  export const Version3: number;

  export const SecurityLevel: { noAuthNoPriv: number; authNoPriv: number; authPriv: number };
  export const AuthProtocols: { none: number; md5: number; sha: number; sha224: number; sha256: number; sha384: number; sha512: number };
  export const PrivProtocols: { none: number; des: number; aes: number; aes256b: number; aes256r: number };

  /** Boolean/Integer/OctetString/OID/IpAddress/Counter/Gauge/TimeTicks/Counter64/NoSuchObject/… + Integer32/Counter32/Gauge32/Unsigned32 aliases. */
  export const ObjectType: Record<string, number>;

  /* --- Agent API (used by smoke-test.ts only) --- */

  export interface MibProviderScalar {
    name: string;
    type: number; // MibProviderType.Scalar
    oid: string;
    scalarType: number; // ObjectType.*
    maxAccess?: number; // MaxAccess.*
    defVal?: unknown;
    constraints?: unknown;
    createHandler?: null | ((req: unknown) => unknown);
  }

  export interface TableColumnDef {
    number: number;
    name: string;
    type: number; // ObjectType.*
    maxAccess?: number;
    rowStatus?: boolean;
    defVal?: unknown;
    constraints?: unknown;
  }

  export interface MibProviderTable {
    name: string;
    type: number; // MibProviderType.Table
    oid: string;
    tableColumns: TableColumnDef[];
    tableIndex: ({ columnName: string } | number)[];
    maxAccess?: number;
    handler?: (req: { done(err?: unknown): void }) => void;
    createHandler?: null | ((req: unknown) => unknown[] | undefined);
  }

  export interface AgentMib {
    setScalarValue(name: string, value: unknown): void;
    getScalarValue(name: string): unknown;
    addTableRow(table: string, row: unknown[]): void;
  }

  export interface Authorizer {
    addCommunity(community: string): void;
    addUser(user: V3User): void;
    getAccessControlModel(): {
      setCommunityAccess(community: string, level: number): void;
      setUserAccess(userName: string, level: number): void;
    };
  }

  export interface Agent {
    registerProvider(provider: MibProviderScalar | MibProviderTable): void;
    getMib(): AgentMib;
    getAuthorizer(): Authorizer;
    close(cb?: () => void): void;
  }

  export function createAgent(
    options: { port?: number; address?: string | null; transport?: string; engineID?: string; disableAuthorization?: boolean; accessControlModelType?: number },
    callback?: (err: Error | null, data?: unknown) => void
  ): Agent;

  export const AccessControlModelType: { None: number; Simple: number };
  export const AccessLevel: { None: number; ReadOnly: number; ReadWrite: number };
  export const MibProviderType: { Scalar: number; Table: number };
  /** 'not-accessible' | 'accessible-for-notify' | 'read-only' | 'read-write' | 'read-create'. */
  export const MaxAccess: Record<string, number>;
}
