/**
 * Action contract for the OpenWRT plugin.
 *
 * An "action" is one unit of work against an appliance, described declaratively
 * so /discover advertises the catalog, /plan composes multi-device intents and
 * /config dispatches a single step to its executor — one registry serves all
 * three (the API never interprets payloads).
 *
 * OpenWRT-specific: every WRITE action executes over SSH (uci + service
 * reloads) regardless of the negotiated read transport — uci syntax is
 * version-stable while LuCI's CGI save endpoints are not. In forced 'luci'
 * mode (or without a usable SSH credential) write actions fail with an
 * actionable error instead of silently degrading.
 */

import type { ActionDescriptor as SdkActionDescriptor, StepCredentials } from '@unm/plugin-sdk';
import { validateInput } from '@unm/plugin-sdk';
import type { ActionResult, CatalogEntry, InputSchema, Plan, PlanStep, ProvisionRequest, RiskLevel } from '@unm/plugin-sdk';
import type { Backend } from '../client/backend';

export type { ActionResult, CatalogEntry, InputSchema, Plan, PlanStep, ProvisionRequest, RiskLevel };
export { validateInput };

/** Everything an action executor needs to run against one appliance. */
export interface ActionContext {
  /** The negotiated data path (LuCI + SSH as available for this request). */
  backend: Backend;
  host: string;
  deviceId?: string;
  /** Assignment credentials incl. provisioned plan material namespaced by ref. */
  credentials: StepCredentials;
}

/** True when the context has a usable SSH path (required for all writes). */
export function sshAvailable(ctx: ActionContext): boolean {
  return ctx.backend.ssh !== null;
}

/** Standard failure result for write actions without an SSH path. */
export function noSshResult(): ActionResult {
  return {
    success: false,
    error: 'Configuration writes require the SSH transport — bind a username/password (or key pair) credential and set transport to auto or ssh.',
  };
}

/** A fully-described action (SDK descriptor + OpenWRT extensions). */
export interface ActionDescriptor extends SdkActionDescriptor<ActionContext> {
  /** True when the change is staged and needs an explicit apply/reconfigure. */
  staged?: boolean;
}
