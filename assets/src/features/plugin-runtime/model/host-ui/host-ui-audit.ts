import {
  PluginHostRpcError,
  type PluginHostRpcContext,
  type PluginHostRpcHandlerOwnerDescriptor,
  type PluginHostRpcSession,
} from "../../lib/host-rpc/host-rpc";
import {
  pluginAuditSucceeded,
  type PluginAuditSink,
} from "../../lib/capability/capability-enforcement";
import { isPluginRuntimeWorkspaceRevoking } from "../../lib/runtime-boundary/runtime-workspace-revocation";
import { contextOwnerDescriptor, ownerKey, pluginContributionId } from "./host-ui-identity";
import type {
  PluginHostUiServices,
  PluginUiCommandRef,
  PluginUiRegistryEntry,
  PluginUiSurface,
} from "./host-ui";

export type PluginUiCommandInvocationAudit =
  | ((entry: PluginUiRegistryEntry) => Promise<void> | void)
  | {
      accepted(entry: PluginUiRegistryEntry): Promise<void> | void;
      rejected?(
        entry: PluginUiRegistryEntry | null,
        ref: PluginUiCommandRef,
        reasonCode: string,
      ): Promise<void> | void;
    };

interface PluginUiAuditDetails {
  type:
    | "plugin.ui.registration.accepted"
    | "plugin.ui.registration.rejected"
    | "plugin.ui.invocation.accepted"
    | "plugin.ui.invocation.rejected"
    | "plugin.ui.registry_entry_disposed"
    | "plugin.ui.iframe.closed_with_live_entries"
    | "plugin.ui.iframe.lifecycle";
  payloadKind: "ui.contribution" | "ui.command";
  contributionId: string;
  localId: string;
  surface: PluginUiSurface;
  result: "allow" | "deny";
  reasonCode?: string;
}

export function auditCommandInvocation(
  auditSink: PluginAuditSink | undefined,
  context: PluginHostRpcContext,
  request: { requestId: string; operation: string },
): PluginUiCommandInvocationAudit {
  return {
    async accepted(entry) {
      await emitUiSecurityAudit(
        auditSink,
        context,
        { requestId: `${request.requestId}:invoke`, operation: "ui.command.invoke" },
        {
          type: "plugin.ui.invocation.accepted",
          payloadKind: "ui.command",
          contributionId: entry.id,
          localId: entry.contribution.local_id,
          surface: entry.contribution.surface,
          result: "allow",
        },
      );
    },
    async rejected(entry, ref, reasonCode) {
      await emitUiSecurityAudit(
        auditSink,
        context,
        { requestId: `${request.requestId}:invoke:reject`, operation: "ui.command.invoke" },
        {
          type: "plugin.ui.invocation.rejected",
          payloadKind: "ui.command",
          contributionId:
            entry?.id ?? pluginContributionId(contextOwnerDescriptor(context), ref.local_id),
          localId: entry?.contribution.local_id ?? ref.local_id,
          surface: entry?.contribution.surface ?? "command",
          result: "deny",
          reasonCode,
        },
      );
    },
  };
}

export async function emitCommandInvocationAccepted(
  audit: PluginUiCommandInvocationAudit | undefined,
  entry: PluginUiRegistryEntry,
): Promise<void> {
  if (!audit) return;
  if (typeof audit === "function") {
    await audit(entry);
    return;
  }
  await audit.accepted(entry);
}

export async function emitCommandInvocationRejected(
  audit: PluginUiCommandInvocationAudit | undefined,
  entry: PluginUiRegistryEntry | null,
  ref: PluginUiCommandRef,
  reasonCode: string,
): Promise<void> {
  if (!audit || reasonCode === "ui_audit_failed") return;
  if (typeof audit === "function") return;
  if (!audit.rejected) return;
  await audit.rejected(
    entry,
    {
      kind: ref.kind,
      local_id: entry?.contribution.local_id ?? ref.local_id,
    },
    reasonCode,
  );
}

export function isAcceptedUiAuditFailure(error: unknown): boolean {
  return error instanceof PluginHostRpcError && error.code === "ui_audit_failed";
}

export function errorReasonCode(error: unknown): string {
  return error instanceof PluginHostRpcError ? error.code : "ui_payload_invalid";
}

export function emitUiCleanupAudit(
  services: PluginHostUiServices,
  session: PluginHostRpcSession | undefined,
  type:
    | "plugin.ui.registry_entry_disposed"
    | "plugin.ui.iframe.closed_with_live_entries"
    | "plugin.ui.iframe.lifecycle",
  owner: PluginHostRpcHandlerOwnerDescriptor,
  details: {
    contributionId: string;
    localId: string;
    surface: PluginUiSurface;
    reasonCode: string;
  },
): void {
  if (!session) return;
  if (details.reasonCode === "session_cleanup") return;
  if (
    (details.reasonCode === "workspace_deleted" || details.reasonCode === "workspace_left") &&
    isPluginRuntimeWorkspaceRevoking(owner.workspaceId)
  ) {
    return;
  }
  void emitUiSecurityAudit(
    services.auditSink,
    session.securityAuditContext(),
    { requestId: `cleanup:${ownerKey(owner)}:${details.localId}`, operation: "ui.cleanup" },
    {
      type,
      payloadKind: "ui.contribution",
      contributionId: details.contributionId,
      localId: details.localId,
      surface: details.surface,
      result: "deny",
      reasonCode: details.reasonCode,
    },
  ).catch(() => undefined);
}

export async function emitUiSecurityAudit(
  auditSink: PluginAuditSink | undefined,
  context: PluginHostRpcContext,
  request: { requestId: string; operation: string },
  details: PluginUiAuditDetails,
): Promise<void> {
  if (!auditSink) {
    throw new PluginHostRpcError(
      "ui_audit_unavailable",
      "UI contribution audit sink is unavailable",
    );
  }

  const createdAt = new Date().toISOString();
  const ok = await pluginAuditSucceeded(
    auditSink({
      protocol: "refmd.security-audit-event",
      version: 1,
      event_id: `audit-${Date.now()}-${Math.random().toString(16).slice(2)}`,
      class: "security_runtime",
      type: details.type,
      actor: context.auditActor,
      pluginId: context.pluginId,
      packageId: context.packageId,
      applicationId: context.applicationId,
      activationId: context.activationId,
      ownerScopeKind: context.ownerScopeKind,
      stateHeadHash: context.stateHeadHash,
      consentHeadHash: context.consentHeadHash,
      capabilityGrantId: context.capabilityGrantId,
      consentEpoch: context.consentEpoch,
      frameGeneration: context.frameGeneration,
      frameScope: context.frameScope,
      workspaceId: context.workspaceId,
      bundleHash: context.bundleHash,
      manifestHash: context.manifestHash,
      capabilityId: context.capabilityId,
      requestId: request.requestId,
      executionContextId: null,
      contextKind: null,
      payloadKind: details.payloadKind,
      plaintextScopeKind: "none",
      plaintextBytes: 0,
      operation: request.operation,
      resourceRef: null,
      result: details.result,
      reasonCode: details.reasonCode,
      scope: {
        workspace_id: context.workspaceId,
        document_id: null,
        share_id: null,
      },
      resource: {
        kind: "plugin",
        id: context.pluginId,
        version_hash: context.bundleHash,
      },
      action: {
        operation: request.operation,
        result: details.result === "allow" ? "allowed" : "denied",
        reason_code: details.reasonCode ?? null,
      },
      sensitivity: {
        plaintext_scope_kind: "none",
        plaintext_bytes: 0,
        egress_bytes: 0,
        storage_bytes: 0,
      },
      correlation: {
        request_id: request.requestId,
        capability_id: context.capabilityId,
        execution_context_id: null,
        authority_event_ref: details.contributionId,
      },
      created_at: createdAt,
    }),
  );

  if (!ok) {
    throw new PluginHostRpcError("ui_audit_failed", "UI contribution audit was rejected");
  }
}
