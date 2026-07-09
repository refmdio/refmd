import type { Accessor } from "solid-js";
import { client, withUserRrpParams } from "@/shared/api/core";
import type { components } from "@/shared/api/schema";
import type {
  PluginAuditEvent,
  PluginAuditSink,
  PluginResourceRef,
} from "../capability/capability-enforcement";
import {
  isPluginRuntimeApplicationRevoking,
  isPluginRuntimeWorkspaceRevoking,
} from "../runtime-boundary/runtime-workspace-revocation";

type RuntimeAuditParams = ReturnType<typeof runtimeAuditParams>;
type PluginOwnerScopeKind = components["schemas"]["PluginRuntimeAuditRequest"]["owner_scope_kind"];
type RuntimeAuditAction = NonNullable<components["schemas"]["PluginRuntimeAuditRequest"]["action"]>;
type RuntimeAuditPost = (
  path: "/api/workspaces/{workspace_id}/plugin-runtime-audit",
  options: {
    params: RuntimeAuditParams;
    body: components["schemas"]["PluginRuntimeAuditRequest"];
  },
) => Promise<{ error?: unknown; response: Response }>;

const postPluginRuntimeAudit: RuntimeAuditPost = (path, options) => client.POST(path, options);
const RUNTIME_AUDIT_RETRY_DELAYS_MS = [250, 1_000, 2_500] as const;

export type FlushablePluginAuditSink = PluginAuditSink & {
  close(reason?: string): void;
  flushPendingAudit(): Promise<void>;
  waitForIdleAudit(idleMs?: number): Promise<void>;
};

export function createDurablePluginRuntimeAuditSink(
  workspaceId: Accessor<string | null>,
  postAudit: RuntimeAuditPost = postPluginRuntimeAudit,
  options: { retryDelaysMs?: readonly number[] } = {},
): FlushablePluginAuditSink {
  let closed = false;
  let unavailable = false;
  const retryDelaysMs = options.retryDelaysMs ?? RUNTIME_AUDIT_RETRY_DELAYS_MS;
  const pending = new Set<Promise<boolean>>();

  const sink = ((event: PluginAuditEvent): Promise<boolean> => {
    const request = postRuntimeAuditEvent(event);
    pending.add(request);
    void request.finally(() => pending.delete(request));
    return request;
  }) as FlushablePluginAuditSink;

  sink.flushPendingAudit = async () => {
    while (pending.size > 0) {
      await Promise.allSettled(pending);
    }
  };
  sink.waitForIdleAudit = async (idleMs = 50) => {
    while (true) {
      await sink.flushPendingAudit();
      await waitForRuntimeAuditRetry(idleMs);
      if (pending.size === 0) return;
    }
  };
  sink.close = () => {
    closed = true;
  };

  return sink;

  async function postRuntimeAuditEvent(event: PluginAuditEvent): Promise<boolean> {
    const currentWorkspaceId = workspaceId();
    if (closed) return false;
    if (!currentWorkspaceId || currentWorkspaceId !== event.workspaceId || unavailable)
      return false;
    if (isPluginRuntimeApplicationRevoking(event.applicationId)) return false;
    if (isBestEffortWorkspaceRevocationCleanup(event)) return false;

    for (let attempt = 0; attempt <= retryDelaysMs.length; attempt += 1) {
      try {
        const result = await postAudit("/api/workspaces/{workspace_id}/plugin-runtime-audit", {
          params: runtimeAuditParams(currentWorkspaceId),
          body: pluginRuntimeAuditRequestBody(event),
        });
        if (result.error === undefined && result.response.status < 400) return true;
        if (!isTransientAuditFailure(result.response.status) || attempt === retryDelaysMs.length) {
          unavailable = true;
          return false;
        }
      } catch {
        if (attempt === retryDelaysMs.length) {
          unavailable = true;
          return false;
        }
      }
      await waitForRuntimeAuditRetry(retryDelaysMs[attempt]);
    }

    unavailable = true;
    return false;
  }
}

function isBestEffortWorkspaceRevocationCleanup(event: PluginAuditEvent): boolean {
  return (
    event.operation === "ui.cleanup" &&
    (event.reasonCode === "workspace_deleted" || event.reasonCode === "workspace_left") &&
    isPluginRuntimeWorkspaceRevoking(event.workspaceId)
  );
}

function isTransientAuditFailure(status: number): boolean {
  return status >= 500;
}

async function waitForRuntimeAuditRetry(ms: number | undefined): Promise<void> {
  if (!ms) return;
  await new Promise<void>((resolve) => {
    window.setTimeout(resolve, ms);
  });
}

function runtimeAuditParams(workspaceId: string) {
  return withUserRrpParams({
    path: { workspace_id: workspaceId },
  });
}

function pluginRuntimeAuditRequestBody(
  event: PluginAuditEvent,
): components["schemas"]["PluginRuntimeAuditRequest"] {
  return {
    protocol: event.protocol,
    version: event.version,
    event_id: event.event_id,
    class: event.class,
    type: event.type,
    actor: {
      user_id: auditString(event.actor.user_id),
      device_id: auditString(event.actor.device_id),
      session_id: auditString(event.actor.session_id),
      principal_kind: event.actor.principal_kind,
      principal_id: auditString(event.actor.principal_id),
    },
    plugin_id: event.pluginId,
    package_id: event.packageId,
    application_id: event.applicationId,
    activation_id: event.activationId,
    owner_scope_kind: pluginOwnerScopeKind(event.ownerScopeKind),
    state_head_hash: event.stateHeadHash,
    consent_head_hash: event.consentHeadHash,
    capability_grant_id: event.capabilityGrantId,
    consent_epoch: event.consentEpoch,
    frame_generation: event.frameGeneration,
    frame_scope: event.frameScope,
    workspace_id: event.workspaceId,
    bundle_hash: event.bundleHash,
    manifest_hash: event.manifestHash,
    capability_id: event.capabilityId,
    request_id: auditString(event.requestId),
    execution_context_id: auditString(event.executionContextId),
    context_kind: auditString(event.contextKind),
    payload_kind: event.payloadKind,
    plaintext_scope_kind: event.plaintextScopeKind,
    plaintext_bytes: event.plaintextBytes,
    resource_ref: pluginRuntimeResourceRef(event.resourceRef),
    operation: event.operation,
    result: event.result,
    reasonCode: event.reasonCode,
    contextKind: event.contextKind ?? undefined,
    payloadKind: event.payloadKind,
    scope: {
      workspace_id: event.scope.workspace_id,
      document_id: auditString(event.scope.document_id),
      share_id: auditString(event.scope.share_id),
    },
    resource: {
      kind: event.resource.kind,
      id: event.resource.id,
      version_hash: auditString(event.resource.version_hash),
    },
    action: pluginRuntimeAction(event.action),
    sensitivity: event.sensitivity,
    correlation: {
      request_id:
        typeof event.correlation.request_id === "string" ? event.correlation.request_id : "",
      capability_id: event.correlation.capability_id,
      execution_context_id: auditString(event.correlation.execution_context_id),
      authority_event_ref: auditString(event.correlation.authority_event_ref),
    },
    created_at: event.created_at,
  };
}

function auditString(value: string | null | undefined): string {
  return value ?? "";
}

function pluginOwnerScopeKind(value: string): PluginOwnerScopeKind {
  if (value === "user" || value === "workspace") return value;
  throw new Error("plugin_owner_scope_invalid");
}

function pluginRuntimeAction(action: PluginAuditEvent["action"]): RuntimeAuditAction {
  const body: RuntimeAuditAction = {
    operation: action.operation,
    result: action.result,
  };

  putAuditString(body, "reason_code", action.reason_code);
  putAuditString(body, "endpoint_id", action.endpoint_id);
  putAuditString(body, "route", action.route);
  putAuditString(body, "method", action.method);
  putAuditString(body, "target_origin", action.target_origin);
  putAuditString(body, "target_path", action.target_path);
  putAuditNumberOrString(body, "request_bytes", action.request_bytes);
  putAuditNumberOrString(body, "response_bytes", action.response_bytes);
  putAuditBooleanOrString(body, "credential_handle_used", action.credential_handle_used);
  putAuditString(body, "proxy_id", action.proxy_id);
  putAuditString(body, "fallback_reason", action.fallback_reason);
  putAuditString(body, "payload", action.payload);
  putAuditString(body, "content", action.content);
  putAuditString(body, "raw", action.raw);
  putAuditString(body, "request_body", action.request_body);

  return body;
}

function putAuditString<T extends keyof RuntimeAuditAction>(
  body: RuntimeAuditAction,
  key: T,
  value: boolean | number | string | null | undefined,
): void {
  if (value === null || value === undefined || value === "") return;
  body[key] = String(value) as RuntimeAuditAction[T];
}

function putAuditNumberOrString<T extends keyof RuntimeAuditAction>(
  body: RuntimeAuditAction,
  key: T,
  value: boolean | number | string | null | undefined,
): void {
  if (value === null || value === undefined || value === "") return;
  if (typeof value === "number" || typeof value === "string") {
    body[key] = value as RuntimeAuditAction[T];
  }
}

function putAuditBooleanOrString<T extends keyof RuntimeAuditAction>(
  body: RuntimeAuditAction,
  key: T,
  value: boolean | number | string | null | undefined,
): void {
  if (value === null || value === undefined || value === "") return;
  if (typeof value === "boolean" || typeof value === "string") {
    body[key] = value as RuntimeAuditAction[T];
  }
}

function pluginRuntimeResourceRef(
  resourceRef: PluginResourceRef | null,
): components["schemas"]["PluginRuntimeAuditRequest"]["resource_ref"] {
  if (resourceRef === null) return {};

  return {
    document_id: auditString(resourceRef.document_id),
    selected_document_ids:
      resourceRef.selected_document_ids === undefined
        ? undefined
        : [...resourceRef.selected_document_ids],
    block_id: auditString(resourceRef.block_id),
    editor_id: auditString(resourceRef.editor_id),
    selection_range: resourceRef.selection_range,
    context_range: resourceRef.context_range,
    max_bytes: resourceRef.max_bytes,
    max_documents: resourceRef.max_documents,
  };
}
