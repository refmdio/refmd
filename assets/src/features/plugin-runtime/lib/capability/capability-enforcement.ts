import type {
  PluginHostRpcContext,
  PluginHostRpcErrorBody,
  PluginHostRpcRequestEnvelope,
} from "../host-rpc/host-rpc";

export const PLUGIN_EXECUTION_CONTEXT_MAX_TTL_MS = 5 * 60 * 1000;
export const PLUGIN_DOCUMENT_WRITE_MAX_BYTES = 256 * 1024;
export const PLUGIN_DOCUMENT_WRITE_RATE_WINDOW_MS = 60 * 1000;
export const PLUGIN_DOCUMENT_WRITE_RATE_MAX_REQUESTS = 120;

export type PluginPermission =
  | `document:read:${"active" | "selected" | "workspace"}`
  | "document:write"
  | `plaintext:render:${"block" | "inline"}:${string}`
  | `editor:${"selection" | "context"}:read`
  | `storage:${"read" | "write"}:${"userLocal" | "cache" | "document" | "workspace"}`
  | "credential:use"
  | `ui:${string}`
  | "network:fetch";

const KNOWN_UI_PERMISSIONS = new Set([
  "ui:command",
  "ui:menu_item",
  "ui:statusbar",
  "ui:sidebar",
  "ui:workspace_tile",
  "ui:auxiliary_pane",
  "ui:document_tree:*",
  "ui:settings_iframe",
  "ui:settings_declarative",
  "ui:declarative_modal",
  "ui:editor",
]);
const STORAGE_PERMISSION_PATTERN = /^storage:(read|write):(userLocal|cache|document|workspace)$/;
const RENDERER_PERMISSION_PATTERN = /^plaintext:render:(block|inline):([a-z][a-z0-9._-]{0,63})$/;
const FORBIDDEN_RENDERER_SLOT_TYPES = new Set(["markdown", "md", "document", "full-document"]);

export function isKnownPluginPermission(permission: string): permission is PluginPermission {
  return (
    permission === "document:write" ||
    permission === "credential:use" ||
    permission === "network:fetch" ||
    permission === "editor:selection:read" ||
    permission === "editor:context:read" ||
    permission === "document:read:active" ||
    permission === "document:read:selected" ||
    permission === "document:read:workspace" ||
    STORAGE_PERMISSION_PATTERN.test(permission) ||
    KNOWN_UI_PERMISSIONS.has(permission) ||
    isKnownRendererPlaintextPermission(permission)
  );
}

function isKnownRendererPlaintextPermission(permission: string): boolean {
  const match = RENDERER_PERMISSION_PATTERN.exec(permission);
  if (!match) return false;
  const kind = match[1];
  const type = match[2] ?? "";
  if (kind === "inline") return type === "code";
  return !FORBIDDEN_RENDERER_SLOT_TYPES.has(type);
}

export type PluginPlaintextReadPermission = Extract<
  PluginPermission,
  | `document:read:${"active" | "selected" | "workspace"}`
  | `plaintext:render:${"block" | "inline"}:${string}`
  | `editor:${"selection" | "context"}:read`
>;

export type PluginExecutionContextKind =
  | "renderer_invocation"
  | "editor_suggestion"
  | "editor_decoration"
  | "formatter"
  | "user_command"
  | "ui_action"
  | "ui_text_refresh"
  | "typed_action"
  | "scheduled_task";

export type PluginExecutionContextHostInvocationKind =
  | "renderer_slot"
  | "editor_suggestion_provider"
  | "editor_decoration_provider"
  | "formatter"
  | "command"
  | "menu"
  | "button"
  | "host_confirmation"
  | "host_action_token"
  | "ui_text_refresh"
  | "typed_action"
  | "scheduled_policy";

export interface PluginExecutionContextHostInvocation {
  kind: PluginExecutionContextHostInvocationKind;
  userGesture: boolean;
  tokenId?: string;
}

export type PluginPlaintextScopeKind =
  | "selection"
  | "editor_context"
  | "block"
  | "inline"
  | "active_document"
  | "selected_documents"
  | "workspace"
  | "none";

export type PluginExecutionContextOperation =
  | "plaintext.read"
  | "document.write"
  | "network.typed_action";

export type PluginHighRiskConsent =
  | "plaintext_document_write"
  | "plaintext_network_egress"
  | "plaintext_cache_storage"
  | "workspace_network_egress";

export interface PluginDocumentScope {
  activeDocumentId?: string | null;
  activeDocumentReadAllowed?: boolean;
  selectedDocumentIds?: readonly string[];
  selectedDocumentsReadAllowed?: boolean;
  allowedDocumentIds?: readonly string[];
  workspaceReadAllowed?: boolean;
}

export interface PluginResourceRef {
  document_id?: string | null;
  selected_document_ids?: readonly string[];
  block_id?: string | null;
  editor_id?: string | null;
  selection_range?: PluginSelectionRangeRef;
  context_range?: PluginSelectionRangeRef;
  max_bytes?: number;
  max_documents?: number;
}

export interface PluginSelectionRangeRef {
  anchor: number;
  head: number;
}

export interface PluginPlaintextScope {
  kind: PluginPlaintextScopeKind;
  maxBytes: number;
}

export interface PluginExecutionContextRecord {
  executionContextId: string;
  kind: PluginExecutionContextKind;
  pluginId: string;
  packageId: string;
  applicationId: string;
  activationId: string;
  ownerScopeKind: string;
  workspaceId: string;
  userId: string;
  deviceId: string;
  bundleHash: string;
  manifestHash: string;
  capabilityId: string;
  capabilityGrantId: string;
  consentEpoch: number;
  frameGeneration: number;
  frameScope?: "primary" | "secondary";
  sessionId: string;
  resource?: PluginResourceRef;
  plaintextScope: PluginPlaintextScope;
  hostInvocation: PluginExecutionContextHostInvocation;
  allowedOperations: readonly PluginExecutionContextOperation[];
  expiresAtMs: number;
  singleUse: boolean;
  consumed?: boolean;
  claimedByRequestId?: string;
}

export interface PluginExecutionContextIssueOptions {
  kind: PluginExecutionContextKind;
  resource?: PluginResourceRef;
  plaintextScope: PluginPlaintextScope;
  hostInvocation: PluginExecutionContextHostInvocation;
  allowedOperations: readonly PluginExecutionContextOperation[];
  expiresAtMs: number;
  singleUse?: boolean;
}

export interface PluginExecutionContextHandle {
  protocol: "refmd.plugin-execution-context";
  version: 1;
  execution_context_id: string;
  kind: PluginExecutionContextKind;
  host_invocation: {
    kind: PluginExecutionContextHostInvocationKind;
    user_gesture: boolean;
    token_id?: string;
  };
  expires_at_ms: number;
  single_use: boolean;
}

export type PluginDocumentAccessPolicy =
  | "active_document"
  | "selected_documents"
  | "workspace_documents"
  | "allowed_document";

export interface PluginPlaintextRpcPolicy {
  operation: PluginExecutionContextOperation;
  requiredPermission: PluginPlaintextReadPermission;
  allowedContextKinds: readonly PluginExecutionContextKind[];
  allowedPlaintextScopes: readonly PluginPlaintextScopeKind[];
  audit: "required";
}

export interface PluginDocumentWriteRpcPolicy {
  operation: "document.write";
  sink: "encrypted_document_body";
  maxBytes: number;
  rateLimit: {
    windowMs: number;
    maxRequests: number;
  };
  highRiskConsent: "required";
}

export interface PluginNetworkFetchRpcPolicy {
  operation: "network.fetch";
  highRiskConsent: "required";
  workspaceExportConsent: "required";
}

export interface PluginCacheStorageWriteRpcPolicy {
  operation: "storage.cache.set";
  highRiskConsent: "required";
}

export interface PluginHostRpcOperationPolicy {
  requiredPermissions?: readonly PluginPermission[];
  anyRequiredPermissions?: readonly PluginPermission[];
  documentAccess?: PluginDocumentAccessPolicy;
  plaintext: PluginPlaintextRpcPolicy | null;
  documentWrite?: PluginDocumentWriteRpcPolicy | null;
  networkFetch?: PluginNetworkFetchRpcPolicy | null;
  cacheStorageWrite?: PluginCacheStorageWriteRpcPolicy | null;
}

const KNOWN_PLAINTEXT_RPC_OPERATIONS = new Set([
  "documents.getActiveDocument",
  "documents.getSelectedDocuments",
  "documents.queryWorkspaceDocuments",
  "renderer.getSource",
  "editor.getSelection",
  "editor.getContext",
  "diagnostics.getContext",
  "decoration.getContext",
  "suggestion.getContext",
  "formatter.getInput",
]);

const FORBIDDEN_SERVER_VISIBLE_METADATA_RPC_OPERATIONS = new Set([
  "documents.updateMetadata",
  "documents.updateTitle",
  "documents.updateFolderMetadata",
  "documents.updateLinkMetadata",
  "documents.writeLinkText",
  "workspace.updateMetadata",
  "workspace.updateSettings",
  "shares.updateMetadata",
  "invites.updateMetadata",
  "git.updateSyncMetadata",
  "plugin.application.updateConfig",
]);

export type PluginAuditEventActionResult = "allowed" | "denied" | "failed" | "completed";

export interface PluginAuditActor {
  user_id: string | null;
  device_id: string | null;
  session_id: string | null;
  principal_kind: "user" | "share_participant" | "system" | "worker";
  principal_id: string | null;
}

export interface PluginAuditEvent {
  protocol: "refmd.security-audit-event";
  version: 1;
  event_id: string;
  class: "security_runtime";
  type:
    | "plugin.plaintext_payload.delivered"
    | "plugin.plaintext_payload.denied"
    | "plugin.ui.registration.accepted"
    | "plugin.ui.registration.rejected"
    | "plugin.ui.invocation.accepted"
    | "plugin.ui.invocation.rejected"
    | "plugin.ui.owner_stale_frame_rejected"
    | "plugin.ui.consent_stale_rejected"
    | "plugin.ui.capability_mismatch_rejected"
    | "plugin.ui.registry_entry_disposed"
    | "plugin.ui.iframe.closed_with_live_entries"
    | "plugin.ui.iframe.lifecycle"
    | "plugin.bundle.imported"
    | "plugin.sandbox.loaded"
    | "plugin.sandbox.destroyed"
    | "plugin.runtime.navigation_suspected"
    | "plugin.capability.issued"
    | "plugin.capability.denied"
    | "plugin.capability.revoked"
    | "plugin.network.requested"
    | "plugin.network.blocked"
    | "plugin.credential.used"
    | "plugin.storage.written"
    | "plugin.document_write.requested";
  actor: PluginAuditActor;
  pluginId: string;
  packageId: string;
  applicationId: string;
  activationId: string;
  ownerScopeKind: string;
  stateHeadHash?: string;
  consentHeadHash?: string;
  capabilityGrantId: string;
  consentEpoch: number;
  frameGeneration: number;
  frameScope?: "primary" | "secondary";
  workspaceId: string;
  bundleHash: string;
  manifestHash: string;
  capabilityId: string;
  requestId: string | null;
  executionContextId: string | null;
  contextKind: PluginExecutionContextKind | null;
  payloadKind:
    | PluginExecutionContextOperation
    | "document.write"
    | "ui.contribution"
    | "ui.command"
    | "ui.workspace_tile_action"
    | "ui.workspace_tile_render"
    | "unknown";
  plaintextScopeKind: PluginPlaintextScopeKind;
  plaintextBytes: number;
  operation: string;
  resourceRef: PluginResourceRef | null;
  result: "allow" | "deny";
  reasonCode?: string;
  scope: {
    workspace_id: string;
    document_id: string | null;
    share_id: null;
  };
  resource: {
    kind: "plugin" | "credential" | "network_endpoint" | "document";
    id: string;
    version_hash: string | null;
  };
  action: {
    operation: string;
    result: PluginAuditEventActionResult;
    reason_code: string | null;
  } & Record<string, boolean | number | string | null>;
  sensitivity: {
    plaintext_scope_kind: PluginPlaintextScopeKind;
    plaintext_bytes: number;
    egress_bytes: number;
    storage_bytes: number;
  };
  correlation: {
    request_id: string | null;
    capability_id: string;
    execution_context_id: string | null;
    authority_event_ref: string | null;
  };
  created_at: string;
}

export type PluginAuditSinkResult = boolean | Promise<boolean>;
export type PluginAuditSink = (event: PluginAuditEvent) => PluginAuditSinkResult;

export interface PluginSecurityAuditDetails {
  type: PluginAuditEvent["type"];
  operation: string;
  result: "allow" | "deny";
  actionResult: PluginAuditEventActionResult | "failed" | "completed";
  requestId?: string | null;
  executionContextId?: string | null;
  contextKind?: PluginExecutionContextKind | null;
  payloadKind?: PluginAuditEvent["payloadKind"];
  plaintextScopeKind?: PluginPlaintextScopeKind;
  plaintextBytes?: number;
  egressBytes?: number;
  storageBytes?: number;
  reasonCode?: string | null;
  resourceRef?: PluginResourceRef | null;
  resourceKind?: PluginAuditEvent["resource"]["kind"];
  resourceId?: string;
  versionHash?: string;
  authorityEventRef?: string | null;
  actionMetadata?: Record<string, boolean | number | string | null>;
}

export function emitPluginSecurityAudit(
  auditSink: PluginAuditSink | null | undefined,
  context: PluginHostRpcContext,
  details: PluginSecurityAuditDetails,
): PluginAuditSinkResult {
  if (!auditSink) return false;

  const requestId = details.requestId ?? null;
  const executionContextId = details.executionContextId ?? null;
  const plaintextScopeKind = details.plaintextScopeKind ?? "none";

  return auditSink({
    protocol: "refmd.security-audit-event",
    version: 1,
    event_id: auditEventId(),
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
    requestId,
    executionContextId,
    contextKind: details.contextKind ?? null,
    payloadKind: details.payloadKind ?? "unknown",
    plaintextScopeKind,
    plaintextBytes: details.plaintextBytes ?? 0,
    operation: details.operation,
    resourceRef: details.resourceRef ?? null,
    result: details.result,
    reasonCode: details.reasonCode ?? undefined,
    scope: {
      workspace_id: context.workspaceId,
      document_id: details.resourceRef?.document_id ?? null,
      share_id: null,
    },
    resource: {
      kind: details.resourceKind ?? "plugin",
      id: details.resourceId ?? context.pluginId,
      version_hash: details.versionHash ?? context.bundleHash,
    },
    action: {
      ...details.actionMetadata,
      operation: details.operation,
      result: details.actionResult,
      reason_code: details.reasonCode ?? null,
    },
    sensitivity: {
      plaintext_scope_kind: plaintextScopeKind,
      plaintext_bytes: details.plaintextBytes ?? 0,
      egress_bytes: details.egressBytes ?? 0,
      storage_bytes: details.storageBytes ?? 0,
    },
    correlation: {
      request_id: requestId,
      capability_id: context.capabilityId,
      execution_context_id: executionContextId,
      authority_event_ref: details.authorityEventRef ?? null,
    },
    created_at: new Date().toISOString(),
  });
}

export async function pluginAuditSucceeded(result: PluginAuditSinkResult): Promise<boolean> {
  try {
    return await result;
  } catch {
    return false;
  }
}

export interface ValidatePluginHostRpcAuthorizationOptions {
  context: PluginHostRpcContext;
  request: PluginHostRpcRequestEnvelope;
  policy: PluginHostRpcOperationPolicy | undefined;
  permissions: ReadonlySet<PluginPermission>;
  highRiskConsents?: ReadonlySet<PluginHighRiskConsent>;
  documentScope: PluginDocumentScope;
  executionContexts: Map<string, PluginExecutionContextRecord>;
  nowMs: number;
  auditSink: PluginAuditSink | null;
}

export interface AuditPluginPlaintextDeniedOptions {
  context: PluginHostRpcContext;
  request: PluginHostRpcRequestEnvelope;
  policy: PluginHostRpcOperationPolicy | undefined;
  executionContexts?: Map<string, PluginExecutionContextRecord>;
  auditSink: PluginAuditSink | null;
}

export interface AuditKnownPluginPlaintextDeniedOptions {
  context: PluginHostRpcContext;
  request: PluginHostRpcRequestEnvelope;
  executionContexts?: Map<string, PluginExecutionContextRecord>;
  auditSink: PluginAuditSink | null;
}

interface PluginPlaintextAuditOptions {
  context: PluginHostRpcContext;
  request: PluginHostRpcRequestEnvelope;
  policy: PluginHostRpcOperationPolicy | undefined;
  executionContexts?: Map<string, PluginExecutionContextRecord>;
  auditSink: PluginAuditSink | null;
}

export function validatePluginPermissionGrant(
  permissions: Iterable<PluginPermission>,
): PluginHostRpcErrorBody | null {
  let hasPlaintextRead = false;
  let hasServerSyncedWrite = false;

  for (const permission of permissions) {
    if (isPlaintextReadPermission(permission)) {
      hasPlaintextRead = true;
    }

    if (permission === "storage:write:workspace" || permission === "storage:write:document") {
      hasServerSyncedWrite = true;
    }
  }

  if (hasPlaintextRead && hasServerSyncedWrite) {
    return {
      code: "dangerous_permission_combination",
      message:
        "plaintext read permissions cannot be combined with server-synced plugin storage write permissions",
    };
  }

  return null;
}

export function validatePluginHostRpcOperationPolicy(
  operation: string,
  policy: PluginHostRpcOperationPolicy,
): PluginHostRpcErrorBody | null {
  if (FORBIDDEN_SERVER_VISIBLE_METADATA_RPC_OPERATIONS.has(operation)) {
    return {
      code: "server_visible_metadata_sink_forbidden",
      message: "third-party plugin Host RPC cannot register server-visible metadata write sinks",
    };
  }

  if (!Object.hasOwn(policy, "plaintext")) {
    return {
      code: "operation_plaintext_classification_required",
      message: "plugin Host RPC operation policy must explicitly classify plaintext delivery",
    };
  }

  if (KNOWN_PLAINTEXT_RPC_OPERATIONS.has(operation) && !policy.plaintext) {
    return {
      code: "plaintext_policy_required",
      message: "known plaintext plugin Host RPC operations require a plaintext policy",
    };
  }

  const capabilityError = validatePlaintextPolicyCapability(policy);
  if (capabilityError) return capabilityError;

  const writePolicyError = validateDocumentWritePolicy(policy);
  if (writePolicyError) return writePolicyError;

  const networkPolicyError = validateNetworkFetchPolicy(policy);
  if (networkPolicyError) return networkPolicyError;

  const cacheStorageWritePolicyError = validateCacheStorageWritePolicy(operation, policy);
  if (cacheStorageWritePolicyError) return cacheStorageWritePolicyError;

  return validateKnownPlaintextOperationPolicy(operation, policy);
}

export function isKnownPlaintextRpcOperation(operation: string): boolean {
  return KNOWN_PLAINTEXT_RPC_OPERATIONS.has(operation);
}

export function validatePluginExecutionContextIssueOptions(
  options: PluginExecutionContextIssueOptions,
  nowMs: number,
): PluginHostRpcErrorBody | null {
  const expirationError = validateExecutionContextExpiration(options.expiresAtMs, nowMs);
  if (expirationError) return expirationError;

  const plaintextScopeMaxBytesError = validatePlaintextMaxBytes(options.plaintextScope.maxBytes);
  if (plaintextScopeMaxBytesError) return plaintextScopeMaxBytesError;

  if (options.plaintextScope.kind === "none") return null;

  const hostInvocationError = validateExecutionContextHostInvocation(options);
  if (hostInvocationError) return hostInvocationError;

  const resource = pluginResourceRef(options.resource);
  if (!resource) {
    return {
      code: "execution_context_resource_required",
      message: "plaintext execution context requires a resource binding",
    };
  }

  const maxBytesError = validateResourceMaxBytes(resource);
  if (maxBytesError) return maxBytesError;

  const maxDocumentsError = validateResourceMaxDocuments(resource);
  if (maxDocumentsError) return maxDocumentsError;

  return validatePlaintextScopeResource(options.plaintextScope.kind, resource);
}

function validateExecutionContextExpiration(
  expiresAtMs: number,
  nowMs: number,
): PluginHostRpcErrorBody | null {
  if (!Number.isFinite(expiresAtMs) || !Number.isSafeInteger(expiresAtMs)) {
    return {
      code: "invalid_execution_context_expiration",
      message: "execution context expiration must be a finite millisecond timestamp",
    };
  }

  if (expiresAtMs <= nowMs) {
    return {
      code: "execution_context_expired",
      message: "execution context expiration must be in the future",
    };
  }

  if (expiresAtMs - nowMs > PLUGIN_EXECUTION_CONTEXT_MAX_TTL_MS) {
    return {
      code: "execution_context_ttl_too_long",
      message: "execution context expiration exceeds the maximum plaintext TTL",
    };
  }

  return null;
}

function validatePlaintextMaxBytes(maxBytes: number): PluginHostRpcErrorBody | null {
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 0) {
    return {
      code: "invalid_plaintext_byte_limit",
      message: "plaintext byte limit must be a finite non-negative safe integer",
    };
  }

  return null;
}

function validateExecutionContextHostInvocation(
  options: PluginExecutionContextIssueOptions,
): PluginHostRpcErrorBody | null {
  const invocation = options.hostInvocation;
  if (!invocation) {
    return {
      code: "host_invocation_required",
      message: "plaintext execution context requires Host-owned invocation provenance",
    };
  }

  const denied = (): PluginHostRpcErrorBody => ({
    code: "host_invocation_denied",
    message: "execution context kind is not allowed for the Host invocation provenance",
  });

  if (options.kind === "renderer_invocation") {
    return invocation.kind === "renderer_slot" && invocation.userGesture === false
      ? null
      : denied();
  }

  if (options.kind === "editor_suggestion") {
    return invocation.kind === "editor_suggestion_provider" && invocation.userGesture === false
      ? null
      : denied();
  }

  if (options.kind === "editor_decoration") {
    return invocation.kind === "editor_decoration_provider" && invocation.userGesture === false
      ? null
      : denied();
  }

  if (options.kind === "formatter") {
    return invocation.kind === "formatter" && invocation.userGesture === true ? null : denied();
  }

  if (options.kind === "user_command") {
    return ["command", "menu", "button"].includes(invocation.kind) &&
      invocation.userGesture === true
      ? null
      : denied();
  }

  if (options.kind === "ui_action") {
    return ["host_confirmation", "host_action_token"].includes(invocation.kind) &&
      invocation.userGesture === true
      ? null
      : denied();
  }

  if (options.kind === "ui_text_refresh") {
    return invocation.kind === "ui_text_refresh" && invocation.userGesture === false
      ? null
      : denied();
  }

  if (options.kind === "typed_action") {
    return invocation.kind === "typed_action" ? null : denied();
  }

  if (options.kind === "scheduled_task") {
    return invocation.kind === "scheduled_policy" && invocation.userGesture === false
      ? null
      : denied();
  }

  return denied();
}

export async function validatePluginHostRpcAuthorization(
  options: ValidatePluginHostRpcAuthorizationOptions,
): Promise<PluginHostRpcErrorBody | null> {
  const { policy } = options;
  if (!policy) return null;

  const resource = pluginResourceRef(options.request.resource);
  const plaintextCapabilityError = validatePlaintextPolicyCapability(policy);
  if (plaintextCapabilityError) {
    return (
      (await auditPluginPlaintextDenied(options, plaintextCapabilityError.code, resource)) ??
      plaintextCapabilityError
    );
  }

  const permissionError = validateRequiredPermissions(policy, options.permissions);
  if (permissionError) {
    return (
      (await auditPluginPlaintextDenied(options, permissionError.code, resource)) ?? permissionError
    );
  }

  const documentScopeError = validateDocumentScope(policy, options, resource);
  if (documentScopeError) {
    return (
      (await auditPluginPlaintextDenied(options, documentScopeError.code, resource)) ??
      documentScopeError
    );
  }

  const writeError = validateDocumentWriteRequest(options, resource);
  if (writeError) return writeError;

  const networkError = validateNetworkFetchRequest(options);
  if (networkError) return networkError;

  const cacheStorageWriteError = validateCacheStorageWriteRequest(options);
  if (cacheStorageWriteError) return cacheStorageWriteError;

  if (!policy.plaintext) return null;

  const plaintextError = validatePlaintextContext(options, resource);
  if (plaintextError) {
    const auditError = await auditPluginPlaintextDenied(options, plaintextError.code, resource);
    if (auditError) return auditError;
    return plaintextError;
  }

  return null;
}

export function consumePluginSingleUseExecutionContext(
  options: ValidatePluginHostRpcAuthorizationOptions,
): void {
  consumeSingleUseExecutionContext(options);
}

export function claimPluginSingleUseExecutionContext(
  options: ValidatePluginHostRpcAuthorizationOptions,
): PluginHostRpcErrorBody | null {
  if (!options.policy?.plaintext) return null;

  const executionContextId = options.request.execution_context_id;
  if (!executionContextId) return null;
  const executionContext = options.executionContexts.get(executionContextId);
  if (!executionContext?.singleUse) return null;

  if (executionContext.consumed) {
    return {
      code: "execution_context_consumed",
      message: "execution context was already consumed",
    };
  }

  if (
    executionContext.claimedByRequestId !== undefined &&
    executionContext.claimedByRequestId !== options.request.request_id
  ) {
    return {
      code: "execution_context_consumed",
      message: "execution context was already consumed",
    };
  }

  executionContext.claimedByRequestId = options.request.request_id;
  return null;
}

export function releasePluginSingleUseExecutionContext(
  options: ValidatePluginHostRpcAuthorizationOptions,
): void {
  if (!options.policy?.plaintext) return;

  const executionContextId = options.request.execution_context_id;
  if (!executionContextId) return;
  const executionContext = options.executionContexts.get(executionContextId);
  if (
    executionContext?.singleUse &&
    executionContext.claimedByRequestId === options.request.request_id &&
    !executionContext.consumed
  ) {
    delete executionContext.claimedByRequestId;
  }
}

export async function finalizePluginPlaintextRpcDelivery(
  options: ValidatePluginHostRpcAuthorizationOptions,
  payload: unknown,
): Promise<PluginHostRpcErrorBody | null> {
  if (options.policy?.plaintext?.audit !== "required") return null;

  const resource = pluginResourceRef(options.request.resource);
  const executionContext = executionContextForAudit(options);
  if (!executionContext) {
    const auditError = await auditPluginPlaintextDenied(
      options,
      "execution_context_not_found",
      resource,
    );
    if (auditError) return auditError;
    return {
      code: "execution_context_not_found",
      message: "execution context is not active for this plugin session",
    };
  }

  if (executionContext.expiresAtMs <= options.nowMs) {
    options.executionContexts.delete(executionContext.executionContextId);
    const auditError = await auditPluginPlaintextDenied(
      options,
      "execution_context_expired",
      resource,
    );
    if (auditError) return auditError;
    return {
      code: "execution_context_expired",
      message: "execution context has expired",
    };
  }

  const plaintextBytes = plaintextPayloadBytes(payload);
  const resourceMaxBytesError = validateResourceMaxBytes(resource);
  if (resourceMaxBytesError) {
    const auditError = await auditPluginPlaintextDenied(
      options,
      resourceMaxBytesError.code,
      resource,
      plaintextBytes,
    );
    if (auditError) return auditError;
    return resourceMaxBytesError;
  }

  const deliveryLimit = Math.min(
    executionContext.plaintextScope.maxBytes,
    resource?.max_bytes ?? Infinity,
  );

  if (plaintextBytes > deliveryLimit) {
    const auditError = await auditPluginPlaintextDenied(
      options,
      "plaintext_payload_too_large",
      resource,
      plaintextBytes,
    );
    if (auditError) return auditError;
    return {
      code: "plaintext_payload_too_large",
      message: "plaintext RPC response exceeds the execution context byte limit",
    };
  }

  const auditOk = await auditPlaintext(options, resource, "allow", undefined, plaintextBytes);
  if (!auditOk) {
    return {
      code: "audit_sink_unavailable",
      message: "plaintext RPC audit event could not be recorded",
    };
  }

  return null;
}

export async function auditPluginPlaintextDenied(
  options: AuditPluginPlaintextDeniedOptions,
  reasonCode: string,
  resource: PluginResourceRef | null = pluginResourceRef(options.request.resource),
  plaintextBytesOverride?: number,
): Promise<PluginHostRpcErrorBody | null> {
  const auditOk = await auditPlaintext(
    {
      context: options.context,
      request: options.request,
      policy: options.policy,
      executionContexts: options.executionContexts,
      auditSink: options.auditSink,
    },
    resource,
    "deny",
    reasonCode,
    plaintextBytesOverride,
  );
  if (auditOk) return null;

  return {
    code: "audit_sink_unavailable",
    message: "plaintext RPC audit event could not be recorded",
  };
}

export async function auditKnownPluginPlaintextDenied(
  options: AuditKnownPluginPlaintextDeniedOptions,
  reasonCode: string,
  resource: PluginResourceRef | null = pluginResourceRef(options.request.resource),
  plaintextBytesOverride?: number,
): Promise<PluginHostRpcErrorBody | null> {
  if (!isKnownPlaintextRpcOperation(options.request.operation)) return null;
  if (!options.auditSink) {
    return {
      code: "audit_sink_unavailable",
      message: "plaintext RPC audit event could not be recorded",
    };
  }

  const executionContext = executionContextForAudit(options);
  const plaintextScopeKind = plaintextScopeKindForAudit(undefined, executionContext, resource);
  const plaintextBytes =
    plaintextBytesOverride ?? plaintextBytesForAudit(executionContext, resource);
  const executionContextId = options.request.execution_context_id ?? null;
  const auditOk = await pluginAuditSucceeded(
    options.auditSink({
      protocol: "refmd.security-audit-event",
      version: 1,
      event_id: auditEventId(),
      class: "security_runtime",
      type: "plugin.plaintext_payload.denied",
      actor: options.context.auditActor,
      pluginId: options.context.pluginId,
      packageId: options.context.packageId,
      applicationId: options.context.applicationId,
      activationId: options.context.activationId,
      ownerScopeKind: options.context.ownerScopeKind,
      stateHeadHash: options.context.stateHeadHash,
      consentHeadHash: options.context.consentHeadHash,
      capabilityGrantId: options.context.capabilityGrantId,
      consentEpoch: options.context.consentEpoch,
      frameGeneration: options.context.frameGeneration,
      frameScope: options.context.frameScope,
      workspaceId: options.context.workspaceId,
      bundleHash: options.context.bundleHash,
      manifestHash: options.context.manifestHash,
      capabilityId: options.context.capabilityId,
      requestId: options.request.request_id,
      executionContextId,
      contextKind: executionContext?.kind ?? null,
      payloadKind: "unknown",
      plaintextScopeKind,
      plaintextBytes,
      operation: options.request.operation,
      resourceRef: resource,
      result: "deny",
      reasonCode,
      scope: {
        workspace_id: options.context.workspaceId,
        document_id: resource?.document_id ?? null,
        share_id: null,
      },
      resource: {
        kind: "plugin",
        id: options.context.pluginId,
        version_hash: options.context.bundleHash,
      },
      action: {
        operation: options.request.operation,
        result: "denied",
        reason_code: reasonCode,
      },
      sensitivity: {
        plaintext_scope_kind: plaintextScopeKind,
        plaintext_bytes: plaintextBytes,
        egress_bytes: 0,
        storage_bytes: 0,
      },
      correlation: {
        request_id: options.request.request_id,
        capability_id: options.context.capabilityId,
        execution_context_id: executionContextId,
        authority_event_ref: null,
      },
      created_at: new Date().toISOString(),
    }),
  );

  if (auditOk) return null;

  return {
    code: "audit_sink_unavailable",
    message: "plaintext RPC audit event could not be recorded",
  };
}

export function isPlaintextReadPermission(permission: PluginPermission): boolean {
  return (
    permission === "document:read:active" ||
    permission === "document:read:selected" ||
    permission === "document:read:workspace" ||
    permission.startsWith("plaintext:render:") ||
    permission === "editor:selection:read" ||
    permission === "editor:context:read"
  );
}

export function hasPlaintextReadPermission(permissions: Iterable<PluginPermission>): boolean {
  for (const permission of permissions) {
    if (isPlaintextReadPermission(permission)) return true;
  }
  return false;
}

export function pluginPayloadByteLength(payload: unknown): number {
  if (payload == null) return 0;
  if (typeof payload === "string") return new TextEncoder().encode(payload).byteLength;
  if (payload instanceof ArrayBuffer) return payload.byteLength;
  if (ArrayBuffer.isView(payload)) return payload.byteLength;

  try {
    return new TextEncoder().encode(JSON.stringify(payload)).byteLength;
  } catch {
    return Number.POSITIVE_INFINITY;
  }
}

function validateDocumentWritePolicy(
  policy: PluginHostRpcOperationPolicy,
): PluginHostRpcErrorBody | null {
  const writePolicy = policy.documentWrite;
  if (writePolicy == null) return null;

  if (writePolicy.operation !== "document.write") {
    return {
      code: "document_write_policy_invalid",
      message: "document write RPC policy must use document.write",
    };
  }

  if (writePolicy.sink !== "encrypted_document_body") {
    return {
      code: "server_visible_metadata_sink_forbidden",
      message: "third-party plugin document writes must target encrypted document body only",
    };
  }

  if (!(policy.requiredPermissions ?? []).includes("document:write")) {
    return {
      code: "document_write_permission_required",
      message: "document write RPC policy must require document:write",
    };
  }

  if (!policy.documentAccess) {
    return {
      code: "document_scope_policy_required",
      message: "document write RPC policy must declare document access",
    };
  }

  if (
    !Number.isSafeInteger(writePolicy.maxBytes) ||
    writePolicy.maxBytes <= 0 ||
    writePolicy.maxBytes > PLUGIN_DOCUMENT_WRITE_MAX_BYTES
  ) {
    return {
      code: "document_write_byte_limit_invalid",
      message: "document write RPC policy must declare a bounded encrypted payload size",
    };
  }

  if (
    !Number.isSafeInteger(writePolicy.rateLimit?.windowMs) ||
    writePolicy.rateLimit.windowMs <= 0 ||
    writePolicy.rateLimit.windowMs > PLUGIN_DOCUMENT_WRITE_RATE_WINDOW_MS
  ) {
    return {
      code: "document_write_rate_limit_invalid",
      message: "document write RPC policy must declare a bounded rate-limit window",
    };
  }

  if (
    !Number.isSafeInteger(writePolicy.rateLimit?.maxRequests) ||
    writePolicy.rateLimit.maxRequests <= 0 ||
    writePolicy.rateLimit.maxRequests > PLUGIN_DOCUMENT_WRITE_RATE_MAX_REQUESTS
  ) {
    return {
      code: "document_write_rate_limit_invalid",
      message: "document write RPC policy must declare a bounded request count",
    };
  }

  if (writePolicy.highRiskConsent !== "required") {
    return {
      code: "high_risk_consent_required",
      message: "document write RPC policy must require high-risk consent",
    };
  }

  return null;
}

function validateDocumentWriteRequest(
  options: ValidatePluginHostRpcAuthorizationOptions,
  resource: PluginResourceRef | null,
): PluginHostRpcErrorBody | null {
  const writePolicy = options.policy?.documentWrite;
  if (!writePolicy) return null;

  if (
    hasPlaintextReadPermission(options.permissions) &&
    !options.highRiskConsents?.has("plaintext_document_write")
  ) {
    return {
      code: "high_risk_consent_required",
      message: "plaintext read and document write require high-risk consent",
    };
  }

  const payloadBytes = pluginPayloadByteLength(options.request.payload);
  const payloadLimit = Math.min(writePolicy.maxBytes, resource?.max_bytes ?? Infinity);

  if (payloadBytes > payloadLimit) {
    return {
      code: "document_write_payload_too_large",
      message: "encrypted document write payload exceeds the configured byte limit",
    };
  }

  return null;
}

function validateNetworkFetchPolicy(
  policy: PluginHostRpcOperationPolicy,
): PluginHostRpcErrorBody | null {
  const networkPolicy = policy.networkFetch;
  if (networkPolicy == null) return null;

  if (networkPolicy.operation !== "network.fetch") {
    return {
      code: "network_fetch_policy_invalid",
      message: "network fetch RPC policy must use network.fetch",
    };
  }

  if (!(policy.requiredPermissions ?? []).includes("network:fetch")) {
    return {
      code: "network_fetch_permission_required",
      message: "network fetch RPC policy must require network:fetch",
    };
  }

  if (networkPolicy.highRiskConsent !== "required") {
    return {
      code: "high_risk_consent_required",
      message: "network fetch RPC policy must require high-risk consent",
    };
  }

  if (networkPolicy.workspaceExportConsent !== "required") {
    return {
      code: "workspace_network_egress_consent_required",
      message: "workspace network export RPC policy must require high-risk consent",
    };
  }

  return null;
}

function validateNetworkFetchRequest(
  options: ValidatePluginHostRpcAuthorizationOptions,
): PluginHostRpcErrorBody | null {
  const networkPolicy = options.policy?.networkFetch;
  if (!networkPolicy) return null;

  if (
    options.permissions.has("document:read:workspace") &&
    !options.highRiskConsents?.has("workspace_network_egress")
  ) {
    return {
      code: "workspace_network_egress_consent_required",
      message: "workspace plaintext read and network fetch require workspace export consent",
    };
  }

  if (
    hasPlaintextReadPermission(options.permissions) &&
    !options.highRiskConsents?.has("plaintext_network_egress")
  ) {
    return {
      code: "high_risk_consent_required",
      message: "plaintext read and network fetch require high-risk consent",
    };
  }

  return null;
}

function validateCacheStorageWritePolicy(
  operation: string,
  policy: PluginHostRpcOperationPolicy,
): PluginHostRpcErrorBody | null {
  const cachePolicy = policy.cacheStorageWrite;
  if (cachePolicy == null) return null;

  if (operation !== "storage.cache.set" || cachePolicy.operation !== "storage.cache.set") {
    return {
      code: "cache_storage_write_policy_invalid",
      message: "cache storage write RPC policy must use storage.cache.set",
    };
  }

  if (!(policy.requiredPermissions ?? []).includes("storage:write:cache")) {
    return {
      code: "cache_storage_write_permission_required",
      message: "cache storage write RPC policy must require storage:write:cache",
    };
  }

  if (cachePolicy.highRiskConsent !== "required") {
    return {
      code: "high_risk_consent_required",
      message: "cache storage write RPC policy must require high-risk consent",
    };
  }

  return null;
}

function validateCacheStorageWriteRequest(
  options: ValidatePluginHostRpcAuthorizationOptions,
): PluginHostRpcErrorBody | null {
  const cachePolicy = options.policy?.cacheStorageWrite;
  if (!cachePolicy) return null;

  if (
    hasPlaintextReadPermission(options.permissions) &&
    !options.highRiskConsents?.has("plaintext_cache_storage")
  ) {
    return {
      code: "high_risk_consent_required",
      message: "plaintext read and cache storage write require high-risk consent",
    };
  }

  return null;
}

function validatePlaintextPolicyCapability(
  policy: PluginHostRpcOperationPolicy,
): PluginHostRpcErrorBody | null {
  const plaintextPolicy = policy.plaintext;
  if (!plaintextPolicy) return null;

  if (plaintextPolicy.audit !== "required") {
    return {
      code: "plaintext_audit_required",
      message: "plaintext RPC policy must require audit",
    };
  }

  const scopeError = validatePlaintextPermissionScope(plaintextPolicy);
  if (scopeError) return scopeError;

  if (!plaintextPermissionMatchesPolicy(plaintextPolicy.requiredPermission, plaintextPolicy)) {
    return {
      code: "plaintext_capability_required",
      message: "plaintext RPC policy must declare a matching typed plaintext permission",
    };
  }

  if (!(policy.requiredPermissions ?? []).includes(plaintextPolicy.requiredPermission)) {
    return {
      code: "plaintext_capability_required",
      message: "plaintext RPC policy permission must be required by the operation policy",
    };
  }

  const requiredDocumentAccess = documentAccessForPlaintextPermission(
    plaintextPolicy.requiredPermission,
  );
  if (requiredDocumentAccess && policy.documentAccess !== requiredDocumentAccess) {
    return {
      code: "document_scope_policy_required",
      message: "document plaintext RPC policy must declare matching document access",
    };
  }

  return null;
}

function validateKnownPlaintextOperationPolicy(
  operation: string,
  policy: PluginHostRpcOperationPolicy,
): PluginHostRpcErrorBody | null {
  const plaintextPolicy = policy.plaintext;
  if (!plaintextPolicy || !KNOWN_PLAINTEXT_RPC_OPERATIONS.has(operation)) return null;

  if (plaintextPolicy.operation !== "plaintext.read") {
    return {
      code: "plaintext_operation_policy_mismatch",
      message: "known plaintext RPC policies must use plaintext.read",
    };
  }

  if (operation === "documents.getActiveDocument") {
    return validateKnownDocumentPlaintextPolicy(policy, "document:read:active", [
      "user_command",
      "ui_action",
      "ui_text_refresh",
      "typed_action",
    ]);
  }

  if (operation === "documents.getSelectedDocuments") {
    return validateKnownDocumentPlaintextPolicy(policy, "document:read:selected", [
      "user_command",
      "ui_action",
      "typed_action",
    ]);
  }

  if (operation === "documents.queryWorkspaceDocuments") {
    return validateKnownDocumentPlaintextPolicy(policy, "document:read:workspace", [
      "user_command",
    ]);
  }

  if (operation === "renderer.getSource") {
    const permission = plaintextPolicy.requiredPermission;
    if (
      !permission.startsWith("plaintext:render:block:") &&
      !permission.startsWith("plaintext:render:inline:")
    ) {
      return {
        code: "plaintext_operation_policy_mismatch",
        message: "renderer source plaintext RPC must use a renderer plaintext permission",
      };
    }

    const expectedScopes = rendererPlaintextScopes(policy.requiredPermissions ?? [permission]);
    return (
      validateDocumentAccessPolicy(policy, ["allowed_document"]) ??
      validateAllowedContextKinds(plaintextPolicy, ["renderer_invocation"]) ??
      validateExactPlaintextScopes(plaintextPolicy, expectedScopes)
    );
  }

  if (operation === "editor.getSelection") {
    const documentAccessError = validateDocumentAccessPolicy(policy, [
      "allowed_document",
      "selected_documents",
    ]);
    if (documentAccessError) return documentAccessError;

    return validateKnownEditorPlaintextPolicy(policy, "editor:selection:read", [
      "formatter",
      "user_command",
      "ui_action",
    ]);
  }

  if (operation === "editor.getContext") {
    const documentAccessError = validateDocumentAccessPolicy(policy, ["allowed_document"]);
    if (documentAccessError) return documentAccessError;

    return validateKnownEditorPlaintextPolicy(policy, "editor:context:read", [
      "editor_suggestion",
      "editor_decoration",
      "formatter",
      "user_command",
    ]);
  }

  if (operation === "diagnostics.getContext" || operation === "suggestion.getContext") {
    const documentAccessError = validateDocumentAccessPolicy(policy, ["allowed_document"]);
    if (documentAccessError) return documentAccessError;

    return validateKnownEditorPlaintextPolicy(policy, "editor:context:read", [
      "editor_suggestion",
      "formatter",
    ]);
  }

  if (operation === "decoration.getContext") {
    const documentAccessError = validateDocumentAccessPolicy(policy, ["allowed_document"]);
    if (documentAccessError) return documentAccessError;

    return validateKnownEditorPlaintextPolicy(policy, "editor:context:read", ["editor_decoration"]);
  }

  if (operation === "formatter.getInput") {
    if (plaintextPolicy.requiredPermission === "editor:selection:read") {
      return (
        validateDocumentAccessPolicy(policy, ["allowed_document", "selected_documents"]) ??
        validateAllowedContextKinds(plaintextPolicy, ["formatter"]) ??
        validateExactPlaintextScopes(plaintextPolicy, ["selection"])
      );
    }

    if (plaintextPolicy.requiredPermission === "editor:context:read") {
      return (
        validateDocumentAccessPolicy(policy, ["allowed_document"]) ??
        validateAllowedContextKinds(plaintextPolicy, ["formatter"]) ??
        validateExactPlaintextScopes(plaintextPolicy, ["editor_context"])
      );
    }

    return {
      code: "plaintext_operation_policy_mismatch",
      message:
        "formatter input plaintext RPC must use editor selection or editor context permission",
    };
  }

  return null;
}

function validateDocumentAccessPolicy(
  policy: PluginHostRpcOperationPolicy,
  allowedDocumentAccess: readonly PluginDocumentAccessPolicy[],
): PluginHostRpcErrorBody | null {
  if (policy.documentAccess && allowedDocumentAccess.includes(policy.documentAccess)) return null;

  return {
    code: "document_scope_policy_required",
    message: "known plaintext RPC policy must declare matching document access",
  };
}

function rendererPlaintextScopes(
  permissions: readonly PluginPermission[],
): readonly PluginPlaintextScopeKind[] {
  const scopes: PluginPlaintextScopeKind[] = [];
  for (const permission of permissions) {
    if (permission.startsWith("plaintext:render:block:")) {
      scopes.push("block");
    } else if (permission.startsWith("plaintext:render:inline:")) {
      scopes.push("inline");
    }
  }
  return Array.from(new Set(scopes));
}

function validateKnownDocumentPlaintextPolicy(
  policy: PluginHostRpcOperationPolicy,
  requiredPermission: Extract<PluginPlaintextReadPermission, `document:read:${string}`>,
  allowedContextKinds: readonly PluginExecutionContextKind[],
): PluginHostRpcErrorBody | null {
  const plaintextPolicy = policy.plaintext;
  if (!plaintextPolicy) return null;

  if (plaintextPolicy.requiredPermission !== requiredPermission) {
    return {
      code: "plaintext_operation_policy_mismatch",
      message: "document plaintext RPC policy uses the wrong document read permission",
    };
  }

  const expectedScope = plaintextScopeForPermission(requiredPermission);
  if (!expectedScope) return null;

  return (
    validateAllowedContextKinds(plaintextPolicy, allowedContextKinds) ??
    validateExactPlaintextScopes(plaintextPolicy, [expectedScope])
  );
}

function validateKnownEditorPlaintextPolicy(
  policy: PluginHostRpcOperationPolicy,
  requiredPermission: Extract<PluginPlaintextReadPermission, `editor:${string}:read`>,
  allowedContextKinds: readonly PluginExecutionContextKind[],
): PluginHostRpcErrorBody | null {
  const plaintextPolicy = policy.plaintext;
  if (!plaintextPolicy) return null;

  if (plaintextPolicy.requiredPermission !== requiredPermission) {
    return {
      code: "plaintext_operation_policy_mismatch",
      message: "editor plaintext RPC policy uses the wrong editor read permission",
    };
  }

  const expectedScope = plaintextScopeForPermission(requiredPermission);
  if (!expectedScope) return null;

  return (
    validateAllowedContextKinds(plaintextPolicy, allowedContextKinds) ??
    validateExactPlaintextScopes(plaintextPolicy, [expectedScope])
  );
}

function validateAllowedContextKinds(
  policy: PluginPlaintextRpcPolicy,
  allowedContextKinds: readonly PluginExecutionContextKind[],
): PluginHostRpcErrorBody | null {
  if (policy.allowedContextKinds.length === 0) {
    return {
      code: "plaintext_context_denied",
      message: "known plaintext RPC policy must allow at least one context kind",
    };
  }

  const allowed = new Set(allowedContextKinds);
  if (policy.allowedContextKinds.every((kind) => allowed.has(kind))) return null;

  return {
    code: "plaintext_context_denied",
    message: "known plaintext RPC policy allows an invalid context kind",
  };
}

function validateExactPlaintextScopes(
  policy: PluginPlaintextRpcPolicy,
  expectedScopes: readonly PluginPlaintextScopeKind[],
): PluginHostRpcErrorBody | null {
  const expected = new Set(expectedScopes);
  const actual = new Set(policy.allowedPlaintextScopes);
  if (
    actual.size === expected.size &&
    policy.allowedPlaintextScopes.every((scope) => expected.has(scope))
  ) {
    return null;
  }

  return {
    code: "plaintext_scope_denied",
    message: "known plaintext RPC policy allows an invalid plaintext scope",
  };
}

function plaintextScopeForPermission(
  permission: PluginPlaintextReadPermission,
): PluginPlaintextScopeKind | null {
  if (permission === "document:read:active") return "active_document";
  if (permission === "document:read:selected") return "selected_documents";
  if (permission === "document:read:workspace") return "workspace";
  if (permission.startsWith("plaintext:render:block:")) return "block";
  if (permission.startsWith("plaintext:render:inline:")) return "inline";
  if (permission === "editor:selection:read") return "selection";
  if (permission === "editor:context:read") return "editor_context";

  return null;
}

function documentAccessForPlaintextPermission(
  permission: PluginPlaintextReadPermission,
): PluginDocumentAccessPolicy | null {
  if (permission === "document:read:active") return "active_document";
  if (permission === "document:read:selected") return "selected_documents";
  if (permission === "document:read:workspace") return "workspace_documents";

  return null;
}

function validatePlaintextPermissionScope(
  policy: PluginPlaintextRpcPolicy,
): PluginHostRpcErrorBody | null {
  const scopes = new Set(policy.allowedPlaintextScopes);

  if (policy.requiredPermission === "editor:context:read") {
    if (scopes.size === 1 && scopes.has("editor_context")) return null;

    return {
      code: "plaintext_scope_denied",
      message: "editor context plaintext policy must use editor_context scope only",
    };
  }

  if (policy.requiredPermission === "editor:selection:read") {
    if (scopes.size === 1 && scopes.has("selection")) return null;

    return {
      code: "plaintext_scope_denied",
      message: "editor selection plaintext policy must use selection scope only",
    };
  }

  return null;
}

function plaintextPermissionMatchesPolicy(
  permission: PluginPlaintextReadPermission,
  policy: PluginPlaintextRpcPolicy,
): boolean {
  const scopes = new Set(policy.allowedPlaintextScopes);

  if (permission === "document:read:active") return scopes.has("active_document");
  if (permission === "document:read:selected") return scopes.has("selected_documents");
  if (permission === "document:read:workspace") return scopes.has("workspace");
  if (permission.startsWith("plaintext:render:block:")) return scopes.has("block");
  if (permission.startsWith("plaintext:render:inline:")) return scopes.has("inline");
  if (permission === "editor:selection:read") return scopes.has("selection");
  if (permission === "editor:context:read") return scopes.has("editor_context");

  return false;
}

function validateRequiredPermissions(
  policy: PluginHostRpcOperationPolicy,
  permissions: ReadonlySet<PluginPermission>,
): PluginHostRpcErrorBody | null {
  for (const permission of policy.requiredPermissions ?? []) {
    if (!permissions.has(permission)) {
      return {
        code: "permission_denied",
        message: `missing plugin permission: ${permission}`,
      };
    }
  }

  const anyRequiredPermissions = policy.anyRequiredPermissions ?? [];
  if (
    anyRequiredPermissions.length > 0 &&
    !anyRequiredPermissions.some((permission) => permissions.has(permission))
  ) {
    return {
      code: "permission_denied",
      message: `missing one of plugin permissions: ${anyRequiredPermissions.join(", ")}`,
    };
  }

  return null;
}

function validateDocumentScope(
  policy: PluginHostRpcOperationPolicy,
  options: ValidatePluginHostRpcAuthorizationOptions,
  resource: PluginResourceRef | null,
): PluginHostRpcErrorBody | null {
  const documentScope = options.documentScope;
  if (!policy.documentAccess) return null;
  if (policy.documentAccess === "workspace_documents") {
    if (!documentScope.workspaceReadAllowed) {
      return {
        code: "document_scope_denied",
        message: "workspace document scope is not allowed for this capability",
      };
    }
    return null;
  }

  if (!resource) {
    return {
      code: "resource_required",
      message: "document-scoped plugin RPC requires a resource",
    };
  }

  if (policy.documentAccess === "active_document") {
    if (
      !activeDocumentScopeAllows(documentScope, resource.document_id) &&
      !executionContextAllowsDocumentAccess(policy, options, resource, "active_document")
    ) {
      return {
        code: "document_scope_denied",
        message: "requested document is not the active document",
      };
    }
  }

  if (policy.documentAccess === "selected_documents") {
    const requested =
      resource.selected_document_ids ?? (resource.document_id ? [resource.document_id] : []);
    if (
      !selectedDocumentScopeAllows(documentScope, requested) &&
      !executionContextAllowsDocumentAccess(policy, options, resource, "selected_documents")
    ) {
      return {
        code: "document_scope_denied",
        message: "requested documents are outside the selected document scope",
      };
    }
  }

  if (policy.documentAccess === "allowed_document") {
    const allowed = new Set(documentScope.allowedDocumentIds ?? []);
    if (
      !resource.document_id ||
      (documentScope.workspaceReadAllowed !== true &&
        !activeDocumentScopeAllows(documentScope, resource.document_id) &&
        !selectedDocumentScopeAllows(documentScope, [resource.document_id]) &&
        !allowed.has(resource.document_id))
    ) {
      return {
        code: "document_scope_denied",
        message: "requested document is outside the allowed document scope",
      };
    }
  }

  return null;
}

function executionContextAllowsDocumentAccess(
  policy: PluginHostRpcOperationPolicy,
  options: ValidatePluginHostRpcAuthorizationOptions,
  resource: PluginResourceRef | null,
  scopeKind: PluginPlaintextScopeKind,
): boolean {
  if (!policy.plaintext || !resource) return false;
  if (!policy.plaintext.allowedPlaintextScopes.includes(scopeKind)) return false;

  const executionContextId = options.request.execution_context_id;
  const executionContext = executionContextId
    ? options.executionContexts.get(executionContextId)
    : undefined;
  if (scopeKind === "selected_documents") {
    const expected = executionContext?.resource?.selected_document_ids ?? [];
    const actual =
      resource.selected_document_ids ?? (resource.document_id ? [resource.document_id] : []);
    return Boolean(
      executionContext?.plaintextScope.kind === scopeKind &&
      expected.length > 0 &&
      sameStringSet(expected, actual),
    );
  }

  return Boolean(
    executionContext?.plaintextScope.kind === scopeKind &&
    resource.document_id &&
    executionContext.resource?.document_id === resource.document_id,
  );
}

function activeDocumentScopeAllows(
  documentScope: PluginDocumentScope,
  documentId: string | null | undefined,
): boolean {
  return Boolean(documentId && documentScope.activeDocumentId === documentId);
}

function selectedDocumentScopeAllows(
  documentScope: PluginDocumentScope,
  documentIds: readonly string[],
): boolean {
  if (documentIds.length === 0) return false;
  const selected = new Set(documentScope.selectedDocumentIds ?? []);
  return documentIds.every((documentId) => selected.has(documentId));
}

function validatePlaintextContext(
  options: ValidatePluginHostRpcAuthorizationOptions,
  resource: PluginResourceRef | null,
): PluginHostRpcErrorBody | null {
  const policy = options.policy?.plaintext;
  if (!policy) return null;

  const executionContextId = options.request.execution_context_id;
  if (!executionContextId) {
    return {
      code: "execution_context_required",
      message: "plaintext RPC requires a Host-issued execution context",
    };
  }

  const executionContext = options.executionContexts.get(executionContextId);
  if (!executionContext) {
    return {
      code: "execution_context_not_found",
      message: "execution context is not active for this plugin session",
    };
  }

  if (executionContext.consumed) {
    return {
      code: "execution_context_consumed",
      message: "execution context was already consumed",
    };
  }

  if (
    executionContext.singleUse &&
    executionContext.claimedByRequestId !== undefined &&
    executionContext.claimedByRequestId !== options.request.request_id
  ) {
    return {
      code: "execution_context_consumed",
      message: "execution context was already consumed",
    };
  }

  if (executionContext.expiresAtMs <= options.nowMs) {
    options.executionContexts.delete(executionContext.executionContextId);
    return {
      code: "execution_context_expired",
      message: "execution context has expired",
    };
  }

  if (executionContext.kind === "scheduled_task") {
    return {
      code: "scheduled_context_reserved",
      message: "scheduled plaintext execution contexts are not enabled",
    };
  }

  const identityError = validateExecutionContextIdentity(options.context, executionContext);
  if (identityError) return identityError;

  if (!policy.allowedContextKinds.includes(executionContext.kind)) {
    return {
      code: "execution_context_kind_denied",
      message: "execution context kind is not allowed for this RPC",
    };
  }

  if (!executionContext.allowedOperations.includes(policy.operation)) {
    return {
      code: "execution_context_operation_denied",
      message: "execution context does not allow this operation",
    };
  }

  if (!policy.allowedPlaintextScopes.includes(executionContext.plaintextScope.kind)) {
    return {
      code: "plaintext_scope_denied",
      message: "execution context plaintext scope is not allowed for this RPC",
    };
  }

  const resourceError = validateExecutionContextResource(executionContext, resource);
  if (resourceError) return resourceError;

  const resourceMaxBytesError = validateResourceMaxBytes(resource);
  if (resourceMaxBytesError) return resourceMaxBytesError;

  const resourceMaxDocumentsError = validateResourceMaxDocuments(resource);
  if (resourceMaxDocumentsError) return resourceMaxDocumentsError;

  if (executionContext.plaintextScope.kind === "workspace") {
    const workspaceLimitError = validateRequiredWorkspaceDocumentQueryLimits(
      resource,
      "plaintext_scope_denied",
    );
    if (workspaceLimitError) return workspaceLimitError;
  }

  if (
    resource?.max_bytes !== undefined &&
    resource.max_bytes > executionContext.plaintextScope.maxBytes
  ) {
    return {
      code: "plaintext_scope_denied",
      message: "requested plaintext byte limit exceeds the execution context scope",
    };
  }

  const expectedResource = executionContext.resource;
  if (
    expectedResource?.max_bytes !== undefined &&
    (resource?.max_bytes === undefined || resource.max_bytes > expectedResource.max_bytes)
  ) {
    return {
      code: "plaintext_scope_denied",
      message: "requested plaintext byte limit exceeds the execution context resource",
    };
  }

  if (
    expectedResource?.max_documents !== undefined &&
    (resource?.max_documents === undefined ||
      resource.max_documents > expectedResource.max_documents)
  ) {
    return {
      code: "plaintext_scope_denied",
      message: "requested document limit exceeds the execution context resource",
    };
  }

  return null;
}

function consumeSingleUseExecutionContext(
  options: ValidatePluginHostRpcAuthorizationOptions,
): void {
  if (!options.policy?.plaintext) return;

  const executionContextId = options.request.execution_context_id;
  if (!executionContextId) return;
  const executionContext = options.executionContexts.get(executionContextId);
  if (executionContext?.singleUse) {
    executionContext.consumed = true;
    delete executionContext.claimedByRequestId;
  }
}

function validateResourceMaxBytes(
  resource: PluginResourceRef | null,
): PluginHostRpcErrorBody | null {
  if (resource?.max_bytes === undefined) return null;
  return validatePlaintextMaxBytes(resource.max_bytes);
}

function validateResourceMaxDocuments(
  resource: PluginResourceRef | null,
): PluginHostRpcErrorBody | null {
  if (resource?.max_documents === undefined) return null;
  if (
    !Number.isSafeInteger(resource.max_documents) ||
    resource.max_documents <= 0 ||
    resource.max_documents > 500
  ) {
    return {
      code: "invalid_document_limit",
      message: "document limit must be a positive bounded safe integer",
    };
  }
  return null;
}

function validateExecutionContextIdentity(
  context: PluginHostRpcContext,
  executionContext: PluginExecutionContextRecord,
): PluginHostRpcErrorBody | null {
  const identityPairs: Array<[keyof PluginHostRpcContext, string | number]> = [
    ["pluginId", executionContext.pluginId],
    ["packageId", executionContext.packageId],
    ["applicationId", executionContext.applicationId],
    ["activationId", executionContext.activationId],
    ["ownerScopeKind", executionContext.ownerScopeKind],
    ["workspaceId", executionContext.workspaceId],
    ["userId", executionContext.userId],
    ["deviceId", executionContext.deviceId],
    ["bundleHash", executionContext.bundleHash],
    ["manifestHash", executionContext.manifestHash],
    ["capabilityId", executionContext.capabilityId],
    ["capabilityGrantId", executionContext.capabilityGrantId],
    ["consentEpoch", executionContext.consentEpoch],
    ["frameGeneration", executionContext.frameGeneration],
    ["sessionId", executionContext.sessionId],
  ];

  for (const [field, expected] of identityPairs) {
    if (context[field] !== expected) {
      return {
        code: "execution_context_identity_mismatch",
        message: "execution context is not bound to this plugin session",
      };
    }
  }

  return null;
}

function validateExecutionContextResource(
  executionContext: PluginExecutionContextRecord,
  resource: PluginResourceRef | null,
): PluginHostRpcErrorBody | null {
  const expected = executionContext.resource;
  if (!expected) {
    if (executionContext.plaintextScope.kind === "none") return null;

    return {
      code: "execution_context_resource_mismatch",
      message: "plaintext execution context is missing its resource binding",
    };
  }
  if (!resource) {
    return {
      code: "execution_context_resource_mismatch",
      message: "execution context requires a matching resource",
    };
  }

  if (expected.document_id !== undefined && expected.document_id !== resource.document_id) {
    return {
      code: "execution_context_resource_mismatch",
      message: "requested document does not match the execution context",
    };
  }

  if (expected.block_id !== undefined && expected.block_id !== resource.block_id) {
    return {
      code: "execution_context_resource_mismatch",
      message: "requested block does not match the execution context",
    };
  }

  if (expected.editor_id !== undefined && expected.editor_id !== resource.editor_id) {
    return {
      code: "execution_context_resource_mismatch",
      message: "requested editor does not match the execution context",
    };
  }

  if (expected.selected_document_ids !== undefined) {
    const actual = resource.selected_document_ids ?? [];
    if (!sameStringSet(expected.selected_document_ids, actual)) {
      return {
        code: "execution_context_resource_mismatch",
        message: "requested selected documents do not match the execution context",
      };
    }
  }

  if (expected.selection_range !== undefined) {
    if (
      !resource.selection_range ||
      !sameSelectionRange(expected.selection_range, resource.selection_range)
    ) {
      return {
        code: "execution_context_resource_mismatch",
        message: "requested selection range does not match the execution context",
      };
    }
  }

  if (expected.context_range !== undefined) {
    if (
      !resource.context_range ||
      !sameSelectionRange(expected.context_range, resource.context_range)
    ) {
      return {
        code: "execution_context_resource_mismatch",
        message: "requested context range does not match the execution context",
      };
    }
  }

  return null;
}

function validatePlaintextScopeResource(
  kind: PluginPlaintextScopeKind,
  resource: PluginResourceRef,
): PluginHostRpcErrorBody | null {
  if (kind === "block" || kind === "inline") {
    if (!resource.document_id || !resource.block_id) {
      return {
        code: "execution_context_resource_required",
        message: "renderer plaintext context requires document_id and block_id",
      };
    }
  }

  if (kind === "active_document" && !resource.document_id) {
    return {
      code: "execution_context_resource_required",
      message: "active document plaintext context requires document_id",
    };
  }

  if (kind === "selected_documents") {
    if (!resource.selected_document_ids?.length) {
      return {
        code: "execution_context_resource_required",
        message: "selected documents plaintext context requires selected_document_ids",
      };
    }
  }

  if (kind === "selection") {
    if (
      (!resource.editor_id && !resource.selected_document_ids?.length && !resource.document_id) ||
      !resource.selection_range
    ) {
      return {
        code: "execution_context_resource_required",
        message:
          "selection plaintext context requires editor_id or document selection resource and selection_range",
      };
    }
  }

  if (kind === "editor_context") {
    if ((!resource.editor_id && !resource.document_id) || !resource.context_range) {
      return {
        code: "execution_context_resource_required",
        message:
          "editor context plaintext context requires editor_id or document_id and context_range",
      };
    }
  }

  if (kind === "workspace") {
    return validateRequiredWorkspaceDocumentQueryLimits(
      resource,
      "execution_context_resource_required",
    );
  }

  return null;
}

function validateRequiredWorkspaceDocumentQueryLimits(
  resource: PluginResourceRef | null,
  code: "execution_context_resource_required" | "plaintext_scope_denied",
): PluginHostRpcErrorBody | null {
  if (resource?.max_documents !== undefined && resource.max_bytes !== undefined) return null;
  return {
    code,
    message: "workspace document query requires max_documents and max_bytes",
  };
}

async function auditPlaintext(
  options: PluginPlaintextAuditOptions,
  resource: PluginResourceRef | null,
  result: "allow" | "deny",
  reasonCode?: string,
  plaintextBytesOverride?: number,
): Promise<boolean> {
  if (options.policy?.plaintext?.audit !== "required") return true;
  if (!options.auditSink) return false;

  const executionContext = executionContextForAudit(options);
  const plaintextScopeKind = plaintextScopeKindForAudit(options.policy, executionContext, resource);
  const plaintextBytes =
    plaintextBytesOverride ?? plaintextBytesForAudit(executionContext, resource);
  const executionContextId = options.request.execution_context_id ?? null;
  const createdAt = new Date().toISOString();

  return pluginAuditSucceeded(
    options.auditSink({
      protocol: "refmd.security-audit-event",
      version: 1,
      event_id: auditEventId(),
      class: "security_runtime",
      type:
        result === "allow"
          ? "plugin.plaintext_payload.delivered"
          : "plugin.plaintext_payload.denied",
      actor: options.context.auditActor,
      pluginId: options.context.pluginId,
      packageId: options.context.packageId,
      applicationId: options.context.applicationId,
      activationId: options.context.activationId,
      ownerScopeKind: options.context.ownerScopeKind,
      stateHeadHash: options.context.stateHeadHash,
      consentHeadHash: options.context.consentHeadHash,
      capabilityGrantId: options.context.capabilityGrantId,
      consentEpoch: options.context.consentEpoch,
      frameGeneration: options.context.frameGeneration,
      frameScope: options.context.frameScope,
      workspaceId: options.context.workspaceId,
      bundleHash: options.context.bundleHash,
      manifestHash: options.context.manifestHash,
      capabilityId: options.context.capabilityId,
      requestId: options.request.request_id,
      executionContextId,
      contextKind: executionContext?.kind ?? null,
      payloadKind: options.policy.plaintext.operation,
      plaintextScopeKind,
      plaintextBytes,
      operation: options.request.operation,
      resourceRef: resource,
      result,
      reasonCode,
      scope: {
        workspace_id: options.context.workspaceId,
        document_id: resource?.document_id ?? null,
        share_id: null,
      },
      resource: {
        kind: "plugin",
        id: options.context.pluginId,
        version_hash: options.context.bundleHash,
      },
      action: {
        operation: options.request.operation,
        result: result === "allow" ? "allowed" : "denied",
        reason_code: reasonCode ?? null,
      },
      sensitivity: {
        plaintext_scope_kind: plaintextScopeKind,
        plaintext_bytes: plaintextBytes,
        egress_bytes: 0,
        storage_bytes: 0,
      },
      correlation: {
        request_id: options.request.request_id,
        capability_id: options.context.capabilityId,
        execution_context_id: executionContextId,
        authority_event_ref: null,
      },
      created_at: createdAt,
    }),
  );
}

function executionContextForAudit(
  options: Pick<PluginPlaintextAuditOptions, "request" | "executionContexts">,
): PluginExecutionContextRecord | null {
  const executionContextId = options.request.execution_context_id;
  if (!executionContextId) return null;
  return options.executionContexts?.get(executionContextId) ?? null;
}

function plaintextScopeKindForAudit(
  policy: PluginHostRpcOperationPolicy | undefined,
  executionContext: PluginExecutionContextRecord | null,
  resource: PluginResourceRef | null,
): PluginPlaintextScopeKind {
  if (executionContext) return executionContext.plaintextScope.kind;
  const allowedScopes = policy?.plaintext?.allowedPlaintextScopes ?? [];
  if (allowedScopes.length === 1 && allowedScopes[0]) return allowedScopes[0];
  if (resource?.selected_document_ids?.length) return "selected_documents";
  if (resource?.block_id) return "block";
  if (resource?.document_id) return "active_document";
  return "none";
}

function plaintextBytesForAudit(
  executionContext: PluginExecutionContextRecord | null,
  resource: PluginResourceRef | null,
): number {
  if (typeof resource?.max_bytes === "number" && Number.isFinite(resource.max_bytes)) {
    return Math.max(0, Math.floor(resource.max_bytes));
  }

  return executionContext?.plaintextScope.maxBytes ?? 0;
}

function plaintextPayloadBytes(payload: unknown): number {
  return plaintextPayloadValueBytes(payload);
}

function plaintextPayloadValueBytes(value: unknown): number {
  if (typeof value === "string") return utf8Bytes(value);

  if (value instanceof ArrayBuffer) return value.byteLength;

  if (ArrayBuffer.isView(value)) return value.byteLength;

  if (typeof Blob !== "undefined" && value instanceof Blob) return value.size;

  if (Array.isArray(value)) {
    return value.reduce((total, item) => total + plaintextPayloadValueBytes(item), 0);
  }

  if (!isObject(value)) return 0;

  let total = 0;
  for (const entryValue of Object.values(value)) {
    total += plaintextPayloadValueBytes(entryValue);
  }
  return total;
}

function utf8Bytes(value: string): number {
  return new TextEncoder().encode(value).byteLength;
}

function auditEventId(): string {
  if (typeof crypto !== "undefined" && typeof crypto.randomUUID === "function") {
    return crypto.randomUUID();
  }

  return `audit-${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

export function pluginResourceRef(value: unknown): PluginResourceRef | null {
  if (!isObject(value)) return null;
  const resource: PluginResourceRef = {};

  if (typeof value.document_id === "string" || value.document_id === null) {
    resource.document_id = value.document_id;
  }

  if (Array.isArray(value.selected_document_ids)) {
    resource.selected_document_ids = value.selected_document_ids.filter(
      (documentId): documentId is string => typeof documentId === "string",
    );
  }

  if (typeof value.block_id === "string" || value.block_id === null) {
    resource.block_id = value.block_id;
  }

  if (typeof value.editor_id === "string" || value.editor_id === null) {
    resource.editor_id = value.editor_id;
  }

  if (isPluginSelectionRangeRef(value.selection_range)) {
    resource.selection_range = value.selection_range;
  }

  if (isPluginSelectionRangeRef(value.context_range)) {
    resource.context_range = value.context_range;
  }

  if (typeof value.max_bytes === "number") {
    resource.max_bytes = value.max_bytes;
  }

  if (typeof value.max_documents === "number") {
    resource.max_documents = value.max_documents;
  }

  return resource;
}

function sameStringSet(a: readonly string[], b: readonly string[]): boolean {
  if (a.length !== b.length) return false;
  const left = new Set(a);
  return b.every((value) => left.has(value));
}

function sameSelectionRange(a: PluginSelectionRangeRef, b: PluginSelectionRangeRef): boolean {
  return a.anchor === b.anchor && a.head === b.head;
}

function isPluginSelectionRangeRef(value: unknown): value is PluginSelectionRangeRef {
  if (!isObject(value)) return false;

  return isSelectionEndpoint(value.anchor) && isSelectionEndpoint(value.head);
}

function isSelectionEndpoint(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}
