import {
  auditKnownPluginPlaintextDenied,
  auditPluginPlaintextDenied,
  claimPluginSingleUseExecutionContext,
  consumePluginSingleUseExecutionContext,
  emitPluginSecurityAudit,
  finalizePluginPlaintextRpcDelivery,
  isKnownPlaintextRpcOperation,
  pluginPayloadByteLength,
  pluginResourceRef,
  pluginAuditSucceeded,
  releasePluginSingleUseExecutionContext,
  validatePluginExecutionContextIssueOptions,
  validatePluginHostRpcAuthorization,
  validatePluginHostRpcOperationPolicy,
  validatePluginPermissionGrant,
  type PluginAuditSink,
  type PluginAuditActor,
  type PluginDocumentScope,
  type PluginExecutionContextHandle,
  type PluginExecutionContextIssueOptions,
  type PluginExecutionContextRecord,
  type PluginHighRiskConsent,
  type PluginHostRpcOperationPolicy,
  type PluginPermission,
  type PluginPlaintextScopeKind,
} from "../capability/capability-enforcement";

export const PLUGIN_HOST_RPC_PROTOCOL = "refmd.plugin-host-rpc";
export const PLUGIN_HOST_RPC_VERSION = 1;
export const PLUGIN_HOST_RPC_DEFAULT_TIMEOUT_MS = 120_000;

type RpcMessageKind =
  | "boot-ready"
  | "boot-port"
  | "boot-ack"
  | "boot-context"
  | "host-lifecycle"
  | "request"
  | "response"
  | "error";
type PluginHostRpcSessionState = "booting" | "authenticating" | "connected" | "closed";

export interface PluginHostFrameWindow {
  postMessage(message: unknown, targetOrigin: string, transfer?: Transferable[]): void;
}

export interface PluginHostFrameLifecycleTarget {
  addEventListener(type: "load" | "error" | "unload", listener: EventListener): void;
  removeEventListener(type: "load" | "error" | "unload", listener: EventListener): void;
  getAttribute?(name: "src"): string | null;
  remove(): void;
}

export interface PluginHostRpcSessionDescriptor {
  pluginId: string;
  packageId: string;
  applicationId: string;
  activationId: string;
  ownerScopeKind: string;
  workspaceId: string;
  userId: string;
  deviceId: string;
  stateHeadHash?: string;
  consentHeadHash?: string;
  bundleHash: string;
  manifestHash: string;
  capabilityId: string;
  capabilityGrantId: string;
  consentEpoch: number;
  permissions?: readonly PluginPermission[];
  highRiskConsents?: readonly PluginHighRiskConsent[];
  documentScope?: PluginDocumentScope;
  documentScopeProvider?: () => PluginDocumentScope | undefined;
  auditSink?: PluginAuditSink;
  auditActor?: PluginAuditActor;
  frameGeneration?: number;
  frameScope?: "primary" | "secondary";
  bootNonce?: string;
  validateSession?: PluginHostRpcSessionValidator;
  contentWindow: PluginHostFrameWindow | null;
  frameElement?: PluginHostFrameLifecycleTarget | null;
  expectsInitialFrameLoad?: boolean;
}

export interface PluginHostRpcContext {
  pluginId: string;
  packageId: string;
  applicationId: string;
  activationId: string;
  ownerScopeKind: string;
  workspaceId: string;
  userId: string;
  deviceId: string;
  stateHeadHash?: string;
  consentHeadHash?: string;
  bundleHash: string;
  manifestHash: string;
  capabilityId: string;
  capabilityGrantId: string;
  consentEpoch: number;
  frameGeneration: number;
  frameScope?: "primary" | "secondary";
  sessionId: string;
  auditActor: PluginAuditActor;
  auditSink?: PluginAuditSink | null;
}

export interface PluginHostRpcRequestEnvelope {
  protocol: typeof PLUGIN_HOST_RPC_PROTOCOL;
  version: typeof PLUGIN_HOST_RPC_VERSION;
  kind: "request";
  request_id: string;
  request_nonce: string;
  plugin_id: string;
  package_id: string;
  application_id: string;
  activation_id: string;
  owner_scope_kind: string;
  workspace_id: string;
  user_id: string;
  device_id: string;
  bundle_hash: string;
  manifest_hash: string;
  capability_id: string;
  capability_grant_id: string;
  consent_epoch: number;
  frame_generation: number;
  operation: string;
  execution_context_id?: string;
  resource?: unknown;
  payload?: unknown;
}

export interface PluginHostRpcResponseEnvelope {
  protocol: typeof PLUGIN_HOST_RPC_PROTOCOL;
  version: typeof PLUGIN_HOST_RPC_VERSION;
  kind: "response";
  request_id: string;
  payload?: unknown;
}

export interface PluginHostRpcErrorEnvelope {
  protocol: typeof PLUGIN_HOST_RPC_PROTOCOL;
  version: typeof PLUGIN_HOST_RPC_VERSION;
  kind: "error";
  request_id: string;
  error: PluginHostRpcErrorBody;
}

export interface PluginHostRpcErrorBody {
  code: string;
  message: string;
}

export interface PluginHostRpcHandlerRequest {
  operation: string;
  resource?: unknown;
  payload?: unknown;
  requestId: string;
  requestNonce: string;
  signal: AbortSignal;
  executionContextId?: string;
  auditExecutionContextId?: string | null;
  plaintextScopeKind?: PluginPlaintextScopeKind;
}

export type PluginHostRpcHandler = (
  context: PluginHostRpcContext,
  request: PluginHostRpcHandlerRequest,
) => unknown | Promise<unknown>;

interface PluginHostRpcHandlerRegistration {
  handler: PluginHostRpcHandler;
  policy: PluginHostRpcOperationPolicy;
}

export interface PluginHostRpcHandlerOwnerDescriptor {
  pluginId: string;
  packageId: string;
  workspaceId: string;
  applicationId: string;
  activationId: string;
  ownerScopeKind: string;
  userId: string;
  deviceId: string;
  bundleHash: string;
  manifestHash?: string;
  frameGeneration: number;
  frameScope?: "primary" | "secondary";
  consentEpoch: number;
  capabilityGrantId: string;
}

export type PluginHostRpcSessionValidator = (
  context: PluginHostRpcContext,
  request: PluginHostRpcRequestEnvelope,
) => PluginHostRpcErrorBody | null;

export type PluginHostWindowMessageHandler = (event: MessageEvent) => boolean;

export interface PluginHostRpcRouterOptions {
  windowTarget?: Pick<Window, "addEventListener" | "removeEventListener">;
  timeoutMs?: number;
  idFactory?: () => string;
  validateSession?: PluginHostRpcSessionValidator;
}

export interface PluginHostRpcRequestOptions {
  policy: PluginHostRpcOperationPolicy;
  executionContextId?: string;
  timeoutMs?: number;
}

interface BootReadyMessage {
  protocol: typeof PLUGIN_HOST_RPC_PROTOCOL;
  version: typeof PLUGIN_HOST_RPC_VERSION;
  kind: "boot-ready";
}

interface BootPortMessage {
  protocol: typeof PLUGIN_HOST_RPC_PROTOCOL;
  version: typeof PLUGIN_HOST_RPC_VERSION;
  kind: "boot-port";
  frame_generation: number;
}

interface BootContextMessage {
  protocol: typeof PLUGIN_HOST_RPC_PROTOCOL;
  version: typeof PLUGIN_HOST_RPC_VERSION;
  kind: "boot-context";
  frame_generation: number;
  runtime_context: PluginHostRpcBootRuntimeContext;
}

interface PluginHostRpcBootRuntimeContext {
  plugin_id: string;
  package_id: string;
  application_id: string;
  activation_id: string;
  owner_scope_kind: string;
  workspace_id: string;
  user_id: string;
  device_id: string;
  bundle_hash: string;
  manifest_hash: string;
  capability_id: string;
  capability_grant_id: string;
  consent_epoch: number;
  frame_scope: "primary" | "secondary";
}

interface BootAckMessage {
  protocol: typeof PLUGIN_HOST_RPC_PROTOCOL;
  version: typeof PLUGIN_HOST_RPC_VERSION;
  kind: "boot-ack";
  boot_nonce: string;
  frame_generation: number;
}

interface HostLifecycleMessage {
  protocol: typeof PLUGIN_HOST_RPC_PROTOCOL;
  version: typeof PLUGIN_HOST_RPC_VERSION;
  kind: "host-lifecycle";
  lifecycle: "close";
  reason: string;
}

interface PendingRpc {
  resolve: (value: unknown) => void;
  reject: (reason: Error) => void;
  timeoutId: ReturnType<typeof setTimeout>;
}

interface DocumentWriteRateCounter {
  windowStartedAtMs: number;
  count: number;
}

type RpcEnvelope =
  | BootReadyMessage
  | BootPortMessage
  | BootAckMessage
  | PluginHostRpcRequestEnvelope
  | PluginHostRpcResponseEnvelope
  | PluginHostRpcErrorEnvelope;

export class PluginHostRpcError extends Error {
  readonly code: string;

  constructor(code: string, message: string) {
    super(message);
    this.name = "PluginHostRpcError";
    this.code = code;
  }
}

export class PluginHostMessageRouter {
  private readonly sessionsById = new Map<string, PluginHostRpcSession>();
  private readonly sessionsByContentWindow = new Map<object, PluginHostRpcSession>();
  private readonly handlers = new Map<string, PluginHostRpcHandlerRegistration>();
  private readonly ownerHandlers = new Map<string, PluginHostRpcHandlerRegistration>();
  private readonly windowMessageHandlers = new Set<PluginHostWindowMessageHandler>();
  private readonly windowTarget: Pick<Window, "addEventListener" | "removeEventListener"> | null;
  private readonly timeoutMs: number;
  private readonly idFactory: () => string;
  private readonly validateSession: PluginHostRpcSessionValidator | null;
  private started = false;
  private readonly messageListener: EventListener = (event) => {
    if (isMessageEventLike(event)) {
      this.handleWindowMessage(event);
    }
  };

  constructor(options: PluginHostRpcRouterOptions = {}) {
    this.windowTarget = options.windowTarget ?? globalWindowTarget();
    this.timeoutMs = options.timeoutMs ?? PLUGIN_HOST_RPC_DEFAULT_TIMEOUT_MS;
    this.idFactory = options.idFactory ?? randomId;
    this.validateSession = options.validateSession ?? null;
  }

  start(): void {
    if (this.started || !this.windowTarget) return;
    this.windowTarget.addEventListener("message", this.messageListener);
    this.started = true;
  }

  stop(reason = "router_stopped"): void {
    this.closeAll(reason);
    if (!this.started || !this.windowTarget) return;
    this.windowTarget.removeEventListener("message", this.messageListener);
    this.started = false;
  }

  registerWindowMessageHandler(handler: PluginHostWindowMessageHandler): () => void {
    this.windowMessageHandlers.add(handler);

    return () => {
      this.windowMessageHandlers.delete(handler);
    };
  }

  registerHandler(
    operation: string,
    handler: PluginHostRpcHandler,
    policy: PluginHostRpcOperationPolicy,
  ): () => void {
    if (!operation) throw new PluginHostRpcError("invalid_operation", "operation is required");
    this.assertValidHandlerPolicy(operation, policy);

    if (this.handlers.has(operation)) {
      throw new PluginHostRpcError(
        "duplicate_operation",
        `handler already registered: ${operation}`,
      );
    }

    this.handlers.set(operation, { handler, policy });

    return () => {
      if (this.handlers.get(operation)?.handler === handler) {
        this.handlers.delete(operation);
      }
    };
  }

  registerOwnerHandler(
    owner: PluginHostRpcHandlerOwnerDescriptor,
    operation: string,
    handler: PluginHostRpcHandler,
    policy: PluginHostRpcOperationPolicy,
  ): () => void {
    if (!operation) throw new PluginHostRpcError("invalid_operation", "operation is required");
    this.assertValidHandlerPolicy(operation, policy);

    const key = ownerHandlerKey(owner, operation);
    if (this.ownerHandlers.has(key)) {
      throw new PluginHostRpcError(
        "duplicate_operation",
        `handler already registered: ${operation}`,
      );
    }

    const registration = { handler, policy };
    this.ownerHandlers.set(key, registration);

    return () => {
      if (this.ownerHandlers.get(key) === registration) {
        this.ownerHandlers.delete(key);
      }
    };
  }

  createSession(descriptor: PluginHostRpcSessionDescriptor): PluginHostRpcSession {
    const contentWindow = descriptor.contentWindow;
    if (!contentWindow) {
      throw new PluginHostRpcError("missing_frame", "plugin iframe contentWindow is required");
    }
    if (!descriptor.capabilityId || !descriptor.capabilityGrantId) {
      throw new PluginHostRpcError(
        "plugin_runtime_capability_grant_required",
        "plugin runtime requires a host-issued capability grant",
      );
    }

    const session = new PluginHostRpcSession({
      ...descriptor,
      contentWindow,
      sessionId: this.idFactory(),
      bootNonce: descriptor.bootNonce ?? this.idFactory(),
      frameGeneration: descriptor.frameGeneration ?? 1,
      timeoutMs: this.timeoutMs,
      idFactory: this.idFactory,
      validateSession: descriptor.validateSession ?? this.validateSession,
      resolveHandler: (session, operation) =>
        this.ownerHandlers.get(ownerHandlerKey(session, operation)) ??
        this.handlers.get(operation) ??
        null,
      unregister: (closedSession) => this.unregisterSession(closedSession),
    });

    this.sessionsById.set(session.sessionId, session);
    this.sessionsByContentWindow.set(session.contentWindow, session);
    return session;
  }

  handleWindowMessage(event: MessageEvent): boolean {
    const message = event.data;
    if (!isBootReadyMessage(message)) {
      const sourceSession = this.sessionForWindowSource(event.source);
      if (!sourceSession) return this.handleAuxiliaryWindowMessage(event);

      sourceSession.close("unexpected_window_message");
      return true;
    }

    const sourceSession = this.sessionForWindowSource(event.source);
    if (!sourceSession) return false;

    if (sourceSession.connected) {
      sourceSession.close("invalid_boot_message");
      return true;
    }

    sourceSession.completeBoot();
    return true;
  }

  private handleAuxiliaryWindowMessage(event: MessageEvent): boolean {
    for (const handler of this.windowMessageHandlers) {
      if (handler(event)) return true;
    }
    return false;
  }

  closeSession(sessionId: string, reason = "closed"): void {
    this.sessionsById.get(sessionId)?.close(reason);
  }

  closeByApplication(applicationId: string, reason = "application_closed"): void {
    this.closeMatching((session) => session.applicationId === applicationId, reason);
  }

  closeByActivation(activationId: string, reason = "activation_closed"): void {
    this.closeMatching((session) => session.activationId === activationId, reason);
  }

  closeByWorkspace(workspaceId: string, reason = "workspace_closed"): void {
    this.closeMatching((session) => session.workspaceId === workspaceId, reason);
  }

  closeByBundle(workspaceId: string, bundleHash: string, reason = "bundle_closed"): void {
    this.closeMatching(
      (session) => session.workspaceId === workspaceId && session.bundleHash === bundleHash,
      reason,
    );
  }

  closeByManifest(workspaceId: string, manifestHash: string, reason = "manifest_closed"): void {
    this.closeMatching(
      (session) => session.workspaceId === workspaceId && session.manifestHash === manifestHash,
      reason,
    );
  }

  closeByCapabilityGrant(capabilityGrantId: string, reason = "capability_grant_closed"): void {
    this.closeMatching((session) => session.capabilityGrantId === capabilityGrantId, reason);
  }

  closeByDocumentAccess(documentId: string, reason = "document_access_closed"): void {
    this.closeMatching((session) => session.allowsDocument(documentId), reason);
  }

  closeAll(reason = "router_closed"): void {
    this.closeMatching(() => true, reason);
  }

  private closeMatching(
    predicate: (session: PluginHostRpcSession) => boolean,
    reason: string,
  ): void {
    for (const session of Array.from(this.sessionsById.values())) {
      if (!predicate(session)) continue;
      session.close(reason);
    }
  }

  private unregisterSession(session: PluginHostRpcSession): void {
    this.sessionsById.delete(session.sessionId);
    this.sessionsByContentWindow.delete(session.contentWindow);
  }

  private sessionForWindowSource(source: MessageEventSource | null): PluginHostRpcSession | null {
    if (!source || typeof source !== "object") return null;
    return this.sessionsByContentWindow.get(source) ?? null;
  }

  private assertValidHandlerPolicy(operation: string, policy: PluginHostRpcOperationPolicy): void {
    if (!policy) {
      throw new PluginHostRpcError(
        "operation_policy_required",
        "plugin Host RPC handlers require an explicit operation policy",
      );
    }
    const policyError = validatePluginHostRpcOperationPolicy(operation, policy);
    if (policyError) {
      throw new PluginHostRpcError(policyError.code, policyError.message);
    }
  }
}

interface PluginHostRpcSessionOptions extends Omit<
  PluginHostRpcSessionDescriptor,
  "contentWindow" | "frameGeneration" | "validateSession"
> {
  contentWindow: PluginHostFrameWindow;
  sessionId: string;
  bootNonce: string;
  frameGeneration: number;
  timeoutMs: number;
  idFactory: () => string;
  validateSession: PluginHostRpcSessionValidator | null;
  resolveHandler: (
    session: PluginHostRpcSession,
    operation: string,
  ) => PluginHostRpcHandlerRegistration | null;
  unregister: (session: PluginHostRpcSession) => void;
}

export class PluginHostRpcSession {
  readonly sessionId: string;
  readonly bootNonce: string;
  readonly pluginId: string;
  readonly packageId: string;
  readonly applicationId: string;
  readonly activationId: string;
  readonly ownerScopeKind: string;
  readonly workspaceId: string;
  readonly userId: string;
  readonly deviceId: string;
  readonly stateHeadHash: string | null;
  readonly consentHeadHash: string | null;
  readonly bundleHash: string;
  readonly manifestHash: string;
  readonly capabilityId: string;
  readonly capabilityGrantId: string;
  readonly consentEpoch: number;
  readonly permissions: ReadonlySet<PluginPermission>;
  readonly highRiskConsents: ReadonlySet<PluginHighRiskConsent>;
  readonly frameGeneration: number;
  readonly frameScope: "primary" | "secondary";
  private expectedInitialFrameLoads: number;
  private readonly initialDocumentScope: PluginDocumentScope;
  private readonly documentScopeProvider: (() => PluginDocumentScope | undefined) | null;
  readonly contentWindow: PluginHostFrameWindow;
  private readonly auditSink: PluginAuditSink | null;
  private readonly auditActor: PluginAuditActor;
  private readonly frameElement: PluginHostFrameLifecycleTarget | null;
  private readonly timeoutMs: number;
  private readonly idFactory: () => string;
  private readonly validateSessionHook: PluginHostRpcSessionValidator | null;
  private readonly resolveHandler: (
    session: PluginHostRpcSession,
    operation: string,
  ) => PluginHostRpcHandlerRegistration | null;
  private readonly unregister: (session: PluginHostRpcSession) => void;
  private readonly acceptedRequestNonces = new Set<string>();
  private readonly executionContexts = new Map<string, PluginExecutionContextRecord>();
  private readonly documentWriteRateCounters = new Map<string, DocumentWriteRateCounter>();
  private readonly pending = new Map<string, PendingRpc>();
  private readonly closeCallbacks = new Set<(reason: string) => void>();
  private readonly bootAuthenticatedCallbacks = new Set<() => void>();
  private state: PluginHostRpcSessionState = "booting";
  private port: MessagePort | null = null;
  private readonly portListener: EventListener = (event) => {
    if (isMessageEventLike(event)) {
      void this.handlePortMessage(event.data);
    }
  };
  private readonly frameLifecycleListener: EventListener = (event) => {
    if (this.expectedInitialFrameLoads > 0 && (event.type === "unload" || event.type === "error")) {
      return;
    }

    if (this.expectedInitialFrameLoads > 0 && event.type === "load") {
      const readFrameSrc = this.frameElement?.getAttribute;
      const frameSrc = readFrameSrc?.call(this.frameElement, "src");
      if (readFrameSrc && (frameSrc === null || frameSrc === "")) {
        return;
      }
      this.expectedInitialFrameLoads -= 1;
      return;
    }

    if (this.state !== "booting" && this.state !== "closed") {
      this.close("frame_navigation");
    }
  };

  constructor(options: PluginHostRpcSessionOptions) {
    this.sessionId = options.sessionId;
    this.bootNonce = options.bootNonce;
    this.pluginId = options.pluginId;
    this.packageId = options.packageId;
    this.applicationId = options.applicationId;
    this.activationId = options.activationId;
    this.ownerScopeKind = options.ownerScopeKind;
    this.workspaceId = options.workspaceId;
    this.userId = options.userId;
    this.deviceId = options.deviceId;
    this.stateHeadHash = options.stateHeadHash ?? null;
    this.consentHeadHash = options.consentHeadHash ?? null;
    this.bundleHash = options.bundleHash;
    this.manifestHash = options.manifestHash;
    this.capabilityId = options.capabilityId;
    this.capabilityGrantId = options.capabilityGrantId;
    this.consentEpoch = options.consentEpoch;
    this.permissions = new Set(options.permissions ?? []);
    this.highRiskConsents = new Set(options.highRiskConsents ?? []);
    this.initialDocumentScope = options.documentScope ?? {};
    this.documentScopeProvider = options.documentScopeProvider ?? null;
    this.auditSink = options.auditSink ?? null;
    this.auditActor = options.auditActor ?? systemAuditActor(this.sessionId);
    this.frameGeneration = options.frameGeneration;
    this.frameScope = options.frameScope ?? "primary";
    this.expectedInitialFrameLoads = options.expectsInitialFrameLoad ? 1 : 0;
    this.contentWindow = options.contentWindow;
    this.frameElement = options.frameElement ?? null;
    this.timeoutMs = options.timeoutMs;
    this.idFactory = options.idFactory;
    this.validateSessionHook = options.validateSession;
    this.resolveHandler = options.resolveHandler;
    this.unregister = options.unregister;
    this.frameElement?.addEventListener("load", this.frameLifecycleListener);
    this.frameElement?.addEventListener("error", this.frameLifecycleListener);
    this.frameElement?.addEventListener("unload", this.frameLifecycleListener);

    const permissionGrantError = validatePluginPermissionGrant(this.permissions);
    if (permissionGrantError) {
      throw new PluginHostRpcError(permissionGrantError.code, permissionGrantError.message);
    }
  }

  get connected(): boolean {
    return this.state === "connected";
  }

  get closed(): boolean {
    return this.state === "closed";
  }

  get documentScope(): PluginDocumentScope {
    return this.documentScopeProvider?.() ?? this.initialDocumentScope;
  }

  onClose(callback: (reason: string) => void): () => void {
    this.closeCallbacks.add(callback);
    return () => {
      this.closeCallbacks.delete(callback);
    };
  }

  onBootAuthenticated(callback: () => void): () => void {
    if (this.state === "connected") {
      callback();
      return () => undefined;
    }
    if (this.state === "closed") return () => undefined;

    this.bootAuthenticatedCallbacks.add(callback);
    return () => {
      this.bootAuthenticatedCallbacks.delete(callback);
    };
  }

  securityAuditContext(): PluginHostRpcContext {
    return this.context();
  }

  allowsDocument(documentId: string): boolean {
    return (
      this.documentScope.workspaceReadAllowed === true ||
      this.documentScope.activeDocumentId === documentId ||
      this.documentScope.selectedDocumentIds?.includes(documentId) === true ||
      this.documentScope.allowedDocumentIds?.includes(documentId) === true
    );
  }

  completeBoot(): void {
    if (this.state !== "booting") return;

    const channel = new MessageChannel();
    this.attachPort(channel.port1);
    this.contentWindow.postMessage(
      {
        protocol: PLUGIN_HOST_RPC_PROTOCOL,
        version: PLUGIN_HOST_RPC_VERSION,
        kind: "boot-port",
        frame_generation: this.frameGeneration,
      } satisfies BootPortMessage,
      "*",
      [channel.port2],
    );
  }

  async request(
    operation: string,
    payload?: unknown,
    resource?: unknown,
    timeoutMs = this.timeoutMs,
    options?: PluginHostRpcRequestOptions,
  ): Promise<unknown> {
    if (this.state !== "connected" || !this.port) {
      throw new PluginHostRpcError("session_not_connected", "plugin session is not connected");
    }

    if (!options?.policy) {
      throw new PluginHostRpcError(
        "operation_policy_required",
        "plugin Host RPC requests require an explicit operation policy",
      );
    }

    const requestId = this.idFactory();
    const envelope: PluginHostRpcRequestEnvelope = {
      protocol: PLUGIN_HOST_RPC_PROTOCOL,
      version: PLUGIN_HOST_RPC_VERSION,
      kind: "request",
      request_id: requestId,
      request_nonce: this.idFactory(),
      plugin_id: this.pluginId,
      package_id: this.packageId,
      application_id: this.applicationId,
      activation_id: this.activationId,
      owner_scope_kind: this.ownerScopeKind,
      workspace_id: this.workspaceId,
      user_id: this.userId,
      device_id: this.deviceId,
      bundle_hash: this.bundleHash,
      manifest_hash: this.manifestHash,
      capability_id: this.capabilityId,
      capability_grant_id: this.capabilityGrantId,
      consent_epoch: this.consentEpoch,
      frame_generation: this.frameGeneration,
      operation,
      execution_context_id: options.executionContextId,
      resource,
      payload,
    };
    const requestTimeoutMs = options.timeoutMs ?? timeoutMs;
    const responsePromise = new Promise((resolve, reject) => {
      const timeoutId = setTimeout(() => {
        this.pending.delete(requestId);
        reject(new PluginHostRpcError("timeout", `plugin RPC timed out: ${operation}`));
      }, requestTimeoutMs);

      this.pending.set(requestId, { resolve, reject, timeoutId });
    });

    const validationError = await this.validateHostDelivery(envelope, options.policy, payload);
    if (validationError) {
      this.rejectPending(requestId, validationError);
      return responsePromise;
    }

    if (!this.pending.has(requestId)) return responsePromise;
    if (this.state !== "connected" || !this.port) {
      this.rejectPending(requestId, {
        code: "session_closed",
        message: "plugin session is closed",
      });
      return responsePromise;
    }

    this.port.postMessage(envelope);
    return responsePromise;
  }

  issueExecutionContext(options: PluginExecutionContextIssueOptions): PluginExecutionContextHandle {
    if (this.state !== "connected") {
      throw new PluginHostRpcError("session_not_connected", "plugin session is not connected");
    }

    const issueError = validatePluginExecutionContextIssueOptions(options, Date.now());
    if (issueError) {
      throw new PluginHostRpcError(issueError.code, issueError.message);
    }

    const executionContextId = this.idFactory();
    const record: PluginExecutionContextRecord = {
      executionContextId,
      kind: options.kind,
      pluginId: this.pluginId,
      packageId: this.packageId,
      applicationId: this.applicationId,
      activationId: this.activationId,
      ownerScopeKind: this.ownerScopeKind,
      workspaceId: this.workspaceId,
      userId: this.userId,
      deviceId: this.deviceId,
      ...(this.stateHeadHash ? { stateHeadHash: this.stateHeadHash } : {}),
      ...(this.consentHeadHash ? { consentHeadHash: this.consentHeadHash } : {}),
      bundleHash: this.bundleHash,
      manifestHash: this.manifestHash,
      capabilityId: this.capabilityId,
      capabilityGrantId: this.capabilityGrantId,
      consentEpoch: this.consentEpoch,
      frameGeneration: this.frameGeneration,
      frameScope: this.frameScope,
      sessionId: this.sessionId,
      resource: options.resource,
      plaintextScope: options.plaintextScope,
      hostInvocation: options.hostInvocation,
      allowedOperations: options.allowedOperations,
      expiresAtMs: options.expiresAtMs,
      singleUse: options.singleUse ?? false,
    };
    this.executionContexts.set(executionContextId, record);

    return {
      protocol: "refmd.plugin-execution-context",
      version: 1,
      execution_context_id: executionContextId,
      kind: record.kind,
      host_invocation: {
        kind: record.hostInvocation.kind,
        user_gesture: record.hostInvocation.userGesture,
        ...(record.hostInvocation.tokenId ? { token_id: record.hostInvocation.tokenId } : {}),
      },
      expires_at_ms: record.expiresAtMs,
      single_use: record.singleUse,
    };
  }

  revokeExecutionContext(executionContextId: string): void {
    this.executionContexts.delete(executionContextId);
  }

  close(reason = "closed"): void {
    if (this.state === "closed") return;
    this.state = "closed";

    if (this.port) {
      this.port.postMessage({
        protocol: PLUGIN_HOST_RPC_PROTOCOL,
        version: PLUGIN_HOST_RPC_VERSION,
        kind: "host-lifecycle",
        lifecycle: "close",
        reason,
      } satisfies HostLifecycleMessage);
      this.port.removeEventListener("message", this.portListener);
      this.port.close();
      this.port = null;
    }

    this.frameElement?.removeEventListener("load", this.frameLifecycleListener);
    this.frameElement?.removeEventListener("error", this.frameLifecycleListener);
    this.frameElement?.removeEventListener("unload", this.frameLifecycleListener);
    this.frameElement?.remove();

    for (const [requestId, pending] of this.pending) {
      clearTimeout(pending.timeoutId);
      pending.reject(new PluginHostRpcError("session_closed", reason));
      this.pending.delete(requestId);
    }

    this.acceptedRequestNonces.clear();
    this.executionContexts.clear();
    this.bootAuthenticatedCallbacks.clear();
    this.unregister(this);
    for (const callback of Array.from(this.closeCallbacks)) {
      callback(reason);
    }
    this.closeCallbacks.clear();
  }

  private attachPort(port: MessagePort): void {
    this.port = port;
    this.state = "authenticating";
    port.addEventListener("message", this.portListener);
    port.start();
  }

  private sendBootContext(): void {
    this.port?.postMessage({
      protocol: PLUGIN_HOST_RPC_PROTOCOL,
      version: PLUGIN_HOST_RPC_VERSION,
      kind: "boot-context",
      frame_generation: this.frameGeneration,
      runtime_context: {
        plugin_id: this.pluginId,
        package_id: this.packageId,
        application_id: this.applicationId,
        activation_id: this.activationId,
        owner_scope_kind: this.ownerScopeKind,
        workspace_id: this.workspaceId,
        user_id: this.userId,
        device_id: this.deviceId,
        bundle_hash: this.bundleHash,
        manifest_hash: this.manifestHash,
        capability_id: this.capabilityId,
        capability_grant_id: this.capabilityGrantId,
        consent_epoch: this.consentEpoch,
        frame_scope: this.frameScope,
      },
    } satisfies BootContextMessage);
  }

  private async handlePortMessage(message: unknown): Promise<void> {
    if (!isRpcEnvelope(message)) return;

    if (message.kind === "boot-ack") {
      if (
        this.state === "authenticating" &&
        message.boot_nonce === this.bootNonce &&
        message.frame_generation === this.frameGeneration
      ) {
        this.state = "connected";
        this.sendBootContext();
        this.notifyBootAuthenticated();
      } else {
        this.close("invalid_boot_ack");
      }
      return;
    }

    if (this.state !== "connected") return;

    if (message.kind === "request") {
      await this.handleRequest(message);
      return;
    }

    if (message.kind === "response") {
      this.resolvePending(message.request_id, message.payload);
      return;
    }

    if (message.kind === "error") {
      this.rejectPending(message.request_id, message.error);
    }
  }

  private notifyBootAuthenticated(): void {
    const callbacks = Array.from(this.bootAuthenticatedCallbacks);
    this.bootAuthenticatedCallbacks.clear();

    for (const callback of callbacks) {
      try {
        callback();
      } catch {
        this.close("boot_authenticated_callback_failed");
      }
    }
  }

  private async handleRequest(message: PluginHostRpcRequestEnvelope): Promise<void> {
    const registration = this.resolveHandler(this, message.operation);
    if (!registration) {
      if (isKnownPlaintextRpcOperation(message.operation)) {
        const auditError = await auditKnownPluginPlaintextDenied(
          {
            context: this.context(),
            request: message,
            executionContexts: this.executionContexts,
            auditSink: this.auditSink,
          },
          "unknown_operation",
        );
        if (auditError) {
          this.postError(message.request_id, auditError.code, auditError.message);
          return;
        }
      }

      this.postError(
        message.request_id,
        "unknown_operation",
        `no handler registered: ${message.operation}`,
      );
      return;
    }

    const validationError = await this.validateRequest(message, registration.policy);
    if (validationError) {
      this.postError(message.request_id, validationError.code, validationError.message);
      return;
    }

    try {
      const payload = await this.invokeHandlerWithTimeout(registration.handler, message);

      const deliveryError = await this.finalizePlaintextDelivery(
        message,
        registration.policy,
        payload,
      );
      if (deliveryError) {
        this.releasePlaintextExecutionContext(message, registration.policy);
        this.postError(message.request_id, deliveryError.code, deliveryError.message);
        return;
      }

      this.consumePlaintextExecutionContext(message, registration.policy);
      this.postResponse(message.request_id, payload);
    } catch (error) {
      this.releasePlaintextExecutionContext(message, registration.policy);
      if (error instanceof PluginHostRpcError) {
        this.postError(message.request_id, error.code, error.message);
        return;
      }

      this.postError(message.request_id, "handler_error", errorMessage(error));
    }
  }

  private async invokeHandlerWithTimeout(
    handler: PluginHostRpcHandler,
    message: PluginHostRpcRequestEnvelope,
  ): Promise<unknown> {
    let timeoutId: ReturnType<typeof setTimeout> | undefined;
    let releaseCloseCallback: (() => void) | undefined;
    const abortController = new AbortController();
    const handlerResult = Promise.resolve().then(() =>
      handler(this.context(), {
        operation: message.operation,
        resource: message.resource,
        payload: message.payload,
        requestId: message.request_id,
        requestNonce: message.request_nonce,
        signal: abortController.signal,
        executionContextId: message.execution_context_id,
        auditExecutionContextId: this.auditExecutionContextId(message),
        plaintextScopeKind: this.auditPlaintextScopeKind(message),
      }),
    );
    const timeout = new Promise<never>((_, reject) => {
      timeoutId = setTimeout(() => {
        const error = new PluginHostRpcError(
          "timeout",
          `plugin Host RPC handler timed out: ${message.operation}`,
        );
        abortController.abort(error);
        reject(error);
      }, this.timeoutMs);
    });
    const closed = new Promise<never>((_, reject) => {
      releaseCloseCallback = this.onClose((reason) => {
        const error = new PluginHostRpcError("session_closed", reason);
        abortController.abort(error);
        reject(error);
      });
    });

    try {
      return await Promise.race([handlerResult, timeout, closed]);
    } finally {
      if (timeoutId) clearTimeout(timeoutId);
      releaseCloseCallback?.();
    }
  }

  private async validateRequest(
    message: PluginHostRpcRequestEnvelope,
    policy: PluginHostRpcOperationPolicy | undefined,
  ): Promise<PluginHostRpcErrorBody | null> {
    if (message.plugin_id !== this.pluginId) {
      return this.withPlaintextDenyAudit(message, policy, {
        code: "plugin_mismatch",
        message: "plugin_id does not match session",
      });
    }

    if (message.application_id !== this.applicationId) {
      return this.withPlaintextDenyAudit(message, policy, {
        code: "application_mismatch",
        message: "application_id does not match session",
      });
    }

    if (message.package_id !== this.packageId) {
      return this.withPlaintextDenyAudit(message, policy, {
        code: "package_mismatch",
        message: "package_id does not match session",
      });
    }

    if (message.activation_id !== this.activationId) {
      return this.withPlaintextDenyAudit(message, policy, {
        code: "activation_mismatch",
        message: "activation_id does not match session",
      });
    }

    if (message.owner_scope_kind !== this.ownerScopeKind) {
      return this.withPlaintextDenyAudit(message, policy, {
        code: "owner_scope_mismatch",
        message: "owner_scope_kind does not match session",
      });
    }

    if (message.workspace_id !== this.workspaceId) {
      return this.withPlaintextDenyAudit(message, policy, {
        code: "workspace_mismatch",
        message: "workspace_id does not match session",
      });
    }

    if (message.user_id !== this.userId) {
      return this.withPlaintextDenyAudit(message, policy, {
        code: "user_mismatch",
        message: "user_id does not match session",
      });
    }

    if (message.device_id !== this.deviceId) {
      return this.withPlaintextDenyAudit(message, policy, {
        code: "device_mismatch",
        message: "device_id does not match session",
      });
    }

    if (message.bundle_hash !== this.bundleHash) {
      return this.withPlaintextDenyAudit(message, policy, {
        code: "bundle_mismatch",
        message: "bundle_hash does not match session",
      });
    }

    if (message.manifest_hash !== this.manifestHash) {
      return this.withPlaintextDenyAudit(message, policy, {
        code: "manifest_mismatch",
        message: "manifest_hash does not match session",
      });
    }

    if (message.capability_id !== this.capabilityId) {
      return this.withPlaintextDenyAudit(message, policy, {
        code: "capability_mismatch",
        message: "capability_id does not match session",
      });
    }

    if (message.capability_grant_id !== this.capabilityGrantId) {
      return this.withPlaintextDenyAudit(message, policy, {
        code: "capability_grant_mismatch",
        message: "capability_grant_id does not match session",
      });
    }

    if (message.consent_epoch !== this.consentEpoch) {
      return this.withPlaintextDenyAudit(message, policy, {
        code: "consent_epoch_mismatch",
        message: "consent_epoch does not match session",
      });
    }

    if (message.frame_generation !== this.frameGeneration) {
      return this.withPlaintextDenyAudit(message, policy, {
        code: "frame_generation_mismatch",
        message: "frame_generation does not match session",
      });
    }

    if (this.acceptedRequestNonces.has(message.request_nonce)) {
      return this.withPlaintextDenyAudit(message, policy, {
        code: "replayed_request_nonce",
        message: "request_nonce was already used on this port",
      });
    }

    this.acceptedRequestNonces.add(message.request_nonce);
    const context = this.context();
    if (policy && !this.validateSessionHook) {
      return this.withPlaintextDenyAudit(
        message,
        policy,
        {
          code: "session_freshness_validator_required",
          message: "policy-protected plugin RPC requires a live session freshness validator",
        },
        context,
      );
    }

    const freshnessError = this.validateSessionHook?.(context, message) ?? null;
    if (freshnessError) {
      return this.withPlaintextDenyAudit(message, policy, freshnessError, context);
    }

    const authorizationOptions = {
      context,
      request: message,
      policy,
      permissions: this.permissions,
      highRiskConsents: this.highRiskConsents,
      documentScope: this.documentScope,
      executionContexts: this.executionContexts,
      nowMs: Date.now(),
      auditSink: this.auditSink,
    };
    const authorizationError = await validatePluginHostRpcAuthorization(authorizationOptions);
    if (authorizationError) {
      return uiBoundaryDenyAuditType(message.operation, authorizationError.code)
        ? this.withPlaintextDenyAudit(message, policy, authorizationError, context)
        : authorizationError;
    }
    const rateLimitError = this.validateDocumentWriteRateLimit(
      message,
      policy,
      authorizationOptions.nowMs,
    );
    if (rateLimitError) return rateLimitError;
    const documentWriteAuditError = await this.auditDocumentWriteRequested(
      message,
      policy,
      context,
    );
    if (documentWriteAuditError) return documentWriteAuditError;
    const executionContextClaimError = claimPluginSingleUseExecutionContext(authorizationOptions);
    if (executionContextClaimError) return executionContextClaimError;
    return null;
  }

  private async validateHostDelivery(
    message: PluginHostRpcRequestEnvelope,
    policy: PluginHostRpcOperationPolicy | undefined,
    payload: unknown,
  ): Promise<PluginHostRpcErrorBody | null> {
    if (!policy) return null;

    const context = this.context();
    if (!this.validateSessionHook) {
      return this.withPlaintextDenyAudit(
        message,
        policy,
        {
          code: "session_freshness_validator_required",
          message: "policy-protected plugin RPC requires a live session freshness validator",
        },
        context,
      );
    }

    const freshnessError = this.validateSessionHook(context, message);
    if (freshnessError) {
      return this.withPlaintextDenyAudit(message, policy, freshnessError, context);
    }

    const authorizationOptions = {
      context,
      request: message,
      policy,
      permissions: this.permissions,
      highRiskConsents: this.highRiskConsents,
      documentScope: this.documentScope,
      executionContexts: this.executionContexts,
      nowMs: Date.now(),
      auditSink: this.auditSink,
    };
    const authorizationError = await validatePluginHostRpcAuthorization(authorizationOptions);
    if (authorizationError) {
      return uiBoundaryDenyAuditType(message.operation, authorizationError.code)
        ? this.withPlaintextDenyAudit(message, policy, authorizationError, context)
        : authorizationError;
    }
    const executionContextClaimError = claimPluginSingleUseExecutionContext(authorizationOptions);
    if (executionContextClaimError) return executionContextClaimError;

    const deliveryError = await finalizePluginPlaintextRpcDelivery(authorizationOptions, payload);
    if (deliveryError) {
      releasePluginSingleUseExecutionContext(authorizationOptions);
      return deliveryError;
    }

    consumePluginSingleUseExecutionContext(authorizationOptions);
    return null;
  }

  private validateDocumentWriteRateLimit(
    message: PluginHostRpcRequestEnvelope,
    policy: PluginHostRpcOperationPolicy | undefined,
    nowMs: number,
  ): PluginHostRpcErrorBody | null {
    const writePolicy = policy?.documentWrite;
    if (!writePolicy) return null;

    const key = documentWriteRateKey(message);
    const current = this.documentWriteRateCounters.get(key);

    if (!current || nowMs - current.windowStartedAtMs >= writePolicy.rateLimit.windowMs) {
      this.documentWriteRateCounters.set(key, { windowStartedAtMs: nowMs, count: 1 });
      return null;
    }

    if (current.count >= writePolicy.rateLimit.maxRequests) {
      return {
        code: "document_write_rate_limited",
        message: "encrypted document write rate limit exceeded",
      };
    }

    current.count += 1;
    return null;
  }

  private auditExecutionContextId(message: PluginHostRpcRequestEnvelope): string | null {
    const executionContextId = message.execution_context_id;
    if (!executionContextId) return null;
    return this.executionContexts.has(executionContextId) ? executionContextId : null;
  }

  private auditPlaintextScopeKind(message: PluginHostRpcRequestEnvelope): PluginPlaintextScopeKind {
    const executionContextId = message.execution_context_id;
    const executionContext = executionContextId
      ? this.executionContexts.get(executionContextId)
      : undefined;
    if (executionContext) return executionContext.plaintextScope.kind;
    return plaintextPermissionScopeKind(this.permissions);
  }

  private async auditDocumentWriteRequested(
    message: PluginHostRpcRequestEnvelope,
    policy: PluginHostRpcOperationPolicy | undefined,
    context: PluginHostRpcContext,
  ): Promise<PluginHostRpcErrorBody | null> {
    const writePolicy = policy?.documentWrite;
    if (!writePolicy) return null;

    const resource = pluginResourceRef(message.resource);
    const auditOk = await pluginAuditSucceeded(
      emitPluginSecurityAudit(this.auditSink, context, {
        type: "plugin.document_write.requested",
        operation: message.operation,
        result: "allow",
        actionResult: "allowed",
        requestId: message.request_id,
        payloadKind: writePolicy.operation,
        resourceRef: resource,
        resourceKind: "document",
        resourceId: resource?.document_id ?? "unknown",
        versionHash: resource?.document_id ?? undefined,
        storageBytes: pluginPayloadByteLength(message.payload),
      }),
    );

    if (auditOk) return null;
    return {
      code: "document_write_audit_unavailable",
      message: "document write audit event could not be recorded",
    };
  }

  private async withPlaintextDenyAudit(
    message: PluginHostRpcRequestEnvelope,
    policy: PluginHostRpcOperationPolicy | undefined,
    error: PluginHostRpcErrorBody,
    context = this.context(),
  ): Promise<PluginHostRpcErrorBody> {
    const uiAuditError = await this.auditUiBoundaryDenied(message, error, context);
    if (uiAuditError) return uiAuditError;

    return (
      (await auditPluginPlaintextDenied(
        {
          context,
          request: message,
          policy,
          executionContexts: this.executionContexts,
          auditSink: this.auditSink,
        },
        error.code,
      )) ?? error
    );
  }

  private async auditUiBoundaryDenied(
    message: PluginHostRpcRequestEnvelope,
    error: PluginHostRpcErrorBody,
    context: PluginHostRpcContext,
  ): Promise<PluginHostRpcErrorBody | null> {
    const auditType = uiBoundaryDenyAuditType(message.operation, error.code);
    if (!auditType) return null;

    const auditOk = await pluginAuditSucceeded(
      emitPluginSecurityAudit(this.auditSink, context, {
        type: auditType,
        operation: message.operation,
        result: "deny",
        actionResult: "denied",
        requestId: message.request_id,
        payloadKind: uiPayloadKind(message.operation),
        reasonCode: error.code,
        authorityEventRef: message.operation,
      }),
    );

    if (!auditOk) {
      return {
        code: "ui_audit_failed",
        message: "UI boundary denial audit event could not be recorded",
      };
    }

    return null;
  }

  private finalizePlaintextDelivery(
    message: PluginHostRpcRequestEnvelope,
    policy: PluginHostRpcOperationPolicy | undefined,
    payload: unknown,
  ): Promise<PluginHostRpcErrorBody | null> {
    return finalizePluginPlaintextRpcDelivery(
      {
        context: this.context(),
        request: message,
        policy,
        permissions: this.permissions,
        highRiskConsents: this.highRiskConsents,
        documentScope: this.documentScope,
        executionContexts: this.executionContexts,
        nowMs: Date.now(),
        auditSink: this.auditSink,
      },
      payload,
    );
  }

  private consumePlaintextExecutionContext(
    message: PluginHostRpcRequestEnvelope,
    policy: PluginHostRpcOperationPolicy | undefined,
  ): void {
    consumePluginSingleUseExecutionContext({
      context: this.context(),
      request: message,
      policy,
      permissions: this.permissions,
      highRiskConsents: this.highRiskConsents,
      documentScope: this.documentScope,
      executionContexts: this.executionContexts,
      nowMs: Date.now(),
      auditSink: this.auditSink,
    });
  }

  private releasePlaintextExecutionContext(
    message: PluginHostRpcRequestEnvelope,
    policy: PluginHostRpcOperationPolicy | undefined,
  ): void {
    releasePluginSingleUseExecutionContext({
      context: this.context(),
      request: message,
      policy,
      permissions: this.permissions,
      highRiskConsents: this.highRiskConsents,
      documentScope: this.documentScope,
      executionContexts: this.executionContexts,
      nowMs: Date.now(),
      auditSink: this.auditSink,
    });
  }

  private postResponse(requestId: string, payload: unknown): void {
    this.port?.postMessage({
      protocol: PLUGIN_HOST_RPC_PROTOCOL,
      version: PLUGIN_HOST_RPC_VERSION,
      kind: "response",
      request_id: requestId,
      payload,
    } satisfies PluginHostRpcResponseEnvelope);
  }

  private postError(requestId: string, code: string, message: string): void {
    this.port?.postMessage({
      protocol: PLUGIN_HOST_RPC_PROTOCOL,
      version: PLUGIN_HOST_RPC_VERSION,
      kind: "error",
      request_id: requestId,
      error: { code, message },
    } satisfies PluginHostRpcErrorEnvelope);
  }

  private resolvePending(requestId: string, payload: unknown): void {
    const pending = this.pending.get(requestId);
    if (!pending) return;
    clearTimeout(pending.timeoutId);
    this.pending.delete(requestId);
    pending.resolve(payload);
  }

  private rejectPending(requestId: string, error: PluginHostRpcErrorBody): void {
    const pending = this.pending.get(requestId);
    if (!pending) return;
    clearTimeout(pending.timeoutId);
    this.pending.delete(requestId);
    pending.reject(new PluginHostRpcError(error.code, error.message));
  }

  private context(): PluginHostRpcContext {
    const context: PluginHostRpcContext = {
      pluginId: this.pluginId,
      packageId: this.packageId,
      applicationId: this.applicationId,
      activationId: this.activationId,
      ownerScopeKind: this.ownerScopeKind,
      workspaceId: this.workspaceId,
      userId: this.userId,
      deviceId: this.deviceId,
      ...(this.stateHeadHash ? { stateHeadHash: this.stateHeadHash } : {}),
      ...(this.consentHeadHash ? { consentHeadHash: this.consentHeadHash } : {}),
      bundleHash: this.bundleHash,
      manifestHash: this.manifestHash,
      capabilityId: this.capabilityId,
      capabilityGrantId: this.capabilityGrantId,
      consentEpoch: this.consentEpoch,
      frameGeneration: this.frameGeneration,
      frameScope: this.frameScope,
      sessionId: this.sessionId,
      auditActor: this.auditActor,
    };
    Object.defineProperty(context, "auditSink", {
      value: this.auditSink,
      enumerable: false,
    });
    return context;
  }
}

function isMessageEventLike(event: Event): event is MessageEvent {
  return "data" in event && "source" in event;
}

function isBootReadyMessage(value: unknown): value is BootReadyMessage {
  return isObject(value) && isBaseEnvelope(value, "boot-ready");
}

function isRpcEnvelope(value: unknown): value is RpcEnvelope {
  if (!isObject(value)) return false;
  if (value.protocol !== PLUGIN_HOST_RPC_PROTOCOL || value.version !== PLUGIN_HOST_RPC_VERSION)
    return false;
  if (typeof value.kind !== "string") return false;

  switch (value.kind as RpcMessageKind) {
    case "request":
      return isRequestEnvelope(value);
    case "response":
      return typeof value.request_id === "string";
    case "error":
      return typeof value.request_id === "string" && isRpcErrorBody(value.error);
    case "boot-ready":
      return true;
    case "boot-port":
      return typeof value.frame_generation === "number";
    case "boot-context":
      return typeof value.frame_generation === "number" && isObject(value.runtime_context);
    case "boot-ack":
      return typeof value.boot_nonce === "string" && typeof value.frame_generation === "number";
    default:
      return false;
  }
}

function isBaseEnvelope(value: Record<string, unknown>, kind: RpcMessageKind): boolean {
  return (
    value.protocol === PLUGIN_HOST_RPC_PROTOCOL &&
    value.version === PLUGIN_HOST_RPC_VERSION &&
    value.kind === kind
  );
}

function isRequestEnvelope(value: unknown): value is PluginHostRpcRequestEnvelope {
  if (!isObject(value)) return false;

  return (
    typeof value.request_id === "string" &&
    typeof value.request_nonce === "string" &&
    typeof value.plugin_id === "string" &&
    typeof value.package_id === "string" &&
    typeof value.application_id === "string" &&
    typeof value.activation_id === "string" &&
    typeof value.owner_scope_kind === "string" &&
    typeof value.workspace_id === "string" &&
    typeof value.user_id === "string" &&
    typeof value.device_id === "string" &&
    typeof value.bundle_hash === "string" &&
    typeof value.manifest_hash === "string" &&
    typeof value.capability_id === "string" &&
    typeof value.capability_grant_id === "string" &&
    typeof value.consent_epoch === "number" &&
    typeof value.frame_generation === "number" &&
    typeof value.operation === "string"
  );
}

function isRpcErrorBody(value: unknown): value is PluginHostRpcErrorBody {
  return isObject(value) && typeof value.code === "string" && typeof value.message === "string";
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function randomId(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function globalWindowTarget(): Pick<Window, "addEventListener" | "removeEventListener"> | null {
  return typeof window === "undefined" ? null : window;
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : "plugin RPC handler failed";
}

function systemAuditActor(sessionId: string): PluginAuditActor {
  return {
    user_id: null,
    device_id: null,
    session_id: sessionId,
    principal_kind: "system",
    principal_id: null,
  };
}

function uiBoundaryDenyAuditType(
  operation: string,
  errorCode: string,
):
  | "plugin.ui.owner_stale_frame_rejected"
  | "plugin.ui.consent_stale_rejected"
  | "plugin.ui.capability_mismatch_rejected"
  | null {
  if (!operation.startsWith("ui.")) return null;

  if (
    errorCode === "capability_mismatch" ||
    errorCode === "capability_grant_mismatch" ||
    errorCode === "permission_denied"
  ) {
    return "plugin.ui.capability_mismatch_rejected";
  }

  if (errorCode === "consent_epoch_mismatch" || errorCode === "consent_stale") {
    return "plugin.ui.consent_stale_rejected";
  }

  if (errorCode === "frame_generation_mismatch" || errorCode === "plugin_runtime_stale") {
    return "plugin.ui.owner_stale_frame_rejected";
  }

  return null;
}

function uiPayloadKind(operation: string): "ui.contribution" | "ui.command" {
  return operation.includes(".register") ||
    operation === "ui.contribution.unregister" ||
    operation === "ui.status.update_item"
    ? "ui.contribution"
    : "ui.command";
}

function ownerHandlerKey(owner: PluginHostRpcHandlerOwnerDescriptor, operation: string): string {
  return JSON.stringify([
    owner.pluginId,
    owner.packageId,
    owner.workspaceId,
    owner.applicationId,
    owner.activationId,
    owner.ownerScopeKind,
    owner.userId,
    owner.deviceId,
    owner.bundleHash,
    owner.manifestHash ?? "",
    owner.frameGeneration,
    owner.frameScope ?? "primary",
    owner.consentEpoch,
    owner.capabilityGrantId,
    operation,
  ]);
}

function documentWriteRateKey(message: PluginHostRpcRequestEnvelope): string {
  const resource = isObject(message.resource) ? message.resource : {};
  const documentId = typeof resource.document_id === "string" ? resource.document_id : "";
  return JSON.stringify([message.operation, documentId]);
}

function plaintextPermissionScopeKind(
  permissions: ReadonlySet<PluginPermission>,
): PluginPlaintextScopeKind {
  if (permissions.has("document:read:workspace")) return "workspace";
  if (permissions.has("document:read:selected")) return "selected_documents";
  if (permissions.has("document:read:active")) return "active_document";
  if (permissions.has("editor:context:read")) return "editor_context";
  if (permissions.has("editor:selection:read")) return "selection";
  for (const permission of permissions) {
    if (permission.startsWith("plaintext:render:block:")) return "block";
  }
  for (const permission of permissions) {
    if (permission.startsWith("plaintext:render:inline:")) return "inline";
  }
  return "none";
}

const defaultPluginHostMessageRouter = new PluginHostMessageRouter();
let defaultPluginHostMessageRouterRetains = 0;

export function getPluginHostMessageRouter(): PluginHostMessageRouter {
  return defaultPluginHostMessageRouter;
}

export function retainPluginHostMessageRouter(): () => void {
  if (defaultPluginHostMessageRouterRetains === 0) {
    defaultPluginHostMessageRouter.start();
  }

  defaultPluginHostMessageRouterRetains += 1;
  let released = false;

  return () => {
    if (released) return;
    released = true;
    defaultPluginHostMessageRouterRetains -= 1;

    if (defaultPluginHostMessageRouterRetains === 0) {
      defaultPluginHostMessageRouter.stop("plugin_host_router_released");
    }
  };
}
