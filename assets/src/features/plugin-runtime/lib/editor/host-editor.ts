import {
  PluginHostRpcError,
  type PluginHostMessageRouter,
  type PluginHostRpcContext,
  type PluginHostRpcHandler,
  type PluginHostRpcHandlerOwnerDescriptor,
  type PluginHostRpcSession,
} from "../host-rpc/host-rpc";
import {
  emitPluginSecurityAudit,
  pluginAuditSucceeded,
  pluginPayloadByteLength,
  type PluginAuditSink,
  type PluginExecutionContextHostInvocation,
  type PluginExecutionContextKind,
  type PluginHostRpcOperationPolicy,
  type PluginPlaintextScopeKind,
  type PluginSelectionRangeRef,
} from "../capability/capability-enforcement";

export type PluginEditorPlaintextKind = "selection" | "context";
export type PluginEditorContributionKind =
  | "command"
  | "editor_command"
  | "decoration"
  | "diagnostics"
  | "suggestion"
  | "formatter";

export interface PluginEditorHandle {
  protocol: "refmd.plugin-editor-handle";
  version: 1;
  editor_id: string;
  document_id: string;
}

export interface PluginEditorContributionDescriptorBase {
  id: string;
  title: string;
  capability?: string;
}

export interface PluginEditorCommandContributionDescriptor extends PluginEditorContributionDescriptorBase {
  kind: "command" | "editor_command";
}

export interface PluginEditorFormatterContributionDescriptor extends PluginEditorContributionDescriptorBase {
  kind: "formatter";
  input: "selection" | "editor_context";
}

export interface PluginEditorDecorationContributionDescriptor extends PluginEditorContributionDescriptorBase {
  kind: "decoration";
  input: "editor_context";
  trigger: "visible_context";
  max_decorations: number;
}

export interface PluginEditorContextContributionDescriptor extends PluginEditorContributionDescriptorBase {
  kind: "diagnostics" | "suggestion";
  input: "editor_context";
}

export type PluginEditorContributionDescriptor =
  | PluginEditorCommandContributionDescriptor
  | PluginEditorFormatterContributionDescriptor
  | PluginEditorDecorationContributionDescriptor
  | PluginEditorContextContributionDescriptor;

interface PluginEditorContributionPayload {
  kind: PluginEditorContributionKind;
  id: string;
  title: string;
  capability?: string;
  input?: PluginEditorPlaintextKind | "editor_context";
  trigger?: "visible_context";
  max_decorations?: number;
}

export interface PluginEditorContributionEntry {
  owner: PluginHostRpcHandlerOwnerDescriptor;
  descriptor: PluginEditorContributionDescriptor;
  session: PluginHostRpcSession | null;
}

export interface PluginEditorRange {
  from: number;
  to: number;
}

export interface PluginEditorPlaintextParams {
  session: PluginHostRpcSession;
  store: PluginEditorPlaintextStore;
  editor: PluginEditorHandle;
  plaintextKind: PluginEditorPlaintextKind;
  invocationKind: Extract<
    PluginExecutionContextKind,
    "formatter" | "editor_suggestion" | "editor_decoration" | "user_command" | "ui_action"
  >;
  hostInvocation: PluginExecutionContextHostInvocation;
  range: PluginSelectionRangeRef;
  plaintext: string;
  maxBytes: number;
}

export interface PluginEditorPlaintextHandle {
  executionContextId: string;
  resource: {
    document_id: string;
    editor_id: string;
    selection_range?: PluginSelectionRangeRef;
    context_range?: PluginSelectionRangeRef;
    max_bytes: number;
  };
  dispose(): void;
}

export interface PluginHostEditorServices {
  plaintextStore: PluginEditorPlaintextStore;
  formatterInput?: PluginEditorPlaintextKind;
  contributionRegistry?: PluginEditorContributionRegistry;
  contributions?: readonly PluginEditorContributionDescriptor[];
  auditSink?: PluginAuditSink;
}

export interface PluginEditorTextEdit {
  range: PluginEditorRange;
  text: string;
}

export interface PluginFormatterResult {
  edits: PluginEditorTextEdit[];
}

export interface PluginDiagnosticItem {
  range: PluginEditorRange;
  severity: "info" | "warning" | "error";
  message: string;
  source?: string;
}

export interface PluginDiagnosticsResult {
  diagnostics: PluginDiagnosticItem[];
}

export interface PluginSuggestionItem {
  id: string;
  label: string;
  insert_text: string;
  range?: PluginEditorRange;
  detail?: string;
}

export interface PluginSuggestionResult {
  suggestions: PluginSuggestionItem[];
}

export interface PluginDecorationItem {
  id: string;
  range: PluginEditorRange;
  style: "highlight" | "underline" | "gutter_marker";
  tone: "neutral" | "info" | "warning";
}

export interface PluginDecorationResult {
  decorations: PluginDecorationItem[];
}

interface EditorPlaintextEntry {
  context: EditorPlaintextContext;
  editor: PluginEditorHandle;
  plaintextKind: PluginEditorPlaintextKind;
  range: PluginSelectionRangeRef;
  plaintext: string | null;
}

interface EditorPlaintextContext {
  pluginId: string;
  applicationId: string;
  workspaceId: string;
  sessionId: string;
}

interface ContributionEntry {
  owner: PluginHostRpcHandlerOwnerDescriptor;
  descriptor: PluginEditorContributionDescriptor;
}

interface EditorOwnerSessionEntry {
  owner: PluginHostRpcHandlerOwnerDescriptor;
  session: PluginHostRpcSession;
}

type PluginEditorDecorationCleanupListener = (sourceIds: readonly string[]) => void;

const EDITOR_NOTIFICATION_POLICY: PluginHostRpcOperationPolicy = { plaintext: null };
const EDITOR_CONTRIBUTION_POLICY: PluginHostRpcOperationPolicy = {
  requiredPermissions: ["ui:editor"],
  plaintext: null,
};
const CONTRIBUTION_ID_PATTERN = /^[a-z][a-z0-9._:-]{0,95}$/;
const HOST_RESERVED_CONTRIBUTION_PREFIXES = ["builtin:", "plugin:"];
const EDITOR_ID_PATTERN = /^[a-zA-Z0-9._:-]{1,160}$/;
const MAX_DESCRIPTOR_TITLE_LENGTH = 120;
const MAX_TEXT_EDIT_COUNT = 64;
const MAX_DIAGNOSTIC_COUNT = 200;
const MAX_SUGGESTION_COUNT = 50;
const MAX_DECORATION_COUNT = 200;
const MAX_MESSAGE_BYTES = 1_024;
const MAX_LABEL_BYTES = 256;
const MAX_RESULT_TEXT_BYTES = 256 * 1024;

export class PluginEditorPlaintextStore {
  private readonly entries = new Map<string, EditorPlaintextEntry>();

  register(executionContextId: string, entry: EditorPlaintextEntry): () => void {
    if (this.entries.has(executionContextId)) {
      throw new PluginHostRpcError(
        "editor_context_duplicate",
        "editor plaintext context is already registered",
      );
    }
    this.entries.set(executionContextId, entry);
    return () => {
      this.entries.delete(executionContextId);
    };
  }

  takePlaintext(
    executionContextId: string,
    context: PluginHostRpcContext,
    plaintextKind: PluginEditorPlaintextKind,
  ): EditorPlaintextEntry | null {
    const entry = this.entries.get(executionContextId);
    if (
      !entry ||
      entry.plaintext === null ||
      !editorContextMatches(entry.context, context) ||
      entry.plaintextKind !== plaintextKind
    ) {
      return null;
    }
    const plaintextEntry = { ...entry };
    entry.plaintext = null;
    return plaintextEntry;
  }
}

export class PluginEditorContributionRegistry {
  private readonly entries = new Map<string, ContributionEntry>();
  private readonly sessions = new Map<string, EditorOwnerSessionEntry>();
  private readonly listeners = new Set<() => void>();
  private readonly decorationCleanupListeners = new Set<PluginEditorDecorationCleanupListener>();

  register(
    owner: PluginHostRpcHandlerOwnerDescriptor,
    descriptor: PluginEditorContributionDescriptor,
  ): () => void {
    assertContributionDescriptor(descriptor);
    const key = contributionKey(owner, descriptor.id);
    if (this.entries.has(key)) {
      throw new PluginHostRpcError(
        "editor_contribution_duplicate",
        "editor contribution is already registered for this owner",
      );
    }
    this.entries.set(key, { owner, descriptor: { ...descriptor } });
    this.notify();
    return () => {
      const entry = this.entries.get(key);
      if (!entry) return;
      this.entries.delete(key);
      this.notifyDecorationCleanup(this.decorationSourceIdsForEntries([entry]));
      this.notify();
    };
  }

  list(): PluginEditorContributionDescriptor[] {
    return [...this.entries.values()].map((entry) => ({ ...entry.descriptor }));
  }

  listEntries(): PluginEditorContributionEntry[] {
    return [...this.entries.values()].map((entry) => ({
      owner: { ...entry.owner },
      descriptor: { ...entry.descriptor },
      session: this.sessions.get(editorOwnerKey(entry.owner))?.session ?? null,
    }));
  }

  retainOwnerSession(
    owner: PluginHostRpcHandlerOwnerDescriptor,
    session: PluginHostRpcSession,
  ): () => void {
    const key = editorOwnerKey(owner);
    this.sessions.set(key, { owner: { ...owner }, session });
    this.notify();
    return () => {
      if (this.sessions.get(key)?.session === session) {
        const sourceIds = this.decorationSourceIdsForOwner(owner);
        this.sessions.delete(key);
        this.notifyDecorationCleanup(sourceIds);
        this.notify();
      }
    };
  }

  clearOwner(owner: PluginHostRpcHandlerOwnerDescriptor): void {
    const removedEntries: ContributionEntry[] = [];
    for (const [key, entry] of this.entries) {
      if (sameOwner(entry.owner, owner)) {
        removedEntries.push(entry);
        this.entries.delete(key);
      }
    }
    this.sessions.delete(editorOwnerKey(owner));
    this.notifyDecorationCleanup(this.decorationSourceIdsForEntries(removedEntries));
    this.notify();
  }

  subscribe(listener: () => void): () => void {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  }

  subscribeDecorationCleanup(listener: PluginEditorDecorationCleanupListener): () => void {
    this.decorationCleanupListeners.add(listener);
    return () => {
      this.decorationCleanupListeners.delete(listener);
    };
  }

  private notify(): void {
    for (const listener of this.listeners) listener();
  }

  private notifyDecorationCleanup(sourceIds: readonly string[]): void {
    if (sourceIds.length === 0) return;
    for (const listener of this.decorationCleanupListeners) listener(sourceIds);
  }

  private decorationSourceIdsForOwner(owner: PluginHostRpcHandlerOwnerDescriptor): string[] {
    return this.decorationSourceIdsForEntries(
      [...this.entries.values()].filter((entry) => sameOwner(entry.owner, owner)),
    );
  }

  private decorationSourceIdsForEntries(entries: readonly ContributionEntry[]): string[] {
    return entries
      .filter((entry) => entry.descriptor.kind === "decoration")
      .map((entry) => pluginEditorDecorationSourceId(entry));
  }
}

export function createPluginEditorPlaintextStore(): PluginEditorPlaintextStore {
  return new PluginEditorPlaintextStore();
}

export function createPluginEditorContributionRegistry(): PluginEditorContributionRegistry {
  return new PluginEditorContributionRegistry();
}

const defaultPluginEditorPlaintextStore = createPluginEditorPlaintextStore();
const defaultPluginEditorContributionRegistry = createPluginEditorContributionRegistry();

export function getDefaultPluginEditorPlaintextStore(): PluginEditorPlaintextStore {
  return defaultPluginEditorPlaintextStore;
}

export function getDefaultPluginEditorContributionRegistry(): PluginEditorContributionRegistry {
  return defaultPluginEditorContributionRegistry;
}

export function createPluginEditorHandle(editorId: string, documentId: string): PluginEditorHandle {
  if (!EDITOR_ID_PATTERN.test(editorId)) {
    throw new PluginHostRpcError("editor_handle_invalid", "editor id is not supported");
  }
  if (!EDITOR_ID_PATTERN.test(documentId)) {
    throw new PluginHostRpcError("editor_handle_invalid", "document id is not supported");
  }
  return {
    protocol: "refmd.plugin-editor-handle",
    version: 1,
    editor_id: editorId,
    document_id: documentId,
  };
}

export function pluginEditorDecorationSourceId(
  entry: Pick<PluginEditorContributionEntry, "owner" | "descriptor">,
): string {
  return [editorOwnerKey(entry.owner), entry.descriptor.id].join(":");
}

export function pluginEditorTextEditsWithinContext(
  edits: readonly PluginEditorTextEdit[],
  contextRange: PluginSelectionRangeRef,
): boolean {
  return edits.every((edit) => pluginEditorRangeWithinContext(edit.range, contextRange));
}

export function pluginEditorDiagnosticsWithinContext(
  diagnostics: readonly PluginDiagnosticItem[],
  contextRange: PluginSelectionRangeRef,
): boolean {
  return diagnostics.every((diagnostic) =>
    pluginEditorRangeWithinContext(diagnostic.range, contextRange),
  );
}

export function pluginEditorSuggestionsWithinContext(
  suggestions: readonly PluginSuggestionItem[],
  contextRange: PluginSelectionRangeRef,
): boolean {
  return suggestions.every(
    (suggestion) =>
      suggestion.range === undefined ||
      pluginEditorRangeWithinContext(suggestion.range, contextRange),
  );
}

export function pluginEditorDecorationsWithinContext(
  decorations: readonly PluginDecorationItem[],
  contextRange: PluginSelectionRangeRef,
): boolean {
  return decorations.every((decoration) =>
    pluginEditorRangeWithinContext(decoration.range, contextRange),
  );
}

export function pluginEditorRangeWithinContext(
  range: PluginEditorRange,
  contextRange: PluginSelectionRangeRef,
): boolean {
  const from = Math.min(contextRange.anchor, contextRange.head);
  const to = Math.max(contextRange.anchor, contextRange.head);
  return range.from >= from && range.to <= to;
}

export function issuePluginEditorPlaintext(
  params: PluginEditorPlaintextParams,
): PluginEditorPlaintextHandle {
  assertEditorHandle(params.editor);
  assertEditorPlaintextInvocation(params);
  assertEditorPlaintextSize(params.plaintext, params.maxBytes);
  assertSelectionRange(params.range);

  const plaintextScope = plaintextScopeForEditorKind(params.plaintextKind);
  const executionContext = params.session.issueExecutionContext({
    kind: params.invocationKind,
    hostInvocation: params.hostInvocation,
    resource: {
      document_id: params.editor.document_id,
      editor_id: params.editor.editor_id,
      ...(params.plaintextKind === "selection"
        ? { selection_range: params.range }
        : { context_range: params.range }),
      max_bytes: params.maxBytes,
    },
    plaintextScope: { kind: plaintextScope, maxBytes: params.maxBytes },
    allowedOperations: ["plaintext.read"],
    expiresAtMs: Date.now() + 5 * 60 * 1000,
    singleUse: true,
  });

  const unregister = params.store.register(executionContext.execution_context_id, {
    context: {
      pluginId: params.session.pluginId,
      applicationId: params.session.applicationId,
      workspaceId: params.session.workspaceId,
      sessionId: params.session.sessionId,
    },
    editor: params.editor,
    plaintextKind: params.plaintextKind,
    range: params.range,
    plaintext: params.plaintext,
  });

  return {
    executionContextId: executionContext.execution_context_id,
    resource: {
      document_id: params.editor.document_id,
      editor_id: params.editor.editor_id,
      ...(params.plaintextKind === "selection"
        ? { selection_range: params.range }
        : { context_range: params.range }),
      max_bytes: params.maxBytes,
    },
    dispose() {
      params.session.revokeExecutionContext(executionContext.execution_context_id);
      unregister();
    },
  };
}

export function registerPluginHostEditorHandlers(
  router: PluginHostMessageRouter,
  services: PluginHostEditorServices,
  owner?: PluginHostRpcHandlerOwnerDescriptor,
  session?: PluginHostRpcSession,
): () => void {
  const unregisterHandlers: (() => void)[] = [];
  const unregisterContributions: (() => void)[] = [];
  const rpcRegisteredContributions = new Map<string, () => void>();

  const unregisterAll = () => {
    for (const unregisterHandler of [...unregisterHandlers].reverse()) {
      unregisterHandler();
    }
    for (const unregisterContribution of [...rpcRegisteredContributions.values()].reverse()) {
      unregisterContribution();
    }
    rpcRegisteredContributions.clear();
    for (const unregisterContribution of [...unregisterContributions].reverse()) {
      unregisterContribution();
    }
  };

  try {
    if (services.contributions && services.contributions.length > 0) {
      if (!services.contributionRegistry || !owner) {
        throw new PluginHostRpcError(
          "editor_contribution_owner_required",
          "editor contributions require an owner-scoped registry",
        );
      }
      for (const descriptor of services.contributions) {
        unregisterContributions.push(services.contributionRegistry.register(owner, descriptor));
      }
    }

    const formatterInput = services.formatterInput ?? "selection";
    unregisterHandlers.push(
      registerHandler(
        router,
        owner,
        "editor.contribution.register",
        editorContributionRegisterHandler(services, owner, rpcRegisteredContributions, session),
        EDITOR_CONTRIBUTION_POLICY,
      ),
    );
    unregisterHandlers.push(
      registerHandler(
        router,
        owner,
        "editor.contribution.unregister",
        editorContributionUnregisterHandler(services, owner, rpcRegisteredContributions, session),
        EDITOR_CONTRIBUTION_POLICY,
      ),
    );
    unregisterHandlers.push(
      registerHandler(
        router,
        owner,
        "editor.getSelection",
        editorPlaintextHandler(services, "selection"),
        editorSelectionPolicy(),
      ),
    );
    unregisterHandlers.push(
      registerHandler(
        router,
        owner,
        "editor.getContext",
        editorPlaintextHandler(services, "context"),
        editorContextPolicy("editor.getContext"),
      ),
    );
    unregisterHandlers.push(
      registerHandler(
        router,
        owner,
        "diagnostics.getContext",
        editorPlaintextHandler(services, "context"),
        editorContextPolicy("diagnostics.getContext"),
      ),
    );
    unregisterHandlers.push(
      registerHandler(
        router,
        owner,
        "suggestion.getContext",
        editorPlaintextHandler(services, "context"),
        editorContextPolicy("suggestion.getContext"),
      ),
    );
    unregisterHandlers.push(
      registerHandler(
        router,
        owner,
        "decoration.getContext",
        editorPlaintextHandler(services, "context"),
        editorContextPolicy("decoration.getContext"),
      ),
    );
    unregisterHandlers.push(
      registerHandler(
        router,
        owner,
        "formatter.getInput",
        editorPlaintextHandler(services, formatterInput),
        formatterInputPolicy(formatterInput),
      ),
    );

    return unregisterAll;
  } catch (error) {
    unregisterAll();
    throw error;
  }
}

function editorContributionRegisterHandler(
  services: PluginHostEditorServices,
  owner: PluginHostRpcHandlerOwnerDescriptor | undefined,
  registered: Map<string, () => void>,
  session: PluginHostRpcSession | undefined,
): PluginHostRpcHandler {
  return async (context, request) => {
    let descriptor: PluginEditorContributionDescriptor | null = null;
    let unregister: (() => void) | null = null;

    try {
      assertEditorRegistrationSessionActive(session, request);
      if (!owner || !services.contributionRegistry) {
        throw new PluginHostRpcError(
          "editor_contribution_owner_required",
          "editor contributions require an owner-scoped registry",
        );
      }
      descriptor = contributionDescriptorPayload(request.payload);
      assertEditorRegistrationSessionActive(session, request);
      if (registered.has(descriptor.id)) {
        throw new PluginHostRpcError(
          "editor_contribution_duplicate",
          "editor contribution is already registered for this owner",
        );
      }
      unregister = services.contributionRegistry.register(owner, descriptor);
      registered.set(descriptor.id, unregister);
      assertEditorRegistrationSessionActive(session, request);
      await emitEditorContributionAudit(services.auditSink, context, request.requestId, {
        type: "plugin.ui.registration.accepted",
        operation: request.operation,
        result: "allow",
        actionResult: "allowed",
        contributionId: descriptor.id,
      });
      return { id: descriptor.id };
    } catch (error) {
      if (descriptor && unregister) {
        unregister();
        registered.delete(descriptor.id);
      }
      if (!isEditorAuditFailure(error) && !isClosedEditorRegistration(error, session, request)) {
        await emitEditorContributionAudit(services.auditSink, context, request.requestId, {
          type: "plugin.ui.registration.rejected",
          operation: request.operation,
          result: "deny",
          actionResult: "denied",
          contributionId: descriptor?.id ?? contributionIdFromPayload(request.payload),
          reasonCode: errorReasonCode(error),
        });
      }
      throw error;
    }
  };
}

function editorContributionUnregisterHandler(
  services: PluginHostEditorServices,
  owner: PluginHostRpcHandlerOwnerDescriptor | undefined,
  registered: Map<string, () => void>,
  session: PluginHostRpcSession | undefined,
): PluginHostRpcHandler {
  return async (context, request) => {
    let localId = "unknown";

    try {
      assertEditorRegistrationSessionActive(session, request);
      if (!owner) {
        throw new PluginHostRpcError(
          "editor_contribution_owner_required",
          "editor contributions require an owner-scoped registry",
        );
      }
      localId = contributionIdPayload(request.payload);
      assertEditorRegistrationSessionActive(session, request);
      const unregister = registered.get(localId);
      if (!unregister) {
        throw new PluginHostRpcError(
          "editor_contribution_unknown",
          "editor contribution is not registered for this owner",
        );
      }
      unregister();
      registered.delete(localId);
      assertEditorRegistrationSessionActive(session, request);
      await emitEditorContributionAudit(services.auditSink, context, request.requestId, {
        type: "plugin.ui.registration.accepted",
        operation: request.operation,
        result: "allow",
        actionResult: "completed",
        contributionId: localId,
      });
      return { removed: true };
    } catch (error) {
      if (!isEditorAuditFailure(error) && !isClosedEditorRegistration(error, session, request)) {
        await emitEditorContributionAudit(services.auditSink, context, request.requestId, {
          type: "plugin.ui.registration.rejected",
          operation: request.operation,
          result: "deny",
          actionResult: "denied",
          contributionId: localId,
          reasonCode: errorReasonCode(error),
        });
      }
      throw error;
    }
  };
}

function assertEditorRegistrationSessionActive(
  session: PluginHostRpcSession | undefined,
  request: { signal: AbortSignal },
): void {
  if (!session) return;
  if (request.signal.aborted || !session.connected) {
    throw new PluginHostRpcError("session_closed", "plugin session is closed");
  }
}

function isClosedEditorRegistration(
  error: unknown,
  session: PluginHostRpcSession | undefined,
  request: { signal: AbortSignal },
): boolean {
  if (request.signal.aborted || (session && !session.connected)) return true;
  return error instanceof PluginHostRpcError && error.code === "session_closed";
}

async function emitEditorContributionAudit(
  auditSink: PluginAuditSink | undefined,
  context: PluginHostRpcContext,
  requestId: string,
  details: {
    type: "plugin.ui.registration.accepted" | "plugin.ui.registration.rejected";
    operation: string;
    result: "allow" | "deny";
    actionResult: "allowed" | "denied" | "completed";
    contributionId: string;
    reasonCode?: string;
  },
): Promise<void> {
  const auditOk = await pluginAuditSucceeded(
    emitPluginSecurityAudit(auditSink, context, {
      type: details.type,
      operation: details.operation,
      result: details.result,
      actionResult: details.actionResult,
      requestId,
      payloadKind: "ui.contribution",
      reasonCode: details.reasonCode,
      authorityEventRef: details.contributionId,
    }),
  );

  if (!auditOk) {
    throw new PluginHostRpcError(
      "editor_contribution_audit_failed",
      "editor contribution audit was rejected",
    );
  }
}

function isEditorAuditFailure(error: unknown): boolean {
  return error instanceof PluginHostRpcError && error.code === "editor_contribution_audit_failed";
}

function errorReasonCode(error: unknown): string {
  return error instanceof PluginHostRpcError ? error.code : "editor_contribution_invalid";
}

function contributionIdFromPayload(payload: unknown): string {
  return isRecord(payload) && typeof payload.id === "string" ? payload.id : "unknown";
}

export function invokePluginEditorCommand(
  session: PluginHostRpcSession,
  descriptor: PluginEditorContributionDescriptor,
  editor: PluginEditorHandle,
  payload: unknown = null,
): Promise<unknown> {
  if (descriptor.kind !== "command" && descriptor.kind !== "editor_command") {
    throw new PluginHostRpcError("editor_command_invalid", "editor command descriptor is required");
  }
  assertContributionDescriptor(descriptor);
  assertEditorHandle(editor);
  return session.request(
    "editor.command.run",
    {
      contribution_id: descriptor.id,
      editor,
      payload,
    },
    undefined,
    undefined,
    { policy: EDITOR_NOTIFICATION_POLICY },
  );
}

export async function requestPluginFormatter(
  session: PluginHostRpcSession,
  descriptor: PluginEditorContributionDescriptor,
  handle: PluginEditorPlaintextHandle,
): Promise<PluginFormatterResult> {
  if (descriptor.kind !== "formatter") {
    throw new PluginHostRpcError(
      "formatter_descriptor_invalid",
      "formatter descriptor is required",
    );
  }
  assertContributionDescriptor(descriptor);
  const result = await session.request(
    "formatter.run",
    { contribution_id: descriptor.id, execution_context_id: handle.executionContextId },
    handle.resource,
    undefined,
    { policy: EDITOR_NOTIFICATION_POLICY },
  );
  return validatePluginFormatterResult(result);
}

export async function requestPluginDiagnostics(
  session: PluginHostRpcSession,
  descriptor: PluginEditorContributionDescriptor,
  handle: PluginEditorPlaintextHandle,
): Promise<PluginDiagnosticsResult> {
  if (descriptor.kind !== "diagnostics") {
    throw new PluginHostRpcError(
      "diagnostics_descriptor_invalid",
      "diagnostics descriptor is required",
    );
  }
  assertContributionDescriptor(descriptor);
  const result = await session.request(
    "diagnostics.run",
    { contribution_id: descriptor.id, execution_context_id: handle.executionContextId },
    handle.resource,
    undefined,
    { policy: EDITOR_NOTIFICATION_POLICY },
  );
  return validatePluginDiagnosticsResult(result);
}

export async function requestPluginSuggestion(
  session: PluginHostRpcSession,
  descriptor: PluginEditorContributionDescriptor,
  handle: PluginEditorPlaintextHandle,
): Promise<PluginSuggestionResult> {
  if (descriptor.kind !== "suggestion") {
    throw new PluginHostRpcError(
      "suggestion_descriptor_invalid",
      "suggestion descriptor is required",
    );
  }
  assertContributionDescriptor(descriptor);
  const result = await session.request(
    "suggestion.run",
    { contribution_id: descriptor.id, execution_context_id: handle.executionContextId },
    handle.resource,
    undefined,
    { policy: EDITOR_NOTIFICATION_POLICY },
  );
  return validatePluginSuggestionResult(result);
}

export async function requestPluginDecoration(
  session: PluginHostRpcSession,
  descriptor: PluginEditorContributionDescriptor,
  handle: PluginEditorPlaintextHandle,
): Promise<PluginDecorationResult> {
  if (descriptor.kind !== "decoration") {
    throw new PluginHostRpcError(
      "decoration_descriptor_invalid",
      "decoration descriptor is required",
    );
  }
  assertContributionDescriptor(descriptor);
  const result = await session.request(
    "decoration.run",
    { contribution_id: descriptor.id, execution_context_id: handle.executionContextId },
    handle.resource,
    undefined,
    { policy: EDITOR_NOTIFICATION_POLICY },
  );
  return validatePluginDecorationResult(result, descriptor.max_decorations);
}

export function validatePluginFormatterResult(result: unknown): PluginFormatterResult {
  if (!isRecord(result) || !Array.isArray(result.edits)) {
    throw new PluginHostRpcError("formatter_result_invalid", "formatter result must include edits");
  }
  if (result.edits.length > MAX_TEXT_EDIT_COUNT) {
    throw new PluginHostRpcError("formatter_result_too_large", "formatter returned too many edits");
  }
  return {
    edits: result.edits.map((edit) => validateTextEdit(edit)),
  };
}

export function validatePluginDiagnosticsResult(result: unknown): PluginDiagnosticsResult {
  if (!isRecord(result) || !Array.isArray(result.diagnostics)) {
    throw new PluginHostRpcError(
      "diagnostics_result_invalid",
      "diagnostics result must include diagnostics",
    );
  }
  if (result.diagnostics.length > MAX_DIAGNOSTIC_COUNT) {
    throw new PluginHostRpcError(
      "diagnostics_result_too_large",
      "diagnostics returned too many items",
    );
  }
  return {
    diagnostics: result.diagnostics.map((diagnostic) => validateDiagnostic(diagnostic)),
  };
}

export function validatePluginSuggestionResult(result: unknown): PluginSuggestionResult {
  if (!isRecord(result) || !Array.isArray(result.suggestions)) {
    throw new PluginHostRpcError(
      "suggestion_result_invalid",
      "suggestion result must include suggestions",
    );
  }
  if (result.suggestions.length > MAX_SUGGESTION_COUNT) {
    throw new PluginHostRpcError(
      "suggestion_result_too_large",
      "suggestion returned too many items",
    );
  }
  return {
    suggestions: result.suggestions.map((suggestion) => validateSuggestion(suggestion)),
  };
}

export function validatePluginDecorationResult(
  result: unknown,
  maxDecorations = MAX_DECORATION_COUNT,
): PluginDecorationResult {
  if (!isRecord(result) || !Array.isArray(result.decorations)) {
    throw new PluginHostRpcError(
      "decoration_result_invalid",
      "decoration result must include decorations",
    );
  }
  if (result.decorations.length > maxDecorations) {
    throw new PluginHostRpcError(
      "decoration_result_too_large",
      "decoration returned too many items",
    );
  }
  return {
    decorations: result.decorations.map((decoration) => validateDecoration(decoration)),
  };
}

function registerHandler(
  router: PluginHostMessageRouter,
  owner: PluginHostRpcHandlerOwnerDescriptor | undefined,
  operation: string,
  handler: PluginHostRpcHandler,
  policy: PluginHostRpcOperationPolicy,
): () => void {
  if (owner) return router.registerOwnerHandler(owner, operation, handler, policy);
  return router.registerHandler(operation, handler, policy);
}

function editorPlaintextHandler(
  services: PluginHostEditorServices,
  plaintextKind: PluginEditorPlaintextKind,
): PluginHostRpcHandler {
  return (context, request) => {
    const executionContextId = request.executionContextId;
    if (!executionContextId) {
      throw new PluginHostRpcError(
        "execution_context_required",
        "editor plaintext requires a Host-issued execution context",
      );
    }

    const entry = services.plaintextStore.takePlaintext(executionContextId, context, plaintextKind);
    if (!entry) {
      throw new PluginHostRpcError(
        "editor_context_unavailable",
        "editor plaintext is not available for this invocation",
      );
    }

    return {
      editor: entry.editor,
      document_id: entry.editor.document_id,
      editor_id: entry.editor.editor_id,
      range: entry.range,
      plaintext: entry.plaintext,
    };
  };
}

function editorSelectionPolicy(): PluginHostRpcOperationPolicy {
  return {
    requiredPermissions: ["editor:selection:read"],
    documentAccess: "allowed_document",
    plaintext: {
      operation: "plaintext.read",
      requiredPermission: "editor:selection:read",
      allowedContextKinds: ["formatter", "user_command", "ui_action"],
      allowedPlaintextScopes: ["selection"],
      audit: "required",
    },
  };
}

function editorContextPolicy(operation: string): PluginHostRpcOperationPolicy {
  const allowedContextKinds =
    operation === "editor.getContext"
      ? (["editor_suggestion", "editor_decoration", "formatter", "user_command"] as const)
      : operation === "decoration.getContext"
        ? (["editor_decoration"] as const)
        : (["editor_suggestion", "formatter"] as const);

  return {
    requiredPermissions: ["editor:context:read"],
    documentAccess: "allowed_document",
    plaintext: {
      operation: "plaintext.read",
      requiredPermission: "editor:context:read",
      allowedContextKinds,
      allowedPlaintextScopes: ["editor_context"],
      audit: "required",
    },
  };
}

function formatterInputPolicy(
  plaintextKind: PluginEditorPlaintextKind,
): PluginHostRpcOperationPolicy {
  const requiredPermission =
    plaintextKind === "selection" ? "editor:selection:read" : "editor:context:read";
  const allowedPlaintextScope = plaintextScopeForEditorKind(plaintextKind);

  return {
    requiredPermissions: [requiredPermission],
    documentAccess: "allowed_document",
    plaintext: {
      operation: "plaintext.read",
      requiredPermission,
      allowedContextKinds: ["formatter"],
      allowedPlaintextScopes: [allowedPlaintextScope],
      audit: "required",
    },
  };
}

function plaintextScopeForEditorKind(
  kind: PluginEditorPlaintextKind,
): Extract<PluginPlaintextScopeKind, "selection" | "editor_context"> {
  return kind === "selection" ? "selection" : "editor_context";
}

function assertEditorPlaintextInvocation(params: PluginEditorPlaintextParams): void {
  if (params.plaintextKind === "selection") {
    if (
      params.invocationKind !== "formatter" &&
      params.invocationKind !== "user_command" &&
      params.invocationKind !== "ui_action"
    ) {
      throw new PluginHostRpcError(
        "editor_invocation_invalid",
        "selection plaintext is not allowed for this invocation",
      );
    }
    return;
  }

  if (
    params.invocationKind !== "editor_suggestion" &&
    params.invocationKind !== "editor_decoration" &&
    params.invocationKind !== "formatter" &&
    params.invocationKind !== "user_command"
  ) {
    throw new PluginHostRpcError(
      "editor_invocation_invalid",
      "editor context plaintext is not allowed for this invocation",
    );
  }
}

function assertEditorHandle(handle: PluginEditorHandle): void {
  if (
    !isRecord(handle) ||
    handle.protocol !== "refmd.plugin-editor-handle" ||
    handle.version !== 1 ||
    typeof handle.editor_id !== "string" ||
    typeof handle.document_id !== "string"
  ) {
    throw new PluginHostRpcError("editor_handle_invalid", "editor handle is invalid");
  }
}

function assertContributionDescriptor(descriptor: PluginEditorContributionPayload): void {
  if (!isRecord(descriptor)) {
    throw new PluginHostRpcError(
      "editor_contribution_invalid",
      "editor contribution must be an object",
    );
  }
  if (
    descriptor.kind !== "command" &&
    descriptor.kind !== "editor_command" &&
    descriptor.kind !== "decoration" &&
    descriptor.kind !== "diagnostics" &&
    descriptor.kind !== "suggestion" &&
    descriptor.kind !== "formatter"
  ) {
    throw new PluginHostRpcError(
      "editor_contribution_invalid",
      "editor contribution kind is not supported",
    );
  }
  assertContributionId(descriptor.id);
  if (
    typeof descriptor.title !== "string" ||
    descriptor.title.trim() === "" ||
    descriptor.title.length > MAX_DESCRIPTOR_TITLE_LENGTH
  ) {
    throw new PluginHostRpcError(
      "editor_contribution_invalid",
      "editor contribution title is not supported",
    );
  }
  if (descriptor.capability !== undefined && typeof descriptor.capability !== "string") {
    throw new PluginHostRpcError(
      "editor_contribution_invalid",
      "editor contribution capability is invalid",
    );
  }
  if (descriptor.kind === "formatter") {
    if (descriptor.input !== "selection" && descriptor.input !== "editor_context") {
      throw new PluginHostRpcError(
        "editor_contribution_invalid",
        "editor formatter input is not supported",
      );
    }
  }
  if (
    (descriptor.kind === "diagnostics" || descriptor.kind === "suggestion") &&
    descriptor.input !== "editor_context"
  ) {
    throw new PluginHostRpcError(
      "editor_contribution_invalid",
      "editor contribution input must be editor_context",
    );
  }
  if (descriptor.kind === "decoration") {
    if (descriptor.input !== "editor_context") {
      throw new PluginHostRpcError(
        "editor_contribution_invalid",
        "editor decoration input must be editor_context",
      );
    }
    if (descriptor.trigger !== "visible_context") {
      throw new PluginHostRpcError(
        "editor_contribution_invalid",
        "editor decoration trigger must be visible_context",
      );
    }
    const maxDecorations = descriptor.max_decorations;
    if (
      !Number.isSafeInteger(maxDecorations) ||
      maxDecorations === undefined ||
      maxDecorations <= 0 ||
      maxDecorations > MAX_DECORATION_COUNT
    ) {
      throw new PluginHostRpcError(
        "editor_contribution_invalid",
        "editor decoration limit is not supported",
      );
    }
  }
  assertNoHostEditorObjectFields(descriptor);
}

function contributionDescriptorPayload(payload: unknown): PluginEditorContributionDescriptor {
  if (!isRecord(payload)) {
    throw new PluginHostRpcError(
      "editor_contribution_invalid",
      "editor contribution must be an object",
    );
  }
  const descriptor = {
    kind: payload.kind,
    id: payload.id,
    title: payload.title,
    ...(payload.capability !== undefined ? { capability: payload.capability } : {}),
    ...(payload.input !== undefined ? { input: payload.input } : {}),
    ...(payload.trigger !== undefined ? { trigger: payload.trigger } : {}),
    ...(payload.max_decorations !== undefined ? { max_decorations: payload.max_decorations } : {}),
  } as PluginEditorContributionPayload;
  assertContributionDescriptor(descriptor);
  assertNoHostEditorObjectFields(payload);
  return descriptor as PluginEditorContributionDescriptor;
}

function contributionIdPayload(payload: unknown): string {
  if (!isRecord(payload) || typeof payload.id !== "string") {
    throw new PluginHostRpcError(
      "editor_contribution_invalid",
      "editor contribution id is not supported",
    );
  }
  assertContributionId(payload.id);
  return payload.id;
}

function assertContributionId(id: string): void {
  if (
    !CONTRIBUTION_ID_PATTERN.test(id) ||
    HOST_RESERVED_CONTRIBUTION_PREFIXES.some((prefix) => id.startsWith(prefix))
  ) {
    throw new PluginHostRpcError(
      "editor_contribution_invalid",
      "editor contribution id is not supported",
    );
  }
}

function assertNoHostEditorObjectFields(value: unknown): void {
  if (!isRecord(value)) return;
  for (const key of Object.keys(value)) {
    if (
      key === "extension" ||
      key === "extensions" ||
      key === "plugin" ||
      key === "plugins" ||
      key === "view" ||
      key === "state" ||
      key === "dom" ||
      key === "element"
    ) {
      throw new PluginHostRpcError(
        "editor_contribution_forbidden",
        "editor contribution cannot carry host editor objects",
      );
    }
  }
}

function assertEditorPlaintextSize(plaintext: string, maxBytes: number): void {
  if (typeof plaintext !== "string") {
    throw new PluginHostRpcError("editor_plaintext_invalid", "editor plaintext must be a string");
  }
  if (!Number.isSafeInteger(maxBytes) || maxBytes <= 0) {
    throw new PluginHostRpcError(
      "editor_plaintext_limit_invalid",
      "editor plaintext byte limit must be positive",
    );
  }
  if (pluginPayloadByteLength(plaintext) > maxBytes) {
    throw new PluginHostRpcError(
      "editor_plaintext_too_large",
      "editor plaintext exceeds the configured byte limit",
    );
  }
}

function validateTextEdit(edit: unknown): PluginEditorTextEdit {
  if (!isRecord(edit)) {
    throw new PluginHostRpcError("formatter_edit_invalid", "formatter edit must be an object");
  }
  const range = validateRange(edit.range);
  const text = boundedString(edit.text, "formatter_edit_invalid", MAX_RESULT_TEXT_BYTES);
  return { range, text };
}

function validateDiagnostic(diagnostic: unknown): PluginDiagnosticItem {
  if (!isRecord(diagnostic)) {
    throw new PluginHostRpcError("diagnostic_item_invalid", "diagnostic item must be an object");
  }
  const range = validateRange(diagnostic.range);
  const severity = diagnostic.severity;
  if (severity !== "info" && severity !== "warning" && severity !== "error") {
    throw new PluginHostRpcError("diagnostic_item_invalid", "diagnostic severity is not supported");
  }
  const message = boundedString(diagnostic.message, "diagnostic_item_invalid", MAX_MESSAGE_BYTES);
  const source =
    diagnostic.source === undefined
      ? undefined
      : boundedString(diagnostic.source, "diagnostic_item_invalid", MAX_LABEL_BYTES);
  return { range, severity, message, ...(source ? { source } : {}) };
}

function validateSuggestion(suggestion: unknown): PluginSuggestionItem {
  if (!isRecord(suggestion)) {
    throw new PluginHostRpcError("suggestion_item_invalid", "suggestion item must be an object");
  }
  const id = boundedString(suggestion.id, "suggestion_item_invalid", MAX_LABEL_BYTES);
  if (!CONTRIBUTION_ID_PATTERN.test(id)) {
    throw new PluginHostRpcError("suggestion_item_invalid", "suggestion id is not supported");
  }
  const label = boundedString(suggestion.label, "suggestion_item_invalid", MAX_LABEL_BYTES);
  const insertText = boundedString(
    suggestion.insert_text,
    "suggestion_item_invalid",
    MAX_RESULT_TEXT_BYTES,
  );
  const range = suggestion.range === undefined ? undefined : validateRange(suggestion.range);
  const detail =
    suggestion.detail === undefined
      ? undefined
      : boundedString(suggestion.detail, "suggestion_item_invalid", MAX_MESSAGE_BYTES);
  return {
    id,
    label,
    insert_text: insertText,
    ...(range ? { range } : {}),
    ...(detail ? { detail } : {}),
  };
}

function validateDecoration(decoration: unknown): PluginDecorationItem {
  if (!isRecord(decoration)) {
    throw new PluginHostRpcError("decoration_item_invalid", "decoration item must be an object");
  }
  const id = boundedString(decoration.id, "decoration_item_invalid", MAX_LABEL_BYTES);
  if (!CONTRIBUTION_ID_PATTERN.test(id)) {
    throw new PluginHostRpcError("decoration_item_invalid", "decoration id is not supported");
  }
  const range = validateRange(decoration.range);
  const style = decoration.style;
  if (style !== "highlight" && style !== "underline" && style !== "gutter_marker") {
    throw new PluginHostRpcError("decoration_item_invalid", "decoration style is not supported");
  }
  const tone = decoration.tone;
  if (tone !== "neutral" && tone !== "info" && tone !== "warning") {
    throw new PluginHostRpcError("decoration_item_invalid", "decoration tone is not supported");
  }
  return { id, range, style, tone };
}

function validateRange(range: unknown): PluginEditorRange {
  if (!isRecord(range)) {
    throw new PluginHostRpcError("editor_range_invalid", "editor range must be an object");
  }
  const from = safeOffset(range.from, "from");
  const to = safeOffset(range.to, "to");
  if (to < from) {
    throw new PluginHostRpcError("editor_range_invalid", "editor range end precedes start");
  }
  return { from, to };
}

function assertSelectionRange(range: PluginSelectionRangeRef): void {
  if (!isRecord(range)) {
    throw new PluginHostRpcError("editor_range_invalid", "editor range must be an object");
  }
  safeOffset(range.anchor, "anchor");
  safeOffset(range.head, "head");
}

function safeOffset(value: unknown, field: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
    throw new PluginHostRpcError("editor_range_invalid", `${field} must be a safe offset`);
  }
  return value;
}

function boundedString(value: unknown, code: string, maxBytes: number): string {
  if (typeof value !== "string" || value.trim() === "") {
    throw new PluginHostRpcError(code, "expected a non-empty string");
  }
  if (pluginPayloadByteLength(value) > maxBytes) {
    throw new PluginHostRpcError(code, "string exceeds the configured byte limit");
  }
  return value;
}

function editorContextMatches(
  expected: EditorPlaintextContext,
  context: PluginHostRpcContext,
): boolean {
  return (
    expected.pluginId === context.pluginId &&
    expected.applicationId === context.applicationId &&
    expected.workspaceId === context.workspaceId &&
    expected.sessionId === context.sessionId
  );
}

function contributionKey(owner: PluginHostRpcHandlerOwnerDescriptor, id: string): string {
  return [editorOwnerKey(owner), id].join(":");
}

function editorOwnerKey(owner: PluginHostRpcHandlerOwnerDescriptor): string {
  return [
    owner.pluginId,
    owner.packageId,
    owner.applicationId,
    owner.activationId,
    owner.ownerScopeKind,
    owner.workspaceId,
    owner.userId,
    owner.deviceId,
    owner.bundleHash,
    owner.manifestHash ?? "",
    owner.frameGeneration,
    owner.consentEpoch,
    owner.capabilityGrantId,
  ].join(":");
}

function sameOwner(
  first: PluginHostRpcHandlerOwnerDescriptor,
  second: PluginHostRpcHandlerOwnerDescriptor,
): boolean {
  return (
    first.pluginId === second.pluginId &&
    first.packageId === second.packageId &&
    first.applicationId === second.applicationId &&
    first.activationId === second.activationId &&
    first.ownerScopeKind === second.ownerScopeKind &&
    first.workspaceId === second.workspaceId &&
    first.userId === second.userId &&
    first.deviceId === second.deviceId &&
    first.bundleHash === second.bundleHash &&
    (first.manifestHash ?? "") === (second.manifestHash ?? "") &&
    first.frameGeneration === second.frameGeneration &&
    first.consentEpoch === second.consentEpoch &&
    first.capabilityGrantId === second.capabilityGrantId
  );
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
