import {
  PluginHostRpcError,
  type PluginHostMessageRouter,
  type PluginHostRpcContext,
  type PluginHostRpcHandler,
  type PluginHostRpcHandlerOwnerDescriptor,
  type PluginHostRpcSession,
} from "../host-rpc/host-rpc";
import {
  pluginPayloadByteLength,
  type PluginHostRpcOperationPolicy,
} from "../capability/capability-enforcement";

export type PluginRendererSlotKind = "block" | "inline";

export interface PluginRendererSlot {
  kind: PluginRendererSlotKind;
  type: string;
}

export interface PluginRendererSourceParams {
  session: PluginHostRpcSession;
  slot: PluginRendererSlot;
  documentId: string;
  blockId?: string | null;
  source: string;
  maxBytes: number;
  store: PluginRendererSourceStore;
  onHeightChange?: (height: number) => void;
}

export interface PluginRendererSourceHandle {
  executionContextId: string;
  maxBytes: number;
  dispose(): void;
}

export interface PluginRendererMountParams {
  slot: PluginRendererSlot;
  workspaceId?: string | null;
  documentId: string;
  blockId?: string | null;
  source: string;
  maxBytes: number;
  container: HTMLElement;
  title?: string;
}

export interface PluginRendererMountedSurface {
  dispose(): void;
}

export interface PluginRendererThemeSnapshot {
  colorScheme: "light" | "dark";
  foreground: string;
  background: string;
  accent: string;
}

export interface PluginHostRendererServices {
  slots: readonly PluginRendererSlot[];
  sourceStore: PluginRendererSourceStore;
  themeSnapshot?: () => PluginRendererThemeSnapshot | null;
}

interface RendererSourceEntry {
  slot: PluginRendererSlot;
  context: RendererSourceContext;
  documentId: string;
  blockId: string | null;
  source: string | null;
  onHeightChange?: (height: number) => void;
}

interface RendererSourceContext {
  pluginId: string;
  packageId: string;
  applicationId: string;
  activationId: string;
  ownerScopeKind: string;
  workspaceId: string;
  userId: string;
  deviceId: string;
  sessionId: string;
}

interface RendererHeightPayload {
  execution_context_id?: unknown;
  height?: unknown;
}

const SLOT_TYPE_PATTERN = /^[a-z][a-z0-9._-]{0,63}$/;
const FORBIDDEN_SLOT_TYPES = new Set(["markdown", "md", "document", "full-document"]);
const RENDERER_NOTIFICATION_POLICY: PluginHostRpcOperationPolicy = { plaintext: null };
const RENDERER_RENDER_TIMEOUT_MS = 120_000;

interface RendererSlotEntry {
  owner: PluginHostRpcHandlerOwnerDescriptor;
  slots: readonly PluginRendererSlot[];
  mount(params: PluginRendererMountParams): PluginRendererMountedSurface | null;
}

export class PluginRendererSourceStore {
  private readonly entries = new Map<string, RendererSourceEntry>();

  register(executionContextId: string, entry: RendererSourceEntry): () => void {
    if (this.entries.has(executionContextId)) {
      throw new PluginHostRpcError(
        "renderer_source_duplicate",
        "renderer source context is already registered",
      );
    }
    this.entries.set(executionContextId, entry);
    return () => {
      this.entries.delete(executionContextId);
    };
  }

  takeSource(
    executionContextId: string,
    context: PluginHostRpcContext,
    slots: readonly PluginRendererSlot[],
  ): RendererSourceEntry | null {
    const entry = this.entries.get(executionContextId);
    if (!entry || entry.source === null) return null;
    if (
      !rendererContextMatches(entry.context, context) ||
      !slots.some((slot) => entry.slot.kind === slot.kind && entry.slot.type === slot.type)
    ) {
      return null;
    }
    return { ...entry };
  }

  setHeight(executionContextId: string, context: PluginHostRpcContext, height: number): void {
    const entry = this.entries.get(executionContextId);
    if (!entry || !rendererContextMatches(entry.context, context)) {
      throw new PluginHostRpcError(
        "renderer_context_unknown",
        "renderer context is not active for this slot",
      );
    }
    entry.onHeightChange?.(height);
  }
}

export function createPluginRendererSourceStore(): PluginRendererSourceStore {
  return new PluginRendererSourceStore();
}

export class PluginRendererSlotRegistry {
  private readonly entries = new Map<string, RendererSlotEntry>();
  private readonly listeners = new Set<() => void>();
  private version = 0;

  register(
    owner: PluginHostRpcHandlerOwnerDescriptor,
    slots: readonly PluginRendererSlot[],
    mount: (params: PluginRendererMountParams) => PluginRendererMountedSurface | null,
  ): () => void {
    assertRendererSlots(slots);
    const key = rendererOwnerKey(owner);
    this.entries.set(key, { owner, slots: slots.map((slot) => ({ ...slot })), mount });
    this.notify();
    return () => {
      if (this.entries.delete(key)) this.notify();
    };
  }

  hasSlot(slot: PluginRendererSlot, workspaceId?: string | null): boolean {
    assertRendererSlot(slot);
    return [...this.entries.values()].some(
      (entry) =>
        (!workspaceId || entry.owner.workspaceId === workspaceId) &&
        entry.slots.some((candidate) => sameRendererSlot(candidate, slot)),
    );
  }

  debugSnapshot(): Array<{
    pluginId: string;
    applicationId: string;
    workspaceId: string;
    slots: readonly PluginRendererSlot[];
  }> {
    return [...this.entries.values()].map((entry) => ({
      pluginId: entry.owner.pluginId,
      applicationId: entry.owner.applicationId,
      workspaceId: entry.owner.workspaceId,
      slots: entry.slots.map((slot) => ({ ...slot })),
    }));
  }

  mount(params: PluginRendererMountParams): PluginRendererMountedSurface | null {
    assertRendererSlot(params.slot);
    for (const entry of this.entries.values()) {
      if (params.workspaceId && entry.owner.workspaceId !== params.workspaceId) continue;
      if (!entry.slots.some((slot) => sameRendererSlot(slot, params.slot))) continue;
      return entry.mount(params);
    }
    return null;
  }

  subscribe(listener: () => void): () => void {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  }

  snapshotVersion(): number {
    return this.version;
  }

  private notify(): void {
    this.version += 1;
    for (const listener of this.listeners) listener();
  }
}

declare global {
  var __refmdDefaultPluginRendererSlotRegistry: PluginRendererSlotRegistry | undefined;
}

const defaultPluginRendererSlotRegistry =
  globalThis.__refmdDefaultPluginRendererSlotRegistry ?? new PluginRendererSlotRegistry();
globalThis.__refmdDefaultPluginRendererSlotRegistry = defaultPluginRendererSlotRegistry;

export function getDefaultPluginRendererSlotRegistry(): PluginRendererSlotRegistry {
  return defaultPluginRendererSlotRegistry;
}

export function issuePluginRendererSource(
  params: PluginRendererSourceParams,
): PluginRendererSourceHandle {
  assertRendererSlot(params.slot);
  assertRendererSourceSize(params.source, params.maxBytes);

  const executionContext = params.session.issueExecutionContext({
    kind: "renderer_invocation",
    hostInvocation: { kind: "renderer_slot", userGesture: false },
    resource: {
      document_id: params.documentId,
      ...(params.blockId ? { block_id: params.blockId } : {}),
      max_bytes: params.maxBytes,
    },
    plaintextScope: { kind: params.slot.kind, maxBytes: params.maxBytes },
    allowedOperations: ["plaintext.read"],
    expiresAtMs: Date.now() + 5 * 60 * 1000,
  });

  const unregister = params.store.register(executionContext.execution_context_id, {
    slot: params.slot,
    context: {
      pluginId: params.session.pluginId,
      packageId: params.session.packageId,
      applicationId: params.session.applicationId,
      activationId: params.session.activationId,
      ownerScopeKind: params.session.ownerScopeKind,
      workspaceId: params.session.workspaceId,
      userId: params.session.userId,
      deviceId: params.session.deviceId,
      sessionId: params.session.sessionId,
    },
    documentId: params.documentId,
    blockId: params.blockId ?? null,
    source: params.source,
    onHeightChange: params.onHeightChange,
  });

  return {
    executionContextId: executionContext.execution_context_id,
    maxBytes: params.maxBytes,
    dispose() {
      params.session.revokeExecutionContext(executionContext.execution_context_id);
      unregister();
    },
  };
}

export function registerPluginHostRendererHandlers(
  router: PluginHostMessageRouter,
  services: PluginHostRendererServices,
  owner?: PluginHostRpcHandlerOwnerDescriptor,
): () => void {
  assertRendererSlots(services.slots);
  const unregisterSource = registerHandler(
    router,
    owner,
    "renderer.getSource",
    rendererSourceHandler(services),
    rendererSourcePolicy(services.slots),
  );
  const unregisterHeight = registerHandler(
    router,
    owner,
    "renderer.setHeight",
    rendererHeightHandler(services),
    { plaintext: null },
  );

  return () => {
    unregisterHeight();
    unregisterSource();
  };
}

export function notifyPluginRendererResize(
  session: PluginHostRpcSession,
  handle: PluginRendererSourceHandle,
  size: { width: number; height: number },
): Promise<unknown> {
  assertRendererDimension(size.width, "width");
  assertRendererDimension(size.height, "height");
  return session.request(
    "renderer.resize",
    {
      execution_context_id: handle.executionContextId,
      width: size.width,
      height: size.height,
    },
    undefined,
    undefined,
    { policy: RENDERER_NOTIFICATION_POLICY },
  );
}

export function notifyPluginRendererTheme(
  session: PluginHostRpcSession,
  handle: PluginRendererSourceHandle,
  theme: PluginRendererThemeSnapshot,
): Promise<unknown> {
  assertThemeSnapshot(theme);
  return session.request(
    "renderer.theme",
    {
      execution_context_id: handle.executionContextId,
      theme,
    },
    undefined,
    undefined,
    { policy: RENDERER_NOTIFICATION_POLICY },
  );
}

export function requestPluginRendererRender(
  session: PluginHostRpcSession,
  handle: PluginRendererSourceHandle,
  slot: PluginRendererSlot,
  documentId: string,
  blockId?: string | null,
): Promise<unknown> {
  assertRendererSlot(slot);
  return session.request(
    "renderer.render",
    {
      execution_context_id: handle.executionContextId,
      kind: slot.kind,
      type: slot.type,
      document_id: documentId,
      block_id: blockId ?? null,
      max_bytes: handle.maxBytes,
    },
    {
      document_id: documentId,
      ...(blockId ? { block_id: blockId } : {}),
      max_bytes: handle.maxBytes,
    },
    RENDERER_RENDER_TIMEOUT_MS,
    { policy: RENDERER_NOTIFICATION_POLICY },
  );
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

function rendererSourceHandler(services: PluginHostRendererServices): PluginHostRpcHandler {
  return (context: PluginHostRpcContext, request) => {
    const executionContextId = request.executionContextId;
    if (!executionContextId) {
      throw new PluginHostRpcError(
        "execution_context_required",
        "renderer source requires a Host-issued execution context",
      );
    }

    const entry = services.sourceStore.takeSource(executionContextId, context, services.slots);
    if (!entry) {
      throw new PluginHostRpcError(
        "renderer_source_unavailable",
        "renderer source is not available for this slot",
      );
    }

    return {
      kind: entry.slot.kind,
      type: entry.slot.type,
      document_id: entry.documentId,
      block_id: entry.blockId,
      source: entry.source,
      theme: services.themeSnapshot?.() ?? null,
    };
  };
}

function rendererHeightHandler(services: PluginHostRendererServices): PluginHostRpcHandler {
  return (context, request) => {
    const payload = rendererHeightPayload(request.payload);
    const executionContextId = requiredPayloadString(
      payload.execution_context_id,
      "execution_context_id",
    );
    const height = rendererDimension(payload.height, "height");
    services.sourceStore.setHeight(executionContextId, context, height);
    return { height };
  };
}

function rendererContextMatches(
  expected: RendererSourceContext,
  context: PluginHostRpcContext,
): boolean {
  return (
    expected.pluginId === context.pluginId &&
    expected.packageId === context.packageId &&
    expected.applicationId === context.applicationId &&
    expected.activationId === context.activationId &&
    expected.ownerScopeKind === context.ownerScopeKind &&
    expected.workspaceId === context.workspaceId &&
    expected.userId === context.userId &&
    expected.deviceId === context.deviceId &&
    expected.sessionId === context.sessionId
  );
}

function rendererOwnerKey(owner: PluginHostRpcHandlerOwnerDescriptor): string {
  return [
    owner.packageId,
    owner.applicationId,
    owner.activationId,
    owner.ownerScopeKind,
    owner.workspaceId,
    owner.userId,
    owner.deviceId,
    owner.bundleHash,
    owner.manifestHash,
    owner.capabilityGrantId,
    owner.consentEpoch,
    owner.frameGeneration,
  ].join(":");
}

function sameRendererSlot(a: PluginRendererSlot, b: PluginRendererSlot): boolean {
  return a.kind === b.kind && a.type === b.type;
}

function rendererSourcePolicy(slots: readonly PluginRendererSlot[]): PluginHostRpcOperationPolicy {
  const firstSlot = slots[0];
  if (!firstSlot) {
    throw new PluginHostRpcError("renderer_slot_invalid", "renderer slot is required");
  }
  const permissions = slots.map((slot) => `plaintext:render:${slot.kind}:${slot.type}` as const);

  return {
    requiredPermissions: permissions,
    documentAccess: "allowed_document",
    plaintext: {
      operation: "plaintext.read",
      requiredPermission: `plaintext:render:${firstSlot.kind}:${firstSlot.type}`,
      allowedContextKinds: ["renderer_invocation"],
      allowedPlaintextScopes: Array.from(new Set(slots.map((slot) => slot.kind))),
      audit: "required",
    },
  };
}

function assertRendererSlots(slots: readonly PluginRendererSlot[]): void {
  if (!Array.isArray(slots) || slots.length === 0) {
    throw new PluginHostRpcError("renderer_slot_invalid", "renderer slot is required");
  }
  const seen = new Set<string>();
  for (const slot of slots) {
    assertRendererSlot(slot);
    const key = `${slot.kind}:${slot.type}`;
    if (seen.has(key)) {
      throw new PluginHostRpcError("renderer_slot_invalid", "renderer slot is duplicated");
    }
    seen.add(key);
  }
}

function assertRendererSlot(slot: PluginRendererSlot): void {
  if (slot.kind !== "block" && slot.kind !== "inline") {
    throw new PluginHostRpcError("renderer_slot_invalid", "renderer slot kind is not supported");
  }
  if (
    !SLOT_TYPE_PATTERN.test(slot.type) ||
    FORBIDDEN_SLOT_TYPES.has(slot.type) ||
    (slot.kind === "inline" && slot.type !== "code")
  ) {
    throw new PluginHostRpcError("renderer_slot_invalid", "renderer slot type is not supported");
  }
}

function assertRendererSourceSize(source: string, maxBytes: number): void {
  if (typeof source !== "string") {
    throw new PluginHostRpcError("renderer_source_invalid", "renderer source must be a string");
  }
  if (!Number.isSafeInteger(maxBytes) || maxBytes <= 0) {
    throw new PluginHostRpcError(
      "renderer_source_limit_invalid",
      "renderer source byte limit must be positive",
    );
  }
  if (pluginPayloadByteLength(source) > maxBytes) {
    throw new PluginHostRpcError(
      "renderer_source_too_large",
      "renderer source exceeds the configured byte limit",
    );
  }
}

function rendererHeightPayload(payload: unknown): RendererHeightPayload {
  if (!isRecord(payload)) {
    throw new PluginHostRpcError("renderer_payload_invalid", "renderer payload must be an object");
  }
  return payload;
}

function requiredPayloadString(value: unknown, field: string): string {
  if (typeof value === "string" && value.trim() !== "") return value;
  throw new PluginHostRpcError(`${field}_invalid`, `${field} must be a non-empty string`);
}

function rendererDimension(value: unknown, field: string): number {
  if (typeof value !== "number") {
    throw new PluginHostRpcError(`${field}_invalid`, `${field} must be a finite number`);
  }
  return assertRendererDimension(value, field);
}

function assertRendererDimension(value: number, field: string): number {
  if (!Number.isFinite(value) || value < 0 || value > 100_000) {
    throw new PluginHostRpcError(`${field}_invalid`, `${field} must be within renderer bounds`);
  }
  return value;
}

function assertThemeSnapshot(theme: PluginRendererThemeSnapshot): void {
  if (theme.colorScheme !== "light" && theme.colorScheme !== "dark") {
    throw new PluginHostRpcError("theme_invalid", "renderer theme color scheme is invalid");
  }
  for (const value of [theme.foreground, theme.background, theme.accent]) {
    if (typeof value !== "string" || !/^#[0-9a-fA-F]{6}$/.test(value)) {
      throw new PluginHostRpcError("theme_invalid", "renderer theme token is invalid");
    }
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
