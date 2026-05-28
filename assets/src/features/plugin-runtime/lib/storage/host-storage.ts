import { registerBeforeSessionCleanup } from "@/shared/lib/auth/session-cleanup";
import { client, ApiError, withUserPopParams } from "@/shared/api/core";
import { base64UrlDecode, base64UrlEncode } from "@/shared/lib/crypto/encoding";
import { deletePluginRuntimePins } from "@/shared/lib/crypto/trust-store";
import { getCryptoWorker } from "@/shared/lib/crypto/worker/client";
import {
  PluginHostRpcError,
  type PluginHostMessageRouter,
  type PluginHostRpcContext,
  type PluginHostRpcHandler,
  type PluginHostRpcHandlerOwnerDescriptor,
} from "../host-rpc/host-rpc";
import {
  emitPluginSecurityAudit,
  pluginAuditSucceeded,
  type PluginHostRpcOperationPolicy,
} from "../capability/capability-enforcement";
import { getDefaultPluginHostCredentialStore } from "../credential/host-credential";

type PluginStorageSurface = "userLocal" | "cache" | "workspace" | "document";
type PluginLocalStorageSurface = Extract<PluginStorageSurface, "userLocal" | "cache">;
type PluginSyncedStorageSurface = Extract<PluginStorageSurface, "workspace" | "document">;
type PluginStorageOperation = "get" | "set" | "delete";
type PluginRecordOperation = "create" | "get" | "delete";

interface PluginHostStorageIdentity {
  userId: string;
  deviceId: string;
}

export interface PluginHostStorageServices {
  identity: () => PluginHostStorageIdentity | null;
  localStore: PluginLocalStore;
  syncedStore?: PluginSyncedStorageStore;
  credentialBroker?: PluginCredentialBroker;
}

export interface PluginLocalStore {
  get<T = unknown>(key: string, aadRecord: Record<string, unknown>): Promise<T | null>;
  set(key: string, value: unknown, aadRecord: Record<string, unknown>): Promise<void>;
  delete(key: string): Promise<void>;
  clearPluginData(): Promise<void>;
  clearPluginApplicationData(target: PluginApplicationLocalDataTarget): Promise<void>;
}

export interface PluginSyncedStorageStore {
  get(params: PluginSyncedStorageReadParams): Promise<unknown | null>;
  set(params: PluginSyncedStorageWriteParams): Promise<void>;
  delete(params: PluginSyncedStorageDeleteParams): Promise<void>;
  createRecord?(params: PluginSyncedRecordCreateParams): Promise<PluginSyncedRecordRef>;
  getRecord?(params: PluginSyncedRecordReadParams): Promise<PluginSyncedRecordValue | null>;
  deleteRecord?(params: PluginSyncedRecordDeleteParams): Promise<void>;
}

export interface PluginCredentialBroker {
  use(params: PluginCredentialUseParams): Promise<PluginCredentialUseResult>;
  revokeHandle(handle: string): void | Promise<void>;
  purgeApplication?(target: PluginApplicationCredentialTarget): void | Promise<void>;
}

export interface PluginApplicationLocalDataTarget {
  workspaceId: string;
  applicationId: string;
  packageId: string;
  activationId: string;
  userId: string;
  deviceId: string;
}

export type PluginApplicationCredentialTarget = PluginApplicationLocalDataTarget;

export interface PluginCredentialUseParams {
  context: PluginHostRpcContext;
  userId: string;
  deviceId: string;
  credentialId: string;
  audience: string;
  endpoint: string;
  method: string;
}

export interface PluginCredentialUseResult {
  handle: string;
  expiresAtMs: number;
  audience: string;
  endpoint: string;
  method: string;
}

export interface PluginSyncedStorageReadParams {
  context: PluginHostRpcContext;
  surface: PluginSyncedStorageSurface;
  key: string;
  documentId: string | null;
}

export interface PluginSyncedStorageWriteParams extends PluginSyncedStorageReadParams {
  value: unknown;
}

export type PluginSyncedStorageDeleteParams = PluginSyncedStorageReadParams;

export interface PluginSyncedRecordCreateParams {
  context: PluginHostRpcContext;
  surface: PluginSyncedStorageSurface;
  kind: string;
  documentId: string | null;
  value: unknown;
}

export interface PluginSyncedRecordRef {
  id: string;
  kind: string;
}

export interface PluginSyncedRecordReadParams {
  context: PluginHostRpcContext;
  surface: PluginSyncedStorageSurface;
  recordId: string;
  documentId: string | null;
}

export type PluginSyncedRecordDeleteParams = PluginSyncedRecordReadParams;

export interface PluginSyncedRecordValue extends PluginSyncedRecordRef {
  value: unknown;
}

interface PluginStoragePayload {
  key?: unknown;
  kind?: unknown;
  record_id?: unknown;
  value?: unknown;
  document_id?: unknown;
}

interface PluginCredentialPayload {
  credential_id?: unknown;
  audience?: unknown;
  endpoint?: unknown;
  method?: unknown;
  secret?: unknown;
  token?: unknown;
  value?: unknown;
}

const LOCAL_STORAGE_SURFACES = new Set<PluginStorageSurface>(["userLocal", "cache"]);
const SYNCED_STORAGE_SURFACES = new Set<PluginStorageSurface>(["workspace", "document"]);
const STORAGE_OPERATIONS: readonly {
  surface: PluginStorageSurface;
  operation: PluginStorageOperation;
  rpcOperation: string;
}[] = [
  { surface: "userLocal", operation: "get", rpcOperation: "storage.userLocal.get" },
  { surface: "userLocal", operation: "set", rpcOperation: "storage.userLocal.set" },
  { surface: "userLocal", operation: "delete", rpcOperation: "storage.userLocal.delete" },
  { surface: "cache", operation: "get", rpcOperation: "storage.cache.get" },
  { surface: "cache", operation: "set", rpcOperation: "storage.cache.set" },
  { surface: "cache", operation: "delete", rpcOperation: "storage.cache.delete" },
  { surface: "workspace", operation: "get", rpcOperation: "storage.workspace.get" },
  { surface: "workspace", operation: "set", rpcOperation: "storage.workspace.set" },
  { surface: "workspace", operation: "delete", rpcOperation: "storage.workspace.delete" },
  { surface: "document", operation: "get", rpcOperation: "storage.document.get" },
  { surface: "document", operation: "set", rpcOperation: "storage.document.set" },
  { surface: "document", operation: "delete", rpcOperation: "storage.document.delete" },
];
const RECORD_OPERATIONS: readonly {
  surface: PluginSyncedStorageSurface;
  operation: PluginRecordOperation;
  rpcOperation: string;
}[] = [
  { surface: "workspace", operation: "create", rpcOperation: "storage.workspace.record.create" },
  { surface: "workspace", operation: "get", rpcOperation: "storage.workspace.record.get" },
  { surface: "workspace", operation: "delete", rpcOperation: "storage.workspace.record.delete" },
  { surface: "document", operation: "create", rpcOperation: "storage.document.record.create" },
  { surface: "document", operation: "get", rpcOperation: "storage.document.record.get" },
  { surface: "document", operation: "delete", rpcOperation: "storage.document.record.delete" },
];

const registeredRouters = new WeakMap<
  PluginHostMessageRouter,
  { retainCount: number; dispose: () => void }
>();

export function createDefaultPluginHostStorageServices(
  identity: () => PluginHostStorageIdentity | null = () => null,
): PluginHostStorageServices {
  return {
    identity,
    localStore: createDskPluginLocalStore(),
    syncedStore: createEncryptedPluginSyncedStorageStore(),
    credentialBroker: getDefaultPluginHostCredentialStore(),
  };
}

export async function purgePluginApplicationLocalData(
  target: PluginApplicationLocalDataTarget,
  services: PluginHostStorageServices = createDefaultPluginHostStorageServices(),
): Promise<void> {
  await Promise.all([
    services.localStore.clearPluginApplicationData(target),
    deletePluginRuntimePins(
      target.workspaceId,
      target.packageId,
      target.applicationId,
      target.activationId,
      target.userId,
    ),
    services.credentialBroker?.purgeApplication?.({
      workspaceId: target.workspaceId,
      packageId: target.packageId,
      applicationId: target.applicationId,
      activationId: target.activationId,
      userId: target.userId,
      deviceId: target.deviceId,
    }),
  ]);
}

export function retainPluginHostStorageHandlers(
  router: PluginHostMessageRouter,
  services: PluginHostStorageServices = createDefaultPluginHostStorageServices(),
): () => void {
  const existing = registeredRouters.get(router);
  if (existing) {
    existing.retainCount += 1;
    return () => releasePluginHostStorageHandlers(router);
  }

  const unregisterHandlers = registerPluginHostStorageHandlers(router, services);
  const unregisterSecureCleanup = registerBeforeSessionCleanup(
    () => services.localStore.clearPluginData(),
    { scope: "secure", order: 100 },
  );

  registeredRouters.set(router, {
    retainCount: 1,
    dispose: () => {
      unregisterHandlers();
      unregisterSecureCleanup();
    },
  });

  return () => releasePluginHostStorageHandlers(router);
}

export function registerPluginHostStorageHandlers(
  router: PluginHostMessageRouter,
  services: PluginHostStorageServices,
  owner?: PluginHostRpcHandlerOwnerDescriptor,
): () => void {
  const unregister = STORAGE_OPERATIONS.map(({ surface, operation, rpcOperation }) =>
    registerHandler(
      router,
      owner,
      rpcOperation,
      storageHandler(surface, operation, services),
      storageOperationPolicy(surface, operation),
    ),
  );

  unregister.push(
    ...RECORD_OPERATIONS.map(({ surface, operation, rpcOperation }) =>
      registerHandler(router, owner, rpcOperation, recordHandler(surface, operation, services), {
        requiredPermissions: [`storage:${operation === "get" ? "read" : "write"}:${surface}`],
        ...(surface === "document" ? { documentAccess: "allowed_document" as const } : {}),
        plaintext: null,
      }),
    ),
  );

  unregister.push(
    registerHandler(router, owner, "credential.use", credentialHandler(services), {
      requiredPermissions: ["credential:use"],
      plaintext: null,
    }),
  );

  return () => {
    for (const unregisterHandler of unregister.reverse()) unregisterHandler();
  };
}

function storageOperationPolicy(
  surface: PluginStorageSurface,
  operation: PluginStorageOperation,
): PluginHostRpcOperationPolicy {
  return {
    requiredPermissions: [`storage:${operation === "get" ? "read" : "write"}:${surface}`],
    ...(surface === "document" ? { documentAccess: "allowed_document" as const } : {}),
    plaintext: null,
    ...(surface === "cache" && operation === "set"
      ? {
          cacheStorageWrite: {
            operation: "storage.cache.set" as const,
            highRiskConsent: "required" as const,
          },
        }
      : {}),
  };
}

export function createDskPluginLocalStore(): PluginLocalStore {
  return {
    async get<T = unknown>(key: string, aadRecord: Record<string, unknown>): Promise<T | null> {
      const plaintext = await getCryptoWorker().loadUiStateWithDsk({ storageKey: key, aadRecord });
      if (plaintext == null) return null;
      return JSON.parse(new TextDecoder().decode(plaintext)) as T;
    },

    async set(key, value, aadRecord) {
      await getCryptoWorker().storeUiStateWithDsk({
        storageKey: key,
        aadRecord,
        plaintext: new TextEncoder().encode(encodeJsonValue(value)),
      });
    },

    async delete(key) {
      await getCryptoWorker().deleteUiStateWithDsk(key);
    },

    async clearPluginData() {
      await getCryptoWorker().clearPluginDataWithDsk();
    },

    async clearPluginApplicationData(target) {
      await getCryptoWorker().clearPluginApplicationDataWithDsk(target);
    },
  };
}

export function createEncryptedPluginSyncedStorageStore(): PluginSyncedStorageStore {
  return {
    async get(params) {
      const entry = await requestPluginStorage("get", params);
      if (!entry) return null;
      const plaintext = await getCryptoWorker().decryptPluginStorage({
        ciphertext: base64UrlDecode(entry.ciphertext),
        nonce: base64UrlDecode(entry.nonce),
        surface: params.surface,
        workspaceId: params.context.workspaceId,
        packageId: params.context.packageId,
        applicationId: params.context.applicationId,
        activationId: entry.activation_id,
        pluginId: params.context.pluginId,
        scopeId: storageScopeId(params),
        key: params.key,
        keyVersion: entry.key_version,
      });
      return JSON.parse(new TextDecoder().decode(plaintext)) as unknown;
    },

    async set(params) {
      const encrypted = await getCryptoWorker().encryptPluginStorage({
        plaintext: new TextEncoder().encode(encodeJsonValue(params.value)),
        surface: params.surface,
        workspaceId: params.context.workspaceId,
        packageId: params.context.packageId,
        applicationId: params.context.applicationId,
        activationId: params.context.activationId,
        pluginId: params.context.pluginId,
        scopeId: storageScopeId(params),
        key: params.key,
      });
      await requestPluginStorage("put", params, {
        plugin_id: params.context.pluginId,
        ciphertext: base64UrlEncode(encrypted.ciphertext),
        nonce: base64UrlEncode(encrypted.nonce),
        key_version: encrypted.keyVersion,
      });
    },

    async delete(params) {
      await requestPluginStorage("delete", params);
    },

    async createRecord(params) {
      const recordId = crypto.randomUUID();
      const encrypted = await getCryptoWorker().encryptPluginStorage({
        plaintext: new TextEncoder().encode(encodeJsonValue(params.value)),
        surface: params.surface,
        workspaceId: params.context.workspaceId,
        packageId: params.context.packageId,
        applicationId: params.context.applicationId,
        activationId: params.context.activationId,
        pluginId: params.context.pluginId,
        scopeId: storageScopeId(params),
        key: pluginRecordStorageKey(recordId, params.kind),
      });
      const record = await requestPluginRecord("post", params, {
        id: recordId,
        plugin_id: params.context.pluginId,
        kind: params.kind,
        encrypted_data: base64UrlEncode(encrypted.ciphertext),
        nonce: base64UrlEncode(encrypted.nonce),
        key_version: encrypted.keyVersion,
      });
      return { id: record.id, kind: record.kind };
    },

    async getRecord(params) {
      const record = await requestPluginRecord("get", params);
      if (!record) return null;
      const plaintext = await getCryptoWorker().decryptPluginStorage({
        ciphertext: base64UrlDecode(record.encrypted_data),
        nonce: base64UrlDecode(record.nonce),
        surface: params.surface,
        workspaceId: params.context.workspaceId,
        packageId: params.context.packageId,
        applicationId: params.context.applicationId,
        activationId: record.activation_id,
        pluginId: params.context.pluginId,
        scopeId: storageScopeId(params),
        key: pluginRecordStorageKey(record.id, record.kind),
        keyVersion: record.key_version,
      });
      return {
        id: record.id,
        kind: record.kind,
        value: JSON.parse(new TextDecoder().decode(plaintext)) as unknown,
      };
    },

    async deleteRecord(params) {
      await requestPluginRecord("delete", params);
    },
  };
}

function releasePluginHostStorageHandlers(router: PluginHostMessageRouter): void {
  const registration = registeredRouters.get(router);
  if (!registration) return;
  registration.retainCount -= 1;
  if (registration.retainCount > 0) return;
  registration.dispose();
  registeredRouters.delete(router);
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

function storageHandler(
  surface: PluginStorageSurface,
  operation: PluginStorageOperation,
  services: PluginHostStorageServices,
): PluginHostRpcHandler {
  return async (context, request) => {
    const identity = requireIdentity(services);
    const payload = storagePayload(request.payload);
    const key = storagePayloadKey(payload);

    if (LOCAL_STORAGE_SURFACES.has(surface)) {
      return handleLocalStorageRequest(
        surface as PluginLocalStorageSurface,
        operation,
        services,
        context,
        identity,
        key,
        payload,
      );
    }

    if (SYNCED_STORAGE_SURFACES.has(surface)) {
      return handleSyncedStorageRequest(
        surface as PluginSyncedStorageSurface,
        operation,
        services,
        context,
        key,
        payload,
      );
    }

    throw new PluginHostRpcError("storage_surface_invalid", "storage surface is not supported");
  };
}

async function handleLocalStorageRequest(
  surface: PluginLocalStorageSurface,
  operation: PluginStorageOperation,
  services: PluginHostStorageServices,
  context: PluginHostRpcContext,
  identity: PluginHostStorageIdentity,
  key: string,
  payload: PluginStoragePayload,
): Promise<unknown> {
  const storageKey = localStorageKey(surface, context, identity, key);
  const aadRecord = localStorageAad(surface, context, identity, key);

  if (operation === "get") {
    return { value: await services.localStore.get(storageKey, aadRecord) };
  }

  if (operation === "delete") {
    await services.localStore.delete(storageKey);
    return { deleted: true };
  }

  assertJsonValue(payload.value ?? null);
  await auditStorageWriteOrThrow(context, surface, key, payload.value ?? null);
  await services.localStore.set(storageKey, payload.value ?? null, aadRecord);
  return { stored: true };
}

async function handleSyncedStorageRequest(
  surface: PluginSyncedStorageSurface,
  operation: PluginStorageOperation,
  services: PluginHostStorageServices,
  context: PluginHostRpcContext,
  key: string,
  payload: PluginStoragePayload,
): Promise<unknown> {
  const syncedStore = services.syncedStore;
  if (!syncedStore) {
    throw new PluginHostRpcError(
      "storage_surface_unavailable",
      "server-synced plugin storage is not configured",
    );
  }

  const documentId = surface === "document" ? storageDocumentId(payload) : null;
  const params = { context, surface, key, documentId };

  if (operation === "get") return { value: await syncedStore.get(params) };
  if (operation === "delete") {
    await syncedStore.delete(params);
    return { deleted: true };
  }

  assertJsonValue(payload.value ?? null);
  await auditStorageWriteOrThrow(context, surface, key, payload.value ?? null);
  await syncedStore.set({ ...params, value: payload.value ?? null });
  return { stored: true };
}

function recordHandler(
  surface: PluginSyncedStorageSurface,
  operation: PluginRecordOperation,
  services: PluginHostStorageServices,
): PluginHostRpcHandler {
  return async (context, request) => {
    const syncedStore = services.syncedStore;
    if (!syncedStore) {
      throw new PluginHostRpcError(
        "storage_surface_unavailable",
        "server-synced plugin storage is not configured",
      );
    }

    const payload = storagePayload(request.payload);
    const documentId = surface === "document" ? storageDocumentId(payload) : null;

    if (operation === "create") {
      const createRecord = syncedStore.createRecord;
      if (!createRecord) throw recordStorageUnavailable();
      const kind = storageRecordKind(payload);
      assertJsonValue(payload.value ?? null);
      await auditStorageWriteOrThrow(context, surface, kind, payload.value ?? null);
      const record = await createRecord({
        context,
        surface,
        kind,
        documentId,
        value: payload.value ?? null,
      });
      return { record_id: record.id, kind: record.kind };
    }

    const recordId = storageRecordId(payload);

    if (operation === "get") {
      const getRecord = syncedStore.getRecord;
      if (!getRecord) throw recordStorageUnavailable();
      const record = await getRecord({ context, surface, recordId, documentId });
      return record ? { record_id: record.id, kind: record.kind, value: record.value } : null;
    }

    const deleteRecord = syncedStore.deleteRecord;
    if (!deleteRecord) throw recordStorageUnavailable();
    await deleteRecord({ context, surface, recordId, documentId });
    return { deleted: true };
  };
}

function credentialHandler(services: PluginHostStorageServices): PluginHostRpcHandler {
  return async (context, request) => {
    const credentialBroker = services.credentialBroker;
    if (!credentialBroker) {
      throw new PluginHostRpcError(
        "credential_surface_unavailable",
        "plugin credential use is not configured",
      );
    }

    const identity = requireIdentity(services);
    const payload = credentialPayload(request.payload);
    rejectCredentialSecretPayload(payload);
    const credentialUse = {
      context,
      userId: identity.userId,
      deviceId: identity.deviceId,
      credentialId: requiredPayloadString(payload.credential_id, "credential_id"),
      audience: requiredPayloadString(payload.audience, "audience"),
      endpoint: requiredPayloadString(payload.endpoint, "endpoint"),
      method: requiredPayloadString(payload.method, "method").toUpperCase(),
    };

    const result = await credentialBroker.use(credentialUse);

    const auditOk = await pluginAuditSucceeded(
      emitPluginSecurityAudit(context.auditSink, context, {
        type: "plugin.credential.used",
        operation: "credential.use",
        result: "allow",
        actionResult: "allowed",
        requestId: request.requestId,
        payloadKind: "unknown",
        resourceKind: "credential",
        resourceId: credentialUse.audience,
      }),
    );
    if (!auditOk) {
      await credentialBroker.revokeHandle(result.handle);
      throw new PluginHostRpcError(
        "credential_audit_unavailable",
        "credential use audit event could not be recorded",
      );
    }

    return {
      protocol: "refmd.plugin-credential-handle",
      version: 1,
      handle: result.handle,
      expires_at_ms: result.expiresAtMs,
      audience: result.audience,
      endpoint: result.endpoint,
      method: result.method,
    };
  };
}

async function auditStorageWriteOrThrow(
  context: PluginHostRpcContext,
  surface: PluginStorageSurface,
  key: string,
  value: unknown,
): Promise<void> {
  const auditOk = await pluginAuditSucceeded(
    emitPluginSecurityAudit(context.auditSink, context, {
      type: "plugin.storage.written",
      operation: `storage.${surface}.set`,
      result: "allow",
      actionResult: "allowed",
      payloadKind: "unknown",
      storageBytes: byteLength(encodeJsonValue(value)),
      resourceKind: "plugin",
      resourceId: `${context.pluginId}:${key}`,
    }),
  );

  if (!auditOk) {
    throw new PluginHostRpcError(
      "storage_audit_unavailable",
      "plugin storage write audit event could not be recorded",
    );
  }
}

function requireIdentity(services: PluginHostStorageServices): PluginHostStorageIdentity {
  const identity = services.identity();
  if (!identity?.userId || !identity.deviceId) {
    throw new PluginHostRpcError(
      "plugin_local_identity_required",
      "plugin storage requires a user and device identity",
    );
  }
  return identity;
}

function storagePayload(payload: unknown): PluginStoragePayload {
  if (!isRecord(payload)) {
    throw new PluginHostRpcError("storage_payload_invalid", "storage payload must be an object");
  }
  return payload;
}

function storagePayloadKey(payload: PluginStoragePayload): string {
  return requiredPayloadString(payload.key, "key");
}

function storageRecordKind(payload: PluginStoragePayload): string {
  return requiredPayloadString(payload.kind, "kind");
}

function storageRecordId(payload: PluginStoragePayload): string {
  return requiredPayloadString(payload.record_id, "record_id");
}

function storageDocumentId(payload: PluginStoragePayload): string {
  return requiredPayloadString(payload.document_id, "document_id");
}

function credentialPayload(payload: unknown): PluginCredentialPayload {
  if (!isRecord(payload)) {
    throw new PluginHostRpcError(
      "credential_payload_invalid",
      "credential payload must be an object",
    );
  }
  return payload;
}

function rejectCredentialSecretPayload(payload: PluginCredentialPayload): void {
  if (payload.secret !== undefined || payload.token !== undefined || payload.value !== undefined) {
    throw new PluginHostRpcError(
      "credential_secret_read_forbidden",
      "plugins may not provide or receive credential secret values",
    );
  }
}

function requiredPayloadString(value: unknown, field: string): string {
  if (typeof value === "string" && value.trim() !== "") return value;
  throw new PluginHostRpcError(`${field}_invalid`, `${field} must be a non-empty string`);
}

function localStorageKey(
  surface: PluginLocalStorageSurface,
  context: PluginHostRpcContext,
  identity: PluginHostStorageIdentity,
  key: string,
): string {
  const prefix = surface === "userLocal" ? "refmd-plugin-user-local" : "refmd-plugin-cache";
  return [
    prefix,
    context.packageId,
    context.applicationId,
    context.activationId,
    context.workspaceId,
    identity.userId,
    identity.deviceId,
    key,
  ].join(":");
}

function localStorageAad(
  surface: PluginLocalStorageSurface,
  context: PluginHostRpcContext,
  identity: PluginHostStorageIdentity,
  key: string,
): Record<string, unknown> {
  return {
    protocol: "refmd.plugin-local-storage",
    version: 1,
    surface,
    workspace_id: context.workspaceId,
    package_id: context.packageId,
    application_id: context.applicationId,
    activation_id: context.activationId,
    plugin_id: context.pluginId,
    user_id: identity.userId,
    device_id: identity.deviceId,
    key,
  };
}

interface PluginStorageEntryEnvelope {
  activation_id: string;
  ciphertext: string;
  nonce: string;
  key_version: number;
}

interface PluginStorageWriteEnvelope {
  plugin_id: string;
  ciphertext: string;
  nonce: string;
  key_version: number;
}

interface PluginRecordEnvelope {
  id: string;
  activation_id: string;
  kind: string;
  encrypted_data: string;
  nonce: string;
  key_version: number;
}

interface PluginRecordWriteEnvelope {
  id: string;
  plugin_id: string;
  kind: string;
  encrypted_data: string;
  nonce: string;
  key_version: number;
}

async function requestPluginStorage(
  method: "get",
  params: PluginSyncedStorageReadParams,
): Promise<PluginStorageEntryEnvelope | null>;
async function requestPluginStorage(
  method: "put",
  params: PluginSyncedStorageWriteParams,
  body: PluginStorageWriteEnvelope,
): Promise<PluginStorageEntryEnvelope>;
async function requestPluginStorage(
  method: "delete",
  params: PluginSyncedStorageDeleteParams,
): Promise<void>;
async function requestPluginStorage(
  method: "get" | "put" | "delete",
  params: PluginSyncedStorageReadParams,
  body?: PluginStorageWriteEnvelope,
): Promise<PluginStorageEntryEnvelope | null | void> {
  const path = "/api/workspaces/{workspace_id}/plugin-runtime/{application_id}/storage/{surface}";
  const requestParams = pluginStorageRequestParams(params);

  if (method === "get") {
    try {
      return throwIfPluginStorageError(
        await client.GET(path, { params: withUserPopParams(requestParams) }),
      );
    } catch (error) {
      if (pluginStorageNotFound(error)) return null;
      throw error;
    }
  }

  if (method === "delete") {
    throwIfPluginMutationError(
      await client.DELETE(path, { params: withUserPopParams(requestParams) }),
    );
    return;
  }

  if (!body) throw recordStorageUnavailable();
  return throwIfPluginStorageError(
    await client.PUT(path, { params: withUserPopParams(requestParams), body }),
  );
}

function pluginStorageRequestParams(params: PluginSyncedStorageReadParams) {
  return {
    path: {
      workspace_id: params.context.workspaceId,
      application_id: params.context.applicationId,
      surface: params.surface,
    },
    query: {
      plugin_id: params.context.pluginId,
      state_head_hash: requireSyncedStorageHead(params.context.stateHeadHash, "state"),
      consent_head_hash: requireSyncedStorageHead(params.context.consentHeadHash, "consent"),
      capability_grant_id: params.context.capabilityGrantId,
      consent_epoch: params.context.consentEpoch,
      frame_generation: params.context.frameGeneration,
      key: params.key,
      ...(params.documentId ? { document_id: params.documentId } : {}),
    },
  };
}

async function requestPluginRecord(
  method: "get",
  params: PluginSyncedRecordReadParams,
): Promise<PluginRecordEnvelope | null>;
async function requestPluginRecord(
  method: "post",
  params: PluginSyncedRecordCreateParams,
  body: PluginRecordWriteEnvelope,
): Promise<PluginRecordEnvelope>;
async function requestPluginRecord(
  method: "delete",
  params: PluginSyncedRecordDeleteParams,
): Promise<void>;
async function requestPluginRecord(
  method: "get" | "post" | "delete",
  params: PluginSyncedRecordCreateParams | PluginSyncedRecordReadParams,
  body?: PluginRecordWriteEnvelope,
): Promise<PluginRecordEnvelope | null | void> {
  const path = "/api/workspaces/{workspace_id}/plugin-runtime/{application_id}/records/{surface}";
  const recordPath =
    "/api/workspaces/{workspace_id}/plugin-runtime/{application_id}/records/{surface}/{record_id}";

  if (method === "post") {
    if (!body) throw recordStorageUnavailable();
    return throwIfPluginRecordError(
      await client.POST(path, {
        params: withUserPopParams(
          pluginRecordCreateRequestParams(params as PluginSyncedRecordCreateParams),
        ),
        body,
      }),
    );
  }

  const readParams = params as PluginSyncedRecordReadParams;
  const requestParams = pluginRecordRequestParams(readParams);

  if (method === "get") {
    try {
      return throwIfPluginRecordError(
        await client.GET(recordPath, { params: withUserPopParams(requestParams) }),
      );
    } catch (error) {
      if (pluginStorageNotFound(error)) return null;
      throw error;
    }
  }

  throwIfPluginMutationError(
    await client.DELETE(recordPath, { params: withUserPopParams(requestParams) }),
  );
}

function pluginRecordCreateRequestParams(params: PluginSyncedRecordCreateParams) {
  return {
    path: {
      workspace_id: params.context.workspaceId,
      application_id: params.context.applicationId,
      surface: params.surface,
    },
    query: {
      plugin_id: params.context.pluginId,
      state_head_hash: requireSyncedStorageHead(params.context.stateHeadHash, "state"),
      consent_head_hash: requireSyncedStorageHead(params.context.consentHeadHash, "consent"),
      capability_grant_id: params.context.capabilityGrantId,
      consent_epoch: params.context.consentEpoch,
      frame_generation: params.context.frameGeneration,
      ...(params.documentId ? { document_id: params.documentId } : {}),
    },
  };
}

function pluginRecordRequestParams(params: PluginSyncedRecordReadParams) {
  return {
    path: {
      workspace_id: params.context.workspaceId,
      application_id: params.context.applicationId,
      surface: params.surface,
      record_id: params.recordId,
    },
    query: {
      plugin_id: params.context.pluginId,
      state_head_hash: requireSyncedStorageHead(params.context.stateHeadHash, "state"),
      consent_head_hash: requireSyncedStorageHead(params.context.consentHeadHash, "consent"),
      capability_grant_id: params.context.capabilityGrantId,
      consent_epoch: params.context.consentEpoch,
      frame_generation: params.context.frameGeneration,
      ...(params.documentId ? { document_id: params.documentId } : {}),
    },
  };
}

function requireSyncedStorageHead(value: string | undefined, kind: "state" | "consent"): string {
  if (typeof value === "string" && value.trim() !== "") return value;
  throw new PluginHostRpcError(
    "plugin_storage_pin_required",
    `server-synced plugin storage requires a pinned ${kind} head`,
  );
}

function pluginRecordStorageKey(recordId: string, kind: string): string {
  return `record:${recordId}:${kind}`;
}

function storageScopeId(params: {
  surface: PluginSyncedStorageSurface;
  context: PluginHostRpcContext;
  documentId: string | null;
}): string {
  return params.surface === "workspace" ? params.context.workspaceId : requiredDocumentId(params);
}

function requiredDocumentId(params: { documentId: string | null }): string {
  if (params.documentId) return params.documentId;
  throw new PluginHostRpcError("document_id_invalid", "document_id must be a non-empty string");
}

function pluginStorageNotFound(error: unknown): boolean {
  return error instanceof ApiError && error.status === 404;
}

function throwIfPluginStorageError(result: {
  data?: PluginStorageEntryEnvelope;
  error?: unknown;
  response: Response;
}): PluginStorageEntryEnvelope {
  if (result.error !== undefined) {
    throw new ApiError(result.response.status, result.error as Record<string, unknown>);
  }
  return result.data as PluginStorageEntryEnvelope;
}

function throwIfPluginRecordError(result: {
  data?: PluginRecordEnvelope;
  error?: unknown;
  response: Response;
}): PluginRecordEnvelope {
  if (result.error !== undefined) {
    throw new ApiError(result.response.status, result.error as Record<string, unknown>);
  }
  return result.data as PluginRecordEnvelope;
}

function throwIfPluginMutationError(result: { error?: unknown; response: Response }): void {
  if (result.error !== undefined) {
    throw new ApiError(result.response.status, result.error as Record<string, unknown>);
  }
}

function recordStorageUnavailable(): PluginHostRpcError {
  return new PluginHostRpcError(
    "storage_record_surface_unavailable",
    "server-synced plugin record storage is not configured",
  );
}

function assertJsonValue(value: unknown): void {
  encodeJsonValue(value);
}

function encodeJsonValue(value: unknown): string {
  try {
    const encoded = JSON.stringify(value);
    if (encoded !== undefined) return encoded;
  } catch {
    // Fall through to the shared storage error below.
  }

  throw new PluginHostRpcError(
    "storage_payload_invalid",
    "storage payload must be JSON serializable",
  );
}

function byteLength(value: string): number {
  return new TextEncoder().encode(value).byteLength;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
