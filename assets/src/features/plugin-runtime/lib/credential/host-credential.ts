import { base64UrlEncode } from "@/shared/lib/crypto/encoding";
import { getCryptoWorker } from "@/shared/lib/crypto/worker/client";
import { PluginHostRpcError } from "../host-rpc/host-rpc";
import type {
  PluginCredentialBroker,
  PluginCredentialUseParams,
  PluginCredentialUseResult,
  PluginApplicationCredentialTarget,
} from "../storage/host-storage";
import type {
  PluginCredentialHeaderResolver,
  PluginCredentialNetworkUseParams,
} from "../network/host-network";

const DEFAULT_CREDENTIAL_HANDLE_TTL_MS = 5 * 60 * 1000;
const MAX_CREDENTIAL_HANDLE_TTL_MS = 15 * 60 * 1000;

export interface PluginHostCredentialRegistration {
  credentialId: string;
  pluginId: string;
  workspaceId: string;
  packageId: string;
  applicationId: string;
  activationId: string;
  userId: string;
  deviceId: string;
  audience: string;
  endpoint: string;
  method: string;
  headers: Record<string, string>;
  ttlMs?: number;
}

interface StoredCredential extends PluginHostCredentialRegistration {
  method: string;
  ttlMs: number;
}

export interface StoredCredentialEnvelope {
  protocol: "refmd.plugin-credential";
  version: 1;
  credentialId: string;
  pluginId: string;
  workspaceId: string;
  packageId: string;
  applicationId: string;
  activationId: string;
  userId: string;
  deviceId: string;
  audience: string;
  endpoint: string;
  method: string;
  headers: Record<string, string>;
  ttlMs: number;
}

export interface PluginCredentialStorageTarget {
  workspaceId: string;
  packageId: string;
  applicationId: string;
  activationId: string;
  userId: string;
  deviceId: string;
  credentialId: string;
}

export interface PluginHostCredentialPersistence {
  store(target: PluginCredentialStorageTarget, credential: StoredCredentialEnvelope): Promise<void>;
  load(target: PluginCredentialStorageTarget): Promise<StoredCredentialEnvelope | null>;
  delete(target: PluginCredentialStorageTarget): Promise<void>;
  purgeApplication(target: PluginApplicationCredentialTarget): Promise<void>;
}

interface IssuedCredentialHandle {
  credential: StoredCredential;
  handle: string;
  expiresAtMs: number;
}

export class PluginHostCredentialStore
  implements PluginCredentialBroker, PluginCredentialHeaderResolver
{
  private readonly credentials = new Map<string, StoredCredential>();
  private readonly handles = new Map<string, IssuedCredentialHandle>();
  private readonly persistence: PluginHostCredentialPersistence;

  constructor(persistence: PluginHostCredentialPersistence = createDskCredentialPersistence()) {
    this.persistence = persistence;
  }

  retainCredential(registration: PluginHostCredentialRegistration): () => void {
    const credential = normalizeCredentialRegistration(registration);
    const key = credentialKey(credential);
    this.credentials.set(key, credential);

    let released = false;
    return () => {
      if (released) return;
      released = true;
      if (this.credentials.get(key) === credential) this.credentials.delete(key);
    };
  }

  async storeCredential(registration: PluginHostCredentialRegistration): Promise<void> {
    const credential = normalizeCredentialRegistration(registration);
    await this.persistence.store(
      credentialStorageTarget(credential),
      toStoredCredentialEnvelope(credential),
    );
    this.credentials.set(credentialKey(credential), credential);
  }

  async loadCredential(params: PluginCredentialUseParams): Promise<boolean> {
    const stored = await this.persistence.load(credentialStorageTargetFromUse(params));
    if (!stored) return false;

    const credential = normalizeCredentialRegistration(assertStoredCredentialEnvelope(stored));
    if (!credentialMatchesUse(credential, params)) return false;

    this.credentials.set(credentialKey(credential), credential);
    return true;
  }

  async deleteCredential(target: PluginCredentialStorageTarget): Promise<void> {
    await this.persistence.delete(target);
    for (const [key, credential] of Array.from(this.credentials.entries())) {
      if (matchesCredentialStorageTarget(credential, target)) this.credentials.delete(key);
    }
    for (const [handle, issued] of Array.from(this.handles.entries())) {
      if (matchesCredentialStorageTarget(issued.credential, target)) this.handles.delete(handle);
    }
  }

  async use(params: PluginCredentialUseParams): Promise<PluginCredentialUseResult> {
    let credential = this.lookupCredential(params);
    if (!credential && (await this.loadCredential(params))) {
      credential = this.lookupCredential(params);
    }
    if (!credential) {
      throw new PluginHostRpcError(
        "credential_not_found",
        "credential is not available for this plugin runtime",
      );
    }

    const handle = `credential.${base64UrlEncode(randomBytes(32))}`;
    const expiresAtMs = Date.now() + credential.ttlMs;
    this.handles.set(handle, { credential, handle, expiresAtMs });
    return {
      handle,
      expiresAtMs,
      audience: credential.audience,
      endpoint: credential.endpoint,
      method: credential.method,
    };
  }

  revokeHandle(handle: string): void {
    this.handles.delete(handle);
  }

  async resolve(params: PluginCredentialNetworkUseParams): Promise<Record<string, string>> {
    const issued = this.handles.get(params.handle);
    if (!issued || issued.expiresAtMs <= Date.now()) {
      if (issued) this.handles.delete(params.handle);
      throw new PluginHostRpcError(
        "credential_handle_invalid",
        "credential handle is expired or unknown",
      );
    }

    const credential = issued.credential;
    if (
      credential.applicationId !== params.context.applicationId ||
      credential.packageId !== params.context.packageId ||
      credential.activationId !== params.context.activationId ||
      credential.pluginId !== params.context.pluginId ||
      credential.workspaceId !== params.context.workspaceId ||
      credential.userId !== params.context.auditActor.user_id ||
      credential.deviceId !== params.context.auditActor.device_id ||
      credential.audience !== params.audience ||
      credential.endpoint !== params.endpoint.url ||
      credential.method !== params.method.toUpperCase()
    ) {
      throw new PluginHostRpcError(
        "credential_handle_scope_mismatch",
        "credential handle is not valid for this network request",
      );
    }

    return { ...credential.headers };
  }

  async purgeApplication(params: PluginApplicationCredentialTarget): Promise<void> {
    await this.persistence.purgeApplication(params);
    for (const [key, credential] of Array.from(this.credentials.entries())) {
      if (matchesApplicationCredential(credential, params)) this.credentials.delete(key);
    }
    for (const [handle, issued] of Array.from(this.handles.entries())) {
      if (matchesApplicationCredential(issued.credential, params)) this.handles.delete(handle);
    }
  }

  private lookupCredential(params: PluginCredentialUseParams): StoredCredential | undefined {
    return this.credentials.get(
      credentialKey({
        credentialId: params.credentialId,
        pluginId: params.context.pluginId,
        workspaceId: params.context.workspaceId,
        packageId: params.context.packageId,
        applicationId: params.context.applicationId,
        activationId: params.context.activationId,
        userId: params.userId,
        deviceId: params.deviceId,
        audience: params.audience,
        endpoint: params.endpoint,
        method: params.method,
      }),
    );
  }
}

const defaultPluginHostCredentialStore = new PluginHostCredentialStore();

export function getDefaultPluginHostCredentialStore(): PluginHostCredentialStore {
  return defaultPluginHostCredentialStore;
}

function normalizeCredentialRegistration(
  registration: PluginHostCredentialRegistration,
): StoredCredential {
  const ttlMs = Math.min(
    registration.ttlMs ?? DEFAULT_CREDENTIAL_HANDLE_TTL_MS,
    MAX_CREDENTIAL_HANDLE_TTL_MS,
  );
  return {
    ...registration,
    method: registration.method.toUpperCase(),
    ttlMs,
    headers: { ...registration.headers },
  };
}

function credentialKey(params: {
  credentialId: string;
  pluginId: string;
  workspaceId: string;
  packageId: string;
  applicationId: string;
  activationId: string;
  userId: string;
  deviceId: string;
  audience: string;
  endpoint: string;
  method: string;
}): string {
  return JSON.stringify([
    params.credentialId,
    params.pluginId,
    params.workspaceId,
    params.packageId,
    params.applicationId,
    params.activationId,
    params.userId,
    params.deviceId,
    params.audience,
    params.endpoint,
    params.method.toUpperCase(),
  ]);
}

function matchesApplicationCredential(
  credential: StoredCredential,
  params: PluginApplicationCredentialTarget,
): boolean {
  return (
    credential.workspaceId === params.workspaceId &&
    credential.packageId === params.packageId &&
    credential.applicationId === params.applicationId &&
    credential.activationId === params.activationId &&
    credential.userId === params.userId &&
    credential.deviceId === params.deviceId
  );
}

function matchesCredentialStorageTarget(
  credential: StoredCredential,
  target: PluginCredentialStorageTarget,
): boolean {
  return (
    credential.workspaceId === target.workspaceId &&
    credential.packageId === target.packageId &&
    credential.applicationId === target.applicationId &&
    credential.activationId === target.activationId &&
    credential.userId === target.userId &&
    credential.deviceId === target.deviceId &&
    credential.credentialId === target.credentialId
  );
}

function credentialStorageTarget(credential: StoredCredential): PluginCredentialStorageTarget {
  return {
    workspaceId: credential.workspaceId,
    packageId: credential.packageId,
    applicationId: credential.applicationId,
    activationId: credential.activationId,
    userId: credential.userId,
    deviceId: credential.deviceId,
    credentialId: credential.credentialId,
  };
}

function credentialStorageTargetFromUse(
  params: PluginCredentialUseParams,
): PluginCredentialStorageTarget {
  return {
    workspaceId: params.context.workspaceId,
    packageId: params.context.packageId,
    applicationId: params.context.applicationId,
    activationId: params.context.activationId,
    userId: params.userId,
    deviceId: params.deviceId,
    credentialId: params.credentialId,
  };
}

function credentialMatchesUse(
  credential: StoredCredential,
  params: PluginCredentialUseParams,
): boolean {
  return (
    credential.pluginId === params.context.pluginId &&
    credential.workspaceId === params.context.workspaceId &&
    credential.packageId === params.context.packageId &&
    credential.applicationId === params.context.applicationId &&
    credential.activationId === params.context.activationId &&
    credential.userId === params.userId &&
    credential.deviceId === params.deviceId &&
    credential.credentialId === params.credentialId &&
    credential.audience === params.audience &&
    credential.endpoint === params.endpoint &&
    credential.method === params.method.toUpperCase()
  );
}

function toStoredCredentialEnvelope(credential: StoredCredential): StoredCredentialEnvelope {
  return {
    protocol: "refmd.plugin-credential",
    version: 1,
    credentialId: credential.credentialId,
    pluginId: credential.pluginId,
    workspaceId: credential.workspaceId,
    packageId: credential.packageId,
    applicationId: credential.applicationId,
    activationId: credential.activationId,
    userId: credential.userId,
    deviceId: credential.deviceId,
    audience: credential.audience,
    endpoint: credential.endpoint,
    method: credential.method,
    headers: { ...credential.headers },
    ttlMs: credential.ttlMs,
  };
}

function assertStoredCredentialEnvelope(value: unknown): StoredCredentialEnvelope {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new PluginHostRpcError("credential_storage_invalid", "stored credential is invalid");
  }
  const record = value as Record<string, unknown>;
  const headers = record.headers;
  if (
    record.protocol !== "refmd.plugin-credential" ||
    record.version !== 1 ||
    typeof record.credentialId !== "string" ||
    typeof record.pluginId !== "string" ||
    typeof record.workspaceId !== "string" ||
    typeof record.packageId !== "string" ||
    typeof record.applicationId !== "string" ||
    typeof record.activationId !== "string" ||
    typeof record.userId !== "string" ||
    typeof record.deviceId !== "string" ||
    typeof record.audience !== "string" ||
    typeof record.endpoint !== "string" ||
    typeof record.method !== "string" ||
    typeof record.ttlMs !== "number" ||
    !headers ||
    typeof headers !== "object" ||
    Array.isArray(headers)
  ) {
    throw new PluginHostRpcError("credential_storage_invalid", "stored credential is invalid");
  }
  return {
    protocol: "refmd.plugin-credential",
    version: 1,
    credentialId: record.credentialId,
    pluginId: record.pluginId,
    workspaceId: record.workspaceId,
    packageId: record.packageId,
    applicationId: record.applicationId,
    activationId: record.activationId,
    userId: record.userId,
    deviceId: record.deviceId,
    audience: record.audience,
    endpoint: record.endpoint,
    method: record.method,
    headers: assertHeaderRecord(headers),
    ttlMs: record.ttlMs,
  };
}

function assertHeaderRecord(value: object): Record<string, string> {
  const headers: Record<string, string> = {};
  for (const [key, headerValue] of Object.entries(value)) {
    if (typeof headerValue !== "string") {
      throw new PluginHostRpcError("credential_storage_invalid", "stored credential is invalid");
    }
    headers[key] = headerValue;
  }
  return headers;
}

function createDskCredentialPersistence(): PluginHostCredentialPersistence {
  return {
    async store(target, credential) {
      await getCryptoWorker().storePluginCredentialWithDsk({
        ...target,
        plaintext: new TextEncoder().encode(JSON.stringify(credential)),
      });
    },

    async load(target) {
      const plaintext = await getCryptoWorker().loadPluginCredentialWithDsk(target);
      if (!plaintext) return null;
      return assertStoredCredentialEnvelope(JSON.parse(new TextDecoder().decode(plaintext)));
    },

    async delete(target) {
      await getCryptoWorker().deletePluginCredentialWithDsk(target);
    },

    async purgeApplication(target) {
      await getCryptoWorker().clearPluginApplicationDataWithDsk(target);
    },
  };
}

function randomBytes(length: number): Uint8Array {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return bytes;
}
