import type { TitleDecryptItem, TitleDecryptResult } from "../types";
import type { ShareCapabilitySigningPublicKeyMaterial } from "../../signature";
import { workerSend, type CryptoWorkerClientMethodContext } from "./shared";
import { canonicalQueryString } from "../../canonical-query";
import { blake3Base64Url } from "../../hash";
import { SHARE_SESSION_SCOPE_HEADER } from "@/shared/lib/auth/session-scope";

export interface ShareBootstrapKeyRef {
  encrypted_key_refs: string[];
}

export interface ShareCanonicalBootstrapFields {
  share_id: string;
  authorization_share_id?: string;
  scope_kind: "document" | "folder";
  scope_id: string;
  permission: "view" | "edit";
  password_protected: boolean;
  share_token_hash: string;
  created_event_hash: string;
  latest_bootstrap_event_hash: string;
  capability_context_hash: string;
  share_capability_secret_commitment: string;
  password_capability_secret_commitment: string;
}

type BootstrapAuthScope = "share" | "user-pop";

export interface DekWorkerClientMethods {
  generateDek(
    documentId: string,
    workspaceId: string,
    dekKeyVersion?: number,
    setActive?: boolean,
  ): Promise<{ encryptedDek: Uint8Array; nonce: Uint8Array; keyVersion: number }>;
  wrapDek(params: {
    documentId: string;
    workspaceId: string;
  }): Promise<{ encryptedDek: Uint8Array; nonce: Uint8Array }>;
  wrapDekForShare(params: {
    documentId: string;
    shareId: string;
    keyVersion?: number;
    shareDekEncryptionKey: Uint8Array;
  }): Promise<{ encryptedDek: Uint8Array; nonce: Uint8Array }>;
  unwrapDek(params: {
    encryptedDek: Uint8Array;
    nonce: Uint8Array;
    documentId: string;
    workspaceId: string;
    keyVersion: number;
    isActive?: boolean;
    kekVersion?: number;
    cacheKey?: string;
  }): Promise<void>;
  encryptTitle(params: {
    title: string;
    documentId: string;
    keyVersion: number;
  }): Promise<{ encrypted: Uint8Array; nonce: Uint8Array }>;
  decryptTitle(params: {
    encrypted: Uint8Array;
    nonce: Uint8Array;
    documentId: string;
    keyVersion: number;
    cacheKey?: string;
  }): Promise<string>;
  decryptTitleBatch(items: TitleDecryptItem[]): Promise<TitleDecryptResult[]>;
  encryptContent(params: {
    plaintext: Uint8Array;
    documentId: string;
    keyVersion: number;
    cacheKey?: string;
  }): Promise<{ ciphertext: Uint8Array; nonce: Uint8Array }>;
  decryptContent(params: {
    ciphertext: Uint8Array;
    nonce: Uint8Array;
    documentId: string;
    keyVersion: number;
    cacheKey?: string;
  }): Promise<Uint8Array>;
  encryptSnapshot(params: {
    plaintext: Uint8Array;
    documentId: string;
    keyVersion: number;
    cacheKey?: string;
  }): Promise<{ ciphertext: Uint8Array; nonce: Uint8Array }>;
  decryptSnapshot(params: {
    ciphertext: Uint8Array;
    nonce: Uint8Array;
    documentId: string;
    keyVersion: number;
    cacheKey?: string;
  }): Promise<Uint8Array>;
  hasDek(documentId: string, keyVersion: number, cacheKey?: string): Promise<boolean>;
  hasDekBatch(
    items: Array<{
      requestId: string;
      documentId: string;
      keyVersion: number;
      cacheKey?: string;
    }>,
  ): Promise<Array<{ requestId: string; hasDek: boolean }>>;
  cacheDek(params: {
    documentId: string;
    dek: Uint8Array;
    keyVersion: number;
    cacheKey?: string;
  }): Promise<void>;
  unwrapShareDek(params: {
    encryptedKeyRefs?: string[];
    dekEncryptionKey?: Uint8Array;
    shareSlug?: string;
    candidateShareSlugs?: string[];
    shareId: string;
    documentId: string;
    keyVersion: number;
    cacheKey?: string;
  }): Promise<void>;
  fetchShareDocumentBootstrap(params: {
    documentToken: string;
    authenticatedWorkspacePinBootstrapHash: string;
  }): Promise<Record<string, unknown> & ShareCanonicalBootstrapFields & ShareBootstrapKeyRef>;
  fetchShareFolderBootstrap(params: {
    folderToken: string;
    authenticatedWorkspacePinBootstrapHash: string;
  }): Promise<Record<string, unknown> & ShareCanonicalBootstrapFields>;
  fetchMountedShareDocumentBootstrap(params: {
    mountId: string;
    documentToken: string;
    authenticatedWorkspacePinBootstrapHash: string;
  }): Promise<Record<string, unknown>>;
  fetchMountedShareFolderBootstrap(params: {
    mountId: string;
    folderToken: string;
    authenticatedWorkspacePinBootstrapHash: string;
  }): Promise<Record<string, unknown>>;
  prepareManagedShareSecrets(params: {
    shareSlug?: string;
    shareUrl?: string;
    password?: string;
    salt?: string;
    kdfParams?: {
      algorithm: string;
      memory: number;
      iterations: number;
      parallelism: number;
      hash_length: number;
    };
  }): Promise<{
    shareSlug: string;
    shareUrlFragment: string;
    shareCapabilitySecretCommitment: string;
    passwordCapabilitySecretCommitment?: string;
    authKey?: string;
    authorizationPublicKeyMaterial: ShareCapabilitySigningPublicKeyMaterial;
    passwordFields?: {
      kdf_params: {
        algorithm: string;
        memory: number;
        iterations: number;
        parallelism: number;
        hash_length: number;
      };
      salt: string;
    };
  }>;
  wrapPreparedShareDek(params: {
    shareSlug: string;
    documentId: string;
    shareId: string;
    keyVersion?: number;
  }): Promise<{ encryptedDek: Uint8Array; nonce: Uint8Array }>;
  prepareOpenShareSecrets(params: { shareSlug: string; shareUrlFragment?: string }): Promise<void>;
  preparePasswordShareSecrets(params: {
    shareSlug: string;
    password: string;
    salt: string;
    kdfParams: { memory: number; iterations: number; parallelism: number };
    challenge: string;
    shareUrlFragment?: string;
  }): Promise<{
    response: string;
  }>;
  preparePasswordShareChallenge(params: {
    shareSlug: string;
    password?: string;
    salt?: string;
    kdfParams?: { memory: number; iterations: number; parallelism: number };
    challenge: string;
  }): Promise<{ response: string }>;
  restoreShareSecretsFromDsk(params: {
    shareSlug: string;
    principalId: string;
    deviceId: string;
  }): Promise<void>;
  hasShareDekEncryptionKey(shareSlug: string): Promise<boolean>;
  cloneShareDekEncryptionKey(sourceShareSlug: string, targetShareSlug: string): Promise<void>;
  clearShareSecrets(shareSlug?: string): Promise<void>;
  persistShareSecretsWithDsk(params: {
    shareSlug: string;
    principalId: string;
    deviceId: string;
  }): Promise<void>;
  persistMountedShareSecretsWithDsk(params: {
    sourceShareSlug: string;
    mountSessionKey: string;
    principalId: string;
    deviceId: string;
  }): Promise<void>;
  evictDek(documentId: string, keyVersion: number, cacheKey?: string): Promise<void>;
  encryptOfflineCache(params: {
    plaintext: Uint8Array;
    documentId: string;
    keyVersion: number;
  }): Promise<{ ciphertext: Uint8Array; nonce: Uint8Array }>;
  decryptOfflineCache(params: {
    ciphertext: Uint8Array;
    nonce: Uint8Array;
    documentId: string;
    keyVersion: number;
  }): Promise<Uint8Array>;
  encryptOfflinePending(params: {
    plaintext: Uint8Array;
    documentId: string;
    keyVersion: number;
  }): Promise<{ ciphertext: Uint8Array; nonce: Uint8Array }>;
  decryptOfflinePending(params: {
    ciphertext: Uint8Array;
    nonce: Uint8Array;
    documentId: string;
    keyVersion: number;
  }): Promise<Uint8Array>;
  storeDekForOffline(params: { documentId: string; keyVersion: number }): Promise<void>;
  restoreDekFromOffline(params: {
    documentId: string;
    keyVersion?: number;
    isActive?: boolean;
  }): Promise<{ restored: boolean; keyVersion?: number; cachedAt?: number }>;
  loadOfflineDekMetadata(documentId: string): Promise<{
    documentId: string;
    keyVersion: number;
    cachedAt: number;
  } | null>;
  deleteDekForOffline(documentId: string): Promise<void>;
}

export const dekWorkerClientMethods: DekWorkerClientMethods &
  ThisType<CryptoWorkerClientMethodContext> = {
  async generateDek(documentId, workspaceId, dekKeyVersion, setActive) {
    return (await this[workerSend]("generate-dek", {
      documentId,
      workspaceId,
      dekKeyVersion,
      setActive,
    })) as {
      encryptedDek: Uint8Array;
      nonce: Uint8Array;
      keyVersion: number;
    };
  },

  async wrapDek(params) {
    return (await this[workerSend]("wrap-dek", params)) as {
      encryptedDek: Uint8Array;
      nonce: Uint8Array;
    };
  },

  async wrapDekForShare(params) {
    return (await this[workerSend]("wrap-dek-for-share", params)) as {
      encryptedDek: Uint8Array;
      nonce: Uint8Array;
    };
  },

  async unwrapDek(params) {
    await this[workerSend]("unwrap-dek", params);
  },

  async encryptTitle(params) {
    return (await this[workerSend]("encrypt-title", params)) as {
      encrypted: Uint8Array;
      nonce: Uint8Array;
    };
  },

  async decryptTitle(params) {
    const result = (await this[workerSend]("decrypt-title", params)) as { title: string };
    return result.title;
  },

  async decryptTitleBatch(items) {
    return (await this[workerSend]("decrypt-title-batch", { items })) as TitleDecryptResult[];
  },

  async encryptContent(params) {
    return (await this[workerSend]("encrypt-content", params)) as {
      ciphertext: Uint8Array;
      nonce: Uint8Array;
    };
  },

  async decryptContent(params) {
    const result = (await this[workerSend]("decrypt-content", params)) as { plaintext: Uint8Array };
    return result.plaintext;
  },

  async encryptSnapshot(params) {
    return (await this[workerSend]("encrypt-snapshot", params)) as {
      ciphertext: Uint8Array;
      nonce: Uint8Array;
    };
  },

  async decryptSnapshot(params) {
    const result = (await this[workerSend]("decrypt-snapshot", params)) as {
      plaintext: Uint8Array;
    };
    return result.plaintext;
  },

  async hasDek(documentId, keyVersion, cacheKey) {
    const requestId = crypto.randomUUID();
    const response = (await this[workerSend]("has-dek-batch", {
      items: [{ requestId, documentId, keyVersion, cacheKey }],
    })) as { results: Array<{ requestId: string; hasDek: boolean }> };
    return response.results[0]?.hasDek ?? false;
  },

  async hasDekBatch(items) {
    if (items.length === 0) return [];
    const HAS_DEK_BATCH_MAX_SIZE = 500;
    const results: Array<{ requestId: string; hasDek: boolean }> = [];
    for (let i = 0; i < items.length; i += HAS_DEK_BATCH_MAX_SIZE) {
      const chunk = items.slice(i, i + HAS_DEK_BATCH_MAX_SIZE);
      const response = (await this[workerSend]("has-dek-batch", { items: chunk })) as {
        results: Array<{ requestId: string; hasDek: boolean }>;
      };
      results.push(...response.results);
    }
    return results;
  },

  async cacheDek(params) {
    await this[workerSend]("cache-dek", params);
  },

  async unwrapShareDek(params) {
    await this[workerSend]("unwrap-share-dek", params);
  },

  async fetchShareDocumentBootstrap(params) {
    const path = `/api/shares/d/${encodeURIComponent(params.documentToken)}/bootstrap`;
    const body = {
      authenticated_workspace_pin_bootstrap_hash: params.authenticatedWorkspacePinBootstrapHash,
    };
    return (await this[workerSend]("fetch-share-document-bootstrap", {
      ...params,
      authHeaders: await bootstrapAuthHeaders(path, body, "share"),
    })) as Record<string, unknown> & ShareCanonicalBootstrapFields & ShareBootstrapKeyRef;
  },

  async fetchShareFolderBootstrap(params) {
    const path = `/api/shares/f/${encodeURIComponent(params.folderToken)}/bootstrap`;
    const body = {
      authenticated_workspace_pin_bootstrap_hash: params.authenticatedWorkspacePinBootstrapHash,
    };
    return (await this[workerSend]("fetch-share-folder-bootstrap", {
      ...params,
      authHeaders: await bootstrapAuthHeaders(path, body, "share"),
    })) as Record<string, unknown> & ShareCanonicalBootstrapFields;
  },

  async fetchMountedShareDocumentBootstrap(params) {
    const path = `/api/mounts/${encodeURIComponent(params.mountId)}/documents/${encodeURIComponent(
      params.documentToken,
    )}/bootstrap`;
    const body = {
      authenticated_workspace_pin_bootstrap_hash: params.authenticatedWorkspacePinBootstrapHash,
    };
    return (await this[workerSend]("fetch-mounted-share-document-bootstrap", {
      ...params,
      authHeaders: await bootstrapAuthHeaders(path, body, "user-pop"),
    })) as Record<string, unknown>;
  },

  async fetchMountedShareFolderBootstrap(params) {
    const path = `/api/mounts/${encodeURIComponent(params.mountId)}/folders/${encodeURIComponent(
      params.folderToken,
    )}/bootstrap`;
    const body = {
      authenticated_workspace_pin_bootstrap_hash: params.authenticatedWorkspacePinBootstrapHash,
    };
    return (await this[workerSend]("fetch-mounted-share-folder-bootstrap", {
      ...params,
      authHeaders: await bootstrapAuthHeaders(path, body, "user-pop"),
    })) as Record<string, unknown>;
  },

  async prepareManagedShareSecrets(params) {
    return (await this[workerSend]("prepare-managed-share-secrets", params)) as {
      shareSlug: string;
      shareUrlFragment: string;
      shareCapabilitySecretCommitment: string;
      passwordCapabilitySecretCommitment?: string;
      authKey?: string;
      authorizationPublicKeyMaterial: ShareCapabilitySigningPublicKeyMaterial;
      passwordFields?: {
        kdf_params: {
          algorithm: string;
          memory: number;
          iterations: number;
          parallelism: number;
          hash_length: number;
        };
        salt: string;
      };
    };
  },

  async wrapPreparedShareDek(params) {
    return (await this[workerSend]("wrap-prepared-share-dek", params)) as {
      encryptedDek: Uint8Array;
      nonce: Uint8Array;
    };
  },

  async prepareOpenShareSecrets(params) {
    await this[workerSend]("prepare-open-share-secrets", params);
  },

  async preparePasswordShareSecrets(params) {
    return (await this[workerSend]("prepare-password-share-secrets", params)) as {
      response: string;
    };
  },

  async preparePasswordShareChallenge(params) {
    return (await this[workerSend]("prepare-password-share-challenge", params)) as {
      response: string;
    };
  },

  async restoreShareSecretsFromDsk(params) {
    await this[workerSend]("restore-share-secrets-from-dsk", params);
  },

  async hasShareDekEncryptionKey(shareSlug) {
    const result = (await this[workerSend]("has-share-dek-encryption-key", { shareSlug })) as {
      available: boolean;
    };
    return result.available;
  },

  async cloneShareDekEncryptionKey(sourceShareSlug, targetShareSlug) {
    await this[workerSend]("clone-share-dek-encryption-key", { sourceShareSlug, targetShareSlug });
  },

  async clearShareSecrets(shareSlug) {
    await this[workerSend]("clear-share-secrets", { shareSlug });
  },

  async persistShareSecretsWithDsk(params) {
    await this[workerSend]("persist-share-secrets-with-dsk", params);
  },

  async persistMountedShareSecretsWithDsk(params) {
    await this[workerSend]("persist-mounted-share-secrets-with-dsk", params);
  },

  async evictDek(documentId, keyVersion, cacheKey) {
    await this[workerSend]("evict-dek", { documentId, keyVersion, cacheKey });
  },

  async encryptOfflineCache(params) {
    return (await this[workerSend]("encrypt-offline-cache", params)) as {
      ciphertext: Uint8Array;
      nonce: Uint8Array;
    };
  },

  async decryptOfflineCache(params) {
    const result = (await this[workerSend]("decrypt-offline-cache", params)) as {
      plaintext: Uint8Array;
    };
    return result.plaintext;
  },

  async encryptOfflinePending(params) {
    return (await this[workerSend]("encrypt-offline-pending", params)) as {
      ciphertext: Uint8Array;
      nonce: Uint8Array;
    };
  },

  async decryptOfflinePending(params) {
    const result = (await this[workerSend]("decrypt-offline-pending", params)) as {
      plaintext: Uint8Array;
    };
    return result.plaintext;
  },

  async storeDekForOffline(params) {
    await this[workerSend]("store-dek-for-offline", params);
  },

  async restoreDekFromOffline(params) {
    return (await this[workerSend]("restore-dek-from-offline", params)) as {
      restored: boolean;
      keyVersion?: number;
      cachedAt?: number;
    };
  },

  async loadOfflineDekMetadata(documentId) {
    const result = (await this[workerSend]("load-offline-dek-metadata", { documentId })) as {
      metadata: { documentId: string; keyVersion: number; cachedAt: number } | null;
    };
    return result.metadata;
  },

  async deleteDekForOffline(documentId) {
    await this[workerSend]("delete-dek-for-offline", { documentId });
  },
};

async function bootstrapAuthHeaders(
  path: string,
  body: Record<string, unknown>,
  scope: BootstrapAuthScope,
): Promise<Record<string, string>> {
  if (scope === "share") {
    return { [SHARE_SESSION_SCOPE_HEADER]: "share" };
  }

  const { getPopHeaders } = await import("@/shared/lib/auth/pop");
  const canonicalQuery = canonicalQueryString("");
  const bodyHash = blake3Base64Url(new TextEncoder().encode(JSON.stringify(body)));
  const headers = await getPopHeaders(undefined, undefined, "user", undefined, {
    body_hash: bodyHash,
    canonical_query: canonicalQuery,
    method: "POST",
    path,
    query_hash: blake3Base64Url(new TextEncoder().encode(canonicalQuery)),
  });
  return headers as unknown as Record<string, string>;
}
