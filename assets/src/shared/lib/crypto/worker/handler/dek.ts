import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import { blake3 } from "@noble/hashes/blake3.js";
import type { TitleDecryptItem, TitleDecryptResult } from "../types";
import type { WorkerKeyState } from "../state";
import { evictCachedDek, getCachedDek, setActiveDekVersion, setCachedDek } from "../state";
import { base64UrlDecode, base64UrlEncode, randomBytes } from "../../encoding";
import {
  buildDocumentContentAad,
  buildDskShareParticipantAuthorizationSecretAad,
  buildOfflineDekCacheAad,
  buildOfflineDocumentCacheAad,
  buildOfflinePendingChangesAad,
  buildPluginStorageAad,
} from "../../aad";
import { decryptTitle, encryptTitle, generateDek, unwrapDek, wrapDek } from "../../dek";
import {
  deriveOpenShareAdmissionKey,
  deriveOpenShareDekEncryptionKey,
  derivePasswordShareAdmissionKey,
  derivePasswordShareDekEncryptionKey,
  unwrapShareDek,
  wrapShareDek,
} from "../../share-dek";
import { deriveAuthKeys } from "../../kdf";
import {
  deriveShareCapabilitySigningPrivateKeyMaterial,
  shareCapabilityPublicKeyMaterialFromPrivate,
} from "../../signature";
import {
  dskDecrypt,
  dskEncrypt,
  type HandlerPayload,
  requireDekForDocument,
  requireDsk,
  requireKekForWorkspace,
} from "./utils";
import {
  deleteDskStoreValueInWorker,
  loadDskStoreValueInWorker,
  storeDskStoreValueInWorker,
} from "./dsk-idb";

const SHARE_SECRET_KEY_PREFIX = "share-secret";
const OFFLINE_DEK_KEY_PREFIX = "refmd-offline-key:dek:";

type OfflineDekStoredEntry = {
  ciphertext: ArrayBuffer;
  iv: ArrayBuffer;
  keyVersion: number;
  cachedAt: number;
};

function shareSecretKey(
  shareSlug: string,
  principalId: string,
  deviceId: string,
  kind: "authorization" | "capability" | "password-auth" | "password-capability",
): string {
  return [SHARE_SECRET_KEY_PREFIX, shareSlug, principalId, deviceId, kind].join(":");
}

export function handleGenerateDek(state: WorkerKeyState, p: HandlerPayload): unknown {
  const documentId = p.documentId as string;
  const cacheKey = (p.cacheKey as string | undefined) ?? documentId;
  const workspaceId = p.workspaceId as string;
  const setActive = (p.setActive as boolean) !== false;
  const { kek, keyVersion: kekVersion } = requireKekForWorkspace(state, workspaceId);

  const dek = generateDek();
  const dekKeyVersion = (p.dekKeyVersion as number) ?? 1;
  setCachedDek(state, cacheKey, dek, dekKeyVersion);
  if (setActive) {
    setActiveDekVersion(state, cacheKey, dekKeyVersion);
  }

  const { encryptedDek, nonce } = wrapDek(dek, kek, documentId, workspaceId);
  return { encryptedDek, nonce, keyVersion: kekVersion };
}

export function handleWrapDek(state: WorkerKeyState, p: HandlerPayload): unknown {
  const documentId = p.documentId as string;
  const cacheKey = (p.cacheKey as string | undefined) ?? documentId;
  const workspaceId = p.workspaceId as string;
  const keyVersion = p.keyVersion as number | undefined;
  const { dek } = requireDekForDocument(state, documentId, keyVersion, cacheKey);
  const { kek } = requireKekForWorkspace(state, workspaceId);

  const { encryptedDek, nonce } = wrapDek(dek, kek, documentId, workspaceId);
  return { encryptedDek, nonce };
}

export function handleWrapDekForShare(state: WorkerKeyState, p: HandlerPayload): unknown {
  const documentId = p.documentId as string;
  const shareId = p.shareId as string;
  const keyVersion = p.keyVersion as number | undefined;
  const shareDekEncryptionKey = p.shareDekEncryptionKey as Uint8Array;
  const { dek } = requireDekForDocument(state, documentId, keyVersion);

  if (!(shareDekEncryptionKey instanceof Uint8Array) || shareDekEncryptionKey.length !== 32) {
    throw new Error("share_dek_encryption_key_required");
  }

  return wrapShareDek({ dek, dekEncryptionKey: shareDekEncryptionKey, shareId, documentId });
}

export function handleUnwrapDek(state: WorkerKeyState, p: HandlerPayload): unknown {
  const encryptedDek = p.encryptedDek as Uint8Array;
  const nonce = p.nonce as Uint8Array;
  const documentId = p.documentId as string;
  const cacheKey = (p.cacheKey as string | undefined) ?? documentId;
  const workspaceId = p.workspaceId as string;
  const keyVersion = p.keyVersion as number;
  const isActive = p.isActive as boolean | undefined;
  const kekVersion = p.kekVersion as number | undefined;
  const { kek } = requireKekForWorkspace(state, workspaceId, kekVersion);

  const dek = unwrapDek(encryptedDek, nonce, kek, documentId, workspaceId);
  setCachedDek(state, cacheKey, dek, keyVersion);
  if (isActive) {
    setActiveDekVersion(state, cacheKey, keyVersion);
  }
  return { status: "ok" };
}

export function handleUnwrapShareDek(state: WorkerKeyState, p: HandlerPayload): unknown {
  const shareId = p.shareId as string;
  const documentId = p.documentId as string;
  const keyVersion = p.keyVersion as number;
  const cacheKey = (p.cacheKey as string | undefined) ?? documentId;
  const encryptedKeyRefs = Array.isArray(p.encryptedKeyRefs)
    ? (p.encryptedKeyRefs as unknown[]).filter(
        (value): value is string => typeof value === "string",
      )
    : [];
  const storedKeyRefs = encryptedKeyRefs
    .map((ref) => state.shareKeyRefs.get(ref))
    .filter(
      (entry): entry is NonNullable<typeof entry> =>
        !!entry &&
        entry.shareId === shareId &&
        entry.documentId === documentId &&
        entry.keyVersion === keyVersion,
    );
  const encryptedDek = storedKeyRefs[0]?.encryptedDek;
  const nonce = storedKeyRefs[0]?.nonce;
  const candidateSlugs = Array.isArray(p.candidateShareSlugs)
    ? (p.candidateShareSlugs as unknown[]).filter(
        (value): value is string => typeof value === "string",
      )
    : [p.shareSlug].filter((value): value is string => typeof value === "string");
  const explicitDekEncryptionKey = p.dekEncryptionKey as Uint8Array | undefined;
  const candidates =
    explicitDekEncryptionKey instanceof Uint8Array
      ? [explicitDekEncryptionKey]
      : candidateSlugs
          .map((slug) => state.shareSecrets.get(slug)?.dekEncryptionKey)
          .filter((value): value is Uint8Array => value instanceof Uint8Array);

  if (candidates.length === 0) {
    throw new Error("share_dek_encryption_key_required");
  }
  if (!(encryptedDek instanceof Uint8Array) || !(nonce instanceof Uint8Array)) {
    throw new Error("share_key_ref_unavailable");
  }

  for (const dekEncryptionKey of candidates) {
    if (dekEncryptionKey.length !== 32) continue;
    try {
      const dek = unwrapShareDek({
        encryptedDek,
        nonce,
        dekEncryptionKey,
        shareId,
        documentId,
      });
      setCachedDek(state, cacheKey, dek, keyVersion);
      return { status: "ok" };
    } catch {
      // Try the next stored candidate.
    }
  }

  throw new Error("share_dek_unwrap_failed");
}

export async function handleFetchShareDocumentBootstrap(
  state: WorkerKeyState,
  p: HandlerPayload,
): Promise<unknown> {
  const documentToken = p.documentToken as string;
  const hash = p.authenticatedWorkspacePinBootstrapHash as string;
  const response = await fetchBootstrapJson(
    `/api/shares/d/${encodeURIComponent(documentToken)}/bootstrap`,
    {
      authenticated_workspace_pin_bootstrap_hash: hash,
    },
    p.authHeaders,
  );

  if (isBootstrapRequired(response)) return response;
  return attachEncryptedKeyRefs(state, response);
}

export async function handleFetchShareFolderBootstrap(
  state: WorkerKeyState,
  p: HandlerPayload,
): Promise<unknown> {
  const folderToken = p.folderToken as string;
  const hash = p.authenticatedWorkspacePinBootstrapHash as string;
  const response = await fetchBootstrapJson(
    `/api/shares/f/${encodeURIComponent(folderToken)}/bootstrap`,
    {
      authenticated_workspace_pin_bootstrap_hash: hash,
    },
    p.authHeaders,
  );

  if (isBootstrapRequired(response)) return response;
  return {
    ...response,
    folder: attachEncryptedKeyRefs(state, assertRecord(response.folder, "share_folder_invalid")),
    entries: assertArray(response.entries, "share_entries_invalid").map((entry) =>
      attachEncryptedKeyRefs(state, assertRecord(entry, "share_entry_invalid")),
    ),
  };
}

export async function handleFetchMountedShareDocumentBootstrap(
  state: WorkerKeyState,
  p: HandlerPayload,
): Promise<unknown> {
  const mountId = p.mountId as string;
  const documentToken = p.documentToken as string;
  const response = await fetchBootstrapJson(
    `/api/mounts/${encodeURIComponent(mountId)}/documents/${encodeURIComponent(documentToken)}/bootstrap`,
    {
      authenticated_workspace_pin_bootstrap_hash:
        p.authenticatedWorkspacePinBootstrapHash as string,
    },
    p.authHeaders,
  );

  return {
    ...response,
    document: attachEncryptedKeyRefs(
      state,
      assertRecord(response.document, "mounted_document_invalid"),
    ),
  };
}

export async function handleFetchMountedShareFolderBootstrap(
  state: WorkerKeyState,
  p: HandlerPayload,
): Promise<unknown> {
  const mountId = p.mountId as string;
  const folderToken = p.folderToken as string;
  const response = await fetchBootstrapJson(
    `/api/mounts/${encodeURIComponent(mountId)}/folders/${encodeURIComponent(folderToken)}/bootstrap`,
    {
      authenticated_workspace_pin_bootstrap_hash:
        p.authenticatedWorkspacePinBootstrapHash as string,
    },
    p.authHeaders,
  );

  return {
    ...response,
    folder: attachEncryptedKeyRefs(state, assertRecord(response.folder, "mounted_folder_invalid")),
    entries: assertArray(response.entries, "mounted_entries_invalid").map((entry) =>
      attachEncryptedKeyRefs(state, assertRecord(entry, "mounted_entry_invalid")),
    ),
  };
}

async function fetchBootstrapJson(
  path: string,
  body: Record<string, unknown>,
  authHeaders: unknown,
): Promise<Record<string, unknown>> {
  const response = await fetch(path, {
    method: "POST",
    credentials: "same-origin",
    headers: {
      ...stringHeaders(authHeaders),
      "content-type": "application/json",
      "x-refmd-crypto-worker": "1",
    },
    body: JSON.stringify(body),
  });
  const payload = (await response.json()) as unknown;
  if (!response.ok) {
    const error = assertRecord(payload, "share_bootstrap_failed").error;
    throw new Error(typeof error === "string" ? error : "share_bootstrap_failed");
  }
  return assertRecord(payload, "share_bootstrap_invalid");
}

function stringHeaders(value: unknown): Record<string, string> {
  if (!value || typeof value !== "object" || Array.isArray(value)) return {};
  return Object.fromEntries(
    Object.entries(value as Record<string, unknown>).filter(
      (entry): entry is [string, string] => typeof entry[1] === "string",
    ),
  );
}

function isBootstrapRequired(response: Record<string, unknown>): boolean {
  return response.bootstrap_required === true;
}

function attachEncryptedKeyRefs(
  state: WorkerKeyState,
  entry: Record<string, unknown>,
): Record<string, unknown> {
  const encryptedDek = base64UrlDecode(assertString(entry.encrypted_dek, "encrypted_dek_invalid"));
  const nonce = base64UrlDecode(assertString(entry.nonce, "nonce_invalid"));
  const shareId = assertString(entry.share_id, "share_id_invalid");
  const documentId = assertString(entry.document_id ?? entry.id, "document_id_invalid");
  const keyVersion = assertNumber(entry.key_version, "key_version_invalid");
  const ref = `share-key-ref:${crypto.randomUUID()}`;
  state.shareKeyRefs.set(ref, {
    encryptedDek,
    nonce,
    shareId,
    documentId,
    keyVersion,
  });
  const { encrypted_dek: _encryptedDek, nonce: _nonce, ...publicEntry } = entry;
  return { ...publicEntry, encrypted_key_refs: [ref] };
}

function assertRecord(value: unknown, code: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(code);
  return value as Record<string, unknown>;
}

function assertArray(value: unknown, code: string): unknown[] {
  if (!Array.isArray(value)) throw new Error(code);
  return value;
}

function assertString(value: unknown, code: string): string {
  if (typeof value !== "string" || value.length === 0) throw new Error(code);
  return value;
}

function assertNumber(value: unknown, code: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value)) throw new Error(code);
  return value;
}

export async function handlePrepareManagedShareSecrets(
  state: WorkerKeyState,
  p: HandlerPayload,
): Promise<unknown> {
  const { shareSlug, capabilitySecret, shareUrlFragment } = resolveManagedShareCapability(p);
  const password = (p.password as string | undefined)?.trim() ?? "";

  if (!shareSlug) throw new Error("share_slug_required");

  if (password) {
    const salt = p.salt as string;
    const kdfParams = p.kdfParams as {
      algorithm: string;
      memory: number;
      iterations: number;
      parallelism: number;
      hash_length: number;
    };
    const derived = await deriveAuthKeys(password, salt, {
      algorithm: "argon2id",
      memory: kdfParams.memory,
      iterations: kdfParams.iterations,
      parallelism: kdfParams.parallelism,
      hash_length: 32,
    });
    const authKey = base64UrlDecode(derived.shareAuthKeyBase64);
    const passwordCapabilitySecret = base64UrlDecode(derived.passwordCapabilitySecretBase64);
    const authorizationSecret = derivePasswordShareAdmissionKey(
      passwordCapabilitySecret,
      capabilitySecret,
    );
    const dekEncryptionKey = derivePasswordShareDekEncryptionKey(
      passwordCapabilitySecret,
      capabilitySecret,
    );
    const shareTokenHash = base64UrlEncode(blake3(base64UrlDecode(shareSlug)));
    const capabilityPrivateKeyMaterial = deriveShareCapabilitySigningPrivateKeyMaterial(
      capabilitySecret,
      shareTokenHash,
    );
    const shareCapabilitySecretCommitment = base64UrlEncode(blake3(capabilitySecret));
    const passwordCapabilitySecretCommitment = base64UrlEncode(blake3(passwordCapabilitySecret));

    const authKeyBase64 = base64UrlEncode(authKey);

    upsertShareSecrets(state, shareSlug, {
      authorizationSecret,
      passwordChallengeAuthKey: authKey,
      dekEncryptionKey,
      capabilitySecret,
      passwordCapabilitySecret,
    });

    derived.puk.fill(0);
    authorizationSecret.fill(0);
    authKey.fill(0);
    passwordCapabilitySecret.fill(0);
    dekEncryptionKey.fill(0);
    capabilitySecret.fill(0);

    return {
      shareSlug,
      shareUrlFragment,
      shareCapabilitySecretCommitment,
      passwordCapabilitySecretCommitment,
      authKey: authKeyBase64,
      authorizationPublicKeyMaterial: shareCapabilityPublicKeyMaterialFromPrivate(
        capabilityPrivateKeyMaterial,
      ),
      passwordFields: {
        kdf_params: {
          algorithm: kdfParams.algorithm,
          memory: kdfParams.memory,
          iterations: kdfParams.iterations,
          parallelism: kdfParams.parallelism,
          hash_length: kdfParams.hash_length,
        },
        salt,
      },
    };
  }

  const authorizationSecret = deriveOpenShareAdmissionKey(capabilitySecret);
  const dekEncryptionKey = deriveOpenShareDekEncryptionKey(capabilitySecret);
  const shareTokenHash = base64UrlEncode(blake3(base64UrlDecode(shareSlug)));
  const capabilityPrivateKeyMaterial = deriveShareCapabilitySigningPrivateKeyMaterial(
    capabilitySecret,
    shareTokenHash,
  );
  const shareCapabilitySecretCommitment = base64UrlEncode(blake3(capabilitySecret));
  upsertShareSecrets(state, shareSlug, {
    authorizationSecret,
    dekEncryptionKey,
    capabilitySecret,
  });
  authorizationSecret.fill(0);
  dekEncryptionKey.fill(0);
  capabilitySecret.fill(0);

  return {
    shareSlug,
    shareUrlFragment,
    shareCapabilitySecretCommitment,
    authorizationPublicKeyMaterial: shareCapabilityPublicKeyMaterialFromPrivate(
      capabilityPrivateKeyMaterial,
    ),
  };
}

function resolveManagedShareCapability(p: HandlerPayload): {
  shareSlug: string;
  capabilitySecret: Uint8Array;
  shareUrlFragment: string;
} {
  if (typeof p.shareUrl === "string") {
    const url = new URL(p.shareUrl, self.location.origin);
    const match = url.pathname.match(/^\/share\/([A-Za-z0-9_-]{22})$/);
    const shareSlug = match?.[1];
    const cap = new URLSearchParams(url.hash.startsWith("#") ? url.hash.slice(1) : url.hash).get(
      "cap",
    );
    if (!shareSlug || !cap) throw new Error("share_capability_secret_required");
    const capabilitySecret = base64UrlDecode(cap);
    if (capabilitySecret.length !== 32) throw new Error("share_capability_secret_required");
    return { shareSlug, capabilitySecret, shareUrlFragment: `cap=${cap}` };
  }

  const shareSlug = p.shareSlug as string;
  const cap = base64UrlEncode(randomBytes(32));
  const capabilitySecret = base64UrlDecode(cap);
  if (capabilitySecret.length !== 32) throw new Error("share_capability_secret_required");
  return { shareSlug, capabilitySecret, shareUrlFragment: `cap=${cap}` };
}

function decodeShareCapabilitySecretFromFragment(shareUrlFragment: string): Uint8Array {
  const fragment = shareUrlFragment.startsWith("#") ? shareUrlFragment.slice(1) : shareUrlFragment;
  const cap = new URLSearchParams(fragment).get("cap");
  if (!cap) throw new Error("share_capability_secret_required");
  const capabilitySecret = base64UrlDecode(cap);
  if (capabilitySecret.length !== 32) throw new Error("share_capability_secret_required");
  return capabilitySecret;
}

export function handleWrapPreparedShareDek(state: WorkerKeyState, p: HandlerPayload): unknown {
  const shareSlug = p.shareSlug as string;
  const documentId = p.documentId as string;
  const shareId = p.shareId as string;
  const keyVersion = p.keyVersion as number | undefined;
  const { dek } = requireDekForDocument(state, documentId, keyVersion);
  const shareDekEncryptionKey = state.shareSecrets.get(shareSlug)?.dekEncryptionKey;
  if (!shareDekEncryptionKey) throw new Error("share_dek_encryption_key_required");
  return wrapShareDek({ dek, dekEncryptionKey: shareDekEncryptionKey, shareId, documentId });
}

function upsertShareSecrets(
  state: WorkerKeyState,
  shareSlug: string,
  secrets: {
    authorizationSecret?: Uint8Array;
    passwordChallengeAuthKey?: Uint8Array;
    dekEncryptionKey?: Uint8Array;
    capabilitySecret?: Uint8Array;
    passwordCapabilitySecret?: Uint8Array;
  },
): void {
  const current = state.shareSecrets.get(shareSlug) ?? {};
  if (secrets.authorizationSecret) {
    current.authorizationSecret?.fill(0);
    current.authorizationSecret = new Uint8Array(secrets.authorizationSecret);
  }
  if (secrets.passwordChallengeAuthKey) {
    current.passwordChallengeAuthKey?.fill(0);
    current.passwordChallengeAuthKey = new Uint8Array(secrets.passwordChallengeAuthKey);
  }
  if (secrets.dekEncryptionKey) {
    current.dekEncryptionKey?.fill(0);
    current.dekEncryptionKey = new Uint8Array(secrets.dekEncryptionKey);
  }
  if (secrets.capabilitySecret) {
    current.capabilitySecret?.fill(0);
    current.capabilitySecret = new Uint8Array(secrets.capabilitySecret);
  }
  if (secrets.passwordCapabilitySecret) {
    current.passwordCapabilitySecret?.fill(0);
    current.passwordCapabilitySecret = new Uint8Array(secrets.passwordCapabilitySecret);
  }
  state.shareSecrets.set(shareSlug, current);
}

function deriveShareDekEncryptionKeyFromStoredSecrets(
  capabilitySecret: Uint8Array,
  passwordCapabilitySecret?: Uint8Array,
): Uint8Array {
  return passwordCapabilitySecret
    ? derivePasswordShareDekEncryptionKey(passwordCapabilitySecret, capabilitySecret)
    : deriveOpenShareDekEncryptionKey(capabilitySecret);
}

export function handlePrepareOpenShareSecrets(state: WorkerKeyState, p: HandlerPayload): unknown {
  const shareSlug = p.shareSlug as string;
  const capabilitySecret = p.shareUrlFragment
    ? decodeShareCapabilitySecretFromFragment(p.shareUrlFragment as string)
    : state.shareSecrets.get(shareSlug)?.capabilitySecret;
  if (!capabilitySecret) throw new Error("share_capability_secret_required");
  const authorizationSecret = deriveOpenShareAdmissionKey(capabilitySecret);
  const dekEncryptionKey = deriveOpenShareDekEncryptionKey(capabilitySecret);
  upsertShareSecrets(state, shareSlug, {
    authorizationSecret,
    dekEncryptionKey,
    capabilitySecret,
  });
  authorizationSecret.fill(0);
  dekEncryptionKey.fill(0);
  capabilitySecret.fill(0);
  return {};
}

export async function handlePreparePasswordShareSecrets(
  state: WorkerKeyState,
  p: HandlerPayload,
): Promise<unknown> {
  const shareSlug = p.shareSlug as string;
  const derived = await deriveAuthKeys(p.password as string, p.salt as string, {
    algorithm: "argon2id",
    memory: (p.kdfParams as { memory: number }).memory,
    iterations: (p.kdfParams as { iterations: number }).iterations,
    parallelism: (p.kdfParams as { parallelism: number }).parallelism,
    hash_length: 32,
  });
  const authKey = base64UrlDecode(derived.shareAuthKeyBase64);
  const challengeBytes = base64UrlDecode(p.challenge as string);
  const hmacKeyBytes = new Uint8Array(authKey.length);
  hmacKeyBytes.set(authKey);
  const hmacChallengeBytes = new Uint8Array(challengeBytes.length);
  hmacChallengeBytes.set(challengeBytes);
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    hmacKeyBytes,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const response = base64UrlEncode(
    new Uint8Array(await crypto.subtle.sign("HMAC", cryptoKey, hmacChallengeBytes)),
  );
  const capabilitySecret = p.shareUrlFragment
    ? decodeShareCapabilitySecretFromFragment(p.shareUrlFragment as string)
    : state.shareSecrets.get(shareSlug)?.capabilitySecret;
  if (!capabilitySecret) throw new Error("share_capability_secret_required");
  const passwordCapabilitySecret = base64UrlDecode(derived.passwordCapabilitySecretBase64);
  const authorizationSecret = derivePasswordShareAdmissionKey(
    passwordCapabilitySecret,
    capabilitySecret,
  );
  const dekEncryptionKey = derivePasswordShareDekEncryptionKey(
    passwordCapabilitySecret,
    capabilitySecret,
  );
  upsertShareSecrets(state, shareSlug, {
    authorizationSecret,
    passwordChallengeAuthKey: authKey,
    dekEncryptionKey,
    capabilitySecret,
    passwordCapabilitySecret,
  });
  derived.puk.fill(0);
  authorizationSecret.fill(0);
  authKey.fill(0);
  passwordCapabilitySecret.fill(0);
  dekEncryptionKey.fill(0);
  capabilitySecret.fill(0);
  return { response };
}

export async function handlePreparePasswordShareChallenge(
  state: WorkerKeyState,
  p: HandlerPayload,
): Promise<unknown> {
  const shareSlug = p.shareSlug as string;
  const challengeBytes = base64UrlDecode(p.challenge as string);
  const authKey = await passwordChallengeAuthKey(state, p, shareSlug);
  const hmacKeyBytes = new Uint8Array(authKey.length);
  hmacKeyBytes.set(authKey);
  const hmacChallengeBytes = new Uint8Array(challengeBytes.length);
  hmacChallengeBytes.set(challengeBytes);
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    hmacKeyBytes,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const response = base64UrlEncode(
    new Uint8Array(await crypto.subtle.sign("HMAC", cryptoKey, hmacChallengeBytes)),
  );
  authKey.fill(0);
  return { response };
}

async function passwordChallengeAuthKey(
  state: WorkerKeyState,
  p: HandlerPayload,
  shareSlug: string,
): Promise<Uint8Array> {
  if (typeof p.password !== "string") {
    const authKey = state.shareSecrets.get(shareSlug)?.passwordChallengeAuthKey;
    if (!authKey) throw new Error("password_admission_secret_unavailable");
    return new Uint8Array(authKey);
  }

  const derived = await deriveAuthKeys(p.password, p.salt as string, {
    algorithm: "argon2id",
    memory: (p.kdfParams as { memory: number }).memory,
    iterations: (p.kdfParams as { iterations: number }).iterations,
    parallelism: (p.kdfParams as { parallelism: number }).parallelism,
    hash_length: 32,
  });
  const authKey = base64UrlDecode(derived.shareAuthKeyBase64);
  const passwordCapabilitySecret = base64UrlDecode(derived.passwordCapabilitySecretBase64);
  const capabilitySecret = state.shareSecrets.get(shareSlug)?.capabilitySecret;
  if (!capabilitySecret) throw new Error("share_capability_secret_required");
  const authorizationSecret = derivePasswordShareAdmissionKey(
    passwordCapabilitySecret,
    capabilitySecret,
  );
  const dekEncryptionKey = derivePasswordShareDekEncryptionKey(
    passwordCapabilitySecret,
    capabilitySecret,
  );
  upsertShareSecrets(state, shareSlug, {
    authorizationSecret,
    passwordChallengeAuthKey: authKey,
    dekEncryptionKey,
    passwordCapabilitySecret,
  });
  derived.puk.fill(0);
  authorizationSecret.fill(0);
  passwordCapabilitySecret.fill(0);
  dekEncryptionKey.fill(0);
  return authKey;
}

export async function handleRestoreShareSecretsFromDsk(
  state: WorkerKeyState,
  p: HandlerPayload,
): Promise<unknown> {
  const dsk = requireDsk(state);
  const shareSlug = p.shareSlug as string;
  const principalId = p.principalId as string;
  const deviceId = p.deviceId as string;
  const wrappedAuth = await loadDskStoreValueInWorker<{ ciphertext: ArrayBuffer; iv: ArrayBuffer }>(
    shareSecretKey(shareSlug, principalId, deviceId, "authorization"),
  );
  const wrappedCapability = await loadDskStoreValueInWorker<{
    ciphertext: ArrayBuffer;
    iv: ArrayBuffer;
  }>(shareSecretKey(shareSlug, principalId, deviceId, "capability"));
  const wrappedPasswordCapability = await loadDskStoreValueInWorker<{
    ciphertext: ArrayBuffer;
    iv: ArrayBuffer;
  }>(shareSecretKey(shareSlug, principalId, deviceId, "password-capability"));
  const wrappedPasswordAuth = await loadDskStoreValueInWorker<{
    ciphertext: ArrayBuffer;
    iv: ArrayBuffer;
  }>(shareSecretKey(shareSlug, principalId, deviceId, "password-auth"));
  if (!wrappedAuth || !wrappedCapability) throw new Error("share_secret_unavailable");
  const authorizationSecret = await dskDecrypt(
    dsk,
    wrappedAuth.ciphertext,
    wrappedAuth.iv,
    buildDskShareParticipantAuthorizationSecretAad(principalId, deviceId, shareSlug),
  );
  const capabilitySecret = await dskDecrypt(
    dsk,
    wrappedCapability.ciphertext,
    wrappedCapability.iv,
    new TextEncoder().encode(`RefMD:v2:share-capability-secret:${shareSlug}`),
  );
  const passwordCapabilitySecret = wrappedPasswordCapability
    ? await dskDecrypt(
        dsk,
        wrappedPasswordCapability.ciphertext,
        wrappedPasswordCapability.iv,
        new TextEncoder().encode(`RefMD:v2:share-password-capability-secret:${shareSlug}`),
      )
    : undefined;
  const passwordChallengeAuthKey = wrappedPasswordAuth
    ? await dskDecrypt(
        dsk,
        wrappedPasswordAuth.ciphertext,
        wrappedPasswordAuth.iv,
        new TextEncoder().encode(`RefMD:v2:share-password-auth-key:${shareSlug}`),
      )
    : undefined;
  const dekEncryptionKey = deriveShareDekEncryptionKeyFromStoredSecrets(
    capabilitySecret,
    passwordCapabilitySecret,
  );
  upsertShareSecrets(state, shareSlug, {
    authorizationSecret,
    passwordChallengeAuthKey,
    dekEncryptionKey,
    capabilitySecret,
    passwordCapabilitySecret,
  });
  authorizationSecret.fill(0);
  passwordChallengeAuthKey?.fill(0);
  dekEncryptionKey.fill(0);
  capabilitySecret?.fill(0);
  passwordCapabilitySecret?.fill(0);
  return { status: "ok" };
}

export function handleHasShareDekEncryptionKey(state: WorkerKeyState, p: HandlerPayload): unknown {
  return { available: !!state.shareSecrets.get(p.shareSlug as string)?.dekEncryptionKey };
}

export function handleCloneShareDekEncryptionKey(
  state: WorkerKeyState,
  p: HandlerPayload,
): unknown {
  const source = state.shareSecrets.get(p.sourceShareSlug as string);
  if (!source?.dekEncryptionKey) throw new Error("share_dek_encryption_key_required");
  upsertShareSecrets(state, p.targetShareSlug as string, {
    dekEncryptionKey: source.dekEncryptionKey,
  });
  return { status: "ok" };
}

export function handleClearShareSecrets(state: WorkerKeyState, p: HandlerPayload): unknown {
  const clearOne = (slug: string) => {
    const secret = state.shareSecrets.get(slug);
    secret?.authorizationSecret?.fill(0);
    secret?.passwordChallengeAuthKey?.fill(0);
    secret?.dekEncryptionKey?.fill(0);
    secret?.capabilitySecret?.fill(0);
    secret?.passwordCapabilitySecret?.fill(0);
    state.shareSecrets.delete(slug);
  };
  const shareSlug = p.shareSlug as string | undefined;
  if (shareSlug) clearOne(shareSlug);
  else for (const slug of Array.from(state.shareSecrets.keys())) clearOne(slug);
  return { status: "ok" };
}

export async function handlePersistShareSecretsWithDsk(
  state: WorkerKeyState,
  p: HandlerPayload,
): Promise<unknown> {
  const dsk = requireDsk(state);
  const shareSlug = p.shareSlug as string;
  const principalId = p.principalId as string;
  const deviceId = p.deviceId as string;
  const source = state.shareSecrets.get(shareSlug);
  if (
    !source?.capabilitySecret ||
    (!source.authorizationSecret && !source.passwordCapabilitySecret)
  ) {
    throw new Error("share_secret_unavailable");
  }
  if (!source.authorizationSecret) throw new Error("share_secret_unavailable");

  await storeDskStoreValueInWorker(
    shareSecretKey(shareSlug, principalId, deviceId, "authorization"),
    await dskEncrypt(
      dsk,
      source.authorizationSecret,
      buildDskShareParticipantAuthorizationSecretAad(principalId, deviceId, shareSlug),
    ),
  );
  await storeDskStoreValueInWorker(
    shareSecretKey(shareSlug, principalId, deviceId, "capability"),
    await dskEncrypt(
      dsk,
      source.capabilitySecret,
      new TextEncoder().encode(`RefMD:v2:share-capability-secret:${shareSlug}`),
    ),
  );
  if (source.passwordCapabilitySecret) {
    await storeDskStoreValueInWorker(
      shareSecretKey(shareSlug, principalId, deviceId, "password-capability"),
      await dskEncrypt(
        dsk,
        source.passwordCapabilitySecret,
        new TextEncoder().encode(`RefMD:v2:share-password-capability-secret:${shareSlug}`),
      ),
    );
  }
  if (source.passwordChallengeAuthKey) {
    await storeDskStoreValueInWorker(
      shareSecretKey(shareSlug, principalId, deviceId, "password-auth"),
      await dskEncrypt(
        dsk,
        source.passwordChallengeAuthKey,
        new TextEncoder().encode(`RefMD:v2:share-password-auth-key:${shareSlug}`),
      ),
    );
  }
  return { stored: true };
}

export async function handlePersistMountedShareSecretsWithDsk(
  state: WorkerKeyState,
  p: HandlerPayload,
): Promise<unknown> {
  const dsk = requireDsk(state);
  const source = state.shareSecrets.get(p.sourceShareSlug as string);
  const mountSessionKey = p.mountSessionKey as string;
  const principalId = p.principalId as string;
  const deviceId = p.deviceId as string;
  if (
    !source?.capabilitySecret ||
    (!source.authorizationSecret && !source.passwordCapabilitySecret)
  ) {
    throw new Error("share_secret_unavailable");
  }
  if (!source.authorizationSecret) throw new Error("share_secret_unavailable");

  await storeDskStoreValueInWorker(
    shareSecretKey(mountSessionKey, principalId, deviceId, "authorization"),
    await dskEncrypt(
      dsk,
      source.authorizationSecret,
      buildDskShareParticipantAuthorizationSecretAad(principalId, deviceId, mountSessionKey),
    ),
  );
  await storeDskStoreValueInWorker(
    shareSecretKey(mountSessionKey, principalId, deviceId, "capability"),
    await dskEncrypt(
      dsk,
      source.capabilitySecret,
      new TextEncoder().encode(`RefMD:v2:share-capability-secret:${mountSessionKey}`),
    ),
  );
  if (source.passwordCapabilitySecret) {
    await storeDskStoreValueInWorker(
      shareSecretKey(mountSessionKey, principalId, deviceId, "password-capability"),
      await dskEncrypt(
        dsk,
        source.passwordCapabilitySecret,
        new TextEncoder().encode(`RefMD:v2:share-password-capability-secret:${mountSessionKey}`),
      ),
    );
  }
  if (source.passwordChallengeAuthKey) {
    await storeDskStoreValueInWorker(
      shareSecretKey(mountSessionKey, principalId, deviceId, "password-auth"),
      await dskEncrypt(
        dsk,
        source.passwordChallengeAuthKey,
        new TextEncoder().encode(`RefMD:v2:share-password-auth-key:${mountSessionKey}`),
      ),
    );
  }
  const dekEncryptionKey = deriveShareDekEncryptionKeyFromStoredSecrets(
    source.capabilitySecret,
    source.passwordCapabilitySecret,
  );

  upsertShareSecrets(state, mountSessionKey, {
    authorizationSecret: source.authorizationSecret,
    passwordChallengeAuthKey: source.passwordChallengeAuthKey,
    dekEncryptionKey,
    capabilitySecret: source.capabilitySecret,
    passwordCapabilitySecret: source.passwordCapabilitySecret,
  });
  dekEncryptionKey.fill(0);
  return { stored: true };
}

export function handleEncryptTitle(state: WorkerKeyState, p: HandlerPayload): unknown {
  const title = p.title as string;
  const documentId = p.documentId as string;
  const keyVersion = p.keyVersion as number;
  const cacheKey = (p.cacheKey as string | undefined) ?? documentId;
  const { dek } = requireDekForDocument(state, documentId, keyVersion, cacheKey);

  const result = encryptTitle(title, dek, documentId, keyVersion);
  return { encrypted: result.encrypted, nonce: result.nonce };
}

export function handleDecryptTitle(state: WorkerKeyState, p: HandlerPayload): unknown {
  const encrypted = p.encrypted as Uint8Array;
  const nonce = p.nonce as Uint8Array;
  const documentId = p.documentId as string;
  const keyVersion = p.keyVersion as number;
  const cacheKey = (p.cacheKey as string | undefined) ?? documentId;
  const { dek } = requireDekForDocument(state, documentId, keyVersion, cacheKey);

  const title = decryptTitle(encrypted, nonce, dek, documentId, keyVersion);
  return { title };
}

export function handleDecryptTitleBatch(state: WorkerKeyState, p: HandlerPayload): unknown {
  const items = p.items as TitleDecryptItem[];
  const results: TitleDecryptResult[] = [];

  for (const item of items) {
    try {
      const cached = getCachedDek(state, item.documentId, item.keyVersion);
      if (!cached) {
        results.push({ documentId: item.documentId, title: null });
        continue;
      }
      const title = decryptTitle(
        item.encrypted,
        item.nonce,
        cached.dek,
        item.documentId,
        item.keyVersion,
      );
      results.push({ documentId: item.documentId, title });
    } catch {
      results.push({ documentId: item.documentId, title: null });
    }
  }

  return results;
}

export function handleEncryptContent(state: WorkerKeyState, p: HandlerPayload): unknown {
  const plaintext = p.plaintext as Uint8Array;
  const documentId = p.documentId as string;
  const keyVersion = p.keyVersion as number;
  const cacheKey = (p.cacheKey as string | undefined) ?? documentId;
  const { dek } = requireDekForDocument(state, documentId, keyVersion, cacheKey);

  const nonce = randomBytes(24);
  const aad = buildDocumentContentAad(documentId, keyVersion);
  const cipher = xchacha20poly1305(dek, nonce, aad);
  const ciphertext = cipher.encrypt(plaintext);

  return { ciphertext, nonce };
}

export function handleDecryptContent(state: WorkerKeyState, p: HandlerPayload): unknown {
  const ciphertext = p.ciphertext as Uint8Array;
  const nonce = p.nonce as Uint8Array;
  const documentId = p.documentId as string;
  const keyVersion = p.keyVersion as number;
  const cacheKey = (p.cacheKey as string | undefined) ?? documentId;
  const { dek } = requireDekForDocument(state, documentId, keyVersion, cacheKey);

  const aad = buildDocumentContentAad(documentId, keyVersion);
  const cipher = xchacha20poly1305(dek, nonce, aad);
  const plaintext = cipher.decrypt(ciphertext);

  return { plaintext };
}

export function handleEncryptPluginStorage(state: WorkerKeyState, p: HandlerPayload): unknown {
  const plaintext = p.plaintext as Uint8Array;
  const surface = p.surface as "workspace" | "document";
  const workspaceId = p.workspaceId as string;
  const packageId = p.packageId as string;
  const applicationId = p.applicationId as string;
  const activationId = p.activationId as string;
  const pluginId = p.pluginId as string;
  const scopeId = p.scopeId as string;
  const key = p.key as string;

  const { encryptionKey, keyVersion } =
    surface === "workspace"
      ? (() => {
          const { kek, keyVersion } = requireKekForWorkspace(state, workspaceId);
          return { encryptionKey: kek, keyVersion };
        })()
      : (() => {
          const { dek, keyVersion } = requireDekForDocument(state, scopeId);
          return { encryptionKey: dek, keyVersion };
        })();

  const nonce = randomBytes(24);
  const aad = buildPluginStorageAad({
    scope: surface,
    workspaceId,
    packageId,
    applicationId,
    activationId,
    pluginId,
    scopeId,
    key,
  });
  const ciphertext = xchacha20poly1305(encryptionKey, nonce, aad).encrypt(plaintext);

  return { ciphertext, nonce, keyVersion };
}

export function handleDecryptPluginStorage(state: WorkerKeyState, p: HandlerPayload): unknown {
  const ciphertext = p.ciphertext as Uint8Array;
  const nonce = p.nonce as Uint8Array;
  const surface = p.surface as "workspace" | "document";
  const workspaceId = p.workspaceId as string;
  const packageId = p.packageId as string;
  const applicationId = p.applicationId as string;
  const activationId = p.activationId as string;
  const pluginId = p.pluginId as string;
  const scopeId = p.scopeId as string;
  const key = p.key as string;
  const keyVersion = p.keyVersion as number;

  const encryptionKey =
    surface === "workspace"
      ? requireKekForWorkspace(state, workspaceId, keyVersion).kek
      : requireDekForDocument(state, scopeId, keyVersion).dek;

  const aad = buildPluginStorageAad({
    scope: surface,
    workspaceId,
    packageId,
    applicationId,
    activationId,
    pluginId,
    scopeId,
    key,
  });
  const plaintext = xchacha20poly1305(encryptionKey, nonce, aad).decrypt(ciphertext);

  return { plaintext };
}

export function handleHasDek(state: WorkerKeyState, p: HandlerPayload): unknown {
  const documentId = p.documentId as string;
  const requiredVersion = p.keyVersion as number | undefined;
  const cacheKey = (p.cacheKey as string | undefined) ?? documentId;
  const cached = getCachedDek(state, cacheKey, requiredVersion);
  return { hasDek: !!cached };
}

export const HAS_DEK_BATCH_MAX_SIZE = 500;

interface HasDekBatchItem {
  requestId: string;
  documentId: string;
  keyVersion: number;
  cacheKey?: string;
}

export function handleHasDekBatch(state: WorkerKeyState, p: HandlerPayload): unknown {
  const items = p.items as HasDekBatchItem[] | undefined;
  if (!Array.isArray(items)) {
    throw new Error("has-dek-batch: items must be an array");
  }
  if (items.length > HAS_DEK_BATCH_MAX_SIZE) {
    throw new Error(
      `has-dek-batch: items exceeds max size ${HAS_DEK_BATCH_MAX_SIZE} (got ${items.length})`,
    );
  }
  const results = items.map((item) => {
    const cacheKey = item.cacheKey ?? item.documentId;
    const cached = getCachedDek(state, cacheKey, item.keyVersion);
    return { requestId: item.requestId, hasDek: !!cached };
  });
  return { results };
}

export function handleCacheDek(state: WorkerKeyState, p: HandlerPayload): unknown {
  const documentId = p.documentId as string;
  const cacheKey = (p.cacheKey as string | undefined) ?? documentId;
  const dek = p.dek as Uint8Array;
  const keyVersion = p.keyVersion as number;
  setCachedDek(state, cacheKey, dek, keyVersion);
  return { status: "ok" };
}

export function handleEvictDek(state: WorkerKeyState, p: HandlerPayload): unknown {
  const documentId = p.documentId as string;
  const cacheKey = (p.cacheKey as string | undefined) ?? documentId;
  const keyVersion = p.keyVersion as number;
  evictCachedDek(state, cacheKey, keyVersion);
  return { status: "ok" };
}

export function handleEncryptOfflineCache(state: WorkerKeyState, p: HandlerPayload): unknown {
  const plaintext = p.plaintext as Uint8Array;
  const documentId = p.documentId as string;
  const keyVersion = p.keyVersion as number;
  const cacheKey = (p.cacheKey as string | undefined) ?? documentId;
  const { dek } = requireDekForDocument(state, documentId, keyVersion, cacheKey);

  const nonce = randomBytes(24);
  const aad = buildOfflineDocumentCacheAad(documentId, keyVersion);
  const cipher = xchacha20poly1305(dek, nonce, aad);
  const ciphertext = cipher.encrypt(plaintext);

  return { ciphertext, nonce };
}

export function handleDecryptOfflineCache(state: WorkerKeyState, p: HandlerPayload): unknown {
  const ciphertext = p.ciphertext as Uint8Array;
  const nonce = p.nonce as Uint8Array;
  const documentId = p.documentId as string;
  const keyVersion = p.keyVersion as number;
  const cacheKey = (p.cacheKey as string | undefined) ?? documentId;
  const { dek } = requireDekForDocument(state, documentId, keyVersion, cacheKey);

  const aad = buildOfflineDocumentCacheAad(documentId, keyVersion);
  const cipher = xchacha20poly1305(dek, nonce, aad);
  const plaintext = cipher.decrypt(ciphertext);

  return { plaintext };
}

export function handleEncryptOfflinePending(state: WorkerKeyState, p: HandlerPayload): unknown {
  const plaintext = p.plaintext as Uint8Array;
  const documentId = p.documentId as string;
  const keyVersion = p.keyVersion as number;
  const cacheKey = (p.cacheKey as string | undefined) ?? documentId;
  const { dek } = requireDekForDocument(state, documentId, keyVersion, cacheKey);

  const nonce = randomBytes(24);
  const aad = buildOfflinePendingChangesAad(documentId, keyVersion);
  const cipher = xchacha20poly1305(dek, nonce, aad);
  const ciphertext = cipher.encrypt(plaintext);

  return { ciphertext, nonce };
}

export function handleDecryptOfflinePending(state: WorkerKeyState, p: HandlerPayload): unknown {
  const ciphertext = p.ciphertext as Uint8Array;
  const nonce = p.nonce as Uint8Array;
  const documentId = p.documentId as string;
  const keyVersion = p.keyVersion as number;
  const cacheKey = (p.cacheKey as string | undefined) ?? documentId;
  const { dek } = requireDekForDocument(state, documentId, keyVersion, cacheKey);

  const aad = buildOfflinePendingChangesAad(documentId, keyVersion);
  const cipher = xchacha20poly1305(dek, nonce, aad);
  const plaintext = cipher.decrypt(ciphertext);

  return { plaintext };
}

export async function handleStoreDekForOffline(
  state: WorkerKeyState,
  p: HandlerPayload,
): Promise<unknown> {
  const dsk = requireDsk(state);
  const documentId = p.documentId as string;
  const keyVersion = p.keyVersion as number;
  const cacheKey = (p.cacheKey as string | undefined) ?? documentId;
  const { dek } = requireDekForDocument(state, documentId, keyVersion, cacheKey);

  const wrapped = await dskEncrypt(dsk, dek, buildOfflineDekCacheAad(documentId, keyVersion));
  await storeDskStoreValueInWorker(offlineDekKey(documentId), {
    ...wrapped,
    keyVersion,
    cachedAt: Date.now(),
  } satisfies OfflineDekStoredEntry);
  return { stored: true };
}

export async function handleRestoreDekFromOffline(
  state: WorkerKeyState,
  p: HandlerPayload,
): Promise<unknown> {
  const dsk = requireDsk(state);
  const documentId = p.documentId as string;
  const cacheKey = (p.cacheKey as string | undefined) ?? documentId;
  const isActive = (p.isActive as boolean | undefined) ?? true;
  const entry = await loadDskStoreValueInWorker<OfflineDekStoredEntry>(offlineDekKey(documentId));
  if (!entry) return { restored: false };
  const keyVersion = (p.keyVersion as number | undefined) ?? entry.keyVersion;
  if (entry.keyVersion !== keyVersion) throw new Error("offline_dek_key_version_mismatch");

  const dek = await dskDecrypt(
    dsk,
    entry.ciphertext,
    entry.iv,
    buildOfflineDekCacheAad(documentId, keyVersion),
  );
  setCachedDek(state, cacheKey, dek, keyVersion);
  if (isActive) {
    setActiveDekVersion(state, cacheKey, keyVersion);
  }
  return { restored: true, keyVersion, cachedAt: entry.cachedAt };
}

export async function handleLoadOfflineDekMetadata(p: HandlerPayload): Promise<unknown> {
  const documentId = p.documentId as string;
  const entry = await loadDskStoreValueInWorker<OfflineDekStoredEntry>(offlineDekKey(documentId));
  if (!entry) return { metadata: null };
  return {
    metadata: {
      documentId,
      keyVersion: entry.keyVersion,
      cachedAt: entry.cachedAt,
    },
  };
}

export async function handleDeleteDekForOffline(p: HandlerPayload): Promise<unknown> {
  await deleteDskStoreValueInWorker(offlineDekKey(p.documentId as string));
  return {};
}

function offlineDekKey(documentId: string): string {
  return `${OFFLINE_DEK_KEY_PREFIX}${documentId}`;
}
