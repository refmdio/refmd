import { base64UrlDecode } from "@/shared/lib/crypto/encoding";
import { getCryptoWorker } from "@/shared/lib/crypto/worker/client";
import { encryptionApi } from "@/shared/api/encryption";
import { workspacesApi } from "@/shared/api/workspaces";
import { sharesApi } from "@/shared/api/shares";
import { ApiError } from "@/shared/api/core";
import { authState } from "@/entities/session";
import { normalizeShareVerificationDirectory } from "@/shared/lib/document/share-verification-directory";
import type { DocumentState } from "../../../model/document-state/types";
import type {
  ShareVerificationDirectory,
  SharedDocumentAccess,
} from "../../../model/document-state/access";
import { refreshSharedDocumentAccess } from "../share-access";

// ── Types ────────────────────────────────────────────────────

interface TofuKeyChangeWarning {
  userId: string;
  deviceId?: string;
  oldFingerprint?: string;
  newFingerprint?: string;
}

type DeviceKeyCacheResult =
  | {
      status: "ok";
      signingKeys: Map<string, Uint8Array>;
      historicalSigningKeys: Map<string, Uint8Array>;
      signingKeyOwners: Map<string, string>;
      memberNames: Map<string, string>;
      revokedSigningKeys: Set<string>;
      rejectedSigningKeys: Set<string>;
    }
  | { status: "key_changed"; warning: TofuKeyChangeWarning };

type ResolveSigningKeyResult =
  | { status: "found"; key: Uint8Array }
  | { status: "not_found" }
  | { status: "key_changed"; warning: TofuKeyChangeWarning };

type SuccessfulDeviceKeyCacheResult = Extract<DeviceKeyCacheResult, { status: "ok" }>;

export function applyDeviceKeyCache(
  state: DocumentState,
  cacheResult: SuccessfulDeviceKeyCacheResult,
): void {
  state.signingKeys = cacheResult.signingKeys;
  state.historicalSigningKeys = cacheResult.historicalSigningKeys;
  state.signingKeyOwners = cacheResult.signingKeyOwners;
  state.memberNames = cacheResult.memberNames;
  state.revokedSigningKeys = cacheResult.revokedSigningKeys;
  state.rejectedSigningKeys = cacheResult.rejectedSigningKeys;
}

export async function buildDocumentSigningKeyCaches(
  state: DocumentState,
  signal?: AbortSignal,
): Promise<DeviceKeyCacheResult> {
  if (state.access.kind === "share") {
    return buildShareDeviceKeyCaches(state.access, signal);
  }

  return buildDeviceKeyCaches(state.workspaceId, signal, state.documentId);
}

// ── Build device key caches ──────────────────────────────────
// Implements the device resolution flow:
//   1. Get workspace members' Identity public keys
//   2. TOFU verify each member's Identity key (via Worker)
//   3. Get each member's device list
//   4. Verify each device's identity_signature cross-sign (via Worker)
//   5. Cache verified device signing keys

const pendingWorkspaceDeviceKeyCaches = new Map<string, Promise<DeviceKeyCacheResult>>();
const workspaceDeviceKeyCacheTtlMs = 60_000;
const workspaceDeviceKeyCaches = new Map<
  string,
  { result: SuccessfulDeviceKeyCacheResult; expiresAt: number }
>();
const shareVerificationDirectoryCacheTtlMs = 60_000;
const shareVerificationDirectoryCache = new Map<
  string,
  { directory: ShareVerificationDirectory | null; expiresAt: number }
>();
const MEMBER_DEVICE_FETCH_CONCURRENCY = 2;

function getShareTofuNamespace(access: SharedDocumentAccess): string {
  const directoryShareId = access.verificationDirectory.share_participant_devices[0]?.share_id;
  return `share:${directoryShareId ?? access.shareId}`;
}

export async function buildDeviceKeyCaches(
  workspaceId: string,
  signal?: AbortSignal,
  documentId?: string,
  forceRefresh = false,
): Promise<DeviceKeyCacheResult> {
  throwIfAborted(signal);

  const baseResult = await buildWorkspaceDeviceKeyCaches(workspaceId, forceRefresh);
  throwIfAborted(signal);

  if (baseResult.status === "key_changed") {
    return baseResult;
  }

  const result = cloneSuccessfulDeviceKeyCacheResult(baseResult);
  if (!documentId) {
    return result;
  }

  const directory = await fetchDocumentShareVerificationDirectory(documentId, forceRefresh);
  throwIfAborted(signal);
  if (!directory) {
    return result;
  }

  const worker = getCryptoWorker();
  const workspaceWarning = await addWorkspaceDirectoryDevicesToCache(
    directory.workspace_devices as Parameters<typeof addWorkspaceDirectoryDevicesToCache>[0],
    result.signingKeys,
    result.historicalSigningKeys,
    result.signingKeyOwners,
    worker,
  );
  if (workspaceWarning) return workspaceWarning;

  const warning = await addShareParticipantDevicesToCache(
    directory.share_participant_devices as Parameters<typeof addShareParticipantDevicesToCache>[0],
    result.signingKeys,
    result.historicalSigningKeys,
    result.signingKeyOwners,
    result.memberNames,
    worker,
  );
  if (warning) return warning;

  return result;
}

function buildWorkspaceDeviceKeyCaches(
  workspaceId: string,
  forceRefresh = false,
): Promise<DeviceKeyCacheResult> {
  const cached = workspaceDeviceKeyCaches.get(workspaceId);
  if (!forceRefresh && cached && cached.expiresAt > Date.now()) {
    return Promise.resolve(cloneSuccessfulDeviceKeyCacheResult(cached.result));
  }

  const pending = pendingWorkspaceDeviceKeyCaches.get(workspaceId);
  if (pending) return pending;

  const refresh = doBuildWorkspaceDeviceKeyCaches(workspaceId).then(
    (result) => {
      pendingWorkspaceDeviceKeyCaches.delete(workspaceId);
      if (result.status === "ok") {
        workspaceDeviceKeyCaches.set(workspaceId, {
          result: cloneSuccessfulDeviceKeyCacheResult(result),
          expiresAt: Date.now() + workspaceDeviceKeyCacheTtlMs,
        });
      } else {
        workspaceDeviceKeyCaches.delete(workspaceId);
      }
      return result;
    },
    (error) => {
      pendingWorkspaceDeviceKeyCaches.delete(workspaceId);
      throw error;
    },
  );
  pendingWorkspaceDeviceKeyCaches.set(workspaceId, refresh);
  return refresh;
}

async function doBuildWorkspaceDeviceKeyCaches(workspaceId: string): Promise<DeviceKeyCacheResult> {
  const worker = getCryptoWorker();
  const signingKeys = new Map<string, Uint8Array>();
  const historicalSigningKeys = new Map<string, Uint8Array>();
  const revokedSigningKeys = new Set<string>();
  const rejectedSigningKeys = new Set<string>();
  const signingKeyOwners = new Map<string, string>();

  // Step 1: Get Identity public keys. Member names are UI metadata and must not
  // fail document initialization when rate-limited.
  const [memberKeysResponse, memberNames] = await Promise.all([
    encryptionApi.getWorkspaceMemberKeys(workspaceId),
    fetchWorkspaceMemberNames(workspaceId),
  ]);

  // Step 2: TOFU verify each member's Identity key (Worker handles IndexedDB trust store)
  for (const member of memberKeysResponse.members) {
    const signingPk = base64UrlDecode(member.signing_public_key);
    const ecdhPk = base64UrlDecode(member.ecdh_public_key);

    const tofuResult = await worker.tofuVerify({
      userId: member.user_id,
      deviceId: member.user_id,
      signingPublicKey: signingPk,
      ecdhPublicKey: ecdhPk,
    });

    if (tofuResult.status === "identity_key_changed" || tofuResult.status === "ecdh_key_mismatch") {
      return {
        status: "key_changed",
        warning: { userId: member.user_id },
      };
    }

    await worker.tofuHandleResult({
      status: tofuResult.status,
      newEntry: {
        userId: member.user_id,
        deviceId: member.user_id,
        signingPublicKey: signingPk,
        ecdhPublicKey: ecdhPk,
        firstSeenAt: Date.now(),
        lastSeenAt: Date.now(),
      },
    });
  }

  // Step 3: Get each member's devices (using user_ids from /member-keys, not /members)
  const memberDevicesResults = await mapWithConcurrencyLimit(
    memberKeysResponse.members,
    MEMBER_DEVICE_FETCH_CONCURRENCY,
    async (member) => {
      try {
        const resp = await workspacesApi.listMemberDevices(workspaceId, member.user_id, true);
        return { userId: member.user_id, devices: resp.devices };
      } catch (err) {
        if (err instanceof ApiError && err.status === 404) {
          return null;
        }
        throw err;
      }
    },
  );
  const memberDevices = memberDevicesResults.filter((r): r is NonNullable<typeof r> => r !== null);

  // Build Identity signing key lookup for cross-sign verification
  const identitySigningKeys = new Map<string, Uint8Array>();
  for (const member of memberKeysResponse.members) {
    identitySigningKeys.set(member.user_id, base64UrlDecode(member.signing_public_key));
  }

  for (const { userId, devices } of memberDevices) {
    const identitySigningPubKey = identitySigningKeys.get(userId);
    if (!identitySigningPubKey) continue;

    for (const dev of devices) {
      // Step 4: Verify identity_signature using TOFU-verified Identity signing public key
      const deviceSigningPk = base64UrlDecode(dev.signing_public_key);
      const deviceEcdhPk = base64UrlDecode(dev.ecdh_public_key);
      const identitySig = base64UrlDecode(dev.identity_signature);

      const clientNonce = base64UrlDecode(dev.client_nonce);
      const crossSignValid = await worker.verifyDeviceIdentitySignature({
        deviceId: dev.device_id,
        deviceSigningPublic: deviceSigningPk,
        deviceEcdhPublic: deviceEcdhPk,
        clientNonce: clientNonce,
        identitySignature: identitySig,
        identitySigningPublic: identitySigningPubKey,
      });

      if (!crossSignValid) {
        rejectedSigningKeys.add(dev.signing_public_key);
        continue;
      }

      // TOFU verify device keys (trust.md: all device key receptions require TOFU)
      const deviceTofuResult = await worker.tofuVerify({
        userId,
        deviceId: dev.device_id,
        signingPublicKey: deviceSigningPk,
        ecdhPublicKey: deviceEcdhPk,
      });

      if (
        deviceTofuResult.status === "identity_key_changed" ||
        deviceTofuResult.status === "ecdh_key_mismatch"
      ) {
        return {
          status: "key_changed" as const,
          warning: { userId, deviceId: dev.device_id },
        };
      }

      await worker.tofuHandleResult({
        status: deviceTofuResult.status,
        newEntry: {
          userId,
          deviceId: dev.device_id,
          signingPublicKey: deviceSigningPk,
          ecdhPublicKey: deviceEcdhPk,
          firstSeenAt: Date.now(),
          lastSeenAt: Date.now(),
        },
      });

      // Revoked workspace devices are kept only for historical payload verification.
      if (dev.revoked_at) {
        historicalSigningKeys.set(dev.signing_public_key, deviceSigningPk);
        revokedSigningKeys.add(dev.signing_public_key);
      } else {
        signingKeys.set(dev.signing_public_key, deviceSigningPk);
      }
      signingKeyOwners.set(dev.signing_public_key, userId);
    }
  }

  return {
    status: "ok",
    signingKeys,
    historicalSigningKeys,
    signingKeyOwners,
    memberNames,
    revokedSigningKeys,
    rejectedSigningKeys,
  };
}

async function fetchWorkspaceMemberNames(workspaceId: string): Promise<Map<string, string>> {
  if (authState()?.user.accountType === "guest") {
    return new Map();
  }

  try {
    const workspaceMembersResponse = await workspacesApi.listMembers(workspaceId);
    return new Map(workspaceMembersResponse.members.map((member) => [member.user_id, member.name]));
  } catch (error) {
    if (error instanceof ApiError && (error.status === 403 || error.status === 429)) {
      return new Map();
    }
    throw error;
  }
}

async function fetchDocumentShareVerificationDirectory(
  documentId: string,
  forceRefresh = false,
): Promise<ShareVerificationDirectory | null> {
  const cached = shareVerificationDirectoryCache.get(documentId);
  if (!forceRefresh && cached && cached.expiresAt > Date.now()) {
    return cached.directory;
  }

  try {
    const directory = normalizeShareVerificationDirectory(
      await sharesApi.getDocumentShareVerificationDirectory(documentId),
    );
    shareVerificationDirectoryCache.set(documentId, {
      directory,
      expiresAt: Date.now() + shareVerificationDirectoryCacheTtlMs,
    });
    return directory;
  } catch (error) {
    if (error instanceof ApiError && error.status === 429) {
      return null;
    }
    if (error instanceof TypeError) {
      shareVerificationDirectoryCache.set(documentId, {
        directory: null,
        expiresAt: Date.now() + 5_000,
      });
      return null;
    }
    throw error;
  }
}

function throwIfAborted(signal?: AbortSignal): void {
  if (signal?.aborted) {
    throw new DOMException("Aborted", "AbortError");
  }
}

function cloneSuccessfulDeviceKeyCacheResult(
  result: SuccessfulDeviceKeyCacheResult,
): SuccessfulDeviceKeyCacheResult {
  return {
    status: "ok",
    signingKeys: new Map(result.signingKeys),
    historicalSigningKeys: new Map(result.historicalSigningKeys),
    signingKeyOwners: new Map(result.signingKeyOwners),
    memberNames: new Map(result.memberNames),
    revokedSigningKeys: new Set(result.revokedSigningKeys),
    rejectedSigningKeys: new Set(result.rejectedSigningKeys),
  };
}

async function addWorkspaceDirectoryDevicesToCache(
  devices: Array<{
    device_id: string;
    user_id: string;
    signing_public_key: string;
    encryption_public_key: string;
    historical?: boolean;
  }>,
  signingKeys: Map<string, Uint8Array>,
  historicalSigningKeys: Map<string, Uint8Array>,
  signingKeyOwners: Map<string, string>,
  worker: ReturnType<typeof getCryptoWorker>,
): Promise<DeviceKeyCacheResult | null> {
  for (const device of devices) {
    const signingPk = base64UrlDecode(device.signing_public_key);
    const ecdhPk = base64UrlDecode(device.encryption_public_key);
    const tofuResult = await worker.tofuVerify({
      userId: device.user_id,
      deviceId: device.device_id,
      signingPublicKey: signingPk,
      ecdhPublicKey: ecdhPk,
    });

    if (tofuResult.status === "identity_key_changed" || tofuResult.status === "ecdh_key_mismatch") {
      return {
        status: "key_changed",
        warning: { userId: device.user_id, deviceId: device.device_id },
      };
    }

    await worker.tofuHandleResult({
      status: tofuResult.status,
      newEntry: {
        userId: device.user_id,
        deviceId: device.device_id,
        signingPublicKey: signingPk,
        ecdhPublicKey: ecdhPk,
        firstSeenAt: Date.now(),
        lastSeenAt: Date.now(),
      },
    });

    if (device.historical) {
      historicalSigningKeys.set(device.signing_public_key, signingPk);
    } else {
      signingKeys.set(device.signing_public_key, signingPk);
    }
    signingKeyOwners.set(device.signing_public_key, device.user_id);
  }

  return null;
}

async function addShareParticipantDevicesToCache(
  devices: Array<{
    share_id: string;
    device_id: string;
    principal_id: string;
    display_name?: string | null;
    signing_public_key: string;
    encryption_public_key: string;
    historical?: boolean;
  }>,
  signingKeys: Map<string, Uint8Array>,
  historicalSigningKeys: Map<string, Uint8Array>,
  signingKeyOwners: Map<string, string>,
  memberNames: Map<string, string>,
  worker: ReturnType<typeof getCryptoWorker>,
): Promise<DeviceKeyCacheResult | null> {
  for (const device of devices) {
    const namespace = `share:${device.share_id}`;
    const signingPk = base64UrlDecode(device.signing_public_key);
    const ecdhPk = base64UrlDecode(device.encryption_public_key);
    const tofuResult = await worker.tofuVerify({
      userId: device.principal_id,
      deviceId: device.device_id,
      signingPublicKey: signingPk,
      ecdhPublicKey: ecdhPk,
      namespace,
    });

    if (tofuResult.status === "identity_key_changed" || tofuResult.status === "ecdh_key_mismatch") {
      return {
        status: "key_changed",
        warning: { userId: device.principal_id, deviceId: device.device_id },
      };
    }

    await worker.tofuHandleResult({
      status: tofuResult.status,
      namespace,
      newEntry: {
        userId: device.principal_id,
        deviceId: device.device_id,
        signingPublicKey: signingPk,
        ecdhPublicKey: ecdhPk,
        firstSeenAt: Date.now(),
        lastSeenAt: Date.now(),
      },
    });

    if (device.historical) {
      historicalSigningKeys.set(device.signing_public_key, signingPk);
    } else {
      signingKeys.set(device.signing_public_key, signingPk);
    }
    signingKeyOwners.set(device.signing_public_key, device.principal_id);
    if (!device.historical) {
      memberNames.set(device.principal_id, device.display_name ?? device.principal_id);
    }
  }

  return null;
}

async function mapWithConcurrencyLimit<T, R>(
  items: readonly T[],
  concurrency: number,
  mapper: (item: T, index: number) => Promise<R>,
): Promise<R[]> {
  if (items.length === 0) return [];

  const results = Array<R>(items.length);
  let nextIndex = 0;

  const workers = Array.from({ length: Math.min(concurrency, items.length) }, async () => {
    while (nextIndex < items.length) {
      const currentIndex = nextIndex++;
      results[currentIndex] = await mapper(items[currentIndex]!, currentIndex);
    }
  });

  await Promise.all(workers);
  return results;
}

async function buildShareDeviceKeyCaches(
  access: SharedDocumentAccess,
  signal?: AbortSignal,
): Promise<DeviceKeyCacheResult> {
  if (signal?.aborted) {
    throw new DOMException("Aborted", "AbortError");
  }

  const worker = getCryptoWorker();
  const signingKeys = new Map<string, Uint8Array>();
  const historicalSigningKeys = new Map<string, Uint8Array>();
  const revokedSigningKeys = new Set<string>();
  const rejectedSigningKeys = new Set<string>();
  const signingKeyOwners = new Map<string, string>();
  const memberNames = new Map<string, string>();
  const namespace = getShareTofuNamespace(access);

  const processDirectoryEntry = async (
    ownerId: string,
    deviceId: string,
    signingPublicKey: string,
    encryptionPublicKey: string,
    displayName?: string,
    historical = false,
  ): Promise<DeviceKeyCacheResult | null> => {
    const signingPk = base64UrlDecode(signingPublicKey);
    const ecdhPk = base64UrlDecode(encryptionPublicKey);

    const tofuResult = await worker.tofuVerify({
      userId: ownerId,
      deviceId,
      signingPublicKey: signingPk,
      ecdhPublicKey: ecdhPk,
      namespace,
    });

    if (tofuResult.status === "identity_key_changed" || tofuResult.status === "ecdh_key_mismatch") {
      return {
        status: "key_changed",
        warning: { userId: ownerId, deviceId },
      };
    }

    await worker.tofuHandleResult({
      status: tofuResult.status,
      namespace,
      newEntry: {
        userId: ownerId,
        deviceId,
        signingPublicKey: signingPk,
        ecdhPublicKey: ecdhPk,
        firstSeenAt: Date.now(),
        lastSeenAt: Date.now(),
      },
    });

    if (historical) {
      historicalSigningKeys.set(signingPublicKey, signingPk);
    } else {
      signingKeys.set(signingPublicKey, signingPk);
    }
    signingKeyOwners.set(signingPublicKey, ownerId);
    if (!historical) {
      memberNames.set(ownerId, displayName ?? ownerId);
    }

    return null;
  };

  const processDirectory = async (directory: ShareVerificationDirectory) => {
    for (const device of directory.workspace_devices) {
      const warning = await processDirectoryEntry(
        device.user_id,
        device.device_id,
        device.signing_public_key,
        device.encryption_public_key,
        undefined,
        device.historical === true,
      );

      if (warning) return warning;
    }

    for (const device of directory.share_participant_devices) {
      const warning = await processDirectoryEntry(
        device.principal_id,
        device.device_id,
        device.signing_public_key,
        device.encryption_public_key,
        device.display_name ?? undefined,
        device.historical === true,
      );

      if (warning) return warning;
    }

    return null;
  };

  const warning = await processDirectory(access.verificationDirectory);
  if (warning) return warning;

  return {
    status: "ok",
    signingKeys,
    historicalSigningKeys,
    signingKeyOwners,
    memberNames,
    revokedSigningKeys,
    rejectedSigningKeys,
  };
}

// ── Resolve signing key ──────────────────────────────────────
// Cache lookup with re-fetch on miss (dedup concurrent re-fetches).

const pendingRefreshes = new Map<string, Promise<DeviceKeyCacheResult>>();

export async function resolveSigningKey(
  pubKeyB64: string,
  state: DocumentState,
  options: { includeHistorical?: boolean } = {},
): Promise<ResolveSigningKeyResult> {
  // 1. Check cache
  const cached = state.signingKeys.get(pubKeyB64);
  if (cached) return { status: "found", key: cached };
  if (options.includeHistorical) {
    const historical = state.historicalSigningKeys.get(pubKeyB64);
    if (historical) return { status: "found", key: historical };
  }

  // 2. Re-fetch with dedup
  const dedupKey =
    state.access.kind === "share" ? `share:${state.access.documentToken}` : state.workspaceId;
  let refresh = pendingRefreshes.get(dedupKey);
  if (!refresh) {
    const nextRefresh =
      state.access.kind === "share"
        ? refreshSharedDocumentAccess(state).then((access) => buildShareDeviceKeyCaches(access))
        : buildDeviceKeyCaches(state.workspaceId, undefined, state.documentId, true);

    refresh = nextRefresh.then(
      (r) => {
        pendingRefreshes.delete(dedupKey);
        return r;
      },
      (err) => {
        pendingRefreshes.delete(dedupKey);
        throw err;
      },
    );
    pendingRefreshes.set(dedupKey, refresh);
  }

  const result = await refresh;
  if (result.status === "key_changed") {
    return { status: "key_changed", warning: result.warning };
  }

  // 3. Replace cache atomically
  state.signingKeys.clear();
  for (const [key, value] of result.signingKeys) {
    state.signingKeys.set(key, value);
  }
  state.historicalSigningKeys.clear();
  for (const [key, value] of result.historicalSigningKeys) {
    state.historicalSigningKeys.set(key, value);
  }
  state.signingKeyOwners.clear();
  for (const [key, value] of result.signingKeyOwners) {
    state.signingKeyOwners.set(key, value);
  }
  state.memberNames.clear();
  for (const [key, value] of result.memberNames) {
    state.memberNames.set(key, value);
  }
  state.revokedSigningKeys = new Set(result.revokedSigningKeys);
  state.rejectedSigningKeys = new Set(result.rejectedSigningKeys);

  // 4. Re-check
  const resolved = state.signingKeys.get(pubKeyB64);
  if (resolved) return { status: "found", key: resolved };
  if (options.includeHistorical) {
    const historical = state.historicalSigningKeys.get(pubKeyB64);
    if (historical) return { status: "found", key: historical };
  }
  return { status: "not_found" };
}
