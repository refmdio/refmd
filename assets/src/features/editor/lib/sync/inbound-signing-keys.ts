import { base64UrlDecode } from "@/shared/lib/crypto/encoding";
import { computeSigningKeyId } from "@/shared/lib/crypto/signature";
import type { HybridSigningPublicKeyMaterial } from "@/shared/lib/crypto/signature-types";
import { getCryptoWorker } from "@/shared/lib/crypto/worker/client";
import { workspacesApi } from "@/shared/api/workspaces";
import { sharesApi } from "@/shared/api/shares";
import { ApiError } from "@/shared/api/core";
import { authState } from "@/entities/session";
import { deviceState } from "@/entities/session";
import { normalizeShareVerificationDirectory } from "@/shared/lib/document/share-verification-directory";
import { fetchVerifiedKeyDirectory } from "@/shared/lib/key-directory/fetch";
import type { DocumentState } from "../../model/document-state/types";
import type {
  ShareVerificationDirectory,
  ShareVerificationParticipantDevice,
  ShareVerificationWorkspaceDevice,
  SharedDocumentAccess,
} from "../../model/document-state/access";
import type { DocumentPayload } from "@/shared/lib/ws/document-payloads";
import { refreshSharedDocumentAccess } from "./share-access";
import { verifyWorkspaceDirectoryDeviceIdentity } from "./inbound-workspace-device-approval";
import { recordSyncPerf } from "./perf";

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
      signingKeys: Map<string, HybridSigningPublicKeyMaterial>;
      historicalSigningKeys: Map<string, HybridSigningPublicKeyMaterial>;
      signingKeyOwners: Map<string, string>;
      memberNames: Map<string, string>;
      revokedSigningKeys: Set<string>;
      rejectedSigningKeys: Set<string>;
      directorySigningKeys: DirectorySigningKeyEntries;
    }
  | { status: "key_changed"; warning: TofuKeyChangeWarning };

export type ResolveSigningKeyResult =
  | { status: "found"; key: HybridSigningPublicKeyMaterial; ownerId: string }
  | { status: "not_found" }
  | { status: "key_changed"; warning: TofuKeyChangeWarning };

type DirectorySigningKeyEntries = Map<
  string,
  { material: HybridSigningPublicKeyMaterial; revoked: boolean }
>;

type SuccessfulDeviceKeyCacheResult = Extract<DeviceKeyCacheResult, { status: "ok" }>;

export function applyDeviceKeyCache(
  state: DocumentState,
  cacheResult: SuccessfulDeviceKeyCacheResult,
): void {
  const nextSigningKeys = new Map(cacheResult.signingKeys);
  const nextHistoricalSigningKeys = new Map(cacheResult.historicalSigningKeys);
  const nextSigningKeyOwners = new Map(cacheResult.signingKeyOwners);
  const nextMemberNames = new Map(cacheResult.memberNames);
  const nextRevokedSigningKeys = new Set(cacheResult.revokedSigningKeys);
  const nextRejectedSigningKeys = new Set(cacheResult.rejectedSigningKeys);

  const shouldPreserveVerifiedLiveKey = (keyId: string) =>
    !nextSigningKeys.has(keyId) &&
    !nextHistoricalSigningKeys.has(keyId) &&
    !nextRevokedSigningKeys.has(keyId) &&
    !nextRejectedSigningKeys.has(keyId);

  for (const [keyId, material] of state.signingKeys) {
    if (!shouldPreserveVerifiedLiveKey(keyId)) continue;
    nextSigningKeys.set(keyId, material);
    const ownerId = state.signingKeyOwners.get(keyId);
    if (ownerId) nextSigningKeyOwners.set(keyId, ownerId);
  }
  for (const [keyId, material] of state.historicalSigningKeys) {
    if (!shouldPreserveVerifiedLiveKey(keyId)) continue;
    nextHistoricalSigningKeys.set(keyId, material);
    const ownerId = state.signingKeyOwners.get(keyId);
    if (ownerId) nextSigningKeyOwners.set(keyId, ownerId);
  }
  for (const [memberId, name] of state.memberNames) {
    if (!nextMemberNames.has(memberId)) nextMemberNames.set(memberId, name);
  }

  state.signingKeys = nextSigningKeys;
  state.historicalSigningKeys = nextHistoricalSigningKeys;
  state.signingKeyOwners = nextSigningKeyOwners;
  state.memberNames = nextMemberNames;
  state.revokedSigningKeys = nextRevokedSigningKeys;
  state.rejectedSigningKeys = nextRejectedSigningKeys;
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
//   4. Verify each device approval signature (via Worker)
//   5. Cache verified device signing keys

const pendingWorkspaceDeviceKeyCaches = new Map<string, Promise<DeviceKeyCacheResult>>();
const workspaceDeviceKeyCacheTtlMs = 60_000;
const workspaceDeviceKeyForceRefreshCooldownMs = 5_000;
const workspaceDeviceKeyCaches = new Map<
  string,
  { result: SuccessfulDeviceKeyCacheResult; expiresAt: number }
>();
const workspaceDeviceKeyForceRefreshAt = new Map<string, number>();
const shareVerificationDirectoryCacheTtlMs = 60_000;
const shareVerificationDirectoryForceRefreshCooldownMs = 5_000;
const pendingShareVerificationDirectoryFetches = new Map<
  string,
  Promise<ShareVerificationDirectory | null>
>();
const shareVerificationDirectoryCache = new Map<
  string,
  { directory: ShareVerificationDirectory | null; expiresAt: number }
>();
const shareVerificationDirectoryForceRefreshAt = new Map<string, number>();
const shareDeviceKeyCacheTtlMs = 60_000;
const pendingShareDeviceKeyCaches = new Map<string, Promise<DeviceKeyCacheResult>>();
const shareDeviceKeyCaches = new Map<
  string,
  { result: SuccessfulDeviceKeyCacheResult; expiresAt: number }
>();
const pendingInitialShareDeviceKeyCaches = new Map<string, Promise<DeviceKeyCacheResult>>();
const initialShareDeviceKeyCaches = new Map<
  string,
  { result: SuccessfulDeviceKeyCacheResult; expiresAt: number }
>();
const MEMBER_DEVICE_FETCH_CONCURRENCY = 2;
const SIGNING_KEY_REFRESH_RETRY_DELAYS_MS = [200, 500, 1_000, 2_000] as const;

function getShareTofuNamespace(access: SharedDocumentAccess): string {
  if (access.source === "mounted" && access.mountId) {
    return `refmd.v2.mounted-share:${access.mountId}:${access.shareId}`;
  }
  const directoryShareId = access.verificationDirectory.share_participant_devices[0]?.share_id;
  return `refmd.v2.share:${directoryShareId ?? access.shareId}`;
}

function getWorkspaceTofuNamespace(workspaceId: string): string {
  return `refmd.v2.workspace:${workspaceId}`;
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
    recordSyncPerf("device_key_cache_key_changed", {
      source: "workspace_base",
      workspaceId,
      documentId: documentId ?? null,
      userId: baseResult.warning.userId,
      deviceId: baseResult.warning.deviceId ?? null,
    });
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
    getWorkspaceTofuNamespace(workspaceId),
    result.signingKeys,
    result.historicalSigningKeys,
    result.directorySigningKeys,
    result.signingKeyOwners,
    worker,
  );
  if (workspaceWarning) return workspaceWarning;

  const warning = await addShareParticipantDevicesToCache(
    directory.share_participant_devices as Parameters<typeof addShareParticipantDevicesToCache>[0],
    result.directorySigningKeys,
    result.signingKeys,
    result.historicalSigningKeys,
    result.signingKeyOwners,
    result.memberNames,
    result.revokedSigningKeys,
    result.rejectedSigningKeys,
    worker,
  );
  if (warning) return warning;

  return result;
}

function buildWorkspaceDeviceKeyCaches(
  workspaceId: string,
  forceRefresh = false,
): Promise<DeviceKeyCacheResult> {
  const now = Date.now();
  const cached = workspaceDeviceKeyCaches.get(workspaceId);
  const forceRefreshSatisfiedRecently =
    forceRefresh &&
    now - (workspaceDeviceKeyForceRefreshAt.get(workspaceId) ?? 0) <
      workspaceDeviceKeyForceRefreshCooldownMs;
  if (cached && cached.expiresAt > now && (!forceRefresh || forceRefreshSatisfiedRecently)) {
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
        if (forceRefresh) {
          workspaceDeviceKeyForceRefreshAt.set(workspaceId, Date.now());
        }
      } else {
        workspaceDeviceKeyCaches.delete(workspaceId);
        workspaceDeviceKeyForceRefreshAt.delete(workspaceId);
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
  const signingKeys = new Map<string, HybridSigningPublicKeyMaterial>();
  const historicalSigningKeys = new Map<string, HybridSigningPublicKeyMaterial>();
  const revokedSigningKeys = new Set<string>();
  const rejectedSigningKeys = new Set<string>();
  const signingKeyOwners = new Map<string, string>();
  const currentDevice = deviceState();
  if (!currentDevice?.deviceId) {
    throw new Error("key_directory_pop_device_required");
  }
  const isGuest = authState()?.user.accountType === "guest";

  const [workspaceDirectory, membersResponse, memberNames] = await Promise.all([
    fetchVerifiedKeyDirectory({
      scopeKind: "workspace",
      scopeId: workspaceId,
      popDeviceId: currentDevice.deviceId,
    }),
    isGuest ? Promise.resolve(null) : workspacesApi.listMembers(workspaceId),
    fetchWorkspaceMemberNames(workspaceId),
  ]);
  const activeDirectorySigningKeys = workspaceSigningKeyEntries(workspaceDirectory.checkpoint);
  const memberIds = isGuest
    ? []
    : (membersResponse?.members.map((member) => member.user_id) ??
      workspaceIdentityOwnerIds(workspaceDirectory.checkpoint));

  const memberDevicesResults = await mapWithConcurrencyLimit(
    memberIds,
    MEMBER_DEVICE_FETCH_CONCURRENCY,
    async (memberId) => {
      try {
        const resp = await workspacesApi.listMemberDevices(workspaceId, memberId, true);
        return { userId: memberId, devices: resp.devices };
      } catch (err) {
        if (err instanceof ApiError && err.status === 404) {
          return null;
        }
        throw err;
      }
    },
  );
  const memberDevices = memberDevicesResults.filter((r): r is NonNullable<typeof r> => r !== null);

  for (const { userId, devices } of memberDevices) {
    for (const dev of devices) {
      const deviceMaterial =
        dev.hybrid_signing_public_key_material as unknown as HybridSigningPublicKeyMaterial;
      const keyId = computeSigningKeyId(deviceMaterial);
      const directoryEntry = activeDirectorySigningKeys.get(keyId);
      if (
        !directoryEntry ||
        directoryEntry.material.owner_kind !== "device" ||
        directoryEntry.material.owner_id !== dev.device_id
      ) {
        rejectedSigningKeys.add(keyId);
        continue;
      }

      if (directoryEntry.revoked) {
        historicalSigningKeys.set(keyId, directoryEntry.material);
        revokedSigningKeys.add(keyId);
      } else {
        signingKeys.set(keyId, directoryEntry.material);
      }
      signingKeyOwners.set(keyId, userId);
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
    directorySigningKeys: activeDirectorySigningKeys,
  };
}

function workspaceSigningKeyEntries(
  checkpointEnvelope: Record<string, unknown>,
): DirectorySigningKeyEntries {
  const payload = checkpointEnvelope.payload;
  if (!payload || typeof payload !== "object") throw new Error("key_directory_checkpoint_invalid");
  const deviceKeys = (payload as { device_keys?: unknown }).device_keys;
  const shareParticipantKeys = (payload as { share_participant_keys?: unknown })
    .share_participant_keys;
  if (!Array.isArray(deviceKeys)) throw new Error("key_directory_device_keys_invalid");

  const entries: DirectorySigningKeyEntries = new Map();
  for (const entry of [
    ...deviceKeys,
    ...(Array.isArray(shareParticipantKeys) ? shareParticipantKeys : []),
  ]) {
    if (!entry || typeof entry !== "object") continue;
    const keyEntry = entry as {
      key_id?: unknown;
      key_material?: unknown;
      revoked_at?: unknown;
    };
    const material = keyEntry.key_material as HybridSigningPublicKeyMaterial;
    if (
      typeof keyEntry.key_id !== "string" ||
      !material ||
      material.protocol !== "refmd.hybrid-signing-key-material" ||
      (material.owner_kind !== "device" && material.owner_kind !== "share_participant_device")
    ) {
      continue;
    }
    entries.set(keyEntry.key_id, {
      material,
      revoked: keyEntry.revoked_at !== undefined,
    });
  }
  return entries;
}

function workspaceIdentityOwnerIds(checkpointEnvelope: Record<string, unknown>): string[] {
  const payload = checkpointEnvelope.payload as Record<string, unknown> | undefined;
  const identityKeys = Array.isArray(payload?.identity_keys) ? payload.identity_keys : [];
  const ids = new Set<string>();
  for (const entry of identityKeys) {
    if (!entry || typeof entry !== "object") continue;
    const keyEntry = entry as {
      key_material?: unknown;
      revoked_at?: unknown;
    };
    if (keyEntry.revoked_at !== undefined) continue;
    const material = keyEntry.key_material as { owner_kind?: unknown; owner_id?: unknown };
    if (material?.owner_kind === "identity" && typeof material.owner_id === "string") {
      ids.add(material.owner_id);
    }
  }
  return [...ids];
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
  const now = Date.now();
  const cached = shareVerificationDirectoryCache.get(documentId);
  const forceRefreshSatisfiedRecently =
    forceRefresh &&
    now - (shareVerificationDirectoryForceRefreshAt.get(documentId) ?? 0) <
      shareVerificationDirectoryForceRefreshCooldownMs;
  if (cached && cached.expiresAt > now && (!forceRefresh || forceRefreshSatisfiedRecently)) {
    return cached.directory;
  }

  const pending = pendingShareVerificationDirectoryFetches.get(documentId);
  if (pending) return pending;

  const fetchDirectory = (async () => {
    try {
      const directory = normalizeShareVerificationDirectory(
        await sharesApi.getDocumentShareVerificationDirectory(documentId),
      );
      shareVerificationDirectoryCache.set(documentId, {
        directory,
        expiresAt: Date.now() + shareVerificationDirectoryCacheTtlMs,
      });
      if (forceRefresh) {
        shareVerificationDirectoryForceRefreshAt.set(documentId, Date.now());
      }
      return directory;
    } catch (error) {
      if (error instanceof ApiError && error.status === 429) {
        shareVerificationDirectoryCache.set(documentId, {
          directory: null,
          expiresAt: Date.now() + shareVerificationDirectoryForceRefreshCooldownMs,
        });
        if (forceRefresh) {
          shareVerificationDirectoryForceRefreshAt.set(documentId, Date.now());
        }
        return null;
      }
      if (error instanceof TypeError) {
        shareVerificationDirectoryCache.set(documentId, {
          directory: null,
          expiresAt: Date.now() + shareVerificationDirectoryForceRefreshCooldownMs,
        });
        if (forceRefresh) {
          shareVerificationDirectoryForceRefreshAt.set(documentId, Date.now());
        }
        return null;
      }
      throw error;
    }
  })();
  pendingShareVerificationDirectoryFetches.set(documentId, fetchDirectory);
  try {
    return await fetchDirectory;
  } finally {
    pendingShareVerificationDirectoryFetches.delete(documentId);
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
    directorySigningKeys: new Map(result.directorySigningKeys),
  };
}
function cloneDeviceKeyCacheResult(result: DeviceKeyCacheResult): DeviceKeyCacheResult {
  return result.status === "ok" ? cloneSuccessfulDeviceKeyCacheResult(result) : result;
}

function shareDeviceDirectoryKey(access: SharedDocumentAccess): string {
  const workspaceDevices = access.verificationDirectory.workspace_devices
    .map((device) => {
      const material = device.hybrid_signing_public_key_material;
      const signingKey = material ? computeSigningKeyId(material) : "missing";
      return [
        "w",
        device.user_id,
        device.device_id,
        device.historical === true ? "historical" : "active",
        signingKey,
      ].join(":");
    })
    .sort()
    .join("|");
  const shareParticipantDevices = access.verificationDirectory.share_participant_devices
    .map((device) => {
      const material = device.hybrid_signing_public_key_material;
      const signingKey = material ? computeSigningKeyId(material) : "missing";
      return [
        "p",
        device.share_id,
        device.principal_id,
        device.device_id,
        device.historical === true ? "historical" : "active",
        signingKey,
      ].join(":");
    })
    .sort()
    .join("|");

  return [
    access.documentToken,
    access.shareId,
    access.authorizationShareId ?? "",
    access.participantDeviceId,
    workspaceDevices,
    shareParticipantDevices,
  ].join("::");
}

function initialShareDeviceKeyCacheKey(
  access: SharedDocumentAccess,
  requiredSigningKeys: ReadonlySet<string>,
): string {
  return `${shareDeviceDirectoryKey(access)}::initial:${[...requiredSigningKeys].sort().join("|")}`;
}

function initialDocumentSigningKeyIds(payload: DocumentPayload): Set<string> {
  const keys = new Set<string>();
  if (payload.snapshot?.publicData.signingKeyId) {
    keys.add(payload.snapshot.publicData.signingKeyId);
  }
  for (const update of payload.updates) {
    if (update.publicData.signingKeyId) {
      keys.add(update.publicData.signingKeyId);
    }
  }
  return keys;
}

async function addWorkspaceDirectoryDevicesToCache(
  devices: ShareVerificationWorkspaceDevice[],
  namespace: string,
  signingKeys: Map<string, HybridSigningPublicKeyMaterial>,
  historicalSigningKeys: Map<string, HybridSigningPublicKeyMaterial>,
  directorySigningKeys: DirectorySigningKeyEntries,
  signingKeyOwners: Map<string, string>,
  worker: ReturnType<typeof getCryptoWorker>,
): Promise<DeviceKeyCacheResult | null> {
  const approvalSigningKeys = new Map<string, HybridSigningPublicKeyMaterial>([
    ...signingKeys,
    ...historicalSigningKeys,
  ]);
  for (const [keyId, entry] of directorySigningKeys) {
    if (!entry.revoked && entry.material.owner_kind === "device") {
      approvalSigningKeys.set(keyId, entry.material);
    }
  }
  for (const device of orderWorkspaceDirectoryDevicesForVerification(devices)) {
    const material = device.hybrid_signing_public_key_material;
    if (!material) continue;
    const signingKey = computeSigningKeyId(material);
    const hasSigningKey = signingKeys.has(signingKey);
    const hasHistoricalSigningKey = historicalSigningKeys.has(signingKey);
    const ecdhPk = base64UrlDecode(device.hybrid_encryption_public_key_material.x25519_public);
    const identityWarning = await verifyWorkspaceDirectoryDeviceIdentity(device, worker, {
      namespace,
      allowFirstSeenIdentity: true,
      approvalSigningKeys,
    });
    if (identityWarning) {
      recordSyncPerf("device_key_cache_key_changed", {
        source: "workspace_directory_identity",
        namespace,
        userId: device.user_id,
        deviceId: device.device_id,
      });
      return {
        status: "key_changed",
        warning: { userId: device.user_id, deviceId: device.device_id },
      };
    }

    if (device.historical) {
      if (!hasSigningKey && !hasHistoricalSigningKey) {
        historicalSigningKeys.set(signingKey, material);
      }
      approvalSigningKeys.set(signingKey, material);
      if (!signingKeyOwners.has(signingKey)) {
        signingKeyOwners.set(signingKey, device.user_id);
      }
      continue;
    }

    const tofuResult = await worker.tofuVerify({
      userId: device.user_id,
      deviceId: device.device_id,
      hybridSigningPublicKeyMaterial: material,
      ecdhPublicKey: ecdhPk,
      namespace,
    });

    if (tofuResult.status === "identity_key_changed" || tofuResult.status === "ecdh_key_mismatch") {
      recordSyncPerf("device_key_cache_key_changed", {
        source: "workspace_directory_device_tofu",
        namespace,
        tofuStatus: tofuResult.status,
        userId: device.user_id,
        deviceId: device.device_id,
      });
      return {
        status: "key_changed",
        warning: { userId: device.user_id, deviceId: device.device_id },
      };
    }

    await worker.tofuHandleResult({
      status: tofuResult.status,
      namespace,
      newEntry: {
        userId: device.user_id,
        deviceId: device.device_id,
        hybridSigningPublicKeyMaterial: material,
        ecdhPublicKey: ecdhPk,
        firstSeenAt: Date.now(),
        lastSeenAt: Date.now(),
      },
    });

    if (!hasSigningKey && !hasHistoricalSigningKey) {
      signingKeys.set(signingKey, material);
    }
    approvalSigningKeys.set(signingKey, material);
    if (!signingKeyOwners.has(signingKey)) {
      signingKeyOwners.set(signingKey, device.user_id);
    }
  }

  return null;
}

function orderWorkspaceDirectoryDevicesForVerification(
  devices: ShareVerificationWorkspaceDevice[],
): ShareVerificationWorkspaceDevice[] {
  const rank = (device: ShareVerificationWorkspaceDevice): number => {
    switch (device.approval_signature_surface) {
      case "genesis_device_bootstrap":
        return 0;
      case "recovery_device_approval":
        return 1;
      case "device_approval":
        return 2;
      default:
        return 3;
    }
  };
  return [...devices].sort((a, b) => rank(a) - rank(b));
}

async function addShareParticipantDevicesToCache(
  devices: ShareVerificationParticipantDevice[],
  directorySigningKeys: DirectorySigningKeyEntries,
  signingKeys: Map<string, HybridSigningPublicKeyMaterial>,
  historicalSigningKeys: Map<string, HybridSigningPublicKeyMaterial>,
  signingKeyOwners: Map<string, string>,
  memberNames: Map<string, string>,
  revokedSigningKeys: Set<string>,
  rejectedSigningKeys: Set<string>,
  worker: ReturnType<typeof getCryptoWorker>,
): Promise<DeviceKeyCacheResult | null> {
  for (const device of devices) {
    const namespace = `refmd.v2.share:${device.share_id}`;
    const material = device.hybrid_signing_public_key_material;
    if (!material) continue;
    const signingKey = computeSigningKeyId(material);
    if (signingKeys.has(signingKey) || historicalSigningKeys.has(signingKey)) {
      continue;
    }
    if (!device.hybrid_encryption_public_key_material) continue;
    const ecdhPk = base64UrlDecode(device.hybrid_encryption_public_key_material.x25519_public);
    const directoryEntry = directorySigningKeys.get(signingKey);
    if (
      !directoryEntry ||
      directoryEntry.material.owner_kind !== "share_participant_device" ||
      directoryEntry.material.owner_id !== device.device_id
    ) {
      rejectedSigningKeys.add(signingKey);
      continue;
    }
    if (directoryEntry.revoked) {
      historicalSigningKeys.set(signingKey, directoryEntry.material);
      revokedSigningKeys.add(signingKey);
      signingKeyOwners.set(signingKey, device.principal_id);
      continue;
    }

    if (device.historical) {
      historicalSigningKeys.set(signingKey, material);
      signingKeyOwners.set(signingKey, device.principal_id);
      continue;
    }

    const tofuResult = await worker.tofuVerify({
      userId: device.principal_id,
      deviceId: device.device_id,
      hybridSigningPublicKeyMaterial: material,
      ecdhPublicKey: ecdhPk,
      namespace,
    });

    if (tofuResult.status === "identity_key_changed" || tofuResult.status === "ecdh_key_mismatch") {
      recordSyncPerf("device_key_cache_key_changed", {
        source: "share_participant_device_tofu",
        namespace,
        tofuStatus: tofuResult.status,
        userId: device.principal_id,
        deviceId: device.device_id,
      });
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
        hybridSigningPublicKeyMaterial: material,
        ecdhPublicKey: ecdhPk,
        firstSeenAt: Date.now(),
        lastSeenAt: Date.now(),
      },
    });

    if (device.historical) {
      historicalSigningKeys.set(signingKey, material);
    } else {
      signingKeys.set(signingKey, material);
    }
    signingKeyOwners.set(signingKey, device.principal_id);
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

export function prewarmShareDocumentSigningKeyCaches(access: SharedDocumentAccess): void {
  const initialDocument = access.initialDocument;
  const prewarm = initialDocument
    ? buildShareDeviceKeyCachesForPayload(access, initialDocument)
    : buildShareDeviceKeyCaches(access);

  void prewarm.catch((error: unknown) => {
    recordSyncPerf("share_device_key_cache_prewarm_failed", {
      documentToken: access.documentToken,
      error: error instanceof Error ? error.message : String(error),
    });
  });
}

export async function buildDocumentSigningKeyCachesForInitialPayload(
  state: DocumentState,
  payload: DocumentPayload,
  signal?: AbortSignal,
): Promise<DeviceKeyCacheResult> {
  if (state.access.kind !== "share") {
    return buildDocumentSigningKeyCaches(state, signal);
  }
  return buildShareDeviceKeyCachesForPayload(state.access, payload, signal);
}

function buildShareDeviceKeyCachesForPayload(
  access: SharedDocumentAccess,
  payload: DocumentPayload,
  signal?: AbortSignal,
): Promise<DeviceKeyCacheResult> {
  return buildShareDeviceKeyCachesForSigningKeys(
    access,
    initialDocumentSigningKeyIds(payload),
    signal,
  );
}

function buildShareDeviceKeyCachesForSigningKeys(
  access: SharedDocumentAccess,
  requiredSigningKeys: ReadonlySet<string>,
  signal?: AbortSignal,
): Promise<DeviceKeyCacheResult> {
  if (signal?.aborted) {
    throw new DOMException("Aborted", "AbortError");
  }
  if (requiredSigningKeys.size === 0) {
    return Promise.resolve({
      status: "ok",
      signingKeys: new Map(),
      historicalSigningKeys: new Map(),
      signingKeyOwners: new Map(),
      memberNames: new Map(),
      revokedSigningKeys: new Set(),
      rejectedSigningKeys: new Set(),
      directorySigningKeys: new Map(),
    });
  }

  const cacheKey = initialShareDeviceKeyCacheKey(access, requiredSigningKeys);
  const cached = initialShareDeviceKeyCaches.get(cacheKey);
  if (cached && cached.expiresAt > Date.now()) {
    return Promise.resolve(cloneSuccessfulDeviceKeyCacheResult(cached.result));
  }
  if (cached) {
    initialShareDeviceKeyCaches.delete(cacheKey);
  }
  const pending = pendingInitialShareDeviceKeyCaches.get(cacheKey);
  if (pending) {
    return pending.then(cloneDeviceKeyCacheResult);
  }

  const build = doBuildShareDeviceKeyCaches(access, signal, requiredSigningKeys).then(
    (result) => {
      pendingInitialShareDeviceKeyCaches.delete(cacheKey);
      if (result.status === "ok") {
        initialShareDeviceKeyCaches.set(cacheKey, {
          result: cloneSuccessfulDeviceKeyCacheResult(result),
          expiresAt: Date.now() + shareDeviceKeyCacheTtlMs,
        });
      } else {
        initialShareDeviceKeyCaches.delete(cacheKey);
      }
      return result;
    },
    (error) => {
      pendingInitialShareDeviceKeyCaches.delete(cacheKey);
      initialShareDeviceKeyCaches.delete(cacheKey);
      throw error;
    },
  );
  pendingInitialShareDeviceKeyCaches.set(cacheKey, build);
  return build.then(cloneDeviceKeyCacheResult);
}

async function buildShareDeviceKeyCaches(
  access: SharedDocumentAccess,
  signal?: AbortSignal,
): Promise<DeviceKeyCacheResult> {
  if (signal?.aborted) {
    throw new DOMException("Aborted", "AbortError");
  }
  const cacheKey = shareDeviceDirectoryKey(access);
  const cached = shareDeviceKeyCaches.get(cacheKey);
  if (cached && cached.expiresAt > Date.now()) {
    return cloneSuccessfulDeviceKeyCacheResult(cached.result);
  }
  if (cached) {
    shareDeviceKeyCaches.delete(cacheKey);
  }
  const pending = pendingShareDeviceKeyCaches.get(cacheKey);
  if (pending) {
    return pending.then(cloneDeviceKeyCacheResult);
  }

  const build = doBuildShareDeviceKeyCaches(access, signal).then(
    (result) => {
      pendingShareDeviceKeyCaches.delete(cacheKey);
      if (result.status === "ok") {
        shareDeviceKeyCaches.set(cacheKey, {
          result: cloneSuccessfulDeviceKeyCacheResult(result),
          expiresAt: Date.now() + shareDeviceKeyCacheTtlMs,
        });
      } else {
        shareDeviceKeyCaches.delete(cacheKey);
      }
      return result;
    },
    (error) => {
      pendingShareDeviceKeyCaches.delete(cacheKey);
      shareDeviceKeyCaches.delete(cacheKey);
      throw error;
    },
  );
  pendingShareDeviceKeyCaches.set(cacheKey, build);
  return build.then(cloneDeviceKeyCacheResult);
}

async function doBuildShareDeviceKeyCaches(
  access: SharedDocumentAccess,
  signal?: AbortSignal,
  requiredSigningKeys?: ReadonlySet<string>,
): Promise<DeviceKeyCacheResult> {
  if (signal?.aborted) {
    throw new DOMException("Aborted", "AbortError");
  }
  const startedAt = performance.now();
  recordSyncPerf("share_device_key_cache_start", {
    documentToken: access.documentToken,
    workspaceDeviceCount: access.verificationDirectory.workspace_devices.length,
    shareParticipantDeviceCount: access.verificationDirectory.share_participant_devices.length,
  });
  const worker = getCryptoWorker();
  const signingKeys = new Map<string, HybridSigningPublicKeyMaterial>();
  const historicalSigningKeys = new Map<string, HybridSigningPublicKeyMaterial>();
  const revokedSigningKeys = new Set<string>();
  const rejectedSigningKeys = new Set<string>();
  const signingKeyOwners = new Map<string, string>();
  const memberNames = new Map<string, string>();
  const namespace = getShareTofuNamespace(access);
  const deferTofuPersistence = Boolean(requiredSigningKeys);
  const approvalSigningKeys = new Map<string, HybridSigningPublicKeyMaterial>();
  for (const checkpoint of [
    access.workspaceKeyDirectoryLatestCheckpoint,
    access.workspaceKeyDirectoryCheckpoint,
  ]) {
    if (!checkpoint) continue;
    for (const [keyId, entry] of workspaceSigningKeyEntries(checkpoint)) {
      if (!entry.revoked && entry.material.owner_kind === "device") {
        approvalSigningKeys.set(keyId, entry.material);
      }
    }
  }

  const processDirectoryEntry = async (
    ownerId: string,
    deviceId: string,
    material: HybridSigningPublicKeyMaterial,
    encryptionPublicKey: string,
    displayName?: string,
    historical = false,
    workspaceDevice?: ShareVerificationWorkspaceDevice,
  ): Promise<DeviceKeyCacheResult | null> => {
    const signingKey = computeSigningKeyId(material);
    if (requiredSigningKeys && !requiredSigningKeys.has(signingKey)) {
      return null;
    }
    const hasSigningKey = signingKeys.has(signingKey);
    const hasHistoricalSigningKey = historicalSigningKeys.has(signingKey);
    const ecdhPk = base64UrlDecode(encryptionPublicKey);
    if (workspaceDevice) {
      const identityWarning = await verifyWorkspaceDirectoryDeviceIdentity(
        workspaceDevice,
        worker,
        {
          namespace,
          allowFirstSeenIdentity: true,
          deferTofuPersistence,
          approvalSigningKeys,
        },
      );
      if (identityWarning) {
        return {
          status: "key_changed",
          warning: { userId: ownerId, deviceId },
        };
      }
    }

    if (hasSigningKey || hasHistoricalSigningKey) {
      approvalSigningKeys.set(signingKey, material);
      return null;
    }

    if (historical) {
      historicalSigningKeys.set(signingKey, material);
      signingKeyOwners.set(signingKey, ownerId);
      approvalSigningKeys.set(signingKey, material);
      return null;
    }

    const tofuNamespace = namespace;

    const tofuResult = await worker.tofuVerify({
      userId: ownerId,
      deviceId,
      hybridSigningPublicKeyMaterial: material,
      ecdhPublicKey: ecdhPk,
      ...(tofuNamespace ? { namespace: tofuNamespace } : {}),
    });

    if (tofuResult.status === "identity_key_changed" || tofuResult.status === "ecdh_key_mismatch") {
      return {
        status: "key_changed",
        warning: { userId: ownerId, deviceId },
      };
    }

    const persistTofuResult = worker.tofuHandleResult({
      status: tofuResult.status,
      ...(tofuNamespace ? { namespace: tofuNamespace } : {}),
      newEntry: {
        userId: ownerId,
        deviceId,
        hybridSigningPublicKeyMaterial: material,
        ecdhPublicKey: ecdhPk,
        firstSeenAt: Date.now(),
        lastSeenAt: Date.now(),
      },
    });
    if (deferTofuPersistence) {
      void persistTofuResult.catch((error: unknown) => {
        recordSyncPerf("share_device_key_cache_tofu_persist_failed", {
          documentToken: access.documentToken,
          error: error instanceof Error ? error.message : String(error),
        });
      });
    } else {
      await persistTofuResult;
    }

    if (historical) {
      historicalSigningKeys.set(signingKey, material);
    } else {
      signingKeys.set(signingKey, material);
    }
    approvalSigningKeys.set(signingKey, material);
    signingKeyOwners.set(signingKey, ownerId);
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
        device.hybrid_signing_public_key_material,
        device.hybrid_encryption_public_key_material.x25519_public,
        undefined,
        device.historical === true,
        device,
      );

      if (warning) return warning;
    }

    for (const device of directory.share_participant_devices) {
      if (!device.hybrid_encryption_public_key_material) {
        return {
          status: "key_changed",
          warning: { userId: device.principal_id, deviceId: device.device_id },
        } satisfies DeviceKeyCacheResult;
      }

      const warning = await processDirectoryEntry(
        device.principal_id,
        device.device_id,
        device.hybrid_signing_public_key_material,
        device.hybrid_encryption_public_key_material.x25519_public,
        device.display_name ?? undefined,
        device.historical === true,
      );

      if (warning) return warning;
    }

    return null;
  };

  const warning = await processDirectory(access.verificationDirectory);
  if (warning) return warning;
  recordSyncPerf("share_device_key_cache_ready", {
    documentToken: access.documentToken,
    elapsedMs: performance.now() - startedAt,
    signingKeyCount: signingKeys.size,
    historicalSigningKeyCount: historicalSigningKeys.size,
  });

  return {
    status: "ok",
    signingKeys,
    historicalSigningKeys,
    signingKeyOwners,
    memberNames,
    revokedSigningKeys,
    rejectedSigningKeys,
    directorySigningKeys: new Map(),
  };
}

// ── Resolve signing key ──────────────────────────────────────
// Cache lookup with a fresh re-fetch on miss.

export async function resolveSigningKey(
  pubKeyB64: string,
  state: DocumentState,
  options: { includeHistorical?: boolean } = {},
): Promise<ResolveSigningKeyResult> {
  // 1. Check cache
  const cached = state.signingKeys.get(pubKeyB64);
  if (cached) {
    const ownerId = state.signingKeyOwners.get(pubKeyB64);
    if (ownerId) return { status: "found", key: cached, ownerId };
  }
  if (options.includeHistorical) {
    const historical = state.historicalSigningKeys.get(pubKeyB64);
    if (historical) {
      const ownerId = state.signingKeyOwners.get(pubKeyB64);
      if (ownerId) return { status: "found", key: historical, ownerId };
    }
  }

  for (const delayMs of [0, ...SIGNING_KEY_REFRESH_RETRY_DELAYS_MS]) {
    if (delayMs > 0) {
      await sleep(delayMs);
    }

    const result =
      state.access.kind === "share"
        ? await refreshSharedDocumentAccess(state).then((access) =>
            buildShareDeviceKeyCaches(access),
          )
        : await buildDeviceKeyCaches(state.workspaceId, undefined, state.documentId, true);
    if (result.status === "key_changed") {
      return { status: "key_changed", warning: result.warning };
    }

    applyDeviceKeyCache(state, result);

    const resolved = lookupCachedSigningKey(pubKeyB64, state, options);
    if (resolved) {
      return resolved;
    }
  }
  return { status: "not_found" };
}

export function lookupCachedSigningKey(
  pubKeyB64: string,
  state: DocumentState,
  options: { includeHistorical?: boolean },
): Extract<ResolveSigningKeyResult, { status: "found" }> | null {
  const active = state.signingKeys.get(pubKeyB64);
  if (active) {
    const ownerId = state.signingKeyOwners.get(pubKeyB64);
    if (ownerId) return { status: "found", key: active, ownerId };
  }
  if (options.includeHistorical) {
    const historical = state.historicalSigningKeys.get(pubKeyB64);
    if (historical) {
      const ownerId = state.signingKeyOwners.get(pubKeyB64);
      if (ownerId) return { status: "found", key: historical, ownerId };
    }
  }
  return null;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
