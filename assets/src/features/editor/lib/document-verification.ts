import { base64UrlDecode } from "@/shared/lib/crypto/encoding";
import { getCryptoWorker } from "@/shared/lib/crypto/worker/client";
import { encryptionApi } from "@/shared/api/encryption";
import { workspacesApi } from "@/shared/api/workspaces";
import { ApiError } from "@/shared/api/core";
import type { DocumentState } from "./document-state-cache";

// ── Types ────────────────────────────────────────────────────

export interface TofuKeyChangeWarning {
  userId: string;
  deviceId?: string;
  oldFingerprint?: string;
  newFingerprint?: string;
}

type DeviceKeyCacheResult =
  | {
      status: "ok";
      signingKeys: Map<string, Uint8Array>;
      signingKeyOwners: Map<string, string>;
      memberNames: Map<string, string>;
      revokedSigningKeys: Set<string>;
      rejectedSigningKeys: Set<string>;
    }
  | { status: "key_changed"; warning: TofuKeyChangeWarning };

export type ResolveSigningKeyResult =
  | { status: "found"; key: Uint8Array }
  | { status: "not_found" }
  | { status: "key_changed"; warning: TofuKeyChangeWarning };

// ── Build device key caches ──────────────────────────────────
// Implements the device resolution flow:
//   1. Get workspace members' Identity public keys
//   2. TOFU verify each member's Identity key (via Worker)
//   3. Get each member's device list
//   4. Verify each device's identity_signature cross-sign (via Worker)
//   5. Cache verified device signing keys

const pendingWorkspaceDeviceKeyCaches = new Map<string, Promise<DeviceKeyCacheResult>>();
const MEMBER_DEVICE_FETCH_CONCURRENCY = 2;

export async function buildDeviceKeyCaches(
  workspaceId: string,
  signal?: AbortSignal,
): Promise<DeviceKeyCacheResult> {
  const pending = pendingWorkspaceDeviceKeyCaches.get(workspaceId);
  if (pending) return pending;

  const refresh = doBuildDeviceKeyCaches(workspaceId, signal).then(
    (result) => {
      pendingWorkspaceDeviceKeyCaches.delete(workspaceId);
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

async function doBuildDeviceKeyCaches(
  workspaceId: string,
  signal?: AbortSignal,
): Promise<DeviceKeyCacheResult> {
  const worker = getCryptoWorker();
  const signingKeys = new Map<string, Uint8Array>();
  const revokedSigningKeys = new Set<string>();
  const rejectedSigningKeys = new Set<string>();
  const signingKeyOwners = new Map<string, string>();

  // Step 1: Get member Identity public keys
  const memberKeysResponse = await encryptionApi.getWorkspaceMemberKeys(workspaceId, { signal });

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

  const memberNames = new Map<string, string>();

  // Step 3: Get each member's devices (using user_ids from /member-keys, not /members)
  const memberDevicesResults = await mapWithConcurrencyLimit(
    memberKeysResponse.members,
    MEMBER_DEVICE_FETCH_CONCURRENCY,
    async (member) => {
      try {
        const resp = await workspacesApi.listMemberDevices(workspaceId, member.user_id, true, {
          signal,
        });
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

      // Cache verified device signing key
      signingKeys.set(dev.signing_public_key, deviceSigningPk);
      signingKeyOwners.set(dev.signing_public_key, userId);
      if (dev.revoked_at) {
        revokedSigningKeys.add(dev.signing_public_key);
      }
    }
  }

  return {
    status: "ok",
    signingKeys,
    signingKeyOwners,
    memberNames,
    revokedSigningKeys,
    rejectedSigningKeys,
  };
}

async function mapWithConcurrencyLimit<T, R>(
  items: readonly T[],
  concurrency: number,
  mapper: (item: T, index: number) => Promise<R>,
): Promise<R[]> {
  if (items.length === 0) return [];

  const results = new Array<R>(items.length);
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

// ── Resolve signing key ──────────────────────────────────────
// Cache lookup with re-fetch on miss (dedup concurrent re-fetches).

const pendingRefreshes = new Map<string, Promise<DeviceKeyCacheResult>>();

export async function resolveSigningKey(
  pubKeyB64: string,
  state: DocumentState,
): Promise<ResolveSigningKeyResult> {
  // 1. Check cache
  const cached = state.signingKeys.get(pubKeyB64);
  if (cached) return { status: "found", key: cached };

  // 2. Re-fetch with dedup
  const dedupKey = state.workspaceId;
  let refresh = pendingRefreshes.get(dedupKey);
  if (!refresh) {
    refresh = buildDeviceKeyCaches(state.workspaceId).then(
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
  return { status: "not_found" };
}
