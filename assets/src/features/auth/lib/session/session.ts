import { base64UrlDecode } from "@/shared/lib/crypto/encoding";
import type { HybridSigningPublicKeyMaterial } from "@/shared/lib/crypto/signature-types";
import { authApi, ApiError, devicesApi } from "@/shared/api";
import { getCryptoWorker, isTofuHardFail } from "@/shared/lib/crypto/worker/client";
import { getPersistedDeviceId } from "@/shared/lib/auth/key-persistence";
import {
  setAuthState,
  setCryptoWorkerReady,
  setFullSession,
  setTofuErrors,
} from "@/entities/session";
import {
  getAllOfflineDocumentMetas,
  ensureOfflineDbReady,
} from "@/shared/lib/offline/storage/store";
import type { DeviceInfo } from "@/shared/api/devices";
export interface SessionRestoreResult {
  userId: string;
  email: string;
  name: string;
  accountType?: string | null;
  sessionId: string;
  deviceId: string | null;
  deviceVerified: boolean;
  expiresAt: string;
  needsPasswordReentry: boolean;
  tofuWarnings: string[];
  identityHybridSigningPublicKeyMaterial: HybridSigningPublicKeyMaterial | null;
  identityEcdhPublic: Uint8Array | null;
  deviceSigningKeyId: string | null;
  deviceKeyCheckpointSequence: number | null;
  deviceKeyCheckpointHash: string | null;
  deviceHybridSigningPublicKeyMaterial: HybridSigningPublicKeyMaterial | null;
  deviceEcdhPublic: Uint8Array | null;
  workerReady: boolean;
}
type SessionRestoreError = "rate_limited" | "transient_error";
let restoreSessionInFlight: Promise<SessionRestoreResult | SessionRestoreError | null> | null =
  null;

export function applyRestoredSessionState(result: SessionRestoreResult): void {
  const auth = {
    user: {
      id: result.userId,
      email: result.email,
      name: result.name,
      accountType: result.accountType,
    },
    sessionId: result.sessionId,
    identityHybridSigningPublicKeyMaterial: result.identityHybridSigningPublicKeyMaterial,
    identityEcdhPublic: result.identityEcdhPublic,
    expiresAt: result.expiresAt,
    needsPasswordReentry: result.needsPasswordReentry,
  };

  if (result.deviceId) {
    setFullSession(auth, {
      deviceId: result.deviceId,
      deviceSigningKeyId: result.deviceSigningKeyId,
      deviceKeyCheckpointSequence: result.deviceKeyCheckpointSequence,
      deviceKeyCheckpointHash: result.deviceKeyCheckpointHash,
      deviceHybridSigningPublicKeyMaterial: result.deviceHybridSigningPublicKeyMaterial,
      deviceEcdhPublic: result.deviceEcdhPublic,
    });
  } else {
    setAuthState(auth);
  }

  if (result.workerReady) {
    setCryptoWorkerReady(true);
  }

  setTofuErrors(result.tofuWarnings);
}
export async function restoreSession(): Promise<SessionRestoreResult | SessionRestoreError | null> {
  if (restoreSessionInFlight) return restoreSessionInFlight;

  restoreSessionInFlight = restoreSessionInternal().finally(() => {
    restoreSessionInFlight = null;
  });
  return restoreSessionInFlight;
}

async function restoreSessionInternal(): Promise<
  SessionRestoreResult | SessionRestoreError | null
> {
  try {
    const me = await authApi.me();
    const worker = getCryptoWorker();
    let workerReady = false;
    let needsPasswordReentry = false;
    const deviceId = me.device_id ?? getPersistedDeviceId(me.user_id);
    // Attempt Crypto Worker initialization from DSK (IndexedDB)
    const hasStoredDsk = await worker.hasStoredDsk();
    const cachedBootstrap = hasStoredDsk
      ? await worker.loadAuthBootstrap().catch(() => null)
      : null;
    const trustedCachedBootstrap =
      cachedBootstrap?.userId === me.user_id && cachedBootstrap.deviceId === deviceId
        ? cachedBootstrap
        : null;
    const hasStoredDeviceKeys =
      hasStoredDsk && deviceId && trustedCachedBootstrap
        ? await worker.hasStoredDeviceKeys().catch(() => false)
        : false;
    if (hasStoredDeviceKeys && deviceId && trustedCachedBootstrap) {
      try {
        await worker.init({
          dsk: null,
          useStoredDsk: true,
          userId: me.user_id,
          deviceId,
          deviceSigningKeyId: trustedCachedBootstrap.deviceSigningKeyId,
          keyRestoreEndpointRef: me.key_restore_endpoint_ref ?? null,
        });
        workerReady = await worker.isReady();
      } catch {
        workerReady = false;
      }
    }
    if (!workerReady && me.device_verified) {
      if (me.auth_type === "password" && hasStoredDeviceKeys) {
        needsPasswordReentry = true;
      } else if (me.auth_type === "password") {
        // The server session is still authenticated, but this browser cannot prove the
        // current device after local key loss. Keep the session and force device recovery.
        me.device_verified = false;
      } else {
        // OAuth without DSK: treat as new device (approval or recovery required)
        me.device_verified = false;
      }
    }
    // Get public keys from Worker (if ready)
    let identityHybridSigningPublicKeyMaterial: HybridSigningPublicKeyMaterial | null = null;
    let identityEcdhPublic: Uint8Array | null = null;
    let deviceSigningKeyId: string | null = trustedCachedBootstrap?.deviceSigningKeyId ?? null;
    let deviceHybridSigningPublicKeyMaterial: HybridSigningPublicKeyMaterial | null = null;
    let deviceEcdhPublic: Uint8Array | null = null;
    if (workerReady) {
      try {
        const pubKeys = await worker.getPublicKeys();
        identityHybridSigningPublicKeyMaterial =
          pubKeys.identityHybridSigningPublicKeyMaterial ?? null;
        identityEcdhPublic = pubKeys.identityEcdhPublic;
        deviceSigningKeyId = pubKeys.deviceSigningKeyId;
        deviceHybridSigningPublicKeyMaterial = pubKeys.deviceHybridSigningPublicKeyMaterial ?? null;
        deviceEcdhPublic = pubKeys.deviceEcdhPublic;
      } catch {
        // Public key retrieval failed
      }
    }
    // TOFU verification (runs inside Worker)
    let tofuWarnings: string[] = [];
    if (workerReady && me.device_verified && deviceId) {
      try {
        const { devices } = await devicesApi.list({ rrpDeviceId: deviceId });
        const tofuResult = await worker.tofuVerifyAllDevices({
          devices: devices.map((d: DeviceInfo) => ({
            name: d.name,
            userId: me.user_id,
            deviceId: d.id,
            ecdhPublicKey: base64UrlDecode(d.hybrid_encryption_public_key_material.x25519_public),
            deviceHybridSigningPublicKeyMaterial: d.hybrid_signing_public_key_material,
            deviceHybridEncryptionPublicKeyMaterial: d.hybrid_encryption_public_key_material,
            identitySignature: d.approval_signature,
            identitySignaturePurpose: d.approval_signature_surface,
            identitySignatureContext: d.approval_proof,
            approvalDeliveryCommitments: d.approval_delivery_commitments,
            approvalDeliveryArtifacts: d.approval_delivery_artifacts,
            clientNonce: d.client_nonce,
          })),
        });
        tofuWarnings = tofuResult.errors;
      } catch (e) {
        if (isTofuHardFail(e)) {
          throw e;
        }
      }
    }
    // Cache user info (DSK-encrypted) for offline session restoration
    if (hasStoredDsk && deviceId && deviceSigningKeyId) {
      worker
        .storeAuthBootstrap({
          userId: me.user_id,
          email: me.email,
          name: me.name,
          deviceId,
          deviceSigningKeyId,
          cachedAt: Date.now(),
        })
        .catch(() => {});
    }
    return {
      userId: me.user_id,
      email: me.email,
      name: me.name,
      accountType: me.account_type,
      sessionId: me.session_id,
      deviceId: deviceId ?? null,
      deviceVerified: me.device_verified,
      expiresAt: me.expires_at,
      needsPasswordReentry,
      tofuWarnings,
      identityHybridSigningPublicKeyMaterial,
      identityEcdhPublic,
      deviceSigningKeyId,
      deviceKeyCheckpointSequence: me.device_key_checkpoint_sequence ?? null,
      deviceKeyCheckpointHash: me.device_key_checkpoint_hash ?? null,
      deviceHybridSigningPublicKeyMaterial,
      deviceEcdhPublic,
      workerReady,
    };
  } catch (err) {
    if (isTofuHardFail(err)) throw err;
    if (err instanceof ApiError) {
      if (err.status === 401 || err.status === 403) return null;
      if (err.status === 429) return "rate_limited";
    }
    return "transient_error";
  }
}

export interface OfflineSessionResult {
  userId: string;
  email: string;
  name: string;
  deviceId: string;
  workerReady: boolean;
  deviceSigningKeyId: string | null;
  deviceHybridSigningPublicKeyMaterial: HybridSigningPublicKeyMaterial | null;
  deviceEcdhPublic: Uint8Array | null;
}
export async function restoreOfflineSession(): Promise<OfflineSessionResult | null> {
  try {
    await ensureOfflineDbReady();
    const worker = getCryptoWorker();
    const cachedUser = await worker.loadAuthBootstrap();
    if (!cachedUser) return null;
    const {
      userId,
      email,
      name,
      deviceId,
      deviceSigningKeyId: cachedDeviceSigningKeyId,
    } = cachedUser;
    if (!deviceId) return null;
    const offlineDocs = await getAllOfflineDocumentMetas();
    if (offlineDocs.length === 0) return null;
    await worker.init({
      dsk: null,
      useStoredDsk: true,
      userId,
      deviceId,
      deviceSigningKeyId: cachedDeviceSigningKeyId,
    });
    // isReady() requires UMK, but offline editing only needs DSK + device keys.
    // For KMSI-disabled sessions after browser restart, UMK is unavailable but
    // the DSK→offline-dek-cache→DEK chain still works for offline document access.
    const workerReady = await worker.isReady();
    let deviceSigningKeyId: string | null = null;
    let deviceHybridSigningPublicKeyMaterial: HybridSigningPublicKeyMaterial | null = null;
    let deviceEcdhPublic: Uint8Array | null = null;
    try {
      const pubKeys = await worker.getPublicKeys();
      deviceSigningKeyId = pubKeys.deviceSigningKeyId;
      deviceHybridSigningPublicKeyMaterial = pubKeys.deviceHybridSigningPublicKeyMaterial ?? null;
      deviceEcdhPublic = pubKeys.deviceEcdhPublic;
    } catch {
      // Best effort
    }
    // Even if !workerReady (no UMK), DSK is set and device keys may be available.
    // Offline document operations (restoreDekFromOffline, decryptOfflineCache) only need DSK.
    return {
      userId,
      email,
      name,
      deviceId,
      workerReady,
      deviceSigningKeyId,
      deviceHybridSigningPublicKeyMaterial,
      deviceEcdhPublic,
    };
  } catch {
    return null;
  }
}
