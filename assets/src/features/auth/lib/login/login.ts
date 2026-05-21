import { base64UrlDecode, base64UrlEncode } from "@/shared/lib/crypto/encoding";
import type { HybridSigningPublicKeyMaterial } from "@/shared/lib/crypto/signature-types";
import { ApiError, authApi, devicesApi } from "@/shared/api";
import { getCryptoWorker, isTofuHardFail } from "@/shared/lib/crypto/worker/client";
import {
  getPersistedDeviceId,
  persistDeviceId,
  persistCurrentKeysWithDsk,
} from "@/shared/lib/auth/key-persistence";
import type { DeviceInfo } from "@/shared/api/devices";
import { AuthError } from "../session/error";
type LoginResult =
  | {
      type: "verified";
      userId: string;
      email: string;
      name: string;
      sessionId: string;
      deviceId: string;
      tofuWarnings: string[];
      workerReady: boolean;
      identityHybridSigningPublicKeyMaterial: HybridSigningPublicKeyMaterial | null;
      identityEcdhPublic: Uint8Array | null;
      deviceSigningKeyId: string | null;
      deviceHybridSigningPublicKeyMaterial: HybridSigningPublicKeyMaterial | null;
      deviceEcdhPublic: Uint8Array | null;
    }
  | {
      type: "device_required";
      userId: string;
      email: string;
      name: string;
      sessionId: string;
    };
export async function login(
  email: string,
  password: string,
  rememberMe: boolean,
): Promise<LoginResult> {
  const worker = getCryptoWorker();
  // Step 1: Get salt and KDF params
  let saltRes = await authApi.getSalt(email);
  // Step 2: Derive keys in Worker (transient password unwrap material, authKey returned)
  // Ensure transient keys are cleared even if subsequent steps throw
  try {
    const { authKey } = await worker.deriveAuthKeys({
      password,
      salt: base64UrlDecode(saltRes.salt),
      kdfParams: saltRes.kdf_params,
    });
    const authKeyBase64 = base64UrlEncode(authKey);
    // Step 3: Authenticate
    let deviceId = getPersistedDeviceId();
    let loginRes: Awaited<ReturnType<typeof authApi.login>>;
    const authenticate = (candidateDeviceId: string | null) =>
      authApi.login({
        email,
        auth_key: authKeyBase64,
        remember_me: rememberMe,
        ...(candidateDeviceId ? { device_id: candidateDeviceId } : {}),
      });
    try {
      loginRes = await authenticate(deviceId);
    } catch (error) {
      if (error instanceof ApiError) {
        const code =
          error.body?.error === "invalid_credentials" ? "invalid_credentials" : "unknown";
        throw new AuthError(code, error.message);
      }
      throw error;
    }
    const userId = loginRes.user.id;
    const userScopedDeviceId = getPersistedDeviceId(userId);
    if (
      (!loginRes.device_verified || !loginRes.keys) &&
      userScopedDeviceId &&
      userScopedDeviceId !== deviceId
    ) {
      loginRes = await authenticate(userScopedDeviceId);
      deviceId = userScopedDeviceId;
    }
    // Step 4: KDF migration uses the canonical login key bundle.
    const migrationUmk = loginRes.keys?.encrypted_umk;
    const migrationNonce = loginRes.keys?.umk_nonce;
    if (
      loginRes.kdf_migration_required &&
      loginRes.target_kdf_params &&
      migrationUmk &&
      migrationNonce
    ) {
      // Init with old password params so the old PUK can unwrap the server UMK.
      await worker.setUserContext(userId);
      await worker.init({
        dsk: null,
        userId,
        deviceId: "",
        serverEncryptedUmk: base64UrlDecode(migrationUmk),
        serverUmkNonce: base64UrlDecode(migrationNonce),
        passwordParams: {
          password,
          salt: base64UrlDecode(saltRes.salt),
          kdfParams: saltRes.kdf_params,
        },
      });
      // Derive new password unwrap material with target params
      const targetParams = loginRes.target_kdf_params;
      const migrationSaltRes = await authApi.getSalt(email);
      const { authKey: newAuthKey } = await worker.deriveAuthKeys({
        password,
        salt: base64UrlDecode(migrationSaltRes.salt),
        kdfParams: targetParams,
      });
      const newWrapped = await worker.wrapUmkForServer(userId);
      await authApi.kdfMigration({
        new_auth_key: base64UrlEncode(newAuthKey),
        new_encrypted_umk: base64UrlEncode(newWrapped.encrypted),
        new_nonce: base64UrlEncode(newWrapped.nonce),
        new_kdf_params: targetParams,
      });
      if (loginRes.keys) {
        loginRes.keys.encrypted_umk = base64UrlEncode(newWrapped.encrypted);
        loginRes.keys.umk_nonce = base64UrlEncode(newWrapped.nonce);
      }
      saltRes = await authApi.getSalt(email);
    }
    // Step 5: Check device status
    if (!loginRes.device_verified || !loginRes.keys) {
      await worker.clearTransientKeys();
      return {
        type: "device_required",
        userId,
        email: loginRes.user.email,
        name: loginRes.user.name,
        sessionId: loginRes.session_id,
      };
    }
    const keys = loginRes.keys;
    // Step 6: Initialize Worker with Worker-owned DSK data + server login keys
    const hadDsk = await worker.hasStoredDsk();
    await worker.setUserContext(userId, deviceId ?? undefined);
    const cachedBootstrap =
      hadDsk && deviceId ? await worker.loadAuthBootstrap().catch(() => null) : null;
    if (
      hadDsk &&
      deviceId &&
      cachedBootstrap?.userId === userId &&
      cachedBootstrap.deviceId === deviceId
    ) {
      await worker.init({
        dsk: null,
        useStoredDsk: true,
        userId,
        deviceId,
        deviceSigningKeyId: cachedBootstrap.deviceSigningKeyId,
        serverEncryptedUmk: base64UrlDecode(keys.encrypted_umk!),
        serverUmkNonce: base64UrlDecode(keys.umk_nonce!),
        encryptedIdentityHybridEncryptionPrivateKeyMaterial: base64UrlDecode(
          keys.encrypted_identity_hybrid_encryption_private_key_material,
        ),
        identityHybridEncryptionPrivateKeyMaterialNonce: base64UrlDecode(
          keys.identity_hybrid_encryption_private_key_material_nonce,
        ),
        identityEncryptionKeyId: keys.identity_encryption_key_id,
        encryptedIdentityHybridSigningPrivateKeyMaterial: base64UrlDecode(
          keys.encrypted_identity_hybrid_signing_private_key_material,
        ),
        identityHybridSigningPrivateKeyMaterialNonce: base64UrlDecode(
          keys.identity_hybrid_signing_private_key_material_nonce,
        ),
        identitySigningKeyId: keys.identity_signing_key_id,
      });
    } else {
      await worker.initFromPassword({
        password,
        salt: base64UrlDecode(saltRes.salt),
        kdfParams: saltRes.kdf_params,
        dsk: null,
        userId,
        deviceId: deviceId ?? "",
        serverEncryptedUmk: base64UrlDecode(keys.encrypted_umk!),
        serverUmkNonce: base64UrlDecode(keys.umk_nonce!),
        encryptedIdentityHybridEncryptionPrivateKeyMaterial: base64UrlDecode(
          keys.encrypted_identity_hybrid_encryption_private_key_material,
        ),
        identityHybridEncryptionPrivateKeyMaterialNonce: base64UrlDecode(
          keys.identity_hybrid_encryption_private_key_material_nonce,
        ),
        identityEncryptionKeyId: keys.identity_encryption_key_id,
        encryptedIdentityHybridSigningPrivateKeyMaterial: base64UrlDecode(
          keys.encrypted_identity_hybrid_signing_private_key_material,
        ),
        identityHybridSigningPrivateKeyMaterialNonce: base64UrlDecode(
          keys.identity_hybrid_signing_private_key_material_nonce,
        ),
        identitySigningKeyId: keys.identity_signing_key_id,
      });
    }
    // Step 7: Persist UMK + device keys (KMSI-aware)
    if (hadDsk) {
      try {
        await persistCurrentKeysWithDsk(userId, { persistUmk: rememberMe });
      } catch {
        // DSK persistence failed; session can continue without adding fallback key caches.
      }
    }
    // Step 8: Check if device keys were restored
    const ready = await worker.isReady();
    let hasDeviceKeys = false;
    if (ready) {
      try {
        const pubKeys = await worker.getPublicKeys();
        hasDeviceKeys = pubKeys.deviceHybridSigningPublicKeyMaterial !== null;
      } catch {
        hasDeviceKeys = false;
      }
    }
    if (!hasDeviceKeys) {
      return {
        type: "device_required",
        userId,
        email: loginRes.user.email,
        name: loginRes.user.name,
        sessionId: loginRes.session_id,
      };
    }
    await worker.setInitialized();
    // Step 9: TOFU verification (in Worker)
    let tofuWarnings: string[] = [];
    try {
      const { devices } = await devicesApi.list({ popDeviceId: deviceId! });
      const tofuResult = await worker.tofuVerifyAllDevices({
        devices: devices.map((d: DeviceInfo) => ({
          name: d.name,
          userId,
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
    const pubKeys = await worker.getPublicKeys();
    const identityHybridSigningPublicKeyMaterial =
      pubKeys.identityHybridSigningPublicKeyMaterial ?? null;
    const deviceHybridSigningPublicKeyMaterial =
      pubKeys.deviceHybridSigningPublicKeyMaterial ?? null;
    if (deviceId && pubKeys.deviceSigningKeyId) {
      persistDeviceId(deviceId, userId);
      await worker
        .storeAuthBootstrap({
          userId,
          email: loginRes.user.email,
          name: loginRes.user.name,
          deviceId,
          deviceSigningKeyId: pubKeys.deviceSigningKeyId,
          cachedAt: Date.now(),
        })
        .catch(() => {
          // Auth bootstrap cache is a cold-start optimization; successful login state is already set.
        });
    }
    return {
      type: "verified",
      userId,
      email: loginRes.user.email,
      name: loginRes.user.name,
      sessionId: loginRes.session_id,
      deviceId: deviceId ?? "",
      tofuWarnings,
      workerReady: true,
      identityHybridSigningPublicKeyMaterial,
      identityEcdhPublic: pubKeys.identityEcdhPublic,
      deviceSigningKeyId: pubKeys.deviceSigningKeyId,
      deviceHybridSigningPublicKeyMaterial,
      deviceEcdhPublic: pubKeys.deviceEcdhPublic,
    };
  } finally {
    await worker.clearTransientKeys().catch(() => {
      // Transient login keys are best-effort cleanup and are replaced on the next auth attempt.
    });
  }
}
