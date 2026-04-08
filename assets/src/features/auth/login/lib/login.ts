import { base64UrlDecode, base64UrlEncode } from "@/shared/lib/crypto/encoding";
import { ApiError, authApi, devicesApi } from "@/shared/api";
import { loadDskInitData, storeWrappedDeviceKeysRaw } from "@/shared/lib/crypto/dsk";
import { getCryptoWorker, isTofuHardFail } from "@/shared/lib/crypto/worker/client";
import {
  getPersistedDeviceId,
  hasPdkData,
  persistPdkWrappedKeys,
  persistWrappedUmk,
  readPdkBlobs,
} from "@/shared/lib/auth/key-persistence";
import type { DeviceInfo } from "@/shared/api/devices";
import type { InitPayload } from "@/shared/lib/crypto/worker/types";
import { AuthError } from "../../lib/auth-error";
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
      identitySigningPublic: Uint8Array | null;
      identityEcdhPublic: Uint8Array | null;
      deviceSigningPublic: Uint8Array | null;
      deviceEcdhPublic: Uint8Array | null;
    }
  | {
      type: "device_required";
      userId: string;
      email: string;
      name: string;
      sessionId: string;
    };
type PdkBlobFields = Pick<
  InitPayload,
  "pdkWrappedUmk" | "pdkWrappedDeviceEcdh" | "pdkWrappedDeviceSigning"
>;
export async function login(
  email: string,
  password: string,
  rememberMe: boolean,
): Promise<LoginResult> {
  const worker = getCryptoWorker();
  // Step 1: Get salt and KDF params
  let saltRes = await authApi.getSalt(email);
  // Step 2: Derive keys in Worker (PUK/PDK stored in Worker, authKey returned)
  // Ensure transient keys are cleared even if subsequent steps throw
  try {
    const { authKey } = await worker.deriveAuthKeys({
      password,
      salt: base64UrlDecode(saltRes.salt),
      kdfParams: saltRes.kdf_params,
    });
    const authKeyBase64 = base64UrlEncode(authKey);
    // Step 3: Authenticate
    const deviceId = getPersistedDeviceId();
    let loginRes: Awaited<ReturnType<typeof authApi.login>>;
    try {
      loginRes = await authApi.login({
        email,
        auth_key: authKeyBase64,
        remember_me: rememberMe,
        ...(deviceId ? { device_id: deviceId } : {}),
      });
    } catch (error) {
      if (error instanceof ApiError) {
        const code =
          error.body?.error === "invalid_credentials" ? "invalid_credentials" : "unknown";
        throw new AuthError(code, error.message);
      }
      throw error;
    }
    const userId = loginRes.user.id;
    const { pdkWrappedUmk, pdkWrappedDeviceEcdh, pdkWrappedDeviceSigning } = readPdkBlobs();
    const pdkBlobs: PdkBlobFields =
      pdkWrappedUmk && pdkWrappedDeviceEcdh && pdkWrappedDeviceSigning
        ? {
            pdkWrappedUmk,
            pdkWrappedDeviceEcdh,
            pdkWrappedDeviceSigning,
          }
        : {};
    // Step 4: KDF migration (before device check — encrypted_umk is available at top level)
    const migrationUmk = loginRes.encrypted_umk ?? loginRes.keys?.encrypted_umk;
    const migrationNonce = loginRes.umk_nonce ?? loginRes.keys?.umk_nonce;
    if (
      loginRes.kdf_migration_required &&
      loginRes.target_kdf_params &&
      migrationUmk &&
      migrationNonce
    ) {
      // Init with old password params: derives old PDK internally to restore device keys
      await worker.setUserContext(userId);
      await worker.init({
        dsk: null,
        userId,
        deviceId: "",
        serverEncryptedUmk: base64UrlDecode(migrationUmk),
        serverUmkNonce: base64UrlDecode(migrationNonce),
        ...pdkBlobs,
        passwordParams: {
          password,
          salt: base64UrlDecode(saltRes.salt),
          kdfParams: saltRes.kdf_params,
        },
      });
      // Derive new PDK/PUK with target params
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
      if (loginRes.encrypted_umk) {
        loginRes.encrypted_umk = base64UrlEncode(newWrapped.encrypted);
        loginRes.umk_nonce = base64UrlEncode(newWrapped.nonce);
      }
      saltRes = await authApi.getSalt(email);
      // Re-wrap keys with new PDK and update localStorage
      if (hasPdkData()) {
        try {
          const newPdkWrapped = await worker.wrapWithPdk({
            passwordParams: {
              password,
              salt: base64UrlDecode(migrationSaltRes.salt),
              kdfParams: targetParams,
            },
          });
          persistPdkWrappedKeys(newPdkWrapped);
          if (newPdkWrapped.wrappedUmk) {
            pdkBlobs.pdkWrappedUmk = newPdkWrapped.wrappedUmk;
          }
          if (newPdkWrapped.wrappedDeviceKeys) {
            pdkBlobs.pdkWrappedDeviceEcdh = newPdkWrapped.wrappedDeviceKeys.ecdh;
            pdkBlobs.pdkWrappedDeviceSigning = newPdkWrapped.wrappedDeviceKeys.signing;
          }
        } catch {
          // Best effort
        }
      }
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
    // Step 6: Initialize Worker with DSK data + server keys
    // PDK blobs are passed to init for DSK-unavailable fallback restoration
    let dskData = await loadDskInitData();
    const hadDsk = dskData?.dsk != null;
    const needPdkPersistence = !hadDsk;
    await worker.setUserContext(userId, deviceId ?? undefined);
    let initPdkWrapped: import("@/shared/lib/crypto/worker/types").InitPdkResult | null = null;
    if (dskData && deviceId) {
      if (dskData.dsk) {
        await worker.setDsk(dskData.dsk);
      }
      const initResult = await worker.init({
        dsk: dskData.dsk,
        wrappedUmk: dskData.wrappedUmk ?? undefined,
        wrappedDeviceEcdh: dskData.wrappedDeviceEcdh ?? undefined,
        wrappedDeviceSigning: dskData.wrappedDeviceSigning ?? undefined,
        userId,
        deviceId,
        serverEncryptedUmk: base64UrlDecode(keys.encrypted_umk!),
        serverUmkNonce: base64UrlDecode(keys.umk_nonce!),
        encryptedIdentityEcdh: base64UrlDecode(keys.encrypted_ecdh_private),
        identityEcdhNonce: base64UrlDecode(keys.encrypted_ecdh_private_nonce),
        encryptedIdentitySigning: base64UrlDecode(keys.encrypted_signing_private),
        identitySigningNonce: base64UrlDecode(keys.encrypted_signing_private_nonce),
        ...pdkBlobs,
        returnPdkWrapped: needPdkPersistence,
      });
      dskData = null;
      initPdkWrapped = initResult.pdkWrapped;
    } else {
      const initResult = await worker.initFromPassword({
        password,
        salt: base64UrlDecode(saltRes.salt),
        kdfParams: saltRes.kdf_params,
        dsk: null,
        userId,
        deviceId: deviceId ?? "",
        serverEncryptedUmk: base64UrlDecode(keys.encrypted_umk!),
        serverUmkNonce: base64UrlDecode(keys.umk_nonce!),
        encryptedIdentityEcdh: base64UrlDecode(keys.encrypted_ecdh_private),
        identityEcdhNonce: base64UrlDecode(keys.encrypted_ecdh_private_nonce),
        encryptedIdentitySigning: base64UrlDecode(keys.encrypted_signing_private),
        identitySigningNonce: base64UrlDecode(keys.encrypted_signing_private_nonce),
        ...pdkBlobs,
        returnPdkWrapped: needPdkPersistence,
      });
      initPdkWrapped = initResult.pdkWrapped;
    }
    // Step 7: Persist UMK + device keys (KMSI-aware)
    if (hadDsk) {
      try {
        const wrappedUmk = await worker.wrapUmkWithDsk(userId);
        await persistWrappedUmk({ wrappedUmk, kmsi: rememberMe, userId });
        // Re-persist device keys with DSK (may have been restored from PDK fallback)
        const wrappedDeviceKeys = await worker.wrapDeviceKeysWithDsk(userId);
        await storeWrappedDeviceKeysRaw(
          wrappedDeviceKeys.wrappedEcdh,
          wrappedDeviceKeys.wrappedSigning,
        );
      } catch {
        // DSK persistence failed — fall back to PDK if possible
        try {
          const pdkFallback = await worker.wrapWithPdk({
            passwordParams: {
              password,
              salt: base64UrlDecode(saltRes.salt),
              kdfParams: saltRes.kdf_params,
            },
          });
          persistPdkWrappedKeys(pdkFallback);
        } catch {
          // PDK fallback also failed — session works but won't survive restart
        }
      }
    } else if (initPdkWrapped) {
      // PDK fallback: store PDK-wrapped blobs returned from init
      persistPdkWrappedKeys(initPdkWrapped);
    }
    // Step 8: Check if device keys were restored (init handles PDK fallback internally)
    const ready = await worker.isReady();
    let hasDeviceKeys = false;
    if (ready) {
      try {
        const pubKeys = await worker.getPublicKeys();
        hasDeviceKeys = pubKeys.deviceSigningPublic !== null;
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
          signingPublicKey: base64UrlDecode(d.signing_public_key),
          ecdhPublicKey: base64UrlDecode(d.ecdh_public_key),
          identitySignature: d.identity_signature ?? null,
          clientNonce: d.client_nonce ?? null,
        })),
      });
      tofuWarnings = tofuResult.errors;
    } catch (e) {
      if (isTofuHardFail(e)) {
        throw e;
      }
    }
    const pubKeys = await worker.getPublicKeys();
    return {
      type: "verified",
      userId,
      email: loginRes.user.email,
      name: loginRes.user.name,
      sessionId: loginRes.session_id,
      deviceId: deviceId ?? "",
      tofuWarnings,
      workerReady: true,
      identitySigningPublic: pubKeys.identitySigningPublic,
      identityEcdhPublic: pubKeys.identityEcdhPublic,
      deviceSigningPublic: pubKeys.deviceSigningPublic,
      deviceEcdhPublic: pubKeys.deviceEcdhPublic,
    };
  } finally {
    await worker.clearTransientKeys().catch(() => {});
  }
}
