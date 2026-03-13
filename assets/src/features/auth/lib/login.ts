import {
  base64UrlDecode,
  base64UrlEncode,
  deriveAuthKeys,
  unwrapUmk,
  wrapUmk,
  decryptIdentityPrivateKeys,
  verifyAllDeviceTofu,
  TofuHardFailError,
} from "@/shared/lib/crypto";
import type { IdentityKeyPair } from "@/shared/lib/crypto";
import { authApi, devicesApi, withPopDevice } from "@/shared/api";
import type { LoginResponse } from "@/shared/api/auth";
import {
  persistUmkForLogin,
  getPersistedDeviceId,
  restoreKeysFromDsk,
  restoreDeviceKeysFromDsk,
  restoreDeviceKeysFromPdk,
  persistSessionPdk,
  hasPdkData,
} from "./key-persistence";
import { storePdkWrappedUmk, storePdkWrappedDeviceKeys } from "@/shared/lib/crypto/pdk";

export type LoginResult =
  | {
      type: "verified";
      userId: string;
      email: string;
      name: string;
      sessionId: string;
      umk: Uint8Array;
      identityKeys: IdentityKeyPair;
      deviceId: string;
      deviceEcdhPrivate: Uint8Array | null;
      deviceSigningPrivate: Uint8Array | null;
      tofuWarnings: string[];
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
  // Step 1: Get salt and KDF params
  const saltRes = await authApi.getSalt(email);

  // Step 2: Derive keys
  let derived = await deriveAuthKeys(password, saltRes.salt, saltRes.kdf_params);

  // Step 3: Authenticate (always send device_id if present — PUK fallback is always available during login)
  const deviceId = getPersistedDeviceId();
  const loginRes = await authApi.login({
    email,
    auth_key: derived.authKeyBase64,
    remember_me: rememberMe,
    ...(deviceId ? { device_id: deviceId } : {}),
  });

  // Step 4: Handle KDF migration if needed (requires UMK access for re-encryption)
  // encrypted_umk is available at top level when kdf_migration_required=true (regardless of device_verified)
  const migrationUmk = loginRes.encrypted_umk ?? loginRes.keys?.encrypted_umk;
  if (loginRes.kdf_migration_required && loginRes.target_kdf_params && migrationUmk) {
    const newDerived = await handleKdfMigration(password, loginRes, derived.puk, derived.pdk);
    derived = newDerived;
  }

  // Step 5: Check device status
  if (!loginRes.device_verified || !loginRes.keys) {
    persistSessionPdk(derived.pdk);
    return {
      type: "device_required",
      userId: loginRes.user.id,
      email: loginRes.user.email,
      name: loginRes.user.name,
      sessionId: loginRes.session_id,
    };
  }

  const userId = loginRes.user.id;
  const keys = loginRes.keys;

  // Step 6: Decrypt UMK — DSK-first, PUK-fallback
  let umk: Uint8Array;
  let deviceEcdhPrivate: Uint8Array | null = null;
  let deviceSigningPrivate: Uint8Array | null = null;

  const dskKeys = await restoreKeysFromDsk(userId);
  if (dskKeys) {
    umk = dskKeys.umk;
    deviceEcdhPrivate = dskKeys.deviceEcdhPrivate;
    deviceSigningPrivate = dskKeys.deviceSigningPrivate;
  } else {
    umk = unwrapUmk(
      base64UrlDecode(keys.encrypted_umk!),
      base64UrlDecode(keys.umk_nonce!),
      derived.puk,
      userId,
    );
  }

  // Step 7: Decrypt identity keys
  const identityKeys = decryptIdentityPrivateKeys(
    {
      encryptedEcdhPrivate: base64UrlDecode(keys.encrypted_ecdh_private),
      ecdhPrivateNonce: base64UrlDecode(keys.encrypted_ecdh_private_nonce),
      encryptedSigningPrivate: base64UrlDecode(keys.encrypted_signing_private),
      signingPrivateNonce: base64UrlDecode(keys.encrypted_signing_private_nonce),
    },
    umk,
    userId,
  );

  // Step 8: Persist UMK
  await persistUmkForLogin({
    umk,
    pdk: derived.pdk,
    kmsi: rememberMe,
    userId,
  });

  persistSessionPdk(derived.pdk);

  // Step 9: Restore device keys if not already obtained from DSK
  if (!deviceSigningPrivate) {
    const dskDeviceKeys = await restoreDeviceKeysFromDsk(userId);
    if (dskDeviceKeys) {
      deviceEcdhPrivate = dskDeviceKeys.ecdhPrivate;
      deviceSigningPrivate = dskDeviceKeys.signingPrivate;
    } else {
      const pdkDeviceKeys = restoreDeviceKeysFromPdk(derived.pdk, userId);
      if (pdkDeviceKeys) {
        deviceEcdhPrivate = pdkDeviceKeys.ecdhPrivate;
        deviceSigningPrivate = pdkDeviceKeys.signingPrivate;
      }
    }
  }

  if (!deviceSigningPrivate) {
    persistSessionPdk(derived.pdk);
    return {
      type: "device_required",
      userId,
      email: loginRes.user.email,
      name: loginRes.user.name,
      sessionId: loginRes.session_id,
    };
  }

  // Step 10: TOFU verification for all devices (pass explicit device keys for PoP since device state isn't set yet)
  let tofuWarnings: string[] = [];
  try {
    const { devices } = await withPopDevice({ deviceId: deviceId!, deviceSigningPrivate }, () =>
      devicesApi.list(),
    );
    tofuWarnings = await verifyAllDeviceTofu(userId, devices, identityKeys.signingPublic ?? null);
  } catch (e) {
    if (e instanceof TofuHardFailError) throw e;
  }

  return {
    type: "verified",
    userId,
    email: loginRes.user.email,
    name: loginRes.user.name,
    sessionId: loginRes.session_id,
    umk,
    identityKeys,
    deviceId: deviceId ?? "",
    deviceEcdhPrivate,
    deviceSigningPrivate,
    tofuWarnings,
  };
}

async function handleKdfMigration(
  password: string,
  loginRes: LoginResponse,
  oldPuk: Uint8Array,
  oldPdk: Uint8Array,
): Promise<Awaited<ReturnType<typeof deriveAuthKeys>>> {
  const targetParams = loginRes.target_kdf_params!;
  const userId = loginRes.user.id;

  // encrypted_umk available at top level (kdf_migration_required=true) or in keys (device_verified=true)
  const encryptedUmk = loginRes.encrypted_umk ?? loginRes.keys?.encrypted_umk;
  const umkNonce = loginRes.umk_nonce ?? loginRes.keys?.umk_nonce;

  // Re-derive with new params
  const saltRes = await authApi.getSalt(loginRes.user.email);
  const newDerived = await deriveAuthKeys(password, saltRes.salt, targetParams);

  if (encryptedUmk && umkNonce) {
    // Decrypt UMK with old PUK, re-encrypt with new PUK
    const umk = unwrapUmk(base64UrlDecode(encryptedUmk), base64UrlDecode(umkNonce), oldPuk, userId);

    const newWrapped = wrapUmk(umk, newDerived.puk, userId);

    await authApi.kdfMigration({
      new_auth_key: newDerived.authKeyBase64,
      new_encrypted_umk: base64UrlEncode(newWrapped.encryptedUmk),
      new_nonce: base64UrlEncode(newWrapped.nonce),
      new_kdf_params: targetParams,
    });

    // Re-wrap local PDK data with new PDK only if device uses PDK fallback (not DSK-capable)
    if (hasPdkData()) {
      storePdkWrappedUmk(newDerived.pdk, umk, userId);

      const oldDeviceKeys = restoreDeviceKeysFromPdk(oldPdk, userId);
      if (oldDeviceKeys) {
        storePdkWrappedDeviceKeys(
          newDerived.pdk,
          oldDeviceKeys.ecdhPrivate,
          oldDeviceKeys.signingPrivate,
          userId,
        );
      }
    }
  }

  return newDerived;
}
