import {
  base64UrlDecode,
  base64UrlEncode,
  deriveAuthKeys,
  unwrapUmk,
  wrapUmk,
  decryptIdentityPrivateKeys,
} from "@/shared/lib/crypto";
import type { IdentityKeyPair } from "@/shared/lib/crypto";
import { authApi } from "@/shared/api";
import type { LoginResponse } from "@/shared/api/auth";
import {
  persistUmkForLogin,
  getPersistedDeviceId,
  restoreDeviceKeysFromDsk,
  restoreDeviceKeysFromPdk,
} from "./key-persistence";

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
  const derived = await deriveAuthKeys(password, saltRes.salt, saltRes.kdf_params);

  // Step 3: Authenticate (send device_id if available)
  const deviceId = getPersistedDeviceId();
  const loginRes = await authApi.login({
    email,
    auth_key: derived.authKeyBase64,
    remember_me: rememberMe,
    ...(deviceId ? { device_id: deviceId } : {}),
  });

  // Step 4: Handle KDF migration if needed
  if (loginRes.kdf_migration_required && loginRes.target_kdf_params) {
    await handleKdfMigration(password, loginRes, derived.puk);
  }

  // Step 5: Check device status
  if (!loginRes.device_verified || !loginRes.keys) {
    return {
      type: "device_required",
      userId: loginRes.user.id,
      email: loginRes.user.email,
      name: loginRes.user.name,
      sessionId: loginRes.session_id,
    };
  }

  // Step 6: Decrypt keys (flat keys structure per design doc)
  const userId = loginRes.user.id;
  const keys = loginRes.keys;

  const umk = unwrapUmk(
    base64UrlDecode(keys.encrypted_umk!),
    base64UrlDecode(keys.umk_nonce!),
    derived.puk,
    userId,
  );

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

  // Step 7: Persist UMK only (don't overwrite existing device keys)
  await persistUmkForLogin({
    umk,
    pdk: derived.pdk,
    kmsi: rememberMe,
  });

  // Step 8: Restore device keys from local storage
  let deviceEcdhPrivate: Uint8Array | null = null;
  let deviceSigningPrivate: Uint8Array | null = null;

  const dskDeviceKeys = await restoreDeviceKeysFromDsk();
  if (dskDeviceKeys) {
    deviceEcdhPrivate = dskDeviceKeys.ecdhPrivate;
    deviceSigningPrivate = dskDeviceKeys.signingPrivate;
  } else {
    // PDK fallback — we have the password so we can derive PDK
    const pdkDeviceKeys = restoreDeviceKeysFromPdk(derived.pdk);
    if (pdkDeviceKeys) {
      deviceEcdhPrivate = pdkDeviceKeys.ecdhPrivate;
      deviceSigningPrivate = pdkDeviceKeys.signingPrivate;
    }
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
  };
}

async function handleKdfMigration(
  password: string,
  loginRes: LoginResponse,
  _oldPuk: Uint8Array,
): Promise<void> {
  const targetParams = loginRes.target_kdf_params!;
  const keys = loginRes.keys;
  if (!keys?.encrypted_umk) return;

  const userId = loginRes.user.id;

  // Re-derive with new params
  const saltRes = await authApi.getSalt(loginRes.user.email);
  const newDerived = await deriveAuthKeys(password, saltRes.salt, targetParams);

  // Decrypt UMK with old PUK, re-encrypt with new PUK
  const umk = unwrapUmk(
    base64UrlDecode(keys.encrypted_umk),
    base64UrlDecode(keys.umk_nonce!),
    _oldPuk,
    userId,
  );

  const newWrapped = wrapUmk(umk, newDerived.puk, userId);

  await authApi.kdfMigration({
    new_auth_key: newDerived.authKeyBase64,
    new_encrypted_umk: base64UrlEncode(newWrapped.encryptedUmk),
    new_nonce: base64UrlEncode(newWrapped.nonce),
    new_kdf_params: targetParams,
  });
}
