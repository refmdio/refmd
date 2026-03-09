import {
  base64UrlEncode,
  randomBytes,
  deriveAuthKeys,
  generateUmk,
  wrapUmk,
  generateRecoveryKey,
  wrapUmkWithRuk,
  generateIdentityKeyPair,
  encryptIdentityKeys,
  generateDeviceKeyPair,
  generateClientNonce,
  signDeviceRegistration,
  generateKek,
  encryptKekForDevice,
  wrapKekWithUmk,
} from "@/shared/lib/crypto";
import type { KdfParams, IdentityKeyPair, DeviceKeyPair } from "@/shared/lib/crypto";
import { authApi, devicesApi, encryptionApi } from "@/shared/api";
import { persistKeys, persistDeviceId, persistDeviceKeysOnly, persistSessionPdk } from "./key-persistence";
import { setDeviceState } from "@/shared/lib/auth-state";

const TARGET_KDF_PARAMS: KdfParams = {
  algorithm: "argon2id",
  memory: 65536,
  iterations: 3,
  parallelism: 4,
  hash_length: 32,
};

export interface RegisterResult {
  userId: string;
  email: string;
  name: string;
  workspaceId: string;
  sessionId: string;
  umk: Uint8Array;
  identityKeys: IdentityKeyPair;
  deviceId: string;
  deviceKeys: DeviceKeyPair;
  recoveryMnemonic: string;
}

export async function register(
  email: string,
  name: string,
  password: string,
): Promise<RegisterResult> {
  // Step 1: Generate salt and derive keys
  const salt = randomBytes(16);
  const saltBase64 = base64UrlEncode(salt);
  const derived = await deriveAuthKeys(password, saltBase64, TARGET_KDF_PARAMS);

  // Step 2: Pre-generate user_id for AAD binding (server accepts client-generated UUID)
  const userId = crypto.randomUUID();

  // Step 3: Generate UMK and wrap with PUK
  const umk = generateUmk();
  const umkWrapped = wrapUmk(umk, derived.puk, userId);

  // Step 4: Generate recovery key
  const recovery = await generateRecoveryKey();
  const recoveryWrapped = wrapUmkWithRuk(umk, recovery.ruk, userId);

  // Step 5: Generate identity keys and encrypt with UMK
  const identityKeys = generateIdentityKeyPair();
  const encryptedIdentity = encryptIdentityKeys(identityKeys, umk, userId);

  // Step 6: Register with server
  const registerRes = await authApi.register({
    user_id: userId,
    email,
    name,
    auth_key: derived.authKeyBase64,
    salt: saltBase64,
    encrypted_umk: base64UrlEncode(umkWrapped.encryptedUmk),
    umk_nonce: base64UrlEncode(umkWrapped.nonce),
    kdf_params: TARGET_KDF_PARAMS,
    recovery_encrypted_umk: base64UrlEncode(recoveryWrapped.encryptedUmk),
    recovery_nonce: base64UrlEncode(recoveryWrapped.nonce),
    ecdh_public_key: base64UrlEncode(identityKeys.ecdhPublic),
    signing_public_key: base64UrlEncode(identityKeys.signingPublic),
    encrypted_ecdh_private: base64UrlEncode(encryptedIdentity.encryptedEcdhPrivate),
    encrypted_ecdh_private_nonce: base64UrlEncode(encryptedIdentity.ecdhPrivateNonce),
    encrypted_signing_private: base64UrlEncode(encryptedIdentity.encryptedSigningPrivate),
    encrypted_signing_private_nonce: base64UrlEncode(encryptedIdentity.signingPrivateNonce),
  });

  // Step 6: Generate device keys and persist early (design: DSK early persistence)
  const deviceKeys = generateDeviceKeyPair();
  persistSessionPdk(derived.pdk);
  await persistDeviceKeysOnly(deviceKeys.ecdhPrivate, deviceKeys.signingPrivate, userId);
  const clientNonce = generateClientNonce();
  const identitySignature = signDeviceRegistration(
    deviceKeys.signingPublic,
    deviceKeys.ecdhPublic,
    clientNonce,
    identityKeys.signingPrivate,
  );

  // Step 7: Bootstrap first device (dedicated endpoint)
  const bootstrapRes = await devicesApi.bootstrap({
    name: getDeviceName(),
    device_type: getDeviceType(),
    identity_signing_public_key: base64UrlEncode(identityKeys.signingPublic),
    device_signing_public_key: base64UrlEncode(deviceKeys.signingPublic),
    device_ecdh_public_key: base64UrlEncode(deviceKeys.ecdhPublic),
    client_nonce: base64UrlEncode(clientNonce),
    identity_signature: base64UrlEncode(identitySignature),
  });

  const deviceId = bootstrapRes.device_id;
  persistDeviceId(deviceId);

  // Step 8: Establish PoP capability by setting device state in memory
  setDeviceState({
    deviceId,
    deviceEcdhPrivate: deviceKeys.ecdhPrivate,
    deviceSigningPrivate: deviceKeys.signingPrivate,
  });

  // Step 9: Generate KEK and save device envelope (PoP required)
  const kek = generateKek();
  const kekWrapped = encryptKekForDevice(
    kek,
    deviceKeys.ecdhPrivate,
    deviceKeys.ecdhPublic,
    registerRes.workspace_id,
    userId,
    deviceId,
    deviceId,
    1,
  );

  await encryptionApi.createWorkspaceKeyWithPop(registerRes.workspace_id, {
    device_id: deviceId,
    key_version: 1,
    sender_device_id: deviceId,
    encrypted_kek: base64UrlEncode(kekWrapped.ciphertext),
    nonce: base64UrlEncode(kekWrapped.nonce),
    is_active: true,
  });

  // Step 10: Save KEK UMK backup (PoP required)
  const kekBackup = wrapKekWithUmk(kek, umk, registerRes.workspace_id, userId, 1);

  await encryptionApi.createKekBackupWithPop(registerRes.workspace_id, {
    key_version: 1,
    encrypted_kek: base64UrlEncode(kekBackup.encryptedKek),
    nonce: base64UrlEncode(kekBackup.nonce),
  });

  // Step 11: Mark encryption setup complete
  await encryptionApi.setupComplete();

  // Step 12: Persist keys locally
  await persistKeys({
    umk,
    deviceEcdhPrivate: deviceKeys.ecdhPrivate,
    deviceSigningPrivate: deviceKeys.signingPrivate,
    pdk: derived.pdk,
    kmsi: false,
    userId,
  });

  return {
    userId,
    email: registerRes.user.email,
    name: registerRes.user.name,
    workspaceId: registerRes.workspace_id,
    sessionId: registerRes.session_id,
    umk,
    identityKeys,
    deviceId,
    deviceKeys,
    recoveryMnemonic: recovery.mnemonic,
  };
}

function getDeviceName(): string {
  const ua = navigator.userAgent;
  if (/Chrome/.test(ua)) return "Chrome";
  if (/Firefox/.test(ua)) return "Firefox";
  if (/Safari/.test(ua)) return "Safari";
  return "Browser";
}

function getDeviceType(): string {
  if (/Mobi|Android/i.test(navigator.userAgent)) return "mobile";
  return "desktop";
}
