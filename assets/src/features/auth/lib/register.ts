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
import { persistKeys, persistDeviceId } from "./key-persistence";

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

  // Step 2: Generate UMK and wrap with PUK
  const umk = generateUmk();
  const umkWrapped = wrapUmk(umk, derived.puk, "pending");

  // Step 3: Generate recovery key
  const recovery = await generateRecoveryKey();
  const recoveryWrapped = wrapUmkWithRuk(umk, recovery.ruk, "pending");

  // Step 4: Generate identity keys and encrypt with UMK
  const identityKeys = generateIdentityKeyPair();
  const encryptedIdentity = encryptIdentityKeys(identityKeys, umk, "pending");

  // Step 5: Register with server
  const registerRes = await authApi.register({
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

  const userId = registerRes.user.id;

  // Now we know the userId, re-wrap UMK with correct AAD
  // (Registration used "pending" as userId placeholder — server stores the provided ciphertext.
  //  For Phase 1 we accept this. In production, the server returns the user ID before
  //  the client finalizes encryption, or we use a two-step flow.)

  // Step 6: Post-registration encryption setup
  // 6a: Register device (first device — self-approved)
  const deviceKeys = generateDeviceKeyPair();
  const clientNonce = generateClientNonce();

  const pendingRes = await devicesApi.createPending({
    name: getDeviceName(),
    device_type: getDeviceType(),
    ecdh_public_key: base64UrlEncode(deviceKeys.ecdhPublic),
    signing_public_key: base64UrlEncode(deviceKeys.signingPublic),
    client_nonce: base64UrlEncode(clientNonce),
  });

  // Self-approve (first device — uses device_registration action)
  const identitySignature = signDeviceRegistration(
    deviceKeys.signingPublic,
    deviceKeys.ecdhPublic,
    clientNonce,
    identityKeys.signingPrivate,
  );

  const approveRes = await devicesApi.approve(pendingRes.id, {
    identity_signature: base64UrlEncode(identitySignature),
  });

  const deviceId = approveRes.device.id;
  persistDeviceId(deviceId);

  // 6b: Generate KEK and save device envelope
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

  await encryptionApi.createWorkspaceKey(registerRes.workspace_id, {
    device_id: deviceId,
    key_version: 1,
    sender_device_id: deviceId,
    encrypted_kek: base64UrlEncode(kekWrapped.ciphertext),
    nonce: base64UrlEncode(kekWrapped.nonce),
    is_active: true,
  });

  // 6c: Save KEK UMK backup
  const kekBackup = wrapKekWithUmk(kek, umk, registerRes.workspace_id, userId, 1);

  await encryptionApi.createKekBackup(registerRes.workspace_id, {
    key_version: 1,
    encrypted_kek: base64UrlEncode(kekBackup.encryptedKek),
    nonce: base64UrlEncode(kekBackup.nonce),
  });

  // 6d: Mark encryption setup complete
  await encryptionApi.setupComplete();

  // 6e: Persist keys locally (DSK/PDK + sessionStorage for non-KMSI)
  await persistKeys({
    umk,
    deviceEcdhPrivate: deviceKeys.ecdhPrivate,
    deviceSigningPrivate: deviceKeys.signingPrivate,
    pdk: derived.pdk,
    kmsi: false,
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
