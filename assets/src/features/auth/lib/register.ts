import { base64UrlEncode, randomBytes } from "@/shared/lib/crypto/encoding";
import { TARGET_KDF_PARAMS } from "@/shared/lib/crypto/kdf";
import { persistWorkspaceKekLocally } from "@/shared/lib/crypto/workspace-kek-persistence";
import { getCryptoWorker } from "@/shared/lib/crypto/worker/client";
import { authApi, devicesApi, encryptionApi } from "@/shared/api";
import { persistDeviceId, persistPdkWrappedKeys } from "@/shared/lib/auth-key-persistence";
import { setDeviceState, setCryptoWorkerReady } from "@/entities/session";
import { getDeviceName, getDeviceType } from "@/shared/lib/device-metadata";
interface RegisterResult {
  userId: string;
  email: string;
  name: string;
  workspaceId: string;
  sessionId: string;
  deviceId: string;
  recoveryMnemonic: string;
  deviceSigningPublic: Uint8Array;
  deviceEcdhPublic: Uint8Array;
  identitySigningPublic: Uint8Array;
  identityEcdhPublic: Uint8Array;
  workerReady: boolean;
}
export async function register(
  email: string,
  name: string,
  password: string,
): Promise<RegisterResult> {
  const worker = getCryptoWorker();
  // Step 1: Generate salt and derive keys (PUK stored transiently in Worker)
  try {
    const salt = randomBytes(16);
    const saltBase64 = base64UrlEncode(salt);
    const { authKey } = await worker.deriveAuthKeys({
      password,
      salt,
      kdfParams: TARGET_KDF_PARAMS,
    });
    const authKeyBase64 = base64UrlEncode(authKey);
    // Step 2: Pre-generate user_id and set Worker context
    const userId = crypto.randomUUID();
    await worker.setUserContext(userId);
    // Step 2b: Load or generate DSK in Worker (for key persistence later)
    const { loadDsk } = await import("@/shared/lib/crypto/dsk");
    let hadDsk = false;
    let dsk = await loadDsk();
    if (dsk) {
      await worker.setDsk(dsk);
      dsk = null;
      hadDsk = true;
    } else {
      try {
        await worker.generateDsk();
        hadDsk = true;
      } catch {
        // DSK unavailable
      }
    }
    // Step 3: Generate UMK (stays in Worker) and wrap with PUK
    await worker.generateUmk();
    const umkWrapped = await worker.wrapUmkForServer(userId);
    // Step 4: Generate recovery key (RUK stays in Worker, UMK wrapped internally)
    const recovery = await worker.generateRecoveryKey();
    // Step 5: Generate identity keys and encrypt with UMK (all in Worker)
    const identityPublic = await worker.generateIdentityKeys();
    const encryptedIdentity = await worker.wrapIdentityKeysForServer(userId);
    // Step 6: Generate device keys (stays in Worker)
    const devicePublic = await worker.generateDeviceKeys();
    // Step 6b: Persist keys BEFORE server registration (crash safety)
    if (hadDsk) {
      const { storeWrappedDeviceKeysRaw } = await import("@/shared/lib/crypto/dsk");
      const { persistWrappedUmk } = await import("@/shared/lib/auth-key-persistence");
      const wrappedUmk = await worker.wrapUmkWithDsk(userId);
      await persistWrappedUmk({ wrappedUmk, kmsi: false, userId });
      const wrappedDeviceKeys = await worker.wrapDeviceKeysWithDsk(userId);
      await storeWrappedDeviceKeysRaw(
        wrappedDeviceKeys.wrappedEcdh,
        wrappedDeviceKeys.wrappedSigning,
      );
    } else {
      const pdkWrapped = await worker.wrapWithPdk({
        passwordParams: { password, salt, kdfParams: TARGET_KDF_PARAMS },
      });
      persistPdkWrappedKeys(pdkWrapped);
    }
    const clientNonce = await worker.generateClientNonce();
    // Step 7: Register with server
    const registerRes = await authApi.register({
      user_id: userId,
      email,
      name,
      auth_key: authKeyBase64,
      salt: saltBase64,
      encrypted_umk: base64UrlEncode(umkWrapped.encrypted),
      umk_nonce: base64UrlEncode(umkWrapped.nonce),
      kdf_params: TARGET_KDF_PARAMS,
      recovery_encrypted_umk: base64UrlEncode(recovery.encryptedUmk),
      recovery_nonce: base64UrlEncode(recovery.nonce),
      ecdh_public_key: base64UrlEncode(identityPublic.ecdhPublic),
      signing_public_key: base64UrlEncode(identityPublic.signingPublic),
      encrypted_ecdh_private: base64UrlEncode(encryptedIdentity.encryptedEcdhPrivate),
      encrypted_ecdh_private_nonce: base64UrlEncode(encryptedIdentity.ecdhPrivateNonce),
      encrypted_signing_private: base64UrlEncode(encryptedIdentity.encryptedSigningPrivate),
      encrypted_signing_private_nonce: base64UrlEncode(encryptedIdentity.signingPrivateNonce),
    });
    const { signature: identitySignature } = await worker.signDeviceRegistration({
      deviceSigningPublic: devicePublic.signingPublic,
      deviceEcdhPublic: devicePublic.ecdhPublic,
      clientNonce,
    });
    // Step 7b: Bootstrap first device (dedicated endpoint)
    const bootstrapRes = await devicesApi.bootstrap({
      name: getDeviceName(),
      device_type: getDeviceType(),
      identity_signing_public_key: base64UrlEncode(identityPublic.signingPublic),
      device_signing_public_key: base64UrlEncode(devicePublic.signingPublic),
      device_ecdh_public_key: base64UrlEncode(devicePublic.ecdhPublic),
      client_nonce: base64UrlEncode(clientNonce),
      identity_signature: base64UrlEncode(identitySignature),
    });
    const deviceId = bootstrapRes.device_id;
    persistDeviceId(deviceId, userId);
    await worker.setUserContext(userId, deviceId);
    await worker.setInitialized();
    // Step 8: Establish PoP capability
    setDeviceState({
      deviceId,
      deviceSigningPublic: devicePublic.signingPublic,
      deviceEcdhPublic: devicePublic.ecdhPublic,
    });
    // Step 9: Generate KEK and save device envelope (PoP required)
    await worker.generateKek(registerRes.workspace_id);
    await persistWorkspaceKekLocally({
      workspaceId: registerRes.workspace_id,
      userId,
      deviceId,
      deviceEcdhPublic: devicePublic.ecdhPublic,
      keyVersion: 1,
      isActive: true,
    });
    // Step 10: Mark encryption setup complete
    await encryptionApi.setupComplete();
    setCryptoWorkerReady(true);
    return {
      userId,
      email: registerRes.user.email,
      name: registerRes.user.name,
      workspaceId: registerRes.workspace_id,
      sessionId: registerRes.session_id,
      deviceId,
      recoveryMnemonic: recovery.mnemonic,
      deviceSigningPublic: devicePublic.signingPublic,
      deviceEcdhPublic: devicePublic.ecdhPublic,
      identitySigningPublic: identityPublic.signingPublic,
      identityEcdhPublic: identityPublic.ecdhPublic,
      workerReady: true,
    };
  } finally {
    await worker.clearTransientKeys().catch(() => {});
  }
}
