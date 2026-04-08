import { authApi } from "@/shared/api";
import type { AuthState } from "@/entities/session";
import { setCryptoWorkerReady, setFullSession } from "@/entities/session";
import { persistDeviceId, persistWrappedUmk } from "@/shared/lib/auth/key-persistence";
import { base64UrlDecode } from "@/shared/lib/crypto/encoding";
import { getCryptoWorker } from "@/shared/lib/crypto/worker/client";
import { loadPersistedDskIntoWorker } from "../session/keys";
import { restoreWorkspaceKeks } from "../session/keks";
import { TrustTransferKeyVerificationError } from "./error";
import { retrieveAndImportTrustState, retryGetUmk } from "./support";
import type { DeviceRegistrationPublicKeys } from "../../model/types";

interface IdentityPublicKeys {
  signingPublic: Uint8Array;
  ecdhPublic: Uint8Array;
}

interface ApprovedDeviceRestorationResult {
  identityPublicKeys: IdentityPublicKeys | null;
  requiresPasswordReentry: boolean;
  dskUnavailableOAuth: boolean;
}

type ApprovedRegistrationResult =
  | {
      kind: "needs_password";
    }
  | {
      kind: "done";
      dskUnavailableOAuth: boolean;
      redirectPath: string;
    };

export async function completeApprovedRegistration(params: {
  auth: AuthState;
  deviceId: string;
  publicKeys: DeviceRegistrationPublicKeys;
  completionRedirectPath: string;
}): Promise<ApprovedRegistrationResult> {
  const restorationResult = await restoreApprovedDeviceSession({
    auth: params.auth,
    deviceId: params.deviceId,
  });
  setCryptoWorkerReady(true);

  setFullSession(
    {
      user: params.auth.user,
      sessionId: params.auth.sessionId,
      identitySigningPublic: restorationResult.identityPublicKeys?.signingPublic ?? null,
      identityEcdhPublic: restorationResult.identityPublicKeys?.ecdhPublic ?? null,
      expiresAt: params.auth.expiresAt,
    },
    {
      deviceId: params.deviceId,
      deviceSigningPublic: params.publicKeys.signingPublic,
      deviceEcdhPublic: params.publicKeys.ecdhPublic,
    },
  );

  persistDeviceId(params.deviceId, params.auth.user.id);

  if (restorationResult.requiresPasswordReentry) {
    return {
      kind: "needs_password",
    };
  }

  return {
    kind: "done",
    dskUnavailableOAuth: restorationResult.dskUnavailableOAuth,
    redirectPath: params.completionRedirectPath,
  };
}

async function restoreApprovedDeviceSession(params: {
  auth: AuthState;
  deviceId: string;
}): Promise<ApprovedDeviceRestorationResult> {
  const { auth, deviceId } = params;
  const worker = getCryptoWorker();

  await worker.setUserContext(auth.user.id, deviceId);

  try {
    await retrieveAndImportTrustState(auth.user.id, deviceId);
  } catch (trustError) {
    if (trustError instanceof TrustTransferKeyVerificationError) {
      throw trustError;
    }
  }

  const umkData = await retryGetUmk(deviceId, 10, 2000, deviceId);
  if (!umkData.sender_signing_public_key || !umkData.sender_ecdh_public_key) {
    throw new Error("UMK response missing sender keys");
  }

  const senderSigningPublic = base64UrlDecode(umkData.sender_signing_public_key);
  const senderEcdhPublic = base64UrlDecode(umkData.sender_ecdh_public_key);
  const senderTofuResult = await worker.tofuVerify({
    userId: auth.user.id,
    deviceId: umkData.sender_device_id,
    signingPublicKey: senderSigningPublic,
    ecdhPublicKey: senderEcdhPublic,
  });

  if (senderTofuResult.status === "identity_key_changed") {
    throw new Error("UMK sender identity key changed. This may indicate tampering.");
  }
  if (senderTofuResult.status === "ecdh_key_mismatch") {
    throw new Error("UMK sender ECDH key mismatch. This may indicate tampering.");
  }
  if (senderTofuResult.status === "first_seen") {
    await worker.tofuTrustDevice({
      userId: auth.user.id,
      deviceId: umkData.sender_device_id,
      signingPublicKey: senderSigningPublic,
      ecdhPublicKey: senderEcdhPublic,
    });
  } else if (senderTofuResult.status === "known_trusted") {
    await worker.tofuUpdateLastSeen({
      userId: auth.user.id,
      deviceId: umkData.sender_device_id,
    });
  }

  await worker.ecdhDecryptUmkFromDevice({
    theirPublic: senderEcdhPublic,
    ciphertext: base64UrlDecode(umkData.encrypted_umk),
    nonce: base64UrlDecode(umkData.nonce),
    senderDeviceId: umkData.sender_device_id,
    targetDeviceId: deviceId,
  });

  const me = await authApi.me();
  let identityPublicKeys: IdentityPublicKeys | null = null;
  if (me.keys) {
    const importedKeys = await worker.importIdentityKeys({
      encryptedEcdhPrivate: base64UrlDecode(me.keys.encrypted_ecdh_private),
      ecdhPrivateNonce: base64UrlDecode(me.keys.encrypted_ecdh_private_nonce),
      encryptedSigningPrivate: base64UrlDecode(me.keys.encrypted_signing_private),
      signingPrivateNonce: base64UrlDecode(me.keys.encrypted_signing_private_nonce),
    });
    identityPublicKeys = {
      signingPublic: importedKeys.identitySigningPublic!,
      ecdhPublic: importedKeys.identityEcdhPublic!,
    };
  }

  await worker.setInitialized();

  const hasPersistedDsk = await loadPersistedDskIntoWorker();
  if (hasPersistedDsk) {
    const wrappedUmk = await worker.wrapUmkWithDsk(auth.user.id);
    await persistWrappedUmk({
      wrappedUmk,
      kmsi: !!me.remember_me,
      userId: auth.user.id,
    });
  }

  if (identityPublicKeys) {
    try {
      const kekResult = await restoreWorkspaceKeks(auth.user.id, deviceId);
      if (kekResult.backupDecryptFailed) {
        console.warn(
          "[device-registration] Some workspace KEKs could not be decrypted from backup",
        );
      }
    } catch {
      // KEK restoration failure is non-blocking for device approval completion.
    }
  }

  const requiresPasswordReentry = !hasPersistedDsk && me.auth_type === "password";
  const dskUnavailableOAuth = !hasPersistedDsk && me.auth_type !== "password";

  await worker.clearTransientKeys();

  return {
    identityPublicKeys,
    requiresPasswordReentry,
    dskUnavailableOAuth,
  };
}
