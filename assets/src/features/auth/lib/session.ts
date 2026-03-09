import { base64UrlDecode, decryptIdentityPrivateKeys } from "@/shared/lib/crypto";
import type { IdentityKeyPair } from "@/shared/lib/crypto";
import { authApi, ApiError } from "@/shared/api";
import {
  restoreKeysFromDsk,
  restoreUmkFromSession,
  restoreDeviceKeysFromDsk,
  getPersistedDeviceId,
  hasPdkData,
} from "./key-persistence";

export interface SessionRestoreResult {
  userId: string;
  email: string;
  name: string;
  sessionId: string;
  deviceId: string | null;
  deviceVerified: boolean;
  expiresAt: string;
  umk: Uint8Array | null;
  identityKeys: IdentityKeyPair | null;
  deviceEcdhPrivate: Uint8Array | null;
  deviceSigningPrivate: Uint8Array | null;
  needsPasswordReentry: boolean;
}

export async function restoreSession(): Promise<SessionRestoreResult | null> {
  try {
    const me = await authApi.me();

    let umk: Uint8Array | null = null;
    let identityKeys: IdentityKeyPair | null = null;
    let deviceEcdhPrivate: Uint8Array | null = null;
    let deviceSigningPrivate: Uint8Array | null = null;
    let needsPasswordReentry = false;

    // Attempt full key restoration from DSK (IndexedDB)
    const dskKeys = await restoreKeysFromDsk(me.user.id);
    if (dskKeys) {
      umk = dskKeys.umk;
      deviceEcdhPrivate = dskKeys.deviceEcdhPrivate;
      deviceSigningPrivate = dskKeys.deviceSigningPrivate;
    } else {
      // Try sessionStorage for UMK (non-KMSI, tab-scoped)
      umk = restoreUmkFromSession();

      // Try DSK for device keys even if UMK came from sessionStorage
      if (umk) {
        const devKeys = await restoreDeviceKeysFromDsk(me.user.id);
        if (devKeys) {
          deviceEcdhPrivate = devKeys.ecdhPrivate;
          deviceSigningPrivate = devKeys.signingPrivate;
        }
      }

      // PDK fallback requires password re-entry when UMK or device keys are missing
      if (hasPdkData() && (!umk || !deviceSigningPrivate)) {
        needsPasswordReentry = true;
      }
    }

    if (me.device_verified && me.keys?.encrypted_ecdh_private && umk) {
      identityKeys = decryptIdentityPrivateKeys(
        {
          encryptedEcdhPrivate: base64UrlDecode(me.keys.encrypted_ecdh_private),
          ecdhPrivateNonce: base64UrlDecode(me.keys.encrypted_ecdh_private_nonce),
          encryptedSigningPrivate: base64UrlDecode(me.keys.encrypted_signing_private),
          signingPrivateNonce: base64UrlDecode(me.keys.encrypted_signing_private_nonce),
        },
        umk,
        me.user.id,
      );
    }

    const deviceId = me.device_id ?? getPersistedDeviceId() ?? null;

    return {
      userId: me.user.id,
      email: me.user.email,
      name: me.user.name,
      sessionId: me.session_id,
      deviceId,
      deviceVerified: me.device_verified,
      expiresAt: me.expires_at,
      umk,
      identityKeys,
      deviceEcdhPrivate,
      deviceSigningPrivate,
      needsPasswordReentry,
    };
  } catch (err) {
    if (err instanceof ApiError && err.status === 401) {
      return null;
    }
    throw err;
  }
}
