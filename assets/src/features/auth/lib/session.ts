import {
  base64UrlDecode,
  decryptIdentityPrivateKeys,
  verifyAllDeviceTofu,
  TofuHardFailError,
} from "@/shared/lib/crypto";
import type { IdentityKeyPair } from "@/shared/lib/crypto";
import { authApi, ApiError, devicesApi, withPopDevice } from "@/shared/api";
import {
  restoreKeysFromDsk,
  restoreUmkFromSession,
  restoreDeviceKeysFromDsk,
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
  tofuWarnings: string[];
}

export type SessionRestoreError = "rate_limited" | "transient_error";

export async function restoreSession(): Promise<SessionRestoreResult | SessionRestoreError | null> {
  try {
    const me = await authApi.me();

    let umk: Uint8Array | null = null;
    let identityKeys: IdentityKeyPair | null = null;
    let deviceEcdhPrivate: Uint8Array | null = null;
    let deviceSigningPrivate: Uint8Array | null = null;
    let needsPasswordReentry = false;

    // Attempt full key restoration from DSK (IndexedDB)
    const dskKeys = await restoreKeysFromDsk(me.user_id);
    if (dskKeys) {
      umk = dskKeys.umk;
      deviceEcdhPrivate = dskKeys.deviceEcdhPrivate;
      deviceSigningPrivate = dskKeys.deviceSigningPrivate;
    } else {
      // Try sessionStorage for UMK (non-KMSI, tab-scoped)
      umk = restoreUmkFromSession();

      // Try DSK for device keys even if UMK came from sessionStorage
      if (umk) {
        const devKeys = await restoreDeviceKeysFromDsk(me.user_id);
        if (devKeys) {
          deviceEcdhPrivate = devKeys.ecdhPrivate;
          deviceSigningPrivate = devKeys.signingPrivate;
        }
      }

      if (me.device_verified && !hasPdkData() && (!umk || !deviceSigningPrivate)) {
        // Verified session but neither DSK nor PDK can restore keys — force re-login
        return null;
      }

      // PDK fallback requires password re-entry (auth_type must be "password")
      if (hasPdkData() && (!umk || !deviceSigningPrivate)) {
        if (me.auth_type === "password") {
          needsPasswordReentry = true;
        } else if (me.device_verified) {
          // Non-password user cannot use PDK fallback — force re-login
          return null;
        }
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
        me.user_id,
      );
    }

    const deviceId = me.device_id ?? null;

    // TOFU verification at session restore
    let tofuWarnings: string[] = [];
    if (me.device_verified && deviceId && deviceSigningPrivate) {
      try {
        const { devices } = await withPopDevice({ deviceId, deviceSigningPrivate }, () =>
          devicesApi.list(),
        );
        tofuWarnings = await verifyAllDeviceTofu(
          me.user_id,
          devices,
          identityKeys?.signingPublic ?? null,
        );
      } catch (e) {
        if (e instanceof TofuHardFailError) throw e;
      }
    }

    return {
      userId: me.user_id,
      email: me.email,
      name: me.name,
      sessionId: me.session_id,
      deviceId,
      deviceVerified: me.device_verified,
      expiresAt: me.expires_at,
      umk,
      identityKeys,
      deviceEcdhPrivate,
      deviceSigningPrivate,
      needsPasswordReentry,
      tofuWarnings,
    };
  } catch (err) {
    if (err instanceof TofuHardFailError) throw err;
    if (err instanceof ApiError) {
      if (err.status === 401 || err.status === 403) return null;
      if (err.status === 429) return "rate_limited";
    }
    return "transient_error";
  }
}
