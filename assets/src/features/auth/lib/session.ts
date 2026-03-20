import { base64UrlDecode } from "@/shared/lib/crypto/encoding";
import { authApi, ApiError, devicesApi } from "@/shared/api";
import { loadDskInitData } from "@/shared/lib/crypto/dsk";
import { getCryptoWorker } from "@/shared/lib/crypto/worker/client";
import { hasPdkData, getPersistedDeviceId } from "./key-persistence";

export interface SessionRestoreResult {
  userId: string;
  email: string;
  name: string;
  sessionId: string;
  deviceId: string | null;
  deviceVerified: boolean;
  expiresAt: string;
  needsPasswordReentry: boolean;
  tofuWarnings: string[];
  identitySigningPublic: Uint8Array | null;
  identityEcdhPublic: Uint8Array | null;
  deviceSigningPublic: Uint8Array | null;
  deviceEcdhPublic: Uint8Array | null;
  workerReady: boolean;
}

export type SessionRestoreError = "rate_limited" | "transient_error";

export async function restoreSession(): Promise<SessionRestoreResult | SessionRestoreError | null> {
  try {
    const me = await authApi.me();
    const worker = getCryptoWorker();

    let workerReady = false;
    let needsPasswordReentry = false;

    const deviceId = me.device_id ?? getPersistedDeviceId();

    // Attempt Crypto Worker initialization from DSK (IndexedDB)
    let dskData = await loadDskInitData();
    if (dskData && deviceId) {
      try {
        // Build identity key data from server response (if available)
        const hasIdentityKeys = me.device_verified && me.keys?.encrypted_ecdh_private;

        await worker.init({
          dsk: dskData.dsk,
          wrappedUmk: me.remember_me !== false ? (dskData.wrappedUmk ?? undefined) : undefined,
          wrappedDeviceEcdh: dskData.wrappedDeviceEcdh ?? undefined,
          wrappedDeviceSigning: dskData.wrappedDeviceSigning ?? undefined,
          userId: me.user_id,
          deviceId,
          ...(hasIdentityKeys
            ? {
                encryptedIdentityEcdh: base64UrlDecode(me.keys!.encrypted_ecdh_private),
                identityEcdhNonce: base64UrlDecode(me.keys!.encrypted_ecdh_private_nonce),
                encryptedIdentitySigning: base64UrlDecode(me.keys!.encrypted_signing_private),
                identitySigningNonce: base64UrlDecode(me.keys!.encrypted_signing_private_nonce),
              }
            : {}),
        });

        workerReady = await worker.isReady();
      } catch (initErr) {
        console.error("[session] Worker init failed:", initErr);
        workerReady = false;
      }
    }

    if (!workerReady && dskData && deviceId) {
      // DSK init didn't restore UMK from IndexedDB. Try sessionStorage (non-KMSI fallback).
      // New format: DSK-wrapped UMK JSON in sessionStorage
      const wrappedJson = sessionStorage.getItem("refmd-session-umk-wrapped");
      if (wrappedJson) {
        try {
          const parsed = JSON.parse(wrappedJson);
          const wrappedUmk = {
            ciphertext: new Uint8Array(parsed.ciphertext).buffer,
            iv: new Uint8Array(parsed.iv).buffer,
          };
          await worker.init({
            dsk: dskData.dsk,
            wrappedUmk,
            wrappedDeviceEcdh: dskData.wrappedDeviceEcdh ?? undefined,
            wrappedDeviceSigning: dskData.wrappedDeviceSigning ?? undefined,
            userId: me.user_id,
            deviceId,
            ...(me.device_verified && me.keys?.encrypted_ecdh_private
              ? {
                  encryptedIdentityEcdh: base64UrlDecode(me.keys.encrypted_ecdh_private),
                  identityEcdhNonce: base64UrlDecode(me.keys.encrypted_ecdh_private_nonce),
                  encryptedIdentitySigning: base64UrlDecode(me.keys.encrypted_signing_private),
                  identitySigningNonce: base64UrlDecode(me.keys.encrypted_signing_private_nonce),
                }
              : {}),
          });
          workerReady = await worker.isReady();
        } catch (sessionFallbackErr) {
          console.error("[session] Worker sessionStorage fallback failed:", sessionFallbackErr);
          workerReady = false;
        }
      }
    }
    dskData = null;

    if (!workerReady && me.device_verified) {
      if (me.auth_type === "password" && hasPdkData()) {
        needsPasswordReentry = true;
      } else if (me.auth_type === "password") {
        // Password user without DSK/PDK: re-login required for PUK-based restore
        return null;
      } else {
        // OAuth without DSK: treat as new device (approval or recovery required)
        me.device_verified = false;
      }
    }

    // Get public keys from Worker (if ready)
    let identitySigningPublic: Uint8Array | null = null;
    let identityEcdhPublic: Uint8Array | null = null;
    let deviceSigningPublic: Uint8Array | null = null;
    let deviceEcdhPublic: Uint8Array | null = null;

    if (workerReady) {
      try {
        const pubKeys = await worker.getPublicKeys();
        identitySigningPublic = pubKeys.identitySigningPublic;
        identityEcdhPublic = pubKeys.identityEcdhPublic;
        deviceSigningPublic = pubKeys.deviceSigningPublic;
        deviceEcdhPublic = pubKeys.deviceEcdhPublic;
      } catch {
        // Public key retrieval failed
      }
    }

    // TOFU verification (runs inside Worker)
    let tofuWarnings: string[] = [];
    if (workerReady && me.device_verified && deviceId) {
      try {
        const { devices } = await devicesApi.list({ popDeviceId: deviceId });
        const tofuResult = await worker.tofuVerifyAllDevices({
          devices: devices.map((d: any) => ({
            name: d.name,
            userId: d.user_id,
            deviceId: d.id,
            signingPublicKey: base64UrlDecode(d.signing_public_key),
            ecdhPublicKey: base64UrlDecode(d.ecdh_public_key),
            identitySignature: d.identity_signature ?? null,
            clientNonce: d.client_nonce ?? null,
          })),
        });
        tofuWarnings = tofuResult.errors;
      } catch (e) {
        if (
          e instanceof Error &&
          (("code" in e && (e as any).code === "tofu_hard_fail") || e.message.includes("TOFU"))
        ) {
          throw e;
        }
      }
    }

    return {
      userId: me.user_id,
      email: me.email,
      name: me.name,
      sessionId: me.session_id,
      deviceId: deviceId ?? null,
      deviceVerified: me.device_verified,
      expiresAt: me.expires_at,
      needsPasswordReentry,
      tofuWarnings,
      identitySigningPublic,
      identityEcdhPublic,
      deviceSigningPublic,
      deviceEcdhPublic,
      workerReady,
    };
  } catch (err) {
    if (
      err instanceof Error &&
      (("code" in err && (err as any).code === "tofu_hard_fail") || err.message.includes("TOFU"))
    )
      throw err;
    if (err instanceof ApiError) {
      if (err.status === 401 || err.status === 403) return null;
      if (err.status === 429) return "rate_limited";
    }
    return "transient_error";
  }
}
