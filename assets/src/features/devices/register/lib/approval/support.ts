import { devicesApi, trustTransferApi } from "@/shared/api";
import { base64UrlDecode } from "@/shared/lib/crypto/encoding";
import { getCryptoWorker } from "@/shared/lib/crypto/worker/client";
import { TrustTransferKeyVerificationError } from "./error";

export async function requestTrustTransferNonce(deviceId: string): Promise<void> {
  try {
    const response = await trustTransferApi.requestNonce(deviceId);
    sessionStorage.setItem(`refmd-transfer-nonce-${deviceId}`, response.nonce);
  } catch {
    // Best-effort: if nonce request fails, trust state transfer won't happen.
  }
}

export async function retryGetUmk(
  deviceId: string,
  maxAttempts: number,
  delayMs: number,
  popDeviceId?: string,
): Promise<Awaited<ReturnType<typeof devicesApi.getUmk>>> {
  for (let attempt = 0; attempt < maxAttempts; attempt++) {
    try {
      return await devicesApi.getUmk(deviceId, popDeviceId ? { popDeviceId } : undefined);
    } catch (error) {
      if (attempt === maxAttempts - 1) throw error;
      await new Promise((resolve) => setTimeout(resolve, delayMs));
    }
  }

  throw new Error("UMK retrieval failed after retries");
}

export async function retrieveAndImportTrustState(userId: string, deviceId: string): Promise<void> {
  let state;
  try {
    state = await trustTransferApi.retrieveState(deviceId);
  } catch {
    // No trust state available (404 or error) — start with empty TOFU store.
    return;
  }

  if (!state.sender_ecdh_public_key || !state.sender_signing_public_key) return;

  const senderEcdhPublic = base64UrlDecode(state.sender_ecdh_public_key);
  const senderSigningPublic = base64UrlDecode(state.sender_signing_public_key);
  const worker = getCryptoWorker();

  const senderTofuResult = await worker.tofuVerify({
    userId,
    deviceId: state.sender_device_id,
    signingPublicKey: senderSigningPublic,
    ecdhPublicKey: senderEcdhPublic,
  });
  if (
    senderTofuResult.status === "identity_key_changed" ||
    senderTofuResult.status === "ecdh_key_mismatch"
  ) {
    throw new TrustTransferKeyVerificationError();
  }

  const storedNonce = sessionStorage.getItem(`refmd-transfer-nonce-${deviceId}`);
  if (!storedNonce) return;

  await worker.decryptTrustState({
    senderDeviceEcdhPublic: senderEcdhPublic,
    senderIdentitySigningPublic: senderSigningPublic,
    senderDeviceId: state.sender_device_id,
    transferNonce: base64UrlDecode(storedNonce),
    ciphertext: base64UrlDecode(state.ciphertext),
    nonce: base64UrlDecode(state.nonce),
    signature: base64UrlDecode(state.signature),
  });

  if (senderTofuResult.status === "first_seen") {
    await worker.tofuTrustDevice({
      userId,
      deviceId: state.sender_device_id,
      signingPublicKey: senderSigningPublic,
      ecdhPublicKey: senderEcdhPublic,
    });
  } else if (senderTofuResult.status === "known_trusted") {
    await worker.tofuUpdateLastSeen({ userId, deviceId: state.sender_device_id });
  }

  sessionStorage.removeItem(`refmd-transfer-nonce-${deviceId}`);
}
