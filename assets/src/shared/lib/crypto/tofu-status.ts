import { getCryptoWorker } from "./worker/client";

interface TofuVerifyParams {
  userId: string;
  deviceId: string;
  signingPublicKey: Uint8Array;
  ecdhPublicKey: Uint8Array;
}

interface TofuVerifyResult {
  status: string;
}

export async function applyTofuVerification(
  params: TofuVerifyParams,
  result: TofuVerifyResult,
): Promise<void> {
  const worker = getCryptoWorker();
  if (result.status === "identity_key_changed" || result.status === "ecdh_key_mismatch") {
    throw new Error("Key verification failed: " + result.status);
  }
  if (result.status === "first_seen") {
    await worker.tofuTrustDevice(params);
  } else if (result.status === "known_trusted") {
    await worker.tofuUpdateLastSeen({
      userId: params.userId,
      deviceId: params.deviceId,
    });
  }
}

export async function verifyAndHandleTofu(params: TofuVerifyParams): Promise<void> {
  const worker = getCryptoWorker();
  const result = (await worker.tofuVerify(params)) as TofuVerifyResult;
  await applyTofuVerification(params, result);
}
