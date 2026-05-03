/**
 * Ephemeral Message Send Helper
 *
 * Encrypts an ephemeral payload with the document DEK and signs
 * the WS envelope with the device signing key via CryptoWorker,
 * then sends via the Phoenix Channel.
 */

import { getCryptoWorker, type CryptoWorkerClient } from "@/shared/lib/crypto/worker/client";
import { base64UrlEncode } from "@/shared/lib/crypto/encoding";
import { pushEphemeral } from "@/shared/lib/ws/phoenix-channel";

export async function sendEphemeralEnvelope(
  payload: Uint8Array,
  documentId: string,
  keyVersion: number,
  deviceId: string,
  signingPubKeyB64: string,
  channelKey = documentId,
  cacheKey?: string,
  workerOverride?: CryptoWorkerClient,
): Promise<void> {
  const worker = workerOverride ?? getCryptoWorker();

  const { ciphertext, nonce } = await worker.encryptContent({
    plaintext: payload,
    documentId,
    keyVersion,
    cacheKey,
  });

  const ciphertextB64 = base64UrlEncode(ciphertext);
  const nonceB64 = base64UrlEncode(nonce);

  const publicData: Record<string, unknown> = {
    docId: documentId,
    deviceId,
    signingPubKey: signingPubKeyB64,
  };

  const { signature } = await worker.signWsEnvelope({
    prefix: "refmd_ephemeral",
    ciphertext: ciphertextB64,
    nonce: nonceB64,
    publicData,
  });

  const sent = pushEphemeral(
    documentId,
    {
      ciphertext: ciphertextB64,
      nonce: nonceB64,
      signature: base64UrlEncode(signature),
      publicData,
    },
    channelKey,
  );

  if (!sent) {
    throw new Error("Ephemeral push failed: channel not joined");
  }
}
