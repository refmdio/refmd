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
import type { DocumentState } from "../../model/document-state/types";
import { buildEphemeralAuthorityBoundary } from "./ephemeral-authority";
import { prepareDocumentAuthorityContext } from "./outbound-admission";

export async function sendEphemeralEnvelope(
  payload: Uint8Array,
  documentId: string,
  state: DocumentState,
  signingKeyId: string,
  channelKey = documentId,
  cacheKey?: string,
  workerOverride?: CryptoWorkerClient,
): Promise<void> {
  const worker = workerOverride ?? getCryptoWorker();
  const keyVersion = state.pendingRotationKeyVersion ?? state.keyVersion;
  const authority = await prepareDocumentAuthorityContext(
    state,
    documentId,
    signingKeyId,
    keyVersion,
  );

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
    signingKeyId: signingKeyId,
    keyVersion,
    ...authority.publicDataFields,
    workspaceEventHeadSequence: authority.authorityBoundary.previous_workspace_event_sequence,
    workspaceEventHeadHash: authority.authorityBoundary.previous_workspace_event_hash,
  };

  const { signature } = await worker.signEditorEphemeral({
    ciphertext: ciphertextB64,
    nonce: nonceB64,
    workspaceId: state.workspaceId,
    publicData,
    authorityBoundary: buildEphemeralAuthorityBoundary({
      workspaceId: state.workspaceId,
      publicData,
    }),
  });

  const sent = pushEphemeral(
    documentId,
    {
      ciphertext: ciphertextB64,
      nonce: nonceB64,
      signature,
      publicData,
    },
    channelKey,
  );

  if (!sent) {
    throw new Error("Ephemeral push failed: channel not joined");
  }
}
