import { base64UrlEncode } from "./encoding";
import { blake3Base64Url } from "./hash";
import { canonicalizeStrictBytes, type StrictJsonValue } from "./jcs";
import { getCryptoWorker } from "./worker/client";

export async function buildCurrentDeviceKeyDeletionProof(params: {
  workspaceId: string;
  userId: string;
  deviceId: string;
  rotationKind: "kek" | "dek";
  scopeKind: "workspace" | "document";
  scopeId: string;
  oldKeyVersion: number;
  rotationCompletedEventHash: string;
  deletedSecretIdsHash: string;
  checkpointEnvelope: Record<string, unknown>;
}): Promise<Record<string, unknown>> {
  const checkpointPayload = params.checkpointEnvelope.payload as
    | Record<string, unknown>
    | undefined;
  if (!checkpointPayload) throw new Error("key_directory_checkpoint_payload_invalid");
  const signingKeyId = activeDeviceSigningKeyId(checkpointPayload, params.deviceId);
  const proofNonce = new Uint8Array(32);
  crypto.getRandomValues(proofNonce);

  const signed = await getCryptoWorker().signDeviceKeyDeletionProof({
    payload: {
      protocol: "refmd.device-key-deletion-proof",
      version: 1,
      workspace_id: params.workspaceId,
      device_id: params.deviceId,
      rotation_kind: params.rotationKind,
      scope_kind: params.scopeKind,
      scope_id: params.scopeId,
      old_key_version: params.oldKeyVersion,
      rotation_completed_event_hash: params.rotationCompletedEventHash,
      deleted_secret_ids_hash: params.deletedSecretIdsHash,
      deleted_storage_classes: [
        "crypto_worker_state",
        "indexeddb_cache",
        "local_encrypted_key_store",
        "offline_cache",
        "pending_queue",
      ],
      local_cache_epoch: 1,
      proof_nonce: base64UrlEncode(proofNonce),
    },
    actor: {
      signer_kind: "workspace_device",
      user_id: params.userId,
      device_id: params.deviceId,
      signing_key_id: signingKeyId,
      key_scope_kind: "workspace",
      key_scope_id: params.workspaceId,
      key_checkpoint_sequence: checkpointPayload.sequence,
      key_checkpoint_hash: blake3Base64Url(
        canonicalizeStrictBytes(checkpointPayload as StrictJsonValue),
      ),
    },
  });
  return {
    payload: signed.payload,
    transcript: signed.transcript,
    signature: signed.signature,
  };
}

export function deletedKeySecretIdsHash(secretId: string): string {
  return blake3Base64Url(canonicalizeStrictBytes({ secret_ids: [secretId] }));
}

function activeDeviceSigningKeyId(
  checkpointPayload: Record<string, unknown>,
  deviceId: string,
): string {
  const keys = checkpointPayload.device_keys;
  if (!Array.isArray(keys)) throw new Error("key_directory_device_keys_invalid");
  const entry = keys.find((candidate) => {
    if (!candidate || typeof candidate !== "object" || Array.isArray(candidate)) return false;
    const record = candidate as Record<string, unknown>;
    const material = record.key_material as Record<string, unknown> | undefined;
    return (
      !("revoked_at" in record) &&
      material?.protocol === "refmd.hybrid-signing-key-material" &&
      material.owner_kind === "device" &&
      material.owner_id === deviceId
    );
  }) as Record<string, unknown> | undefined;
  if (!entry || typeof entry.key_id !== "string") {
    throw new Error("key_directory_device_key_missing");
  }
  return entry.key_id;
}
