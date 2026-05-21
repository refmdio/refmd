import { base64UrlEncode } from "@/shared/lib/crypto/encoding";
import { canonicalizeStrictBytes } from "@/shared/lib/crypto/jcs";
import { blake3 } from "@noble/hashes/blake3.js";

export function computeSnapshotProofLinkHash(params: {
  documentId: string;
  snapshotId: string;
  parentSnapshotId: string;
  parentProofHash: string;
  ciphertextHash: string;
  snapshotSignatureHash: string;
  snapshotAdmissionEventHash: string;
}): string {
  return base64UrlEncode(
    blake3(
      canonicalizeStrictBytes({
        protocol: "refmd.snapshot-proof-link",
        version: 1,
        document_id: params.documentId,
        snapshot_id: params.snapshotId,
        parent_snapshot_id: params.parentSnapshotId,
        parent_proof_hash: params.parentProofHash,
        ciphertext_hash: params.ciphertextHash,
        snapshot_signature_hash: params.snapshotSignatureHash,
        snapshot_admission_event_hash: params.snapshotAdmissionEventHash,
      }),
    ),
  );
}
