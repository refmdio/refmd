import { blake3Base64Url } from "@/shared/lib/crypto/hash";
import { canonicalizeStrictBytes, type StrictJsonValue } from "@/shared/lib/crypto/jcs";

interface DocumentUpdateHashFields {
  clock: number;
  signing_key_id: string;
  document_id: string;
  encrypted_content: string;
  key_version: number;
  nonce: string;
  ref_snapshot_id: string | null;
  timestamp: number;
}

export function computeDocumentUpdateHash(fields: DocumentUpdateHashFields): string {
  return blake3Base64Url(canonicalizeStrictBytes(fields as unknown as StrictJsonValue));
}
