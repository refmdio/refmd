import { describe, expect, it } from "vite-plus/test";
import type { VerifiedSignedPqWrapOperation } from "@/shared/lib/anti-rollback/key-directory-pin/wrap-operation-proof";
import { assertRecipientDeliveryAdmissionBindings } from "@/shared/lib/anti-rollback/key-directory-pin/recipient-delivery-admission";
import { recipientDeliveryAdmissionFixture } from "@/shared/lib/anti-rollback/key-directory-pin/recipient-delivery-admission.test-support";
import type { HybridEncryptionPrivateKeyMaterial } from "./hybrid-encryption";
import type { HybridSigningPublicKeyMaterial } from "./signature";
import { verifyPqWrapSignature } from "./signature";
import { blake3Base64Url } from "./hash";
import { decodeBase64UrlStrict, encodeBase64Url } from "./encoding";
import { canonicalizeStrictBytes, parseJsonStrictBytes, type StrictJsonValue } from "./jcs";
import {
  openSignedPqWrap,
  signedPqWrapEventBody,
  signedPqWrapRecordFromEnvelope,
  type SignedPqWrapRecord,
} from "./signed-pq-wrap";
import { nativeHpkeOpen } from "./worker/native-hpke";

type PatchOperation =
  | { op: "replace"; path: string; value: StrictJsonValue }
  | { op: "remove"; path: string };

interface NegativeVector {
  base: string;
  mutation: string;
  operations: PatchOperation[];
  expected_error: string;
}

interface SignedPqWrapFixture {
  schema_version: number;
  case_id: string;
  plaintext_b64u: string;
  recipient_private_key_material: HybridEncryptionPrivateKeyMaterial;
  sender_signing_public_key_material: HybridSigningPublicKeyMaterial;
  record: SignedPqWrapRecord;
  verified_operation: VerifiedSignedPqWrapOperation;
  canonical: Record<string, string>;
  hashes: Record<string, string>;
  negative: NegativeVector[];
}

const nodeFsPromises = "node:fs/promises";
const { readFile } = await import(/* @vite-ignore */ nodeFsPromises);
const fixture = JSON.parse(
  await readFile("../native/refmd_crypto/testdata/refmd-signed-pq-wrap-v1.json", "utf8"),
) as SignedPqWrapFixture;

describe("immutable RefMD signed PQ wrap vector", () => {
  it("matches every canonical preimage and digest", () => {
    expect(fixture.schema_version).toBe(1);
    expect(fixture.case_id).toBe("signed-pq-wrap-v1");

    for (const encoded of Object.values(fixture.canonical)) {
      const bytes = decodeBase64UrlStrict(encoded);
      expect(Array.from(canonicalizeStrictBytes(parseJsonStrictBytes(bytes)))).toEqual(
        Array.from(bytes),
      );
    }

    expect(canonicalBytes(fixture.record.resource)).toBe(fixture.canonical.resource_jcs_b64u);
    expect(canonicalBytes(signedPqWrapEventBody(fixture.record))).toBe(
      fixture.canonical.event_body_jcs_b64u,
    );
    expect(hashCanonical(fixture.canonical.resource_jcs_b64u)).toBe(fixture.hashes.resource_hash);
    expect(hashCanonical(fixture.canonical.hpke_info_jcs_b64u)).toBe(fixture.hashes.hpke_info_hash);
    expect(hashCanonical(fixture.canonical.aad_jcs_b64u)).toBe(fixture.hashes.aad_hash);
    expect(hashCanonical(fixture.canonical.wrap_body_jcs_b64u)).toBe(fixture.hashes.wrap_body_hash);
    expect(hashCanonical(fixture.canonical.event_body_jcs_b64u)).toBe(
      fixture.hashes.wrap_event_body_hash,
    );
    expect(hashCanonical(fixture.canonical.event_jcs_b64u)).toBe(fixture.hashes.wrap_event_hash);
    expect(hashCanonical(fixture.canonical.signature_transcript_jcs_b64u)).toBe(
      fixture.record.transcript_hash,
    );
  });

  it("opens the exact fixed ciphertext through the Rust/WASM production boundary", () => {
    const record = signedPqWrapRecordFromEnvelope(fixture.record);
    expect(
      openSignedPqWrap({
        record,
        recipientPrivateKeyMaterial: fixture.recipient_private_key_material,
        senderSigningPublicKeyMaterial: fixture.sender_signing_public_key_material,
        verifiedOperation: fixture.verified_operation,
      }),
    ).toEqual(decodeBase64UrlStrict(fixture.plaintext_b64u));
  });

  it.each(fixture.negative.filter((vector) => vector.base === fixture.case_id))(
    "rejects $mutation",
    (negative) => {
      expect(negative.base).toBe(fixture.case_id);
      const mutated = structuredClone(fixture);
      for (const operation of negative.operations) applyPatch(mutated, operation);

      expect(() =>
        openSignedPqWrap({
          record: signedPqWrapRecordFromEnvelope(mutated.record),
          recipientPrivateKeyMaterial: mutated.recipient_private_key_material,
          senderSigningPublicKeyMaterial: mutated.sender_signing_public_key_material,
          verifiedOperation: mutated.verified_operation,
        }),
      ).toThrow(negative.expected_error);
    },
  );

  it.each(fixture.negative.filter((vector) => vector.base.startsWith("recipient-delivery-")))(
    "rejects $mutation before recipient delivery decryption",
    (negative) => {
      const kind =
        negative.base === "recipient-delivery-guest-v1"
          ? "guest_invitation"
          : "workspace_invitation";
      const mutated = recipientDeliveryAdmissionFixture(kind);
      for (const operation of negative.operations) applyPatch(mutated, operation);

      expect(() => assertRecipientDeliveryAdmissionBindings(mutated)).toThrow(
        negative.expected_error,
      );
    },
  );

  it.each(
    fixture.negative.filter((vector) =>
      [
        "signed-pq-wrap-aad-v1",
        "signed-pq-wrap-hpke-info-v1",
        "signed-pq-wrap-body-v1",
        "signed-pq-wrap-event-body-v1",
        "signed-pq-wrap-signature-transcript-v1",
      ].includes(vector.base),
    ),
  )("rejects independent $mutation", (negative) => {
    expect(() => executeCanonicalMutation(negative)).toThrow(negative.expected_error);
  });
});

function executeCanonicalMutation(negative: NegativeVector): void {
  const canonicalField = canonicalFieldForBase(negative.base);
  const value = parseJsonStrictBytes(decodeBase64UrlStrict(fixture.canonical[canonicalField]));
  if (value === null || Array.isArray(value) || typeof value !== "object") {
    throw new Error("fixture_canonical_base_invalid");
  }
  const mutated = structuredClone(value);
  for (const operation of negative.operations) applyPatch(mutated, operation);
  const mutatedBytes = canonicalizeStrictBytes(mutated);

  if (negative.base === "signed-pq-wrap-aad-v1") {
    openWithCanonicalOverride({ aad: mutatedBytes });
    return;
  }
  if (negative.base === "signed-pq-wrap-hpke-info-v1") {
    openWithCanonicalOverride({ info: mutatedBytes });
    return;
  }

  const transcript = parseJsonStrictBytes(
    decodeBase64UrlStrict(fixture.canonical.signature_transcript_jcs_b64u),
  );
  if (transcript === null || Array.isArray(transcript) || typeof transcript !== "object") {
    throw new Error("fixture_signature_transcript_invalid");
  }
  const mutatedTranscript = structuredClone(transcript) as Record<string, StrictJsonValue>;
  if (negative.base === "signed-pq-wrap-body-v1") {
    setTranscriptSubjectHash(mutatedTranscript, "wrap_body_hash", blake3Base64Url(mutatedBytes));
  } else if (negative.base === "signed-pq-wrap-event-body-v1") {
    setTranscriptSubjectHash(
      mutatedTranscript,
      "wrap_event_body_hash",
      blake3Base64Url(mutatedBytes),
    );
  } else {
    for (const operation of negative.operations) applyPatch(mutatedTranscript, operation);
  }

  if (
    !verifyPqWrapSignature({
      transcript: mutatedTranscript,
      signature: fixture.record.signature,
      publicKeyMaterial: fixture.sender_signing_public_key_material,
    })
  ) {
    throw new Error("signed_pq_wrap_signature_invalid");
  }
}

function openWithCanonicalOverride(override: { info?: Uint8Array; aad?: Uint8Array }): void {
  nativeHpkeOpen({
    privateKey: decodeBase64UrlStrict(
      fixture.recipient_private_key_material.mlkem768_x25519_private,
      32,
    ),
    enc: decodeBase64UrlStrict(fixture.record.hpke.enc, 1120),
    info: override.info ?? decodeBase64UrlStrict(fixture.canonical.hpke_info_jcs_b64u),
    aad: override.aad ?? decodeBase64UrlStrict(fixture.canonical.aad_jcs_b64u),
    ciphertext: decodeBase64UrlStrict(fixture.record.hpke.ciphertext),
  });
}

function setTranscriptSubjectHash(
  transcript: Record<string, StrictJsonValue>,
  field: string,
  value: string,
): void {
  const subjectHashes = transcript.subject_hashes;
  if (subjectHashes === null || Array.isArray(subjectHashes) || typeof subjectHashes !== "object") {
    throw new Error("fixture_signature_subject_hashes_invalid");
  }
  (subjectHashes as Record<string, StrictJsonValue>)[field] = value;
}

function canonicalFieldForBase(base: string): string {
  switch (base) {
    case "signed-pq-wrap-aad-v1":
      return "aad_jcs_b64u";
    case "signed-pq-wrap-hpke-info-v1":
      return "hpke_info_jcs_b64u";
    case "signed-pq-wrap-body-v1":
      return "wrap_body_jcs_b64u";
    case "signed-pq-wrap-event-body-v1":
      return "event_body_jcs_b64u";
    case "signed-pq-wrap-signature-transcript-v1":
      return "signature_transcript_jcs_b64u";
    default:
      throw new Error("fixture_canonical_base_invalid");
  }
}

function canonicalBytes(value: StrictJsonValue): string {
  return encodeBase64Url(canonicalizeStrictBytes(value));
}

function hashCanonical(encoded: string): string {
  return blake3Base64Url(decodeBase64UrlStrict(encoded));
}

function applyPatch(target: object, operation: PatchOperation): void {
  const segments = operation.path
    .split("/")
    .slice(1)
    .map((segment) => segment.replaceAll("~1", "/").replaceAll("~0", "~"));
  if (segments.length === 0) throw new Error("fixture_patch_path_invalid");

  let owner: Record<string, unknown> | unknown[] = target as Record<string, unknown>;
  for (const segment of segments.slice(0, -1)) {
    const child = patchValue(owner, segment);
    if (child === null || typeof child !== "object") {
      throw new Error("fixture_patch_path_invalid");
    }
    owner = child as Record<string, unknown> | unknown[];
  }

  const field = segments.at(-1)!;
  if (Array.isArray(owner)) {
    const index = patchIndex(owner, field);
    if (operation.op === "remove") owner.splice(index, 1);
    else owner[index] = operation.value;
    return;
  }
  if (!(field in owner)) throw new Error("fixture_patch_path_invalid");
  if (operation.op === "remove") delete owner[field];
  else owner[field] = operation.value;
}

function patchValue(owner: Record<string, unknown> | unknown[], segment: string): unknown {
  return Array.isArray(owner) ? owner[patchIndex(owner, segment)] : owner[segment];
}

function patchIndex(owner: unknown[], segment: string): number {
  const index = Number(segment);
  if (!Number.isInteger(index) || index < 0 || index >= owner.length) {
    throw new Error("fixture_patch_path_invalid");
  }
  return index;
}
