import { describe, expect, it } from "vite-plus/test";
import { blake3Base64Url } from "@/shared/lib/crypto/hash";
import { canonicalizeStrictBytes, type StrictJsonValue } from "@/shared/lib/crypto/jcs";
import { verifyRotationDeletionEvidences } from "./rotation-deletion-evidence";

const USER_ID = "11111111-1111-4111-8111-111111111111";
const DEVICE_ID = "22222222-2222-4222-8222-222222222222";
const WORKSPACE_ID = "33333333-3333-4333-8333-333333333333";
const DOCUMENT_ID = "44444444-4444-4444-8444-444444444444";

describe("KEK rotation deletion evidence", () => {
  it("binds the manifest to the exact proof and wipe-required sets", () => {
    const proof = { payload: { device_id: DEVICE_ID }, transcript: {}, signature: {} };
    const manifest = {
      protocol: "refmd.old-key-deletion-manifest",
      version: 1,
      rotation_kind: "kek",
      scope_kind: "workspace",
      scope_id: WORKSPACE_ID,
      old_key_version: 1,
      rotation_completed_event_hash: "completed-event",
      deleted_secret_ids_hash: "deleted-secrets",
      deleted_wrap_ids_hash: "deleted-wraps",
      active_device_deletion_proofs_hash: hash({ proof_hashes: [hash(proof.payload)] }),
      wipe_required_device_ids_hash: hash({ device_ids: [] }),
      server_rejects_old_key_uploads_after_sequence: 9,
    };
    const event = {
      payload: {
        protocol: "refmd.key-directory-event",
        version: 1,
        scope_kind: "workspace",
        scope_id: WORKSPACE_ID,
        sequence: 9,
        event_type: "old_key_deleted",
        body: {
          rotation_kind: "kek",
          scope_kind: "workspace",
          scope_id: WORKSPACE_ID,
          old_key_version: 1,
          deletion_manifest_hash: hash(manifest),
        },
      },
      signatures: [],
    };
    const evidence = {
      old_key_deleted_event_hash: hash(event.payload),
      workspace_id: WORKSPACE_ID,
      rotation_kind: "kek",
      scope_kind: "workspace",
      scope_id: WORKSPACE_ID,
      old_key_version: 1,
      deletion_manifest: manifest,
      device_key_deletion_proofs: { proofs: [proof] },
      wipe_required_device_ids: [],
    };

    expect(() =>
      verifyRotationDeletionEvidences({
        scopeKind: "workspace",
        scopeId: WORKSPACE_ID,
        events: [event],
        evidences: [evidence],
      }),
    ).not.toThrow();

    expect(() =>
      verifyRotationDeletionEvidences({
        scopeKind: "workspace",
        scopeId: WORKSPACE_ID,
        events: [event],
        evidences: [{ ...evidence, wipe_required_device_ids: [DEVICE_ID] }],
      }),
    ).toThrow("rotation_deletion_manifest_mismatch");

    expect(() =>
      verifyRotationDeletionEvidences({
        scopeKind: "workspace",
        scopeId: WORKSPACE_ID,
        events: [event],
        evidences: [
          {
            ...evidence,
            device_key_deletion_proofs: {
              proofs: [{ ...proof, payload: { device_id: "substituted" } }],
            },
          },
        ],
      }),
    ).toThrow("rotation_deletion_manifest_mismatch");

    expect(() =>
      verifyRotationDeletionEvidences({
        scopeKind: "workspace",
        scopeId: WORKSPACE_ID,
        events: [event],
        evidences: [
          {
            ...evidence,
            device_key_deletion_proofs: { proofs: [proof, proof] },
          },
        ],
      }),
    ).toThrow("rotation_deletion_evidence_duplicate");

    expect(() =>
      verifyRotationDeletionEvidences({
        scopeKind: "workspace",
        scopeId: WORKSPACE_ID,
        events: [event],
        evidences: [
          {
            ...evidence,
            device_key_deletion_proofs: { proofs: [] },
            wipe_required_device_ids: [DEVICE_ID, DEVICE_ID],
          },
        ],
      }),
    ).toThrow("rotation_deletion_evidence_duplicate");

    expect(() =>
      verifyRotationDeletionEvidences({
        scopeKind: "workspace",
        scopeId: WORKSPACE_ID,
        events: [event],
        evidences: [{ ...evidence, device_key_deletion_proofs: undefined }],
      }),
    ).toThrow("rotation_deletion_proofs_missing");
  });
});

describe("identity rotation deletion evidence", () => {
  it("binds the deletion manifest to the signed proof set and wipe-required devices", () => {
    const proof = { payload: { device_id: DEVICE_ID }, transcript: {}, signature: {} };
    const proofHash = hash(proof.payload);
    const manifest = {
      protocol: "refmd.identity-old-key-deletion-manifest",
      version: 1,
      rotation_kind: "identity",
      scope_kind: "user",
      scope_id: USER_ID,
      old_identity_signing_key_id: "old-signing",
      old_identity_encryption_key_id: "old-encryption",
      new_identity_signing_key_id: "new-signing",
      rotation_completed_event_hash: "completed-event",
      deleted_identity_secret_ids_hash: "deleted-identities",
      active_identity_deletion_proofs_hash: hash({ proof_hashes: [proofHash] }),
      wipe_required_device_ids_hash: hash({ device_ids: [] }),
      server_rejects_old_identity_after_sequence: 9,
    };
    const event = {
      payload: {
        protocol: "refmd.key-directory-event",
        version: 1,
        scope_kind: "user",
        scope_id: USER_ID,
        sequence: 9,
        event_type: "old_key_deleted",
        body: {
          rotation_kind: "identity",
          scope_kind: "user",
          scope_id: USER_ID,
          old_identity_signing_key_id: "old-signing",
          old_identity_encryption_key_id: "old-encryption",
          new_identity_signing_key_id: "new-signing",
          rotation_completed_event_hash: "completed-event",
          deletion_manifest_hash: hash(manifest),
        },
      },
      signatures: [],
    };
    const evidence = {
      old_key_deleted_event_hash: hash(event.payload),
      user_id: USER_ID,
      rotation_kind: "identity",
      scope_kind: "user",
      scope_id: USER_ID,
      old_key_version: 1,
      deletion_manifest: manifest,
      device_key_deletion_proofs: { proofs: [proof] },
      wipe_required_device_ids: [],
    };

    expect(() =>
      verifyRotationDeletionEvidences({
        scopeKind: "user",
        scopeId: USER_ID,
        events: [event],
        evidences: [evidence],
      }),
    ).not.toThrow();

    expect(() =>
      verifyRotationDeletionEvidences({
        scopeKind: "user",
        scopeId: USER_ID,
        events: [event],
        evidences: [
          {
            ...evidence,
            device_key_deletion_proofs: {
              proofs: [{ ...proof, payload: { device_id: "tampered" } }],
            },
          },
        ],
      }),
    ).toThrow("rotation_deletion_manifest_mismatch");
  });
});

describe("DEK rotation deletion evidence", () => {
  it("binds document evidence and proof sets to its workspace directory", () => {
    const proof = { payload: { device_id: DEVICE_ID }, transcript: {}, signature: {} };
    const completionManifest = {
      protocol: "refmd.rotation-completion-manifest",
      version: 1,
      rotation_kind: "dek",
      scope_kind: "document",
      scope_id: DOCUMENT_ID,
      old_key_version: 1,
      new_key_version: 2,
      started_event_hash: "started-event",
      new_key_records: [],
      rewritten_records: {},
      deleted_wrap_ids_hash: "deleted-wraps",
      semantic_state_proof_hash: "state-proof",
    };
    const completedEvent = {
      payload: {
        protocol: "refmd.key-directory-event",
        version: 1,
        scope_kind: "workspace",
        scope_id: WORKSPACE_ID,
        sequence: 8,
        event_type: "rotation_completed",
        body: {
          rotation_kind: "dek",
          scope_kind: "document",
          scope_id: DOCUMENT_ID,
          old_key_version: 1,
          new_key_version: 2,
          completion_manifest_hash: hash(completionManifest),
        },
      },
      signatures: [],
    };
    const manifest = {
      protocol: "refmd.old-key-deletion-manifest",
      version: 1,
      rotation_kind: "dek",
      scope_kind: "document",
      scope_id: DOCUMENT_ID,
      old_key_version: 1,
      rotation_completed_event_hash: hash(completedEvent.payload),
      deleted_secret_ids_hash: "deleted-secrets",
      deleted_wrap_ids_hash: "deleted-wraps",
      active_device_deletion_proofs_hash: hash({ proof_hashes: [hash(proof.payload)] }),
      wipe_required_device_ids_hash: hash({ device_ids: [] }),
      server_rejects_old_key_uploads_after_sequence: 9,
    };
    const event = {
      payload: {
        protocol: "refmd.key-directory-event",
        version: 1,
        scope_kind: "workspace",
        scope_id: WORKSPACE_ID,
        sequence: 9,
        event_type: "old_key_deleted",
        body: {
          rotation_kind: "dek",
          scope_kind: "document",
          scope_id: DOCUMENT_ID,
          old_key_version: 1,
          deletion_manifest_hash: hash(manifest),
        },
      },
      signatures: [],
    };
    const evidence = {
      old_key_deleted_event_hash: hash(event.payload),
      document_id: DOCUMENT_ID,
      workspace_id: WORKSPACE_ID,
      rotation_kind: "dek",
      scope_kind: "document",
      scope_id: DOCUMENT_ID,
      old_key_version: 1,
      completion_manifest: completionManifest,
      deletion_manifest: manifest,
      device_key_deletion_proofs: { proofs: [proof] },
      wipe_required_device_ids: [],
    };

    expect(() =>
      verifyRotationDeletionEvidences({
        scopeKind: "workspace",
        scopeId: WORKSPACE_ID,
        events: [completedEvent, event],
        evidences: [evidence],
      }),
    ).not.toThrow();

    expect(() =>
      verifyRotationDeletionEvidences({
        scopeKind: "workspace",
        scopeId: WORKSPACE_ID,
        events: [completedEvent, event],
        evidences: [{ ...evidence, workspace_id: USER_ID }],
      }),
    ).toThrow("rotation_deletion_evidence_mismatch");

    expect(() =>
      verifyRotationDeletionEvidences({
        scopeKind: "workspace",
        scopeId: WORKSPACE_ID,
        events: [completedEvent, event],
        evidences: [{ ...evidence, device_key_deletion_proofs: { proofs: [] } }],
      }),
    ).toThrow("rotation_deletion_manifest_mismatch");
  });
});

function hash(value: StrictJsonValue): string {
  return blake3Base64Url(canonicalizeStrictBytes(value));
}
