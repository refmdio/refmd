import { describe, expect, it } from "vite-plus/test";
import {
  generateHybridEncryptionPrivateKeyMaterial,
  publicHybridEncryptionMaterialFromPrivate,
} from "./hybrid-encryption";
import {
  createSignedPqWrap,
  finalizeSignedPqWrapOperationCheckpoint,
  openSignedPqWrap,
} from "./signed-pq-wrap";
import { generateHybridSigningPrivateKeyMaterial, publicKeyMaterialFromPrivate } from "./signature";

const HASH_A = "F3Yv3dlppFOSXWVxesPuohMgtmtUNC_eFRKNbK8hIV8";
const HASH_B = "EOXPPTyKT580aMjMWO6oSJKiL9rbwayyJBAZAETB1VM";

describe("signed PQ wrap", () => {
  it("rejects share-scoped wrap resources with workspace scope", () => {
    const senderDeviceId = crypto.randomUUID();
    const recipientDeviceId = crypto.randomUUID();
    const workspaceId = crypto.randomUUID();
    const senderSigning = generateHybridSigningPrivateKeyMaterial("device", senderDeviceId);
    const recipientEncryption = generateHybridEncryptionPrivateKeyMaterial(
      "device",
      recipientDeviceId,
    );

    expect(() =>
      createSignedPqWrap({
        purpose: "share_participant_bootstrap_wrap",
        plaintext: crypto.getRandomValues(new Uint8Array(32)),
        recipientPublicKeyMaterial: publicHybridEncryptionMaterialFromPrivate(recipientEncryption),
        senderSigningPrivateKeyMaterial: senderSigning,
        senderUserId: crypto.randomUUID(),
        senderDeviceId,
        resource: {
          workspace_id: workspaceId,
          share_id: crypto.randomUUID(),
          share_participant_principal_id: crypto.randomUUID(),
          share_participant_device_id: recipientDeviceId,
          scope_kind: "workspace",
          scope_id: workspaceId,
          permission: "edit",
          document_scope_hash: HASH_A,
          share_session_id: crypto.randomUUID(),
          share_key_version: 1,
          dek_version: 1,
          bootstrap_version: 1,
        },
        eventScope: { scope_kind: "workspace", scope_id: workspaceId },
        operationCheckpoint: {
          sequence: 1,
          checkpointHash: HASH_A,
          coveredHeadSequence: 1,
          coveredHeadHash: HASH_B,
        },
      }),
    ).toThrow("signed_pq_wrap_resource_scope_invalid");
  });

  it("rejects share-scoped wrap resources with none scope ids", () => {
    const senderDeviceId = crypto.randomUUID();
    const recipientDeviceId = crypto.randomUUID();
    const workspaceId = crypto.randomUUID();
    const senderSigning = generateHybridSigningPrivateKeyMaterial("device", senderDeviceId);
    const recipientEncryption = generateHybridEncryptionPrivateKeyMaterial(
      "device",
      recipientDeviceId,
    );

    expect(() =>
      createSignedPqWrap({
        purpose: "share_participant_bootstrap_wrap",
        plaintext: crypto.getRandomValues(new Uint8Array(32)),
        recipientPublicKeyMaterial: publicHybridEncryptionMaterialFromPrivate(recipientEncryption),
        senderSigningPrivateKeyMaterial: senderSigning,
        senderUserId: crypto.randomUUID(),
        senderDeviceId,
        resource: {
          workspace_id: workspaceId,
          share_id: crypto.randomUUID(),
          share_participant_principal_id: crypto.randomUUID(),
          share_participant_device_id: recipientDeviceId,
          scope_kind: "document",
          scope_id: "none",
          permission: "edit",
          document_scope_hash: HASH_A,
          share_session_id: crypto.randomUUID(),
          share_key_version: 1,
          dek_version: 1,
          bootstrap_version: 1,
        },
        eventScope: { scope_kind: "workspace", scope_id: workspaceId },
        operationCheckpoint: {
          sequence: 1,
          checkpointHash: HASH_A,
          coveredHeadSequence: 1,
          coveredHeadHash: HASH_B,
        },
      }),
    ).toThrow("signed_pq_wrap_resource_scope_invalid");
  });

  it("rejects share-scoped wrap resources with malformed hash fields", () => {
    const senderDeviceId = crypto.randomUUID();
    const recipientDeviceId = crypto.randomUUID();
    const workspaceId = crypto.randomUUID();
    const senderSigning = generateHybridSigningPrivateKeyMaterial("device", senderDeviceId);
    const recipientEncryption = generateHybridEncryptionPrivateKeyMaterial(
      "device",
      recipientDeviceId,
    );

    expect(() =>
      createSignedPqWrap({
        purpose: "share_participant_bootstrap_wrap",
        plaintext: crypto.getRandomValues(new Uint8Array(32)),
        recipientPublicKeyMaterial: publicHybridEncryptionMaterialFromPrivate(recipientEncryption),
        senderSigningPrivateKeyMaterial: senderSigning,
        senderUserId: crypto.randomUUID(),
        senderDeviceId,
        resource: {
          workspace_id: workspaceId,
          share_id: crypto.randomUUID(),
          share_participant_principal_id: crypto.randomUUID(),
          share_participant_device_id: recipientDeviceId,
          scope_kind: "document",
          scope_id: crypto.randomUUID(),
          permission: "edit",
          document_scope_hash: "not-a-blake3-hash",
          share_session_id: crypto.randomUUID(),
          share_key_version: 1,
          dek_version: 1,
          bootstrap_version: 1,
        },
        eventScope: { scope_kind: "workspace", scope_id: workspaceId },
        operationCheckpoint: {
          sequence: 1,
          checkpointHash: HASH_A,
          coveredHeadSequence: 1,
          coveredHeadHash: HASH_B,
        },
      }),
    ).toThrow("signed_pq_wrap_resource_hash_invalid");
  });

  it("allows unprotected share secret backups to carry no password capability commitment", () => {
    const senderDeviceId = crypto.randomUUID();
    const recipientDeviceId = crypto.randomUUID();
    const workspaceId = crypto.randomUUID();
    const senderSigning = generateHybridSigningPrivateKeyMaterial("device", senderDeviceId);
    const recipientEncryption = generateHybridEncryptionPrivateKeyMaterial(
      "device",
      recipientDeviceId,
    );

    expect(() =>
      createSignedPqWrap({
        purpose: "share_link_secret_backup_wrap",
        plaintext: crypto.getRandomValues(new Uint8Array(32)),
        recipientPublicKeyMaterial: publicHybridEncryptionMaterialFromPrivate(recipientEncryption),
        senderSigningPrivateKeyMaterial: senderSigning,
        senderUserId: crypto.randomUUID(),
        senderDeviceId,
        resource: shareLinkSecretBackupResource({
          workspace_id: workspaceId,
          scope_id: crypto.randomUUID(),
          recipient_device_id: recipientDeviceId,
          password_protected: false,
          password_capability_secret_commitment: "none",
        }),
        eventScope: { scope_kind: "workspace", scope_id: workspaceId },
        operationCheckpoint: {
          sequence: 1,
          checkpointHash: HASH_A,
          coveredHeadSequence: 1,
          coveredHeadHash: HASH_B,
        },
      }),
    ).not.toThrow();
  });

  it("rejects protected share secret backups without a password capability commitment", () => {
    const senderDeviceId = crypto.randomUUID();
    const recipientDeviceId = crypto.randomUUID();
    const workspaceId = crypto.randomUUID();
    const senderSigning = generateHybridSigningPrivateKeyMaterial("device", senderDeviceId);
    const recipientEncryption = generateHybridEncryptionPrivateKeyMaterial(
      "device",
      recipientDeviceId,
    );

    expect(() =>
      createSignedPqWrap({
        purpose: "share_link_secret_backup_wrap",
        plaintext: crypto.getRandomValues(new Uint8Array(32)),
        recipientPublicKeyMaterial: publicHybridEncryptionMaterialFromPrivate(recipientEncryption),
        senderSigningPrivateKeyMaterial: senderSigning,
        senderUserId: crypto.randomUUID(),
        senderDeviceId,
        resource: shareLinkSecretBackupResource({
          workspace_id: workspaceId,
          scope_id: crypto.randomUUID(),
          recipient_device_id: recipientDeviceId,
          password_protected: true,
          password_capability_secret_commitment: "none",
        }),
        eventScope: { scope_kind: "workspace", scope_id: workspaceId },
        operationCheckpoint: {
          sequence: 1,
          checkpointHash: HASH_A,
          coveredHeadSequence: 1,
          coveredHeadHash: HASH_B,
        },
      }),
    ).toThrow("signed_pq_wrap_resource_hash_invalid");
  });

  it("rejects HPKE body substitution even when the signed body hash is preserved", () => {
    const senderDeviceId = crypto.randomUUID();
    const recipientDeviceId = crypto.randomUUID();
    const workspaceId = crypto.randomUUID();
    const senderSigning = generateHybridSigningPrivateKeyMaterial("device", senderDeviceId);
    const recipientEncryption = generateHybridEncryptionPrivateKeyMaterial(
      "device",
      recipientDeviceId,
    );
    const resource = {
      workspace_id: workspaceId,
      target_user_id: crypto.randomUUID(),
      target_device_id: recipientDeviceId,
      kek_version: 1,
    };
    const base = {
      purpose: "workspace_device_kek_wrap" as const,
      plaintext: crypto.getRandomValues(new Uint8Array(32)),
      recipientPublicKeyMaterial: publicHybridEncryptionMaterialFromPrivate(recipientEncryption),
      senderSigningPrivateKeyMaterial: senderSigning,
      senderUserId: crypto.randomUUID(),
      senderDeviceId,
      resource,
      eventScope: { scope_kind: "workspace", scope_id: workspaceId } as const,
      operationCheckpoint: {
        sequence: 1,
        checkpointHash: HASH_A,
        coveredHeadSequence: 1,
        coveredHeadHash: HASH_B,
      },
    };
    const initial = createSignedPqWrap(base);
    const valid = finalizeSignedPqWrapOperationCheckpoint({
      record: initial,
      operationCheckpoint: {
        sequence: 2,
        checkpointHash: HASH_B,
        coveredHeadSequence: initial.event.wrap_event_sequence,
        coveredHeadHash: initial.event.wrap_event_hash,
      },
      senderSigningPrivateKeyMaterial: senderSigning,
    });
    const replacement = createSignedPqWrap({
      ...base,
      plaintext: crypto.getRandomValues(new Uint8Array(32)),
    });

    expect(
      openSignedPqWrap({
        record: valid,
        recipientPrivateKeyMaterial: recipientEncryption,
        senderSigningPublicKeyMaterial: publicKeyMaterialFromPrivate(senderSigning),
        expectedOperationCheckpoint: {
          sequence: valid.operation_checkpoint.checkpoint_sequence,
          checkpointHash: valid.operation_checkpoint.checkpoint_hash,
        },
      }),
    ).toEqual(base.plaintext);

    expect(() =>
      openSignedPqWrap({
        record: {
          ...valid,
          hpke: replacement.hpke,
        },
        recipientPrivateKeyMaterial: recipientEncryption,
        senderSigningPublicKeyMaterial: publicKeyMaterialFromPrivate(senderSigning),
        expectedOperationCheckpoint: {
          sequence: valid.operation_checkpoint.checkpoint_sequence,
          checkpointHash: valid.operation_checkpoint.checkpoint_hash,
        },
      }),
    ).toThrow("signed_pq_wrap_event_body_hash_mismatch");
  });
});

function shareLinkSecretBackupResource(overrides: Record<string, unknown> = {}) {
  return {
    workspace_id: crypto.randomUUID(),
    share_id: crypto.randomUUID(),
    token_hash: HASH_A,
    scope_kind: "document",
    scope_id: crypto.randomUUID(),
    permission: "edit",
    password_protected: false,
    created_event_hash: HASH_A,
    share_capability_secret_commitment: HASH_A,
    password_capability_secret_commitment: HASH_A,
    workspace_pin_bootstrap_hash: HASH_A,
    recipient_user_id: crypto.randomUUID(),
    recipient_device_id: crypto.randomUUID(),
    recipient_encryption_key_id: HASH_A,
    key_checkpoint_hash: HASH_A,
    ...overrides,
  };
}
