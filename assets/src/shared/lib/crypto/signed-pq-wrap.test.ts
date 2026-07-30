import { describe, expect, it } from "vite-plus/test";
import {
  generateHybridEncryptionPrivateKeyMaterial,
  publicHybridEncryptionMaterialFromPrivate,
} from "./hybrid-encryption";
import {
  createGenesisWorkspaceMemberEnvelopePrecommit,
  createSignedPqWrapPrecommit,
  createSignedPqWrap,
  finalizeSignedPqWrapOperationCheckpoint,
  openSignedPqWrap,
  signedPqWrapEventBody,
  type SignedPqWrapRecord,
} from "./signed-pq-wrap";
import { generateHybridSigningPrivateKeyMaterial, publicKeyMaterialFromPrivate } from "./signature";
import { base64UrlDecode, base64UrlEncode } from "./encoding";
import { blake3Base64Url } from "./hash";
import { canonicalizeStrictBytes, type StrictJsonValue } from "./jcs";
import { CURRENT_PROTOCOL_VERSION, CURRENT_SUITE_RANK, SUITE_IDS } from "./suite";
import type { VerifiedSignedPqWrapOperation } from "@/shared/lib/anti-rollback/key-directory-pin/wrap-operation-proof";

const HASH_A = "F3Yv3dlppFOSXWVxesPuohMgtmtUNC_eFRKNbK8hIV8";
const HASH_B = "EOXPPTyKT580aMjMWO6oSJKiL9rbwayyJBAZAETB1VM";

describe("signed PQ wrap", () => {
  it("creates an unsigned workspace device KEK wrap precommit with exact checkpoint bindings", () => {
    const userId = crypto.randomUUID();
    const senderDeviceId = crypto.randomUUID();
    const targetDeviceId = crypto.randomUUID();
    const workspaceId = crypto.randomUUID();
    const precommit = createSignedPqWrapPrecommit({
      purpose: "workspace_device_kek_wrap",
      plaintext: crypto.getRandomValues(new Uint8Array(32)),
      recipientPublicKeyMaterial: publicHybridEncryptionMaterialFromPrivate(
        generateHybridEncryptionPrivateKeyMaterial("device", targetDeviceId),
      ),
      senderSigningPrivateKeyMaterial: generateHybridSigningPrivateKeyMaterial(
        "device",
        senderDeviceId,
      ),
      senderUserId: userId,
      senderDeviceId,
      resource: {
        workspace_id: workspaceId,
        target_user_id: userId,
        target_device_id: targetDeviceId,
        kek_version: 2,
      },
      eventScope: { scope_kind: "workspace", scope_id: workspaceId },
      senderKeyCheckpoint: { sequence: 7, checkpointHash: HASH_A },
      recipientKeyCheckpoint: {
        scopeKind: "workspace",
        scopeId: workspaceId,
        sequence: 7,
        checkpointHash: HASH_A,
      },
    });

    expect(Object.keys(precommit).sort()).toEqual(
      [
        "event_scope",
        "hpke",
        "protocol",
        "protocol_version",
        "purpose",
        "recipient",
        "resource",
        "sender",
        "suite_id",
        "suite_rank",
      ].sort(),
    );
    expect(precommit).toMatchObject({
      purpose: "workspace_device_kek_wrap",
      sender: {
        device_id: senderDeviceId,
        key_checkpoint_sequence: 7,
        key_checkpoint_hash: HASH_A,
      },
      recipient: {
        recipient_kind: "device",
        device_id: targetDeviceId,
        key_checkpoint_sequence: 7,
        key_checkpoint_hash: HASH_A,
      },
      event_scope: { scope_kind: "workspace", scope_id: workspaceId },
    });
    expect("event" in precommit).toBe(false);
    expect("operation_checkpoint" in precommit).toBe(false);
    expect("signature" in precommit).toBe(false);
  });

  it("creates the exact Genesis workspace member envelope precommit", () => {
    const userId = crypto.randomUUID();
    const deviceId = crypto.randomUUID();
    const workspaceId = crypto.randomUUID();
    const identityEncryption = publicHybridEncryptionMaterialFromPrivate(
      generateHybridEncryptionPrivateKeyMaterial("identity", userId),
    );

    const precommit = createGenesisWorkspaceMemberEnvelopePrecommit({
      plaintext: crypto.getRandomValues(new Uint8Array(32)),
      recipientPublicKeyMaterial: identityEncryption,
      senderSigningPrivateKeyMaterial: generateHybridSigningPrivateKeyMaterial("device", deviceId),
      userId,
      deviceId,
      workspaceId,
    });

    expect(Object.keys(precommit).sort()).toEqual(
      [
        "authorization_key_directory_checkpoint_hash",
        "authorization_key_directory_checkpoint_sequence",
        "kek_version",
        "protocol",
        "target_identity_encryption_key_id",
        "target_identity_key_material_hash",
        "target_user_id",
        "version",
        "workspace_id",
        "wrap",
      ].sort(),
    );
    expect(precommit).toMatchObject({
      protocol: "refmd.workspace-member-envelope",
      version: 1,
      workspace_id: workspaceId,
      target_user_id: userId,
      kek_version: 1,
      authorization_key_directory_checkpoint_sequence: 1,
      authorization_key_directory_checkpoint_hash: "GENESIS",
      wrap: {
        protocol: "refmd.signed-pq-hybrid-wrap",
        protocol_version: CURRENT_PROTOCOL_VERSION,
        suite_id: SUITE_IDS.SIGNED_PQ_HYBRID_WRAP,
        suite_rank: CURRENT_SUITE_RANK,
        purpose: "workspace_member_kek_wrap",
        resource: { workspace_id: workspaceId, target_user_id: userId, kek_version: 1 },
        sender: {
          signer_kind: "device",
          user_id: userId,
          device_id: deviceId,
          key_scope_kind: "workspace",
          key_scope_id: workspaceId,
          key_checkpoint_sequence: 0,
          key_checkpoint_hash: "GENESIS",
        },
        recipient: {
          recipient_kind: "user_identity",
          user_id: userId,
          key_scope_kind: "workspace",
          key_scope_id: workspaceId,
          key_checkpoint_sequence: 0,
          key_checkpoint_hash: "GENESIS",
        },
        event_scope: { scope_kind: "workspace", scope_id: workspaceId },
        hpke: { mode: "base", kem_id: 0x647a, kdf_id: 1, aead_id: 3 },
      },
    });
    expect(base64UrlDecode(precommit.wrap.hpke.enc)).toHaveLength(1120);
    expect(base64UrlDecode(precommit.wrap.hpke.ciphertext)).toHaveLength(48);
    expect(precommit.target_identity_key_material_hash).toBe(
      blake3Base64Url(canonicalizeStrictBytes(identityEncryption as unknown as StrictJsonValue)),
    );
  });

  it.each(["workspace_invitation_package_key_wrap", "guest_invitation_package_key_wrap"])(
    "rejects removed invitation package purpose %s",
    (purpose) => {
      const senderDeviceId = crypto.randomUUID();
      const recipientDeviceId = crypto.randomUUID();
      const workspaceId = crypto.randomUUID();

      expect(() =>
        createSignedPqWrap({
          purpose,
          plaintext: crypto.getRandomValues(new Uint8Array(32)),
          recipientPublicKeyMaterial: publicHybridEncryptionMaterialFromPrivate(
            generateHybridEncryptionPrivateKeyMaterial("device", recipientDeviceId),
          ),
          senderSigningPrivateKeyMaterial: generateHybridSigningPrivateKeyMaterial(
            "device",
            senderDeviceId,
          ),
          senderUserId: crypto.randomUUID(),
          senderDeviceId,
          resource: {},
          eventScope: { scope_kind: "workspace", scope_id: workspaceId },
          operationCheckpoint: {
            sequence: 1,
            checkpointHash: HASH_A,
            coveredHeadSequence: 1,
            coveredHeadHash: HASH_B,
          },
        } as never),
      ).toThrow("signed_pq_wrap_purpose_invalid");
    },
  );

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
        verifiedOperation: verifiedOperationFor(valid),
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
        verifiedOperation: verifiedOperationFor(valid),
      }),
    ).toThrow("signed_pq_wrap_event_body_hash_mismatch");
  });

  it("rejects a record substituted after operation-proof verification", () => {
    const senderDeviceId = crypto.randomUUID();
    const recipientDeviceId = crypto.randomUUID();
    const workspaceId = crypto.randomUUID();
    const senderSigning = generateHybridSigningPrivateKeyMaterial("device", senderDeviceId);
    const recipientEncryption = generateHybridEncryptionPrivateKeyMaterial(
      "device",
      recipientDeviceId,
    );
    const initial = createSignedPqWrap({
      purpose: "workspace_device_kek_wrap",
      plaintext: crypto.getRandomValues(new Uint8Array(32)),
      recipientPublicKeyMaterial: publicHybridEncryptionMaterialFromPrivate(recipientEncryption),
      senderSigningPrivateKeyMaterial: senderSigning,
      senderUserId: crypto.randomUUID(),
      senderDeviceId,
      resource: {
        workspace_id: workspaceId,
        target_user_id: crypto.randomUUID(),
        target_device_id: recipientDeviceId,
        kek_version: 1,
      },
      eventScope: { scope_kind: "workspace", scope_id: workspaceId },
      operationCheckpoint: {
        sequence: 1,
        checkpointHash: HASH_A,
        coveredHeadSequence: 1,
        coveredHeadHash: HASH_B,
      },
    });
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
    const verifiedOperation = verifiedOperationFor(valid);
    const substituted = {
      ...valid,
      signature: {
        ...valid.signature,
        ed25519: `${valid.signature.ed25519.slice(0, -1)}${
          valid.signature.ed25519.endsWith("A") ? "B" : "A"
        }`,
      },
    };

    expect(() =>
      openSignedPqWrap({
        record: substituted,
        recipientPrivateKeyMaterial: recipientEncryption,
        senderSigningPublicKeyMaterial: publicKeyMaterialFromPrivate(senderSigning),
        verifiedOperation,
      }),
    ).toThrow("signed_pq_wrap_operation_verification_mismatch");
  });

  it("rejects tampered ML-KEM ciphertext at the worker decapsulation boundary", () => {
    const senderDeviceId = crypto.randomUUID();
    const recipientDeviceId = crypto.randomUUID();
    const workspaceId = crypto.randomUUID();
    const senderSigning = generateHybridSigningPrivateKeyMaterial("device", senderDeviceId);
    const recipientEncryption = generateHybridEncryptionPrivateKeyMaterial(
      "device",
      recipientDeviceId,
    );
    const initial = createSignedPqWrap({
      purpose: "workspace_device_kek_wrap",
      plaintext: crypto.getRandomValues(new Uint8Array(32)),
      recipientPublicKeyMaterial: publicHybridEncryptionMaterialFromPrivate(recipientEncryption),
      senderSigningPrivateKeyMaterial: senderSigning,
      senderUserId: crypto.randomUUID(),
      senderDeviceId,
      resource: {
        workspace_id: workspaceId,
        target_user_id: crypto.randomUUID(),
        target_device_id: recipientDeviceId,
        kek_version: 1,
      },
      eventScope: { scope_kind: "workspace", scope_id: workspaceId },
      operationCheckpoint: {
        sequence: 1,
        checkpointHash: HASH_A,
        coveredHeadSequence: 1,
        coveredHeadHash: HASH_B,
      },
    });
    const tamperedInitial = tamperSignedMlkemCiphertext(initial);
    const valid = finalizeSignedPqWrapOperationCheckpoint({
      record: tamperedInitial,
      operationCheckpoint: {
        sequence: 2,
        checkpointHash: HASH_B,
        coveredHeadSequence: tamperedInitial.event.wrap_event_sequence,
        coveredHeadHash: tamperedInitial.event.wrap_event_hash,
      },
      senderSigningPrivateKeyMaterial: senderSigning,
    });
    expect(() =>
      openSignedPqWrap({
        record: valid,
        recipientPrivateKeyMaterial: recipientEncryption,
        senderSigningPublicKeyMaterial: publicKeyMaterialFromPrivate(senderSigning),
        verifiedOperation: verifiedOperationFor(valid),
      }),
    ).toThrow("hpke_open_failed");
  });

  it("chains a wrap after an earlier event in the same operation", () => {
    const senderDeviceId = crypto.randomUUID();
    const recipientDeviceId = crypto.randomUUID();
    const workspaceId = crypto.randomUUID();
    const plaintext = crypto.getRandomValues(new Uint8Array(32));
    const senderSigning = generateHybridSigningPrivateKeyMaterial("device", senderDeviceId);
    const recipientEncryption = generateHybridEncryptionPrivateKeyMaterial(
      "device",
      recipientDeviceId,
    );
    const initial = createSignedPqWrap({
      purpose: "workspace_device_kek_wrap",
      plaintext,
      recipientPublicKeyMaterial: publicHybridEncryptionMaterialFromPrivate(recipientEncryption),
      senderSigningPrivateKeyMaterial: senderSigning,
      senderUserId: crypto.randomUUID(),
      senderDeviceId,
      resource: {
        workspace_id: workspaceId,
        target_user_id: crypto.randomUUID(),
        target_device_id: recipientDeviceId,
        kek_version: 1,
      },
      eventScope: { scope_kind: "workspace", scope_id: workspaceId },
      operationCheckpoint: {
        sequence: 3,
        checkpointHash: HASH_A,
        coveredHeadSequence: 7,
        coveredHeadHash: HASH_A,
      },
      eventPrevious: { sequence: 8, hash: HASH_B },
    });
    expect(initial.event.wrap_event_sequence).toBe(9);
    const finalized = finalizeSignedPqWrapOperationCheckpoint({
      record: initial,
      operationCheckpoint: {
        sequence: 4,
        checkpointHash: HASH_B,
        coveredHeadSequence: 10,
        coveredHeadHash: HASH_A,
      },
      senderSigningPrivateKeyMaterial: senderSigning,
    });

    expect(
      openSignedPqWrap({
        record: finalized,
        recipientPrivateKeyMaterial: recipientEncryption,
        senderSigningPublicKeyMaterial: publicKeyMaterialFromPrivate(senderSigning),
        verifiedOperation: verifiedOperationFor(finalized),
      }),
    ).toEqual(plaintext);
  });
});

function tamperSignedMlkemCiphertext(record: SignedPqWrapRecord): SignedPqWrapRecord {
  const enc = base64UrlDecode(record.hpke.enc);
  enc[0] ^= 0x01;
  const hpke = { ...record.hpke, enc: base64UrlEncode(enc) };
  const info = {
    label: "RefMD HPKE info v1",
    protocol: record.protocol,
    protocol_version: record.protocol_version,
    suite_id: record.suite_id,
    suite_rank: record.suite_rank,
    purpose: record.purpose,
    resource_hash: blake3Base64Url(canonicalizeStrictBytes(record.resource)),
    sender_user_id: record.sender.user_id,
    sender_device_id: record.sender.device_id,
    sender_signing_key_id: record.sender.signing_key_id,
    sender_key_scope_kind: record.sender.key_scope_kind,
    sender_key_scope_id: record.sender.key_scope_id,
    sender_key_checkpoint_hash: record.sender.key_checkpoint_hash,
    recipient_kind: record.recipient.recipient_kind,
    recipient_key_id: record.recipient.encryption_key_id,
    recipient_key_scope_kind: record.recipient.key_scope_kind,
    recipient_key_scope_id: record.recipient.key_scope_id,
    recipient_key_checkpoint_hash: record.recipient.key_checkpoint_hash,
    event_scope_kind: record.event_scope.scope_kind,
    event_scope_id: record.event_scope.scope_id,
  } satisfies StrictJsonValue;
  const aad = {
    label: "RefMD PQ wrap AAD v1",
    protocol: record.protocol,
    protocol_version: record.protocol_version,
    suite_id: record.suite_id,
    suite_rank: record.suite_rank,
    purpose: record.purpose,
    resource: record.resource,
    sender: record.sender,
    recipient: record.recipient,
    event_scope: record.event_scope,
    hpke: {
      mode: "base",
      kem_id: hpke.kem_id,
      kdf_id: hpke.kdf_id,
      aead_id: hpke.aead_id,
      enc: hpke.enc,
    },
  } satisfies StrictJsonValue;
  const wrapBody = {
    label: "RefMD PQ wrap body v1",
    protocol: record.protocol,
    version: CURRENT_PROTOCOL_VERSION,
    suite_id: SUITE_IDS.SIGNED_PQ_HYBRID_WRAP,
    suite_rank: CURRENT_SUITE_RANK,
    purpose: record.purpose,
    resource: record.resource,
    sender: record.sender,
    recipient: record.recipient,
    event_scope: record.event_scope,
    hpke,
    hpke_info_hash: blake3Base64Url(canonicalizeStrictBytes(info)),
    aad_hash: blake3Base64Url(canonicalizeStrictBytes(aad)),
  } satisfies StrictJsonValue;
  const eventBody = {
    purpose: record.purpose,
    recipient: record.recipient,
    resource: record.resource,
    resource_hash: blake3Base64Url(canonicalizeStrictBytes(record.resource)),
    sender: record.sender,
    wrap_body_hash: blake3Base64Url(canonicalizeStrictBytes(wrapBody)),
    wrap_protocol: record.protocol,
    wrap_suite_id: record.suite_id,
    wrap_suite_rank: record.suite_rank,
    wrap_version: record.protocol_version,
  } satisfies StrictJsonValue;
  const eventBodyHash = blake3Base64Url(canonicalizeStrictBytes(eventBody));
  const event = {
    protocol: "refmd.key-directory-event",
    version: CURRENT_PROTOCOL_VERSION,
    scope_kind: record.event_scope.scope_kind,
    scope_id: record.event_scope.scope_id,
    sequence: record.event.wrap_event_sequence,
    event_type: "wrap_issued",
    actor: record.sender,
    previous_event_hash: record.operation_checkpoint.covered_event_head_hash,
    body: eventBody,
  } satisfies StrictJsonValue;

  return {
    ...record,
    hpke,
    event: {
      ...record.event,
      wrap_event_body_hash: eventBodyHash,
      wrap_event_hash: blake3Base64Url(canonicalizeStrictBytes(event)),
    },
  };
}

function verifiedOperationFor(record: SignedPqWrapRecord): VerifiedSignedPqWrapOperation {
  const eventBody = signedPqWrapEventBody(record) as Record<string, StrictJsonValue>;
  return {
    protocol: "refmd.verified-signed-pq-wrap-operation",
    version: 1,
    sequence: record.operation_checkpoint.checkpoint_sequence,
    checkpointHash: record.operation_checkpoint.checkpoint_hash,
    coveredHeadSequence: record.operation_checkpoint.covered_event_head_sequence,
    coveredHeadHash: record.operation_checkpoint.covered_event_head_hash,
    wrapEventSequence: record.event.wrap_event_sequence,
    wrapEventHash: record.event.wrap_event_hash,
    wrapEventBodyHash: record.event.wrap_event_body_hash,
    wrapBodyHash: eventBody.wrap_body_hash as string,
    transcriptHash: record.transcript_hash,
    recordCommitmentHash: blake3Base64Url(
      canonicalizeStrictBytes(record as unknown as StrictJsonValue),
    ),
  } as VerifiedSignedPqWrapOperation;
}

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
