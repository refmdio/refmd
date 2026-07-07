import { ed25519 } from "@noble/curves/ed25519.js";
import { blake3 } from "@noble/hashes/blake3.js";
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";
import { describe, expect, it } from "vite-plus/test";
import { decodeBase64UrlStrict, encodeBase64Url } from "./encoding";
import { blake3Base64Url } from "./hash";
import {
  HYBRID_ENCRYPTION_KEY_MATERIAL_PROTOCOL,
  computeHybridEncryptionKeyId,
  type HybridEncryptionPublicKeyMaterial,
} from "./hybrid-encryption";
import { canonicalizeStrictBytes, type StrictJsonValue } from "./jcs";
import { CURRENT_PROTOCOL_VERSION, CURRENT_SUITE_RANK, SUITE_IDS } from "./suite";
import {
  __testActiveSigningSurfaces,
  type ActiveSigningSurface,
  assertSigningSurfaceOwner,
  getActiveSigningSurface,
} from "./signing-surface";
import {
  SIGNATURE_TRANSCRIPT_LABEL,
  SIGNATURE_TRANSCRIPT_PROTOCOL,
  SIGNING_PRIVATE_KEY_MATERIAL_PROTOCOL,
  buildDeviceApprovalTranscript,
  buildDeviceKeyDeletionProofTranscript,
  buildDeviceRevocationTranscript,
  buildDocumentSnapshotTranscript,
  buildDocumentUpdateTranscript,
  buildEditorEphemeralSessionTranscript,
  buildEditorEphemeralTranscript,
  buildGenesisDeviceBootstrapTranscript,
  buildInitialKeyDeliveryTranscript,
  buildInitiatorAkeCommitmentTranscript,
  computeSigningKeyId,
  createDeviceApprovalSignature,
  createDeviceRevocationSignature,
  decodeHybridSignatureFromTransport,
  deriveShareCapabilitySigningPrivateKeyMaterial,
  encodeHybridSignatureForTransport,
  generateHybridSigningPrivateKeyMaterial,
  publicKeyMaterialFromPrivate,
  buildKeyDirectoryCheckpointTranscript,
  buildKeyDirectoryEventTranscript,
  buildPinGossipStatementTranscript,
  buildPluginBundleApprovalTranscript,
  buildPluginConsentEventTranscript,
  buildPluginNetworkProxyRequestTranscript,
  buildPopTranscript,
  buildPqWrapTranscript,
  buildRecipientBoundAuthorizationTranscript,
  buildRecoveryAuthorizationProofTranscript,
  buildRecoveryDeviceApprovalTranscript,
  buildRecoverySessionTranscript,
  buildResponderPrekeyTranscript,
  buildWorkspacePinBootstrapTranscript,
  createPopRequestSignature,
  signDeviceKeyDeletionProofSignature,
  signDocumentSnapshotSignature,
  signDocumentUpdateSignature,
  signEditorEphemeralSessionSignature,
  signEditorEphemeralSignature,
  signGenesisDeviceBootstrapSignature,
  signInitialKeyDeliverySignature,
  signInitiatorAkeCommitmentSignature,
  signPinGossipStatementSignature,
  signPluginBundleApprovalSignature,
  signPluginConsentEventSignature,
  signPluginNetworkProxyRequestSignature,
  signKeyDirectoryCheckpointSignature,
  signKeyDirectoryEventSignature,
  signPqWrapSignature,
  signRecipientBoundAuthorizationSignature,
  signRecoveryAuthorizationProofSignature,
  signRecoveryDeviceApprovalSignature,
  signRecoverySessionSignature,
  signResponderPrekeySignature,
  signShareParticipantDeviceAuthorizationSignature,
  signWorkspacePinBootstrapSignature,
  verifyDeviceApprovalSignature,
  verifyDeviceKeyDeletionProofSignature,
  verifyDeviceRevocationSignature,
  verifyDocumentSnapshotSignature,
  verifyDocumentUpdateSignature,
  verifyEditorEphemeralSessionSignature,
  verifyEditorEphemeralSignature,
  verifyGenesisDeviceBootstrapSignature,
  verifyInitialKeyDeliverySignature,
  verifyInitiatorAkeCommitmentSignature,
  verifyKeyDirectoryCheckpointSignature,
  verifyKeyDirectoryEventSignature,
  verifyPinGossipStatementSignature,
  verifyPluginBundleApprovalSignature,
  verifyPluginConsentEventSignature,
  verifyPluginNetworkProxyRequestSignature,
  verifyPopRequestSignature,
  verifyPqWrapSignature,
  verifyRecipientBoundAuthorizationSignature,
  verifyRecoveryAuthorizationProofSignature,
  verifyRecoveryDeviceApprovalSignature,
  verifyRecoverySessionSignature,
  verifyResponderPrekeySignature,
  verifyShareCapabilityAuthorizationSignature,
  verifyShareParticipantDeviceAuthorizationSignature,
  verifyWorkspacePinBootstrapSignature,
  shareCapabilityPublicKeyMaterialFromPrivate,
  signShareCapabilityAuthorizationSignature,
  type AnyHybridSigningPublicKeyMaterial,
  type HybridSignature,
  type HybridSigningPrivateKeyMaterial,
  type SigningOwnerKind,
} from "./signature";
import {
  buildShareCapabilityAuthorizationTranscript,
  buildShareParticipantDeviceAuthorizationTranscript,
} from "./signature-share-transcripts";

const enc = new TextEncoder();
const TEST_DEVICE_ID = "00000000-0000-4000-8000-000000000001";
const TEST_OTHER_DEVICE_ID = "00000000-0000-4000-8000-000000000002";
const TEST_USER_ID = "00000000-0000-4000-8000-000000000003";

function expectedActiveSigningSurfacePairs(): string[][] {
  const keyDirectoryEvents = [
    "wrap_issued",
    "identity_key_added",
    "device_key_added",
    "member_added",
    "member_role_changed",
    "member_removed",
    "signing_key_revoked",
    "encryption_key_revoked",
    "suite_policy_changed",
    "share_created",
    "share_metadata_updated",
    "share_key_scope_added",
    "share_key_scope_replaced",
    "share_key_scope_removed",
    "share_exclusion_changed",
    "share_revoked",
    "recipient_bound_delivery_admitted",
    "workspace_invitation_created",
    "workspace_invitation_bootstrap_updated",
    "workspace_invitation_revoked",
    "workspace_invitation_redeemed",
    "guest_invitation_created",
    "guest_invitation_bootstrap_updated",
    "guest_invitation_revoked",
    "guest_invitation_redeemed",
    "guest_grant_revoked",
    "guest_device_revoked",
    "rotation_started",
    "rotation_completed",
    "old_key_deleted",
    "document_update_accepted",
    "document_write_session_admitted",
    "document_write_state_changed",
    "document_snapshot_accepted",
  ];

  return [
    ["pq_wrap", "none"],
    ["workspace_pin_bootstrap", "none"],
    ["recipient_bound_authorization", "none"],
    ["share_capability_authorization", "none"],
    ["share_participant_device_authorization", "none"],
    ["genesis_device_bootstrap", "none"],
    ["device_approval", "none"],
    ["plugin_bundle_approval", "none"],
    ["plugin_consent_event", "none"],
    ["plugin_network_proxy_request", "none"],
    ["responder_prekey", "none"],
    ["initiator_ake_commitment", "none"],
    ["recovery_device_approval", "none"],
    ["device_revocation", "none"],
    ["recovery_session", "none"],
    ["recovery_authorization_proof", "none"],
    ["pin_gossip_statement", "none"],
    ...[
      "identity_initial",
      "workspace_initial",
      "identity_active",
      "identity_rotation",
      "workspace_authorized",
      "invitation_redeem_authority",
      "share_participant_document_operation",
      "device_authorized",
    ].map((variant) => ["key_directory_checkpoint", variant]),
    ...keyDirectoryEvents.map((variant) => ["key_directory_event", variant]),
    ...[
      "http_user_device",
      "http_share_participant_device",
      "channel_user_device",
      "channel_share_participant_device",
    ].map((variant) => ["pop_request", variant]),
    ...["umk_distribution", "device_approval_kek_initial", "trust_transfer"].map((variant) => [
      "initial_key_delivery",
      variant,
    ]),
    ...["device_key_deletion_proof", "identity_key_deletion_proof"].map((variant) => [
      "device_key_deletion_proof",
      variant,
    ]),
    ...["workspace_device", "share_participant_device"].flatMap((variant) => [
      ["document_update", variant],
      ["document_snapshot", variant],
      ["editor_ephemeral", variant],
      ["editor_ephemeral_session", variant],
    ]),
  ];
}

describe("hybrid signature primitive", () => {
  it("generates full hybrid signing key material", () => {
    const privateKeyMaterial = generateHybridSigningPrivateKeyMaterial(
      "device",
      TEST_OTHER_DEVICE_ID,
    );
    expect(privateKeyMaterial.owner_kind).toBe("device");
    expect(privateKeyMaterial.owner_id).toBe(TEST_OTHER_DEVICE_ID);
    expect(() => publicKeyMaterialFromPrivate(privateKeyMaterial)).not.toThrow();
  });

  it("signs and verifies only when Ed25519 and ML-DSA-65 both match the transcript", () => {
    const privateKeyMaterial = testPrivateKeyMaterial();
    const publicKeyMaterial = publicKeyMaterialFromPrivate(privateKeyMaterial);
    const transcript = testTranscript();
    const signature = createPopRequestSignature({
      transcript,
      privateKeyMaterial,
    });

    expect(
      verifyPopRequestSignature({
        transcript,
        signature,
        publicKeyMaterial,
      }),
    ).toBe(true);
    expect(signature.signing_key_id).toBe(computeSigningKeyId(publicKeyMaterial));
    expect(signature.transcript_hash).toBe(blake3Base64Url(canonicalizeStrictBytes(transcript)));

    expect(
      verifyInitialKeyDeliverySignature({
        transcript,
        signature,
        publicKeyMaterial,
      }),
    ).toBe(false);
    expect(
      verifyPopRequestSignature({
        transcript: { ...(transcript as Record<string, StrictJsonValue>), challenge: "different" },
        signature,
        publicKeyMaterial,
      }),
    ).toBe(false);
    expect(
      verifyPopRequestSignature({
        transcript: {
          ...(transcript as Record<string, StrictJsonValue>),
          generic_authority_boundary: { role: "admin" },
        },
        signature,
        publicKeyMaterial,
      }),
    ).toBe(false);
    expect(
      verifyPopRequestSignature({
        transcript: {
          ...(transcript as Record<string, StrictJsonValue>),
          owner_id: TEST_OTHER_DEVICE_ID,
        },
        signature,
        publicKeyMaterial,
      }),
    ).toBe(false);
    expect(
      verifyPopRequestSignature({
        transcript: {
          ...(transcript as Record<string, StrictJsonValue>),
          transcript_owner: "refmd.pop.other",
        },
        signature,
        publicKeyMaterial,
      }),
    ).toBe(false);
    expect(
      verifyPopRequestSignature({
        transcript: {
          ...(transcript as Record<string, StrictJsonValue>),
          surface_id: "device_approval",
        },
        signature,
        publicKeyMaterial,
      }),
    ).toBe(false);
    expect(
      verifyPopRequestSignature({
        transcript: { ...(transcript as Record<string, StrictJsonValue>), surface_variant: "none" },
        signature,
        publicKeyMaterial,
      }),
    ).toBe(false);
    expect(
      verifyPopRequestSignature({
        transcript,
        signature: { ...signature, ed25519: flipBase64UrlByte(signature.ed25519) },
        publicKeyMaterial,
      }),
    ).toBe(false);
    expect(
      verifyPopRequestSignature({
        transcript,
        signature: { ...signature, mldsa65: flipBase64UrlByte(signature.mldsa65) },
        publicKeyMaterial,
      }),
    ).toBe(false);
  });

  it("signs share capability authorization with share-capability key material", () => {
    const shareTokenHash = blake3Base64Url(enc.encode("share-token"));
    const privateKeyMaterial = deriveShareCapabilitySigningPrivateKeyMaterial(
      blake3(enc.encode("share-capability-secret")),
      shareTokenHash,
    );
    const publicKeyMaterial = shareCapabilityPublicKeyMaterialFromPrivate(privateKeyMaterial);
    const transcript = buildShareCapabilityAuthorizationTranscript({
      shareTokenHash,
      workspacePinBootstrapHash: blake3Base64Url(enc.encode("workspace-pin-bootstrap")),
      shareId: crypto.randomUUID(),
      scopeKind: "document",
      scopeId: crypto.randomUUID(),
      permission: "edit",
      passwordProtected: false,
      createdEventHash: blake3Base64Url(enc.encode("created-event")),
      latestBootstrapEventHash: blake3Base64Url(enc.encode("latest-bootstrap-event")),
      capabilityContextHash: blake3Base64Url(enc.encode("capability-context")),
      shareCapabilitySecretCommitment: blake3Base64Url(enc.encode("share-capability-secret")),
      passwordCapabilitySecretCommitment: "none",
    });

    const signature = signShareCapabilityAuthorizationSignature({
      privateKeyMaterial,
      transcript,
    });

    expect(signature.signing_key_id).toBe(computeSigningKeyId(publicKeyMaterial));
  });

  it("signs and verifies pin gossip statements with owner-exact transcript schema", () => {
    const privateKeyMaterial = testPrivateKeyMaterial();
    const publicKeyMaterial = publicKeyMaterialFromPrivate(privateKeyMaterial);
    const transcript = buildPinGossipStatementTranscript({
      ownerDeviceId: TEST_DEVICE_ID,
      pinGossip: {
        workspace_id: crypto.randomUUID(),
        checkpoint_hash: blake3Base64Url(enc.encode("pin-checkpoint")),
        checkpoint_sequence: 3,
        observed_at: 1_700_000_000,
      },
    });
    const signature = signPinGossipStatementSignature({
      privateKeyMaterial,
      transcript,
    });

    expect(
      verifyPinGossipStatementSignature({
        transcript,
        signature,
        publicKeyMaterial,
      }),
    ).toBe(true);

    const changedStatement = {
      ...(transcript as Record<string, StrictJsonValue>),
      pin_gossip: {
        ...((transcript as Record<string, StrictJsonValue>).pin_gossip as Record<
          string,
          StrictJsonValue
        >),
        statement: {
          workspace_id: crypto.randomUUID(),
        },
      },
    } as StrictJsonValue;

    expect(
      verifyPinGossipStatementSignature({
        transcript: changedStatement,
        signature,
        publicKeyMaterial,
      }),
    ).toBe(false);
    expect(
      verifyPinGossipStatementSignature({
        transcript: {
          ...(transcript as Record<string, StrictJsonValue>),
          pin_gossip: {
            ...((transcript as Record<string, StrictJsonValue>).pin_gossip as Record<
              string,
              StrictJsonValue
            >),
            extra: "not allowed",
          },
        } as StrictJsonValue,
        signature,
        publicKeyMaterial,
      }),
    ).toBe(false);
  });

  it("rejects null key directory previous hashes in transcript validation", () => {
    const privateKeyMaterial = testPrivateKeyMaterial();

    expect(() =>
      signKeyDirectoryEventSignature({
        privateKeyMaterial,
        transcript: keyDirectoryEventTranscriptWithNullPreviousHash(),
      }),
    ).toThrow();

    expect(() =>
      signKeyDirectoryCheckpointSignature({
        privateKeyMaterial,
        transcript: keyDirectoryCheckpointTranscriptWithNullPreviousHash(),
      }),
    ).toThrow();
  });

  it("rejects downgrade-shaped signatures and key material", () => {
    const privateKeyMaterial = testPrivateKeyMaterial();
    const publicKeyMaterial = publicKeyMaterialFromPrivate(privateKeyMaterial);
    const transcript = testTranscript();
    const signature = createPopRequestSignature({
      transcript,
      privateKeyMaterial,
    });

    expect(
      verifyPopRequestSignature({
        transcript,
        signature: { ...signature, mldsa65: undefined } as unknown as HybridSignature,
        publicKeyMaterial,
      }),
    ).toBe(false);
    expect(
      verifyPopRequestSignature({
        transcript,
        signature: { ...signature, ed25519: undefined } as unknown as HybridSignature,
        publicKeyMaterial,
      }),
    ).toBe(false);
    expect(
      verifyPopRequestSignature({
        transcript,
        signature: { ...signature, suite_rank: 1 } as unknown as HybridSignature,
        publicKeyMaterial,
      }),
    ).toBe(false);
    expect(
      verifyPopRequestSignature({
        transcript,
        signature: {
          ...signature,
          suite_id: "refmd-v2-ed25519-only" as typeof SUITE_IDS.HYBRID_SIGNATURE,
        },
        publicKeyMaterial,
      }),
    ).toBe(false);
    expect(
      verifyPopRequestSignature({
        transcript,
        signature: { ...signature, signing_key_id: flipBase64UrlByte(signature.signing_key_id) },
        publicKeyMaterial,
      }),
    ).toBe(false);
    expect(
      verifyPopRequestSignature({
        transcript,
        signature: { ...signature, extra: "field" } as unknown as HybridSignature,
        publicKeyMaterial,
      }),
    ).toBe(false);
    expect(
      verifyPopRequestSignature({
        transcript,
        signature,
        publicKeyMaterial: {
          ...publicKeyMaterial,
          ed25519_public: flipBase64UrlByte(publicKeyMaterial.ed25519_public),
        },
      }),
    ).toBe(false);
    expect(
      verifyPopRequestSignature({
        transcript,
        signature,
        publicKeyMaterial: {
          ...publicKeyMaterial,
          mldsa65_public: flipBase64UrlByte(publicKeyMaterial.mldsa65_public),
        },
      }),
    ).toBe(false);
  });

  it("accepts only canonical signature transport JSON", () => {
    const privateKeyMaterial = testPrivateKeyMaterial();
    const publicKeyMaterial = publicKeyMaterialFromPrivate(privateKeyMaterial);
    const transcript = testTranscript();
    const signature = createPopRequestSignature({
      transcript,
      privateKeyMaterial,
    });

    const encoded = encodeHybridSignatureForTransport(signature);
    expect(
      verifyPopRequestSignature({
        transcript,
        signature: decodeHybridSignatureFromTransport(encoded),
        publicKeyMaterial,
      }),
    ).toBe(true);

    const nonCanonical = encodeBase64Url(
      new TextEncoder().encode(JSON.stringify(signature, null, 2)),
    );
    expect(() => decodeHybridSignatureFromTransport(nonCanonical)).toThrow(
      "non_canonical_signature_transport",
    );
  });
});

describe("active signing surface inventory", () => {
  it("resolves expected active surfaces and rejects disabled/unlisted surfaces", () => {
    const seenOwners = new Set<string>();
    const actualSurfaces = __testActiveSigningSurfaces();
    const actualKeys = actualSurfaces.map((entry) =>
      inventoryPairKey(entry.signing_purpose, entry.variant),
    );
    const expectedKeys = expectedActiveSigningSurfacePairs().map(([signingPurpose, variant]) =>
      inventoryPairKey(signingPurpose, variant),
    );
    const disabledPairs = [
      ["snapshot_proof", "share_participant_device"],
      ["snapshot_proof", "workspace_device"],
      ["trust_transfer", "none"],
    ];

    expect(new Set(actualKeys).size).toBe(actualKeys.length);
    expect([...actualKeys].sort()).toEqual([...expectedKeys].sort());

    for (const entry of actualSurfaces) {
      expect(Object.keys(entry).sort()).toEqual([
        "owner_kind",
        "protocol_version",
        "signing_purpose",
        "suite_id",
        "surface_id",
        "transcript_owner",
        "variant",
      ]);
      expect(seenOwners.has(entry.transcript_owner)).toBe(false);
      seenOwners.add(entry.transcript_owner);
      expect(disabledPairs).not.toContainEqual([entry.signing_purpose, entry.variant]);
      expect(getActiveSigningSurface(entry.signing_purpose, entry.variant)).toBe(entry);
    }

    expect(getActiveSigningSurface("plugin_bundle_approval", "none").surface_id).toBe(
      "plugin_bundle_approval",
    );
    expect(() => getActiveSigningSurface("trust_transfer", "none")).toThrow(
      "signing_surface_not_active",
    );
    expect(() => getActiveSigningSurface("snapshot_proof", "workspace_device")).toThrow(
      "signing_surface_not_active",
    );
    expect(() => getActiveSigningSurface("pop_request", "none")).toThrow(
      "signing_surface_not_active",
    );
  });

  it("executes owner-exact positive and negative vectors for every active surface", () => {
    const coverages = activeSurfaceCoverages();
    const coverageKeys = coverages.map((coverage) =>
      inventoryPairKey(coverage.signingPurpose, coverage.variant),
    );
    const runtimeKeys = __testActiveSigningSurfaces().map((entry) =>
      inventoryPairKey(entry.signing_purpose, entry.variant),
    );

    expect(new Set(coverageKeys).size).toBe(coverageKeys.length);
    expect([...coverageKeys].sort()).toEqual([...runtimeKeys].sort());

    for (const coverage of coverages) {
      const privateKeyMaterial = testPrivateKeyMaterialForOwner(
        coverage.ownerKind,
        coverage.ownerId,
      );
      const publicKeyMaterial = publicKeyMaterialForOwner(privateKeyMaterial);
      const transcript = coverage.buildTranscript(publicKeyMaterial);
      const signature = coverage.sign({ transcript, privateKeyMaterial });

      if (coverage.signingPurpose === "plugin_bundle_approval") {
        expect((transcript as Record<string, StrictJsonValue>).subject_protocol).toBe(
          "refmd.plugin-bundle-approval",
        );
      }

      if (coverage.signingPurpose === "plugin_consent_event") {
        expect((transcript as Record<string, StrictJsonValue>).subject_protocol).toBe(
          "refmd.plugin-consent-event",
        );
      }

      expect(coverage.verify({ transcript, signature, publicKeyMaterial })).toBe(true);
      expect(
        coverage.verify({
          transcript,
          signature: withoutSignatureField(signature, "mldsa65"),
          publicKeyMaterial,
        }),
      ).toBe(false);
      expect(
        coverage.verify({
          transcript,
          signature: withoutSignatureField(signature, "ed25519"),
          publicKeyMaterial,
        }),
      ).toBe(false);
      expect(
        coverage.verify({
          transcript: { ...(transcript as Record<string, StrictJsonValue>), owner_id: "wrong" },
          signature,
          publicKeyMaterial,
        }),
      ).toBe(false);
      expect(
        coverage.verify({
          transcript: {
            ...(transcript as Record<string, StrictJsonValue>),
            transcript_owner: "refmd.invalid.transcript_owner",
          },
          signature,
          publicKeyMaterial,
        }),
      ).toBe(false);
      expect(
        coverage.verify({
          transcript: { ...(transcript as Record<string, StrictJsonValue>), surface_id: "wrong" },
          signature,
          publicKeyMaterial,
        }),
      ).toBe(false);
      expect(
        coverage.verify({
          transcript: {
            ...(transcript as Record<string, StrictJsonValue>),
            surface_variant: "wrong",
          },
          signature,
          publicKeyMaterial,
        }),
      ).toBe(false);
      expect(
        coverage.verify({
          transcript: {
            ...(transcript as Record<string, StrictJsonValue>),
            generic_authority_boundary: { role: "admin" },
          },
          signature,
          publicKeyMaterial,
        }),
      ).toBe(false);
    }
  }, 60_000);

  it("requires plugin actors to be scoped to the subject workspace", () => {
    const privateKeyMaterial = generateHybridSigningPrivateKeyMaterial("device", testUuid(401));
    const publicKeyMaterial = publicKeyMaterialFromPrivate(privateKeyMaterial);
    const actor = pluginDeviceActorFixture(publicKeyMaterial) as Record<string, StrictJsonValue>;
    const approval = pluginBundleApprovalSubjectFixture(publicKeyMaterial);
    const consent = pluginConsentSubjectFixture(publicKeyMaterial);

    expect(() =>
      buildPluginBundleApprovalTranscript({
        actor: { ...actor, key_scope_kind: "user", key_scope_id: actor.user_id },
        approval,
      }),
    ).toThrow("plugin_bundle_approval_actor_invalid");
    expect(() =>
      buildPluginBundleApprovalTranscript({
        actor: { ...actor, key_scope_id: testUuid(599) },
        approval,
      }),
    ).toThrow("plugin_bundle_approval_actor_invalid");
    expect(() =>
      buildPluginConsentEventTranscript({
        actor: { ...actor, key_scope_kind: "user", key_scope_id: actor.user_id },
        consent,
      }),
    ).toThrow("plugin_consent_event_actor_invalid");
    expect(() =>
      buildPluginConsentEventTranscript({
        actor: { ...actor, key_scope_id: testUuid(599) },
        consent,
      }),
    ).toThrow("plugin_consent_event_actor_invalid");
    expect(() =>
      buildPluginConsentEventTranscript({
        actor: { ...actor, user_id: testUuid(599) },
        consent,
      }),
    ).toThrow("plugin_consent_event_actor_invalid");
    expect(() =>
      buildPluginConsentEventTranscript({
        actor,
        consent: {
          ...(consent as Record<string, StrictJsonValue>),
          device_id: testUuid(599),
        },
      }),
    ).toThrow("plugin_consent_event_actor_invalid");
    expect(() =>
      buildPluginConsentEventTranscript({
        actor,
        consent: { ...(consent as Record<string, StrictJsonValue>), user_id: testUuid(599) },
      }),
    ).toThrow("plugin_consent_event_actor_invalid");
  });

  it("requires plugin proxy request nested subject fields before signing", () => {
    const privateKeyMaterial = generateHybridSigningPrivateKeyMaterial("device", testUuid(401));
    const publicKeyMaterial = publicKeyMaterialFromPrivate(privateKeyMaterial);
    const subject = pluginNetworkProxyRequestSubjectFixture(publicKeyMaterial);

    const missingPaths = [
      ["proxy", "id"],
      ["target", "method"],
      ["target", "body_text"],
      ["endpoint", "max_request_bytes"],
      ["runtime", "frame_generation"],
      ["runtime", "capability_grant_id"],
      ["runtime", "credential_handle_used"],
    ];

    for (const path of missingPaths) {
      expect(() =>
        buildPluginNetworkProxyRequestTranscript({
          subject: deleteNestedKey(subject, path),
        }),
      ).toThrow("plugin_network_proxy_request_subject_invalid");
    }
  });

  it("allows plugin proxy request subjects without optional credential audience", () => {
    const privateKeyMaterial = generateHybridSigningPrivateKeyMaterial("device", testUuid(401));
    const publicKeyMaterial = publicKeyMaterialFromPrivate(privateKeyMaterial);
    const subject = deleteNestedKey(pluginNetworkProxyRequestSubjectFixture(publicKeyMaterial), [
      "endpoint",
      "credential_audience",
    ]);

    expect(() =>
      buildPluginNetworkProxyRequestTranscript({
        subject,
      }),
    ).not.toThrow();
  });

  it("rejects plugin proxy request extra nested subject fields before signing", () => {
    const privateKeyMaterial = generateHybridSigningPrivateKeyMaterial("device", testUuid(401));
    const publicKeyMaterial = publicKeyMaterialFromPrivate(privateKeyMaterial);
    const subject = pluginNetworkProxyRequestSubjectFixture(publicKeyMaterial);
    const transcript = buildPluginNetworkProxyRequestTranscript({ subject });

    const extraPaths = [
      ["proxy", "operator_label"],
      ["target", "redirect_policy"],
      ["endpoint", "policy"],
      ["runtime", "deployment_id"],
    ];

    for (const path of extraPaths) {
      const malformedSubject = setNestedKey(subject, path, "unexpected");
      expect(() =>
        buildPluginNetworkProxyRequestTranscript({
          subject: malformedSubject,
        }),
      ).toThrow("plugin_network_proxy_request_subject_invalid");
      expect(() =>
        signPluginNetworkProxyRequestSignature({
          transcript: {
            ...(transcript as Record<string, StrictJsonValue>),
            subject: malformedSubject,
          },
          privateKeyMaterial,
        }),
      ).toThrow("plugin_network_proxy_request_subject_invalid");
    }
  });

  it("rejects workspace fields on user-owned package approval subjects", () => {
    const privateKeyMaterial = generateHybridSigningPrivateKeyMaterial("device", testUuid(401));
    const publicKeyMaterial = publicKeyMaterialFromPrivate(privateKeyMaterial);
    const actor = {
      signer_kind: "device",
      user_id: testUuid(417),
      device_id: publicKeyMaterial.owner_id,
      signing_key_id: computeSigningKeyId(publicKeyMaterial),
      key_scope_kind: "user",
      key_scope_id: testUuid(417),
      key_checkpoint_sequence: 1,
      key_checkpoint_hash: hash("plugin-checkpoint"),
    } satisfies StrictJsonValue;
    const approval: Record<string, StrictJsonValue> = {
      ...(pluginBundleApprovalSubjectFixture(publicKeyMaterial) as Record<string, StrictJsonValue>),
      owner_scope_kind: "user",
      owner_user_id: testUuid(417),
    };
    delete approval.owner_workspace_id;

    const transcript = buildPluginBundleApprovalTranscript({
      actor,
      approval,
    });

    expect(() =>
      signPluginBundleApprovalSignature({
        transcript,
        privateKeyMaterial,
      }),
    ).toThrow("unexpected_keys");
  });

  it("rejects forbidden owner kinds and surface-owner combinations", () => {
    const privateKeyMaterial = testPrivateKeyMaterial();
    const publicKeyMaterial = publicKeyMaterialFromPrivate(privateKeyMaterial);
    const transcript = testTranscript();
    const signature = createPopRequestSignature({
      transcript,
      privateKeyMaterial,
    });

    expect(
      verifyPopRequestSignature({
        transcript,
        signature,
        publicKeyMaterial: {
          ...publicKeyMaterial,
          owner_kind: "plugin_publisher" as never,
        },
      }),
    ).toBe(false);
    expect(getActiveSigningSurface("pq_wrap", "none").owner_kind).toBe("device");
    expect(getActiveSigningSurface("workspace_pin_bootstrap", "none").owner_kind).toBe("device");
    expect(getActiveSigningSurface("recipient_bound_authorization", "none").owner_kind).toBe(
      "device",
    );
    const documentUpdateSurface = getActiveSigningSurface(
      "key_directory_event",
      "document_update_accepted",
    );
    expect(documentUpdateSurface.owner_kind).toBe("device");
    expect(() =>
      assertSigningSurfaceOwner(documentUpdateSurface, "share_participant_device"),
    ).not.toThrow();
    const documentWriteSessionSurface = getActiveSigningSurface(
      "key_directory_event",
      "document_write_session_admitted",
    );
    expect(documentWriteSessionSurface.owner_kind).toBe("device");
    expect(() =>
      assertSigningSurfaceOwner(documentWriteSessionSurface, "share_participant_device"),
    ).not.toThrow();
    expect(
      getActiveSigningSurface("device_key_deletion_proof", "identity_key_deletion_proof")
        .owner_kind,
    ).toBe("device");
  });
});

function inventoryPairKey(signingPurpose: string, variant: string): string {
  return `${signingPurpose}\u0000${variant}`;
}

type SurfaceSignParams = {
  transcript: StrictJsonValue;
  privateKeyMaterial: HybridSigningPrivateKeyMaterial;
};

type SurfaceVerifyParams = {
  transcript: StrictJsonValue;
  signature: HybridSignature;
  publicKeyMaterial: AnyHybridSigningPublicKeyMaterial;
};

type SurfaceCoverage = {
  signingPurpose: string;
  variant: string;
  ownerKind: SigningOwnerKind;
  ownerId: string;
  buildTranscript: (publicKeyMaterial: AnyHybridSigningPublicKeyMaterial) => StrictJsonValue;
  sign: (params: SurfaceSignParams) => HybridSignature;
  verify: (params: SurfaceVerifyParams) => boolean;
};

function activeSurfaceCoverages(): SurfaceCoverage[] {
  return __testActiveSigningSurfaces().map((surface) => ({
    signingPurpose: surface.signing_purpose,
    variant: surface.variant,
    ownerKind: surface.owner_kind,
    ownerId: ownerIdForSurface(surface),
    buildTranscript: (publicKeyMaterial) => buildSurfaceTranscript(surface, publicKeyMaterial),
    sign: signerForPurpose(surface.signing_purpose),
    verify: verifierForPurpose(surface.signing_purpose),
  }));
}

function buildSurfaceTranscript(
  surface: ActiveSigningSurface,
  publicKeyMaterial: AnyHybridSigningPublicKeyMaterial,
): StrictJsonValue {
  switch (surface.signing_purpose) {
    case "pq_wrap":
      return buildPqWrapTranscript({
        ownerDeviceId: publicKeyMaterial.owner_id,
        actor: keyDirectoryActorFixture(publicKeyMaterial),
        authorityBoundary: pqWrapAuthorityBoundaryFixture(),
        subjectHashes: subjectHashesFixture(),
      });
    case "key_directory_checkpoint":
      return buildKeyDirectoryCheckpointTranscript({
        variant: surface.variant as Parameters<
          typeof buildKeyDirectoryCheckpointTranscript
        >[0]["variant"],
        ownerKind: publicKeyMaterial.owner_kind,
        ownerId: publicKeyMaterial.owner_id,
        checkpointPayload: checkpointPayloadFixture(publicKeyMaterial),
        signer: keyDirectoryActorFixture(publicKeyMaterial),
      });
    case "key_directory_event":
      return buildKeyDirectoryEventTranscript({
        eventType: surface.variant as Parameters<
          typeof buildKeyDirectoryEventTranscript
        >[0]["eventType"],
        ownerKind: publicKeyMaterial.owner_kind,
        ownerId: publicKeyMaterial.owner_id,
        eventPayload: keyDirectoryEventPayloadFixture(surface.variant, publicKeyMaterial),
      });
    case "workspace_pin_bootstrap":
      return buildWorkspacePinBootstrapTranscript({
        ownerDeviceId: publicKeyMaterial.owner_id,
        workspaceId: testUuid(401),
        bootstrap: workspacePinBootstrapFixture(publicKeyMaterial),
      });
    case "recipient_bound_authorization": {
      const signingKeyId = computeSigningKeyId(publicKeyMaterial);
      return buildRecipientBoundAuthorizationTranscript({
        ownerId: publicKeyMaterial.owner_id,
        actorUserId: testUuid(402),
        actorDeviceId: publicKeyMaterial.owner_id,
        signingKeyId,
        authorizationPayload: recipientBoundAuthorizationPayload(signingKeyId),
      });
    }
    case "share_capability_authorization":
      return buildShareCapabilityAuthorizationTranscript(shareCapabilityAuthorizationParams());
    case "share_participant_device_authorization":
      return buildShareParticipantDeviceAuthorizationTranscript({
        shareId: testUuid(430),
        shareSessionId: testUuid(431),
        shareParticipantPrincipalId: testUuid(432),
        shareParticipantDeviceId: publicKeyMaterial.owner_id,
        participantSigningKeyId: computeSigningKeyId(publicKeyMaterial),
        participantEncryptionKeyId: hash("participant-encryption"),
        capabilityContextHash: hash("capability-context"),
        shareCreatedEventHash: hash("share-created"),
        latestBootstrapEventHash: hash("latest-bootstrap"),
        scopeKind: "document",
        scopeId: testUuid(433),
        permission: "edit",
      });
    case "pop_request":
      return buildPopTranscript({
        variant: surface.variant as Parameters<typeof buildPopTranscript>[0]["variant"],
        ownerKind: publicKeyMaterial.owner_kind,
        ownerId: publicKeyMaterial.owner_id,
        actor: popActorFixture(surface.variant, publicKeyMaterial),
        challenge: "challenge",
        session: popSessionFixture(surface.variant),
        resource: popResourceFixture(surface.variant),
      });
    case "genesis_device_bootstrap": {
      const devicePublic = publicKeyMaterialFromPrivate(
        testPrivateKeyMaterialForOwner("device", testUuid(411)),
      );
      const encryptionPublic = fixedEncryptionPublicMaterial(
        "device",
        devicePublic.owner_id,
        "genesis-device-encryption",
      );
      return buildGenesisDeviceBootstrapTranscript({
        ownerId: publicKeyMaterial.owner_id,
        deviceId: devicePublic.owner_id,
        deviceHybridSigningPublicKeyMaterial: devicePublic,
        deviceEcdhPublicKey: encodeBase64Url(deterministicBytes("genesis-ecdh", 32)),
        deviceHybridEncryptionPublicKeyMaterial: encryptionPublic,
        clientNonce: encodeBase64Url(deterministicBytes("genesis-client-nonce", 16)),
        registrationChallengeHash: hash("challenge"),
        identitySigningKeyId: computeSigningKeyId(publicKeyMaterial),
        userIdentityPublicKeyHash: hash("identity"),
      });
    }
    case "device_approval": {
      const approvedPublic = publicKeyMaterialFromPrivate(
        testPrivateKeyMaterialForOwner("device", testUuid(412)),
      );
      const encryptionPublic = fixedEncryptionPublicMaterial(
        "device",
        approvedPublic.owner_id,
        "device-approval-encryption",
      );
      return buildDeviceApprovalTranscript({
        ownerId: testUuid(413),
        approverDeviceId: publicKeyMaterial.owner_id,
        approvedDeviceId: approvedPublic.owner_id,
        approvedDeviceHybridSigningPublicKeyMaterial: approvedPublic,
        approvedDeviceEcdhPublicKey: encodeBase64Url(
          deterministicBytes("device-approval-ecdh", 32),
        ),
        approvedDeviceHybridEncryptionPublicKeyMaterial: encryptionPublic,
        clientNonce: encodeBase64Url(deterministicBytes("device-approval-client-nonce", 16)),
        approvedDeviceRegistrationSasHash: hash("sas"),
        pendingRegistrationId: approvedPublic.owner_id,
        pendingRegistrationChallengeHash: hash("challenge"),
        approvingOwnerKind: "device",
        approvingOwnerId: publicKeyMaterial.owner_id,
        approvingSigningKeyId: computeSigningKeyId(publicKeyMaterial),
        approvingKeyCheckpointSequence: 1,
        approvingKeyCheckpointHash: hash("approver-checkpoint"),
        approvingDeviceKeyDirectoryProofHash: hash("proof"),
        targetDeviceId: approvedPublic.owner_id,
        targetDeviceSigningKeyId: computeSigningKeyId(approvedPublic),
        targetDeviceHybridSigningPublicKeyMaterialHash: blake3Base64Url(
          canonicalizeStrictBytes(approvedPublic as unknown as StrictJsonValue),
        ),
        targetDeviceHybridEncryptionPublicKeyMaterialHash: blake3Base64Url(
          canonicalizeStrictBytes(encryptionPublic as unknown as StrictJsonValue),
        ),
        targetDeviceEncryptionKeyId: computeHybridEncryptionKeyId(encryptionPublic),
        targetDeviceClientNonceHash: hash("target-client-nonce"),
        targetKeyCheckpointSequence: 1,
        targetKeyCheckpointHash: hash("target-checkpoint"),
        umkDistributionDeliveryCommitment: deliveryCommitmentFixture("umk_distribution"),
        trustTransferDeliveryCommitment: deliveryCommitmentFixture("trust_transfer"),
        deviceApprovalKekInitialDeliveryCommitments: [
          deliveryCommitmentFixture("device_approval_kek_initial"),
        ],
      });
    }
    case "plugin_bundle_approval":
      return buildPluginBundleApprovalTranscript({
        actor: pluginDeviceActorFixture(publicKeyMaterial),
        approval: pluginBundleApprovalSubjectFixture(publicKeyMaterial),
      });
    case "plugin_consent_event":
      return buildPluginConsentEventTranscript({
        actor: pluginDeviceActorFixture(publicKeyMaterial),
        consent: pluginConsentSubjectFixture(publicKeyMaterial),
      });
    case "plugin_network_proxy_request":
      return buildPluginNetworkProxyRequestTranscript({
        subject: pluginNetworkProxyRequestSubjectFixture(publicKeyMaterial),
      });
    case "responder_prekey":
      return buildResponderPrekeyTranscript({
        ownerDeviceId: publicKeyMaterial.owner_id,
        prekeyPayload: { protocol: "refmd.responder-prekey", prekey_id: "prekey" },
        responder: {
          device_id: publicKeyMaterial.owner_id,
          signing_key_id: computeSigningKeyId(publicKeyMaterial),
        },
        freshness: { challenge_hash: hash("challenge") },
      });
    case "initiator_ake_commitment":
      return buildInitiatorAkeCommitmentTranscript({
        ownerDeviceId: publicKeyMaterial.owner_id,
        commitmentPayload: {
          protocol: "refmd.initiator-ake-commitment",
          operation_id: "operation",
        },
        initiator: {
          device_id: publicKeyMaterial.owner_id,
          signing_key_id: computeSigningKeyId(publicKeyMaterial),
        },
        akeInputs: { x25519_ephemeral_public: hash("x25519") },
        binding: {
          operation_id: "operation",
          context_hash: hash("context"),
          directory_hash: hash("directory"),
          recipient_hash: hash("recipient"),
          server_challenge: "challenge",
        },
      });
    case "initial_key_delivery":
      return buildInitialKeyDeliveryTranscript({
        ownerDeviceId: publicKeyMaterial.owner_id,
        variant: surface.variant as Parameters<
          typeof buildInitialKeyDeliveryTranscript
        >[0]["variant"],
        deliverySigningBody: {
          protocol: "refmd.initial-key-delivery",
          variant: surface.variant,
        },
        sender: {
          user_id: testUuid(414),
          device_id: publicKeyMaterial.owner_id,
          signing_key_id: computeSigningKeyId(publicKeyMaterial),
        },
        recipient: {
          user_id: testUuid(415),
          device_id: testUuid(416),
          encryption_key_id: hash("recipient-encryption-key"),
        },
        ake: {
          ake_transcript_hash: hash("ake"),
          initiator_commitment_hash: hash("commitment"),
          purpose: surface.variant,
          operation_id: "operation",
        },
        delivery: {
          delivery_id: "delivery",
          context_hash: hash("context"),
          payload_kind: "payload",
          ciphertext_hash: hash("ciphertext"),
        },
        authority: { sender_authority_kind: "device" },
      });
    case "recovery_device_approval": {
      const approvedPublic = publicKeyMaterialFromPrivate(
        testPrivateKeyMaterialForOwner("device", testUuid(418)),
      );
      const encryptionPublic = fixedEncryptionPublicMaterial(
        "device",
        approvedPublic.owner_id,
        "recovery-device-approval-encryption",
      );
      return buildRecoveryDeviceApprovalTranscript({
        ownerId: publicKeyMaterial.owner_id,
        approvingSigningKeyId: computeSigningKeyId(publicKeyMaterial),
        approvingKeyCheckpointSequence: 1,
        approvingKeyCheckpointHash: hash("checkpoint"),
        pendingRegistrationId: approvedPublic.owner_id,
        pendingRegistrationChallengeHash: hash("challenge"),
        recoverySessionTranscriptHash: hash("session"),
        recoveryCapabilityHash: hash("capability"),
        pendingRegistrationBindingHash: hash("binding"),
        approvedDeviceId: approvedPublic.owner_id,
        approvedDeviceHybridSigningPublicKeyMaterial: approvedPublic,
        approvedDeviceEcdhPublicKey: encodeBase64Url(deterministicBytes("recovery-ecdh", 32)),
        approvedDeviceHybridEncryptionPublicKeyMaterial: encryptionPublic,
        clientNonce: encodeBase64Url(deterministicBytes("recovery-client-nonce", 16)),
        targetKeyCheckpointSequence: 1,
        targetKeyCheckpointHash: hash("target"),
      });
    }
    case "device_revocation":
      return buildDeviceRevocationTranscript({
        ownerId: testUuid(417),
        actorUserId: testUuid(417),
        actorDeviceId: publicKeyMaterial.owner_id,
        signingKeyId: computeSigningKeyId(publicKeyMaterial),
        revokedDeviceId: testUuid(418),
        revocationMode: "self_revocation",
        revokedAtMs: 1_775_000_000_000,
      });
    case "recovery_session":
      return buildRecoverySessionTranscript({
        ownerId: publicKeyMaterial.owner_id,
        recipientDeviceId: testUuid(419),
        pendingRegistrationId: testUuid(420),
        recoverySessionId: testUuid(421),
        serverChallengeHash: hash("challenge"),
        recoveredIdentitySigningKeyId: computeSigningKeyId(publicKeyMaterial),
        recoveryAuthorizationKeyId: hash("authorization"),
        candidateUserCheckpointSequence: 1,
        candidateUserCheckpointHash: hash("checkpoint"),
        candidateUserEventHeadSequence: 1,
        candidateUserEventHeadHash: hash("event"),
        recoveryCapabilityHash: hash("capability"),
        pendingRegistrationBindingHash: hash("binding"),
      });
    case "recovery_authorization_proof":
      return buildRecoveryAuthorizationProofTranscript({
        ownerId: publicKeyMaterial.owner_id,
        recoveryAuthorizationKeyId: computeSigningKeyId(publicKeyMaterial),
        recipientDeviceId: testUuid(419),
        pendingRegistrationBindingHash: hash("binding"),
        serverChallengeHash: hash("challenge"),
      });
    case "pin_gossip_statement":
      return buildPinGossipStatementTranscript({
        ownerDeviceId: publicKeyMaterial.owner_id,
        pinGossip: { statement: "security-vector" },
      });
    case "device_key_deletion_proof":
      return buildDeviceKeyDeletionProofTranscript({
        payload: deviceKeyDeletionPayloadFixture(publicKeyMaterial.owner_id, surface.variant),
        actor: {
          device_id: publicKeyMaterial.owner_id,
          signing_key_id: computeSigningKeyId(publicKeyMaterial),
          user_id: testUuid(417),
        },
      });
    case "document_update":
      return buildDocumentUpdateTranscript(
        documentOperationParamsFixture("document_update", publicKeyMaterial),
      );
    case "document_snapshot":
      return buildDocumentSnapshotTranscript(
        documentOperationParamsFixture("document_snapshot", publicKeyMaterial),
      );
    case "editor_ephemeral":
      return buildEditorEphemeralTranscript(editorEphemeralParamsFixture(publicKeyMaterial));
    case "editor_ephemeral_session":
      return buildEditorEphemeralSessionTranscript(
        editorEphemeralSessionParamsFixture(publicKeyMaterial),
      );
    default:
      throw new Error(`surface_coverage_missing:${surface.signing_purpose}:${surface.variant}`);
  }
}

function signerForPurpose(signingPurpose: string): (params: SurfaceSignParams) => HybridSignature {
  switch (signingPurpose) {
    case "pq_wrap":
      return signPqWrapSignature;
    case "key_directory_checkpoint":
      return signKeyDirectoryCheckpointSignature;
    case "key_directory_event":
      return signKeyDirectoryEventSignature;
    case "workspace_pin_bootstrap":
      return signWorkspacePinBootstrapSignature;
    case "recipient_bound_authorization":
      return signRecipientBoundAuthorizationSignature;
    case "share_capability_authorization":
      return signShareCapabilityAuthorizationSignature;
    case "share_participant_device_authorization":
      return signShareParticipantDeviceAuthorizationSignature;
    case "pop_request":
      return createPopRequestSignature;
    case "genesis_device_bootstrap":
      return signGenesisDeviceBootstrapSignature;
    case "device_approval":
      return createDeviceApprovalSignature;
    case "plugin_bundle_approval":
      return signPluginBundleApprovalSignature;
    case "plugin_consent_event":
      return signPluginConsentEventSignature;
    case "plugin_network_proxy_request":
      return signPluginNetworkProxyRequestSignature;
    case "responder_prekey":
      return signResponderPrekeySignature;
    case "initiator_ake_commitment":
      return signInitiatorAkeCommitmentSignature;
    case "initial_key_delivery":
      return signInitialKeyDeliverySignature;
    case "recovery_device_approval":
      return signRecoveryDeviceApprovalSignature;
    case "device_revocation":
      return createDeviceRevocationSignature;
    case "recovery_session":
      return signRecoverySessionSignature;
    case "recovery_authorization_proof":
      return signRecoveryAuthorizationProofSignature;
    case "pin_gossip_statement":
      return signPinGossipStatementSignature;
    case "device_key_deletion_proof":
      return signDeviceKeyDeletionProofSignature;
    case "document_update":
      return signDocumentUpdateSignature;
    case "document_snapshot":
      return signDocumentSnapshotSignature;
    case "editor_ephemeral":
      return signEditorEphemeralSignature;
    case "editor_ephemeral_session":
      return signEditorEphemeralSessionSignature;
    default:
      throw new Error(`surface_signer_missing:${signingPurpose}`);
  }
}

function verifierForPurpose(signingPurpose: string): (params: SurfaceVerifyParams) => boolean {
  switch (signingPurpose) {
    case "pq_wrap":
      return verifyPqWrapSignature;
    case "key_directory_checkpoint":
      return verifyKeyDirectoryCheckpointSignature;
    case "key_directory_event":
      return verifyKeyDirectoryEventSignature;
    case "workspace_pin_bootstrap":
      return verifyWorkspacePinBootstrapSignature;
    case "recipient_bound_authorization":
      return verifyRecipientBoundAuthorizationSignature;
    case "share_capability_authorization":
      return verifyShareCapabilityAuthorizationSignature;
    case "share_participant_device_authorization":
      return verifyShareParticipantDeviceAuthorizationSignature;
    case "pop_request":
      return verifyPopRequestSignature;
    case "genesis_device_bootstrap":
      return verifyGenesisDeviceBootstrapSignature;
    case "device_approval":
      return verifyDeviceApprovalSignature;
    case "plugin_bundle_approval":
      return verifyPluginBundleApprovalSignature;
    case "plugin_consent_event":
      return verifyPluginConsentEventSignature;
    case "plugin_network_proxy_request":
      return verifyPluginNetworkProxyRequestSignature;
    case "responder_prekey":
      return verifyResponderPrekeySignature;
    case "initiator_ake_commitment":
      return verifyInitiatorAkeCommitmentSignature;
    case "initial_key_delivery":
      return verifyInitialKeyDeliverySignature;
    case "recovery_device_approval":
      return verifyRecoveryDeviceApprovalSignature;
    case "device_revocation":
      return verifyDeviceRevocationSignature;
    case "recovery_session":
      return verifyRecoverySessionSignature;
    case "recovery_authorization_proof":
      return verifyRecoveryAuthorizationProofSignature;
    case "pin_gossip_statement":
      return verifyPinGossipStatementSignature;
    case "device_key_deletion_proof":
      return verifyDeviceKeyDeletionProofSignature;
    case "document_update":
      return verifyDocumentUpdateSignature;
    case "document_snapshot":
      return verifyDocumentSnapshotSignature;
    case "editor_ephemeral":
      return verifyEditorEphemeralSignature;
    case "editor_ephemeral_session":
      return verifyEditorEphemeralSessionSignature;
    default:
      throw new Error(`surface_verifier_missing:${signingPurpose}`);
  }
}

function ownerIdForSurface(surface: ActiveSigningSurface): string {
  if (surface.signing_purpose === "share_capability_authorization") {
    return hash("share-token");
  }
  switch (surface.owner_kind) {
    case "identity":
      return testUuid(201);
    case "device":
      return testUuid(202);
    case "share_participant_device":
      return testUuid(203);
    case "invitation_redeem_authority":
      return testUuid(204);
    default:
      throw new Error(`surface_owner_missing:${surface.owner_kind}`);
  }
}

function testPrivateKeyMaterialForOwner(
  ownerKind: SigningOwnerKind,
  ownerId: string,
): HybridSigningPrivateKeyMaterial {
  const ed25519Private = seed(`${ownerKind}:${ownerId}:ed25519-private`);
  const ed25519Public = ed25519.getPublicKey(ed25519Private);
  const mldsaKeys = ml_dsa65.keygen(seed(`${ownerKind}:${ownerId}:mldsa65-private`));
  return {
    protocol: SIGNING_PRIVATE_KEY_MATERIAL_PROTOCOL,
    version: CURRENT_PROTOCOL_VERSION,
    owner_kind: ownerKind,
    owner_id: ownerId,
    ed25519_private: encodeBase64Url(ed25519Private),
    ed25519_public: encodeBase64Url(ed25519Public),
    mldsa65_private: encodeBase64Url(mldsaKeys.secretKey),
    mldsa65_public: encodeBase64Url(mldsaKeys.publicKey),
    suite_id: SUITE_IDS.HYBRID_SIGNATURE,
    suite_rank: CURRENT_SUITE_RANK,
  };
}

function publicKeyMaterialForOwner(
  privateKeyMaterial: HybridSigningPrivateKeyMaterial,
): AnyHybridSigningPublicKeyMaterial {
  if (privateKeyMaterial.owner_kind === "share_capability") {
    return shareCapabilityPublicKeyMaterialFromPrivate(privateKeyMaterial);
  }
  return publicKeyMaterialFromPrivate(privateKeyMaterial);
}

function withoutSignatureField(
  signature: HybridSignature,
  field: "ed25519" | "mldsa65",
): HybridSignature {
  const mutated: Partial<HybridSignature> = { ...signature };
  delete mutated[field];
  return mutated as HybridSignature;
}

function fixedEncryptionPublicMaterial(
  ownerKind: "identity" | "device" | "share_participant_device",
  ownerId: string,
  label: string,
): HybridEncryptionPublicKeyMaterial {
  const x25519Public = deterministicBytes(`${label}:x25519`, 32);
  const mlkem768Public = deterministicBytes(`${label}:mlkem768`, 1184);
  const hybridPublic = new Uint8Array(mlkem768Public.length + x25519Public.length);
  hybridPublic.set(mlkem768Public);
  hybridPublic.set(x25519Public, mlkem768Public.length);

  return {
    protocol: HYBRID_ENCRYPTION_KEY_MATERIAL_PROTOCOL,
    version: CURRENT_PROTOCOL_VERSION,
    suite_id: SUITE_IDS.SIGNED_PQ_HYBRID_WRAP,
    suite_rank: CURRENT_SUITE_RANK,
    owner_kind: ownerKind,
    owner_id: ownerId,
    x25519_public: encodeBase64Url(x25519Public),
    mlkem768_public: encodeBase64Url(mlkem768Public),
    hybrid_public: encodeBase64Url(hybridPublic),
  };
}

function keyDirectoryActorFixture(
  publicKeyMaterial: AnyHybridSigningPublicKeyMaterial,
): Record<string, StrictJsonValue> {
  if (publicKeyMaterial.owner_kind === "identity") {
    return {
      signer_kind: "identity",
      user_id: publicKeyMaterial.owner_id,
      signing_key_id: computeSigningKeyId(publicKeyMaterial),
    };
  }
  if (publicKeyMaterial.owner_kind === "share_participant_device") {
    return {
      signer_kind: "share_participant_device",
      share_id: testUuid(408),
      share_participant_principal_id: testUuid(407),
      share_participant_device_id: publicKeyMaterial.owner_id,
      signing_key_id: computeSigningKeyId(publicKeyMaterial),
      key_scope_kind: "workspace",
      key_scope_id: testUuid(401),
      key_checkpoint_sequence: 1,
      key_checkpoint_hash: hash("checkpoint"),
    };
  }
  if (publicKeyMaterial.owner_kind === "invitation_redeem_authority") {
    return {
      signer_kind: "invitation_redeem_authority",
      invitation_id: testUuid(409),
      signing_key_id: computeSigningKeyId(publicKeyMaterial),
    };
  }
  return {
    signer_kind: "device",
    user_id: testUuid(417),
    device_id: publicKeyMaterial.owner_id,
    signing_key_id: computeSigningKeyId(publicKeyMaterial),
    key_scope_kind: "workspace",
    key_scope_id: testUuid(401),
    key_checkpoint_sequence: 1,
    key_checkpoint_hash: hash("checkpoint"),
  };
}

function pluginDeviceActorFixture(
  publicKeyMaterial: AnyHybridSigningPublicKeyMaterial,
): StrictJsonValue {
  return {
    signer_kind: "device",
    user_id: testUuid(417),
    device_id: publicKeyMaterial.owner_id,
    signing_key_id: computeSigningKeyId(publicKeyMaterial),
    key_scope_kind: "workspace",
    key_scope_id: testUuid(502),
    key_checkpoint_sequence: 1,
    key_checkpoint_hash: hash("plugin-checkpoint"),
  };
}

function pluginBundleApprovalSubjectFixture(
  publicKeyMaterial: AnyHybridSigningPublicKeyMaterial,
): StrictJsonValue {
  return {
    plugin_id: "com.example.signature",
    package_id: testUuid(503),
    application_scope_kind: "workspace",
    workspace_id: testUuid(502),
    owner_scope_kind: "workspace",
    owner_workspace_id: testUuid(502),
    version: "1.0.0",
    source_kind: "local_upload",
    source_url_hash: "NO_SOURCE_URL",
    archive_hash: hash("archive"),
    bundle_hash: hash("bundle"),
    manifest_hash: hash("manifest"),
    main_js_hash: hash("main-js"),
    styles_css_hash: hash("styles-css"),
    resource_manifest_hash: hash("resources"),
    permissions_hash: hash("permissions"),
    endpoint_hash: hash("endpoint"),
    renderer_slots_hash: hash("renderer-slots"),
    document_scope_hash: hash("document-scope"),
    approver_user_id: testUuid(417),
    approver_device_id: publicKeyMaterial.owner_id,
    approval_epoch: 1,
    previous_approval_event_hash: "GENESIS",
    created_at_ms: 1_775_000_000_000,
  };
}

function pluginConsentSubjectFixture(
  publicKeyMaterial: AnyHybridSigningPublicKeyMaterial,
): StrictJsonValue {
  return {
    plugin_id: "com.example.signature",
    package_id: testUuid(503),
    application_id: testUuid(501),
    activation_id: testUuid(504),
    owner_scope_kind: "workspace",
    application_scope_kind: "workspace",
    version: "1.0.0",
    bundle_hash: hash("bundle"),
    manifest_hash: hash("manifest"),
    resource_manifest_hash: hash("resources"),
    permissions_hash: hash("permissions"),
    endpoint_hash: hash("endpoint"),
    document_scope_hash: hash("document-scope"),
    signer_device_id: publicKeyMaterial.owner_id,
    signer_user_id: testUuid(417),
    user_id: testUuid(417),
    device_id: publicKeyMaterial.owner_id,
    workspace_id: testUuid(502),
    consent_epoch: 1,
    previous_event_hash: "GENESIS",
    decision: "allow",
  };
}

function pluginNetworkProxyRequestSubjectFixture(
  publicKeyMaterial: AnyHybridSigningPublicKeyMaterial,
): StrictJsonValue {
  return {
    protocol: "refmd.plugin-network-proxy-request-subject",
    version: CURRENT_PROTOCOL_VERSION,
    request_id: "request-one",
    proxy: {
      id: "workspace-proxy",
      scope: "workspace",
      origin: "https://proxy.example/refmd",
    },
    target: {
      url: "https://api.github.com/repos/refmdio/refmd/issues",
      method: "GET",
      headers: { accept: "application/json" },
      body_text: "",
    },
    endpoint: {
      id: "github-rest",
      max_request_bytes: 1024,
      max_response_bytes: 2048,
      credential_audience: "api.github.com",
    },
    runtime: {
      workspace_id: testUuid(502),
      plugin_id: "com.example.signature",
      package_id: testUuid(503),
      application_id: testUuid(501),
      activation_id: testUuid(504),
      frame_generation: 1,
      user_id: testUuid(417),
      device_id: publicKeyMaterial.owner_id,
      owner_scope_kind: "workspace",
      consent_epoch: 1,
      capability_grant_id: "capability-grant-one",
      request_id: "request-one",
      credential_handle_used: false,
    },
  };
}

function deleteNestedKey(value: StrictJsonValue, path: readonly string[]): StrictJsonValue {
  if (path.length === 0) return value;
  if (!value || typeof value !== "object" || Array.isArray(value)) return value;
  const [key, ...rest] = path;
  const copy = { ...(value as Record<string, StrictJsonValue>) };
  if (rest.length === 0) {
    delete copy[key];
  } else {
    copy[key] = deleteNestedKey(copy[key], rest);
  }
  return copy;
}

function setNestedKey(
  value: StrictJsonValue,
  path: readonly string[],
  nextValue: StrictJsonValue,
): StrictJsonValue {
  if (path.length === 0) return nextValue;
  if (!value || typeof value !== "object" || Array.isArray(value)) return value;
  const [key, ...rest] = path;
  const copy = { ...(value as Record<string, StrictJsonValue>) };
  copy[key] = setNestedKey(copy[key], rest, nextValue);
  return copy;
}

function checkpointPayloadFixture(
  publicKeyMaterial: AnyHybridSigningPublicKeyMaterial,
): StrictJsonValue {
  return {
    allowed_suite_ids: [SUITE_IDS.HYBRID_SIGNATURE],
    covered_event_head: {
      head_hash: hash("head"),
      head_sequence: 1,
    },
    min_suite_rank: CURRENT_SUITE_RANK,
    previous_checkpoint_hash: hash("previous-checkpoint"),
    scope_id: publicKeyMaterial.owner_id,
    scope_kind: "workspace",
    sequence: 1,
    signer: keyDirectoryActorFixture(publicKeyMaterial),
    suite_policy_version: 1,
  } as StrictJsonValue;
}

function keyDirectoryEventPayloadFixture(
  variant: string,
  publicKeyMaterial: AnyHybridSigningPublicKeyMaterial,
): StrictJsonValue {
  return {
    actor: keyDirectoryActorFixture(publicKeyMaterial),
    body: { event_type: variant, resource_id: "refmd.security-vector" },
    event_type: variant,
    previous_event_hash: hash("previous-event"),
    scope_id: publicKeyMaterial.owner_id,
    scope_kind: "workspace",
    sequence: 1,
  } as StrictJsonValue;
}

function workspacePinBootstrapFixture(
  publicKeyMaterial: AnyHybridSigningPublicKeyMaterial,
): StrictJsonValue {
  return {
    protocol: "refmd.workspace-pin-bootstrap",
    version: CURRENT_PROTOCOL_VERSION,
    workspace_id: testUuid(401),
    checkpoint_sequence: 45,
    checkpoint_hash: hash("checkpoint"),
    event_head_sequence: 44,
    event_head_hash: hash("head"),
    suite_policy_version: 1,
    min_suite_rank: CURRENT_SUITE_RANK,
    allowed_suite_ids_hash: hash("allowed-suite-ids"),
    issuer: keyDirectoryActorFixture(publicKeyMaterial),
    issuing_event_hash: hash("head"),
    expires_event_sequence: 9_007_199_254_740_991,
    bootstrap_nonce: hash("workspace-pin-bootstrap-nonce"),
  } as StrictJsonValue;
}

function recipientBoundAuthorizationPayload(signingKeyId: string): Record<string, unknown> {
  return {
    protocol: "refmd.recipient-bound-authorization",
    version: CURRENT_PROTOCOL_VERSION,
    authorization_id: testUuid(404),
    redeem_attempt_id: testUuid(405),
    workspace_id: testUuid(406),
    context_kind: "guest_invitation",
    context_id: testUuid(407),
    resource_hash: hash("resource"),
    recipient: {
      recipient_kind: "guest",
      recipient_principal_id: testUuid(408),
      recipient_device_id: testUuid(409),
      encryption_key_id: hash("encryption-key"),
    },
    workspace_pin_bootstrap_hash: hash("workspace-pin-bootstrap"),
    current_checkpoint_sequence: 45,
    current_checkpoint_hash: hash("checkpoint"),
    current_event_head_sequence: 44,
    current_event_head_hash: hash("event-head"),
    redeem_authority_signing_key_id: signingKeyId,
    recipient_redeem_nonce: encodeBase64Url(deterministicBytes("recipient-redeem-nonce", 32)),
    recipient_nonce_state_hash: hash("nonce-state"),
    live_redeem_challenge_hash: hash("live-challenge"),
    redeem_freshness_proof_hash: hash("freshness-proof"),
    not_after_event_sequence: 45,
  };
}

function shareCapabilityAuthorizationParams(): Parameters<
  typeof buildShareCapabilityAuthorizationTranscript
>[0] {
  return {
    shareTokenHash: hash("share-token"),
    workspacePinBootstrapHash: hash("workspace-pin-bootstrap"),
    shareId: testUuid(408),
    scopeKind: "document",
    scopeId: testUuid(409),
    permission: "view",
    passwordProtected: false,
    createdEventHash: hash("created"),
    latestBootstrapEventHash: hash("latest"),
    capabilityContextHash: hash("context"),
    shareCapabilitySecretCommitment: hash("capability"),
    passwordCapabilitySecretCommitment: "none",
  };
}

function popActorFixture(
  variant: string,
  publicKeyMaterial: AnyHybridSigningPublicKeyMaterial,
): Record<string, StrictJsonValue> {
  if (variant.includes("share_participant_device")) {
    return {
      signer_kind: "share_participant_device",
      share_id: testUuid(420),
      share_participant_principal_id: testUuid(410),
      share_participant_device_id: publicKeyMaterial.owner_id,
      signing_key_id: computeSigningKeyId(publicKeyMaterial),
      key_scope_kind: "workspace",
      key_scope_id: testUuid(421),
      key_checkpoint_sequence: 1,
      key_checkpoint_hash: hash("pop-workspace-checkpoint"),
    };
  }
  return {
    signer_kind: "device",
    user_id: testUuid(410),
    device_id: publicKeyMaterial.owner_id,
    signing_key_id: computeSigningKeyId(publicKeyMaterial),
    key_scope_kind: "user",
    key_scope_id: testUuid(410),
    key_checkpoint_sequence: 1,
    key_checkpoint_hash: hash("pop-user-checkpoint"),
  };
}

function popSessionFixture(variant: string): Record<string, StrictJsonValue> {
  if (variant.includes("share_participant_device")) {
    return {
      session_id_hash: hash("session"),
      session_kind: "share_participant",
      share_id: testUuid(420),
      is_recovery: false,
    };
  }
  return {
    session_id_hash: hash("session"),
    session_kind: "user",
    is_recovery: false,
  };
}

function popResourceFixture(variant: string): StrictJsonValue {
  if (variant.startsWith("http_")) {
    return {
      body_hash: hash(""),
      canonical_query: "",
      method: "GET",
      path: "/api/security-vector",
      query_hash: hash(""),
    };
  }
  return {
    channel_event: "phx_join",
    document_id: testUuid(423),
    event_name: "phx_join",
    join_push_kind: "document_join",
    payload_hash: hash("payload"),
    scope_kind: variant.includes("share_participant_device") ? "share" : "user",
    share_id: variant.includes("share_participant_device") ? testUuid(408) : "none",
    topic: `document:${testUuid(423)}`,
  };
}

function pqWrapAuthorityBoundaryFixture(): StrictJsonValue {
  return {
    covered_event_head_hash: hash("head"),
    covered_event_head_sequence: 1,
    event_hash: hash("event"),
    operation_checkpoint_hash: hash("checkpoint"),
    operation_checkpoint_sequence: 1,
    scope_id: testUuid(401),
    scope_kind: "workspace",
  };
}

function subjectHashesFixture(): StrictJsonValue {
  return {
    aad_hash: hash("aad"),
    hpke_info_hash: hash("hpke-info"),
    resource_hash: hash("resource"),
    wrap_body_hash: hash("wrap-body"),
    wrap_event_body_hash: hash("wrap-event-body"),
    wrap_event_hash: hash("wrap-event"),
  };
}

function deliveryCommitmentFixture(purpose: string): StrictJsonValue {
  return {
    purpose,
    variant: purpose,
    delivery_id: `${purpose}-delivery`,
    recipient_device_id: testUuid(412),
    sender_device_id: testUuid(202),
    delivery_record_hash: hash(`${purpose}-record`),
    key_checkpoint_hash: hash(`${purpose}-checkpoint`),
  };
}

function deviceKeyDeletionPayloadFixture(
  deviceId: string,
  variant: string,
): Record<string, unknown> {
  return {
    deleted_secret_ids: ["dek:1"],
    deleted_secret_ids_hash: hash("deleted-secret-ids"),
    deleted_storage_classes: ["local"],
    deletion_proof_kind: variant,
    device_id: deviceId,
    old_key_version: 1,
    rotation_completed_event_hash: hash("rotation-completed"),
    rotation_kind: "workspace_key_rotation",
    scope_id: testUuid(401),
    scope_kind: "workspace",
    workspace_id: testUuid(401),
  };
}

function documentOperationParamsFixture(
  purpose: "document_update" | "document_snapshot",
  publicKeyMaterial: AnyHybridSigningPublicKeyMaterial,
): Parameters<typeof buildDocumentUpdateTranscript>[0] {
  const signingKeyId = computeSigningKeyId(publicKeyMaterial);
  const publicData: Record<string, unknown> = {
    authorityId: testUuid(401),
    authorityKind:
      publicKeyMaterial.owner_kind === "share_participant_device"
        ? "share_participant_device"
        : "workspace_device",
    authorityContextKey: signingKeyId,
    authorityPermissionVersion: 1,
    authorityScopeId: testUuid(402),
    docId: testUuid(423),
    keyCheckpointHash: hash("checkpoint"),
    keyCheckpointSequence: 1,
    keyVersion: 1,
    ownerId: publicKeyMaterial.owner_id,
    ownerKind: publicKeyMaterial.owner_kind,
    signingKeyId,
  };
  if (purpose === "document_snapshot") {
    Object.assign(publicData, {
      parentProofHash: "GENESIS",
      parentSnapshotId: "GENESIS",
      parentSnapshotUpdateClocks: {},
      snapshotId: testUuid(425),
    });
  } else {
    Object.assign(publicData, {
      clock: 0,
      minDekVersion: 1,
      refSnapshotId: testUuid(424),
      timestamp: 1,
      updateHash: hash("update"),
      writeSessionCounter: 1,
      writeSessionEventHash: hash("write-session"),
      writeSessionId: hash("write-session-id"),
    });
  }

  return {
    ownerKind: publicKeyMaterial.owner_kind as SigningOwnerKind,
    ownerId: publicKeyMaterial.owner_id,
    workspaceId: testUuid(401),
    actorUserId: testUuid(417),
    actorDeviceId: publicKeyMaterial.owner_id,
    signingKeyId,
    publicData,
    authorityBoundary:
      purpose === "document_update"
        ? {
            document_permission_proof_hash: hash("permission"),
            min_dek_version: 1,
            write_session_counter: 1,
            write_session_event_hash: hash("write-session"),
            write_session_id: hash("write-session-id"),
          }
        : {
            admission_event_type: `${purpose}_accepted`,
            admission_nonce: hash("nonce"),
            document_permission_proof_hash: hash("permission"),
            min_dek_version: 1,
            previous_workspace_event_hash: hash("head"),
            previous_workspace_event_sequence: 1,
          },
    ciphertext: encodeBase64Url(deterministicBytes("document-operation-ciphertext", 48)),
    nonce: encodeBase64Url(deterministicBytes("document-operation-nonce", 24)),
  };
}

function editorEphemeralParamsFixture(
  publicKeyMaterial: AnyHybridSigningPublicKeyMaterial,
): Parameters<typeof buildEditorEphemeralTranscript>[0] {
  return {
    ownerKind: publicKeyMaterial.owner_kind as SigningOwnerKind,
    ownerId: publicKeyMaterial.owner_id,
    actorUserId: testUuid(422),
    actorDeviceId: publicKeyMaterial.owner_id,
    signingKeyId: computeSigningKeyId(publicKeyMaterial),
    workspaceId: testUuid(401),
    publicData: {
      authorityId: testUuid(401),
      docId: testUuid(423),
      keyCheckpointHash: hash("checkpoint"),
      keyCheckpointSequence: 1,
    },
    authorityBoundary: {
      workspace_event_head_sequence: 1,
      workspace_event_head_hash: hash("checkpoint"),
      actor_active_proof_hash: hash("actor-active-proof"),
      document_permission_proof_hash: hash("document-permission-proof"),
      expires_event_sequence: 2,
    },
    ciphertext: encodeBase64Url(deterministicBytes("editor-ephemeral-ciphertext", 32)),
    nonce: encodeBase64Url(deterministicBytes("editor-ephemeral-nonce", 24)),
  };
}

function editorEphemeralSessionParamsFixture(
  publicKeyMaterial: AnyHybridSigningPublicKeyMaterial,
): Parameters<typeof buildEditorEphemeralSessionTranscript>[0] {
  return {
    ownerKind: publicKeyMaterial.owner_kind as SigningOwnerKind,
    ownerId: publicKeyMaterial.owner_id,
    workspaceId: testUuid(401),
    documentId: testUuid(423),
    channelId: testUuid(423),
    actorUserId: testUuid(424),
    actorDeviceId: publicKeyMaterial.owner_id,
    signingKeyId: computeSigningKeyId(publicKeyMaterial),
    sessionId: testUuid(425),
    proofDirection: "join",
    proofType: "session_admission",
    sessionNonce: hash("session-nonce"),
    counter: 1,
    expiresEventSequence: 2,
    keyCheckpointSequence: 1,
    keyCheckpointHash: hash("checkpoint"),
    authorityBoundary: {
      workspace_event_head_sequence: 1,
      workspace_event_head_hash: hash("head"),
      actor_active_proof_hash: hash("actor"),
      document_permission_proof_hash: hash("permission"),
    },
  };
}

function hash(label: string): string {
  return blake3Base64Url(enc.encode(label));
}

function testUuid(id: number): string {
  return `00000000-0000-4000-8000-${id.toString().padStart(12, "0")}`;
}

function deterministicBytes(label: string, size: number): Uint8Array {
  const chunks: number[] = [];
  let counter = 0;
  while (chunks.length < size) {
    chunks.push(...blake3(enc.encode(`${label}:${counter}`)));
    counter += 1;
  }
  return new Uint8Array(chunks.slice(0, size));
}

function testPrivateKeyMaterial(): HybridSigningPrivateKeyMaterial {
  const ed25519Private = seed("ed25519-private");
  const ed25519Public = ed25519.getPublicKey(ed25519Private);
  const mldsaKeys = ml_dsa65.keygen(seed("mldsa65-private"));
  return {
    protocol: SIGNING_PRIVATE_KEY_MATERIAL_PROTOCOL,
    version: CURRENT_PROTOCOL_VERSION,
    owner_kind: "device",
    owner_id: TEST_DEVICE_ID,
    ed25519_private: encodeBase64Url(ed25519Private),
    ed25519_public: encodeBase64Url(ed25519Public),
    mldsa65_private: encodeBase64Url(mldsaKeys.secretKey),
    mldsa65_public: encodeBase64Url(mldsaKeys.publicKey),
    suite_id: SUITE_IDS.HYBRID_SIGNATURE,
    suite_rank: CURRENT_SUITE_RANK,
  };
}

function testTranscript(): StrictJsonValue {
  return {
    protocol: SIGNATURE_TRANSCRIPT_PROTOCOL,
    label: SIGNATURE_TRANSCRIPT_LABEL,
    version: CURRENT_PROTOCOL_VERSION,
    transcript_owner: "refmd.pop.request.http_user_device",
    surface_id: "pop_request",
    surface_variant: "http_user_device",
    signing_purpose: "pop_request",
    owner_kind: "device",
    owner_id: TEST_DEVICE_ID,
    signature_suite_id: SUITE_IDS.HYBRID_SIGNATURE,
    signature_suite_rank: CURRENT_SUITE_RANK,
    challenge: "TjFQ5y_BaUt2XlscmYxEEw",
    pop_variant: "http_user_device",
    transport: "http",
    actor: {
      signer_kind: "device",
      device_id: TEST_DEVICE_ID,
      user_id: TEST_USER_ID,
      signing_key_id: computeSigningKeyId(publicKeyMaterialFromPrivate(testPrivateKeyMaterial())),
      key_scope_kind: "user",
      key_scope_id: TEST_USER_ID,
      key_checkpoint_sequence: 1,
      key_checkpoint_hash: blake3Base64Url(new TextEncoder().encode("test-checkpoint")),
    },
    request: {
      body_hash: blake3Base64Url(new Uint8Array()),
      canonical_query: "a=1",
      method: "GET",
      path: "/api/test",
      query_hash: blake3Base64Url(new TextEncoder().encode("a=1")),
    },
    session: {
      is_recovery: false,
      session_id_hash: blake3Base64Url(new TextEncoder().encode("test-session")),
      session_kind: "user",
    },
  };
}

function keyDirectoryEventTranscriptWithNullPreviousHash(): StrictJsonValue {
  const signingKeyId = computeSigningKeyId(publicKeyMaterialFromPrivate(testPrivateKeyMaterial()));
  const eventPayload = {
    protocol: "refmd.key-directory.event",
    version: 1,
    scope_kind: "workspace",
    scope_id: "workspace-1",
    sequence: 2,
    previous_event_hash: blake3Base64Url(enc.encode("previous-event")),
    event_type: "device_key_added",
    actor: {
      signer_kind: "device",
      user_id: TEST_USER_ID,
      device_id: TEST_DEVICE_ID,
      signing_key_id: signingKeyId,
      key_scope_kind: "workspace",
      key_scope_id: "workspace-1",
      key_checkpoint_sequence: 1,
      key_checkpoint_hash: blake3Base64Url(enc.encode("checkpoint")),
    },
    body: {
      user_id: TEST_USER_ID,
      device_id: TEST_DEVICE_ID,
      signing_key_id: signingKeyId,
      encryption_key_id: blake3Base64Url(enc.encode("encryption-key")),
    },
  } as const;

  const transcript = buildKeyDirectoryEventTranscript({
    eventType: "device_key_added",
    ownerKind: "device",
    ownerId: TEST_DEVICE_ID,
    eventPayload: eventPayload as unknown as StrictJsonValue,
  }) as Record<string, unknown>;
  (transcript.event as Record<string, unknown>).previous_event_hash = null;
  return transcript as StrictJsonValue;
}

function keyDirectoryCheckpointTranscriptWithNullPreviousHash(): StrictJsonValue {
  const signingKeyId = computeSigningKeyId(publicKeyMaterialFromPrivate(testPrivateKeyMaterial()));
  const signer = {
    signer_kind: "device",
    user_id: TEST_USER_ID,
    device_id: TEST_DEVICE_ID,
    signing_key_id: signingKeyId,
    authorizing_checkpoint_sequence: 1,
    authorizing_checkpoint_hash: blake3Base64Url(enc.encode("previous-checkpoint")),
  } as const;
  const checkpointPayload = {
    protocol: "refmd.key-directory.checkpoint",
    version: 1,
    scope_kind: "workspace",
    scope_id: "workspace-1",
    sequence: 2,
    previous_checkpoint_hash: blake3Base64Url(enc.encode("previous-checkpoint")),
    covered_event_head: {
      head_sequence: 2,
      head_hash: blake3Base64Url(enc.encode("event-head")),
    },
    allowed_suite_ids: [SUITE_IDS.HYBRID_SIGNATURE],
    min_suite_rank: CURRENT_SUITE_RANK,
    suite_policy_version: 1,
    signer,
  } as const;

  const transcript = buildKeyDirectoryCheckpointTranscript({
    variant: "workspace_authorized",
    ownerKind: "device",
    ownerId: TEST_DEVICE_ID,
    checkpointPayload: checkpointPayload as unknown as StrictJsonValue,
    signer: signer as unknown as StrictJsonValue,
  }) as Record<string, unknown>;
  (transcript.scope as Record<string, unknown>).previous_checkpoint_hash = null;
  return transcript as StrictJsonValue;
}

function seed(label: string): Uint8Array {
  return blake3(enc.encode(`refmd-test:${label}`));
}

function flipBase64UrlByte(value: string): string {
  const bytes = decodeBase64UrlStrict(value);
  bytes[0] = bytes[0]! ^ 1;
  return encodeBase64Url(bytes);
}
