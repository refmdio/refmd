import { ed25519 } from "@noble/curves/ed25519.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";
import { constantTimeEqual, decodeBase64UrlStrict, encodeBase64Url } from "./encoding";
import { assertBlake3Base64Url, blake3Base64Url } from "./hash";
import { canonicalizeStrictBytes, parseJsonStrictBytes, type StrictJsonValue } from "./jcs";
import { assertSigningSurfaceOwner, getActiveSigningSurface } from "./signing-surface";
import { CURRENT_PROTOCOL_VERSION, CURRENT_SUITE_RANK, SUITE_IDS } from "./suite";
import {
  SIGNATURE_TRANSCRIPT_LABEL,
  SIGNATURE_TRANSCRIPT_PROTOCOL,
  transcriptBase,
  type SigningOwnerKind,
} from "./signature-transcript-core";
import type {
  HybridSignature,
  HybridSigningPrivateKeyMaterial,
  HybridSigningPublicKeyMaterial,
  AnyHybridSigningPublicKeyMaterial,
  PersistentSigningOwnerKind,
  ShareCapabilitySigningPublicKeyMaterial,
  SignHybridSignatureParams,
  VerifyHybridSignatureParams,
} from "./signature-types";
import {
  COMMON_TRANSCRIPT_KEYS,
  KEY_DIRECTORY_EVENT_VARIANTS,
  NESTED_OWNER_EXACT_KEYS,
  OWNER_EXACT_PAYLOAD_KEYS,
} from "./signature-transcript-schemas";

export const SIGNATURE_PROTOCOL_ID = "refmd.hybrid-signature";
export const SIGNING_PUBLIC_KEY_MATERIAL_PROTOCOL = "refmd.hybrid-signing-key-material";
export const SIGNING_PRIVATE_KEY_MATERIAL_PROTOCOL = "refmd.hybrid-signing-private-key-material";

export const HYBRID_SIGNATURE_LENGTHS = {
  ED25519_PRIVATE: 32,
  ED25519_PUBLIC: 32,
  ED25519_SIGNATURE: 64,
  MLDSA65_PRIVATE: 4032,
  MLDSA65_PUBLIC: 1952,
  MLDSA65_SIGNATURE: 3309,
} as const;

const MLDSA_CONTEXT_PREFIX = "RefMD:v2:";
const textEncoder = new TextEncoder();

export { KEY_DIRECTORY_EVENT_VARIANTS } from "./signature-transcript-schemas";
export {
  SIGNATURE_TRANSCRIPT_LABEL,
  SIGNATURE_TRANSCRIPT_PROTOCOL,
  collaborationVariant,
  numberValue,
  stringValue,
  type SigningOwnerKind,
} from "./signature-transcript-core";
export type {
  HybridSignature,
  IdentityHybridSigningPublicKeyMaterial,
  DeviceHybridSigningPublicKeyMaterial,
  HybridSigningPrivateKeyMaterial,
  HybridSigningPublicKeyMaterial,
  AnyHybridSigningPublicKeyMaterial,
  ShareCapabilitySigningPublicKeyMaterial,
  SignHybridSignatureParams,
  VerifyHybridSignatureParams,
} from "./signature-types";

export {
  buildDeviceApprovalTranscript,
  buildDeviceRevocationTranscript,
  buildGenesisDeviceBootstrapTranscript,
  buildPopTranscript,
} from "./signature-device-transcripts";
export {
  buildInitialKeyDeliveryTranscript,
  buildInitiatorAkeCommitmentTranscript,
  buildKeyDirectoryCheckpointTranscript,
  buildKeyDirectoryEventTranscript,
  buildPinGossipStatementTranscript,
  buildPqWrapTranscript,
  buildRecipientBoundAuthorizationTranscript,
  buildResponderPrekeyTranscript,
  buildWorkspacePinBootstrapTranscript,
} from "./signature-key-directory-transcripts";
export {
  buildShareCapabilityAuthorizationTranscript,
  buildShareParticipantDeviceAuthorizationTranscript,
} from "./signature-share-transcripts";
export {
  buildDeviceKeyDeletionProofTranscript,
  buildPendingRegistrationBindingHash,
  buildRecoveryAuthorizationProofTranscript,
  buildRecoveryDeviceApprovalTranscript,
  buildRecoverySessionTranscript,
} from "./signature-recovery-transcripts";
export {
  buildDocumentSnapshotTranscript,
  buildDocumentUpdateTranscript,
  buildEditorEphemeralSessionTranscript,
  buildEditorEphemeralTranscript,
} from "./signature-collaboration-transcripts";

export function generateHybridSigningPrivateKeyMaterial(
  ownerKind: PersistentSigningOwnerKind,
  ownerId: string,
): HybridSigningPrivateKeyMaterial {
  assertOwnerKind(ownerKind);
  assertNonEmptyString(ownerId, "owner_id_invalid");
  const ed25519Private = ed25519.utils.randomSecretKey();
  const ed25519Public = ed25519.getPublicKey(ed25519Private);
  const mldsa65Keys = ml_dsa65.keygen();

  return {
    protocol: SIGNING_PRIVATE_KEY_MATERIAL_PROTOCOL,
    version: CURRENT_PROTOCOL_VERSION,
    owner_kind: ownerKind,
    owner_id: ownerId,
    ed25519_private: encodeBase64Url(ed25519Private),
    ed25519_public: encodeBase64Url(ed25519Public),
    mldsa65_private: encodeBase64Url(mldsa65Keys.secretKey),
    mldsa65_public: encodeBase64Url(mldsa65Keys.publicKey),
    suite_id: SUITE_IDS.HYBRID_SIGNATURE,
    suite_rank: CURRENT_SUITE_RANK,
  };
}

export function deriveShareCapabilitySigningPrivateKeyMaterial(
  capabilitySecret: Uint8Array,
  shareTokenHash: string,
): HybridSigningPrivateKeyMaterial {
  if (!(capabilitySecret instanceof Uint8Array) || capabilitySecret.length !== 32) {
    throw new Error("share_capability_secret_required");
  }
  assertBlake3Base64Url(shareTokenHash);

  const ed25519Private = hkdf(
    sha256,
    capabilitySecret,
    new Uint8Array(32),
    textEncoder.encode("RefMD:v2:share-capability-ed25519-seed"),
    32,
  );
  const mldsa65Seed = hkdf(
    sha256,
    capabilitySecret,
    new Uint8Array(32),
    textEncoder.encode("RefMD:v2:share-capability-mldsa65-seed"),
    32,
  );
  const ed25519Public = ed25519.getPublicKey(ed25519Private);
  const mldsa65Keys = ml_dsa65.keygen(mldsa65Seed);

  return {
    protocol: SIGNING_PRIVATE_KEY_MATERIAL_PROTOCOL,
    version: CURRENT_PROTOCOL_VERSION,
    owner_kind: "share_capability",
    owner_id: shareTokenHash,
    ed25519_private: encodeBase64Url(ed25519Private),
    ed25519_public: encodeBase64Url(ed25519Public),
    mldsa65_private: encodeBase64Url(mldsa65Keys.secretKey),
    mldsa65_public: encodeBase64Url(mldsa65Keys.publicKey),
    suite_id: SUITE_IDS.HYBRID_SIGNATURE,
    suite_rank: CURRENT_SUITE_RANK,
  };
}

export function computeSigningKeyId(material: AnyHybridSigningPublicKeyMaterial): string {
  assertHybridSigningPublicKeyMaterial(material);
  return blake3Base64Url(canonicalizeStrictBytes(material as unknown as StrictJsonValue));
}

export function ed25519PublicKeyFromMaterial(material: unknown): Uint8Array {
  assertHybridSigningPublicKeyMaterial(material);
  return decodeBase64UrlStrict(material.ed25519_public, HYBRID_SIGNATURE_LENGTHS.ED25519_PUBLIC);
}

export function publicKeyMaterialFromPrivate(
  material: HybridSigningPrivateKeyMaterial,
): HybridSigningPublicKeyMaterial {
  assertHybridSigningPrivateKeyMaterial(material);
  if (material.owner_kind === "share_capability") {
    throw new Error("persistent_signing_owner_kind_invalid");
  }
  return {
    protocol: SIGNING_PUBLIC_KEY_MATERIAL_PROTOCOL,
    version: CURRENT_PROTOCOL_VERSION,
    owner_kind: material.owner_kind,
    owner_id: material.owner_id,
    ed25519_public: material.ed25519_public,
    mldsa65_public: material.mldsa65_public,
    suite_id: SUITE_IDS.HYBRID_SIGNATURE,
    suite_rank: CURRENT_SUITE_RANK,
  };
}

export function shareCapabilityPublicKeyMaterialFromPrivate(
  material: HybridSigningPrivateKeyMaterial,
): ShareCapabilitySigningPublicKeyMaterial {
  assertHybridSigningPrivateKeyMaterial(material);
  if (material.owner_kind !== "share_capability") {
    throw new Error("share_capability_signing_owner_kind_invalid");
  }
  return {
    protocol: SIGNING_PUBLIC_KEY_MATERIAL_PROTOCOL,
    version: CURRENT_PROTOCOL_VERSION,
    owner_kind: "share_capability",
    owner_id: material.owner_id,
    ed25519_public: material.ed25519_public,
    mldsa65_public: material.mldsa65_public,
    suite_id: SUITE_IDS.HYBRID_SIGNATURE,
    suite_rank: CURRENT_SUITE_RANK,
  };
}

function signHybridSignature({
  signingPurpose,
  transcript,
  privateKeyMaterial,
}: SignHybridSignatureParams): HybridSignature {
  assertSigningPurpose(signingPurpose);
  assertHybridSigningPrivateKeyMaterial(privateKeyMaterial);
  assertTranscript(
    transcript,
    signingPurpose,
    privateKeyMaterial.owner_kind,
    privateKeyMaterial.owner_id,
  );

  const transcriptBytes = canonicalizeStrictBytes(transcript);
  const ed25519Private = decodeBase64UrlStrict(
    privateKeyMaterial.ed25519_private,
    HYBRID_SIGNATURE_LENGTHS.ED25519_PRIVATE,
  );
  const mldsa65Private = decodeBase64UrlStrict(
    privateKeyMaterial.mldsa65_private,
    HYBRID_SIGNATURE_LENGTHS.MLDSA65_PRIVATE,
  );
  const publicKeyMaterial =
    privateKeyMaterial.owner_kind === "share_capability"
      ? shareCapabilityPublicKeyMaterialFromPrivate(privateKeyMaterial)
      : publicKeyMaterialFromPrivate(privateKeyMaterial);

  return {
    protocol: SIGNATURE_PROTOCOL_ID,
    version: CURRENT_PROTOCOL_VERSION,
    suite_id: SUITE_IDS.HYBRID_SIGNATURE,
    suite_rank: CURRENT_SUITE_RANK,
    signing_key_id: computeSigningKeyId(publicKeyMaterial),
    transcript_hash: blake3Base64Url(transcriptBytes),
    ed25519: encodeBase64Url(ed25519.sign(transcriptBytes, ed25519Private)),
    mldsa65: encodeBase64Url(
      ml_dsa65.sign(transcriptBytes, mldsa65Private, { context: mldsaContext(signingPurpose) }),
    ),
  };
}

function verifyHybridSignature(params: VerifyHybridSignatureParams): boolean {
  try {
    assertHybridSignature(params);
    return true;
  } catch {
    return false;
  }
}

function assertHybridSignature({
  signingPurpose,
  transcript,
  signature,
  publicKeyMaterial,
}: VerifyHybridSignatureParams): void {
  assertSigningPurpose(signingPurpose);
  assertHybridSigningPublicKeyMaterial(publicKeyMaterial);
  assertSignatureShape(signature);
  assertTranscript(
    transcript,
    signingPurpose,
    publicKeyMaterial.owner_kind,
    publicKeyMaterial.owner_id,
  );

  const transcriptBytes = canonicalizeStrictBytes(transcript);
  const expectedTranscriptHash = blake3Base64Url(transcriptBytes);
  if (!constantStringEqual(signature.transcript_hash, expectedTranscriptHash)) {
    throw new Error("transcript_hash_mismatch");
  }

  const expectedSigningKeyId = computeSigningKeyId(publicKeyMaterial);
  if (!constantStringEqual(signature.signing_key_id, expectedSigningKeyId)) {
    throw new Error("signing_key_id_mismatch");
  }

  const ed25519Public = decodeBase64UrlStrict(
    publicKeyMaterial.ed25519_public,
    HYBRID_SIGNATURE_LENGTHS.ED25519_PUBLIC,
  );
  const mldsa65Public = decodeBase64UrlStrict(
    publicKeyMaterial.mldsa65_public,
    HYBRID_SIGNATURE_LENGTHS.MLDSA65_PUBLIC,
  );
  const ed25519Signature = decodeBase64UrlStrict(
    signature.ed25519,
    HYBRID_SIGNATURE_LENGTHS.ED25519_SIGNATURE,
  );
  const mldsa65Signature = decodeBase64UrlStrict(
    signature.mldsa65,
    HYBRID_SIGNATURE_LENGTHS.MLDSA65_SIGNATURE,
  );

  if (!ed25519.verify(ed25519Signature, transcriptBytes, ed25519Public)) {
    throw new Error("ed25519_signature_invalid");
  }
  if (
    !ml_dsa65.verify(mldsa65Signature, transcriptBytes, mldsa65Public, {
      context: mldsaContext(signingPurpose),
    })
  ) {
    throw new Error("mldsa65_signature_invalid");
  }
}

type SignSurfaceSignatureParams = Omit<SignHybridSignatureParams, "signingPurpose">;
type VerifySurfaceSignatureParams = Omit<VerifyHybridSignatureParams, "signingPurpose">;

function signSurfaceSignature(
  signingPurpose: string,
  params: SignSurfaceSignatureParams,
): HybridSignature {
  return signHybridSignature({ signingPurpose, ...params });
}

function verifySurfaceSignature(
  signingPurpose: string,
  params: VerifySurfaceSignatureParams,
): boolean {
  return verifyHybridSignature({ signingPurpose, ...params });
}

export function createPopRequestSignature(params: SignSurfaceSignatureParams): HybridSignature {
  return signSurfaceSignature("pop_request", params);
}

export function verifyPopRequestSignature(params: VerifySurfaceSignatureParams): boolean {
  return verifySurfaceSignature("pop_request", params);
}

export function signDocumentUpdateSignature(params: SignSurfaceSignatureParams): HybridSignature {
  return signSurfaceSignature("document_update", params);
}

export function verifyDocumentUpdateSignature(params: VerifySurfaceSignatureParams): boolean {
  return verifySurfaceSignature("document_update", params);
}

export function signDocumentSnapshotSignature(params: SignSurfaceSignatureParams): HybridSignature {
  return signSurfaceSignature("document_snapshot", params);
}

export function verifyDocumentSnapshotSignature(params: VerifySurfaceSignatureParams): boolean {
  return verifySurfaceSignature("document_snapshot", params);
}

export function signEditorEphemeralSignature(params: SignSurfaceSignatureParams): HybridSignature {
  return signSurfaceSignature("editor_ephemeral", params);
}

export function verifyEditorEphemeralSignature(params: VerifySurfaceSignatureParams): boolean {
  return verifySurfaceSignature("editor_ephemeral", params);
}

export function signEditorEphemeralSessionSignature(
  params: SignSurfaceSignatureParams,
): HybridSignature {
  return signSurfaceSignature("editor_ephemeral_session", params);
}

export function verifyEditorEphemeralSessionSignature(
  params: VerifySurfaceSignatureParams,
): boolean {
  return verifySurfaceSignature("editor_ephemeral_session", params);
}

export function signGenesisDeviceBootstrapSignature(
  params: SignSurfaceSignatureParams,
): HybridSignature {
  return signSurfaceSignature("genesis_device_bootstrap", params);
}

export function verifyGenesisDeviceBootstrapSignature(
  params: VerifySurfaceSignatureParams,
): boolean {
  return verifySurfaceSignature("genesis_device_bootstrap", params);
}

export function createDeviceApprovalSignature(params: SignSurfaceSignatureParams): HybridSignature {
  return signSurfaceSignature("device_approval", params);
}

export function verifyDeviceApprovalSignature(params: VerifySurfaceSignatureParams): boolean {
  return verifySurfaceSignature("device_approval", params);
}

export function buildPluginBundleApprovalTranscript(params: {
  actor: StrictJsonValue;
  approval: StrictJsonValue;
}): StrictJsonValue {
  const actor = assertStrictRecord(params.actor, "plugin_bundle_approval_actor_invalid");
  const approval = assertStrictRecord(params.approval, "plugin_bundle_approval_subject_invalid");
  assertPluginActorOwnerScope(actor, approval, "plugin_bundle_approval_actor_invalid");
  const ownerId = stringRecordValue(actor, "device_id", "plugin_bundle_approval_actor_invalid");
  const surface = getActiveSigningSurface("plugin_bundle_approval", "none");

  return transcriptBase("plugin_bundle_approval", surface, "device", ownerId, {
    subject_hash: blake3Base64Url(canonicalizeStrictBytes(approval)),
    subject_protocol: "refmd.plugin-bundle-approval",
    subject_version: CURRENT_PROTOCOL_VERSION,
    actor,
    approval,
  });
}

export function verifyPluginBundleApprovalSignature(params: VerifySurfaceSignatureParams): boolean {
  return verifySurfaceSignature("plugin_bundle_approval", params);
}

export function signPluginBundleApprovalSignature(
  params: SignSurfaceSignatureParams,
): HybridSignature {
  return signSurfaceSignature("plugin_bundle_approval", params);
}

export function buildPluginConsentEventTranscript(params: {
  actor: StrictJsonValue;
  consent: StrictJsonValue;
}): StrictJsonValue {
  const actor = assertStrictRecord(params.actor, "plugin_consent_event_actor_invalid");
  const consent = assertStrictRecord(params.consent, "plugin_consent_event_subject_invalid");
  assertPluginActorWorkspaceScope(actor, consent, "plugin_consent_event_actor_invalid");
  assertPluginConsentActorSubjectBinding(actor, consent, "plugin_consent_event_actor_invalid");
  const ownerId = stringRecordValue(actor, "device_id", "plugin_consent_event_actor_invalid");
  const surface = getActiveSigningSurface("plugin_consent_event", "none");

  return transcriptBase("plugin_consent_event", surface, "device", ownerId, {
    subject_hash: blake3Base64Url(canonicalizeStrictBytes(consent)),
    subject_protocol: "refmd.plugin-consent-event",
    subject_version: CURRENT_PROTOCOL_VERSION,
    actor,
    consent,
  });
}

export function verifyPluginConsentEventSignature(params: VerifySurfaceSignatureParams): boolean {
  return verifySurfaceSignature("plugin_consent_event", params);
}

export function signPluginConsentEventSignature(
  params: SignSurfaceSignatureParams,
): HybridSignature {
  return signSurfaceSignature("plugin_consent_event", params);
}

export function buildPluginNetworkProxyRequestTranscript(params: {
  subject: StrictJsonValue;
}): StrictJsonValue {
  const subject = assertStrictRecord(
    params.subject,
    "plugin_network_proxy_request_subject_invalid",
  );
  assertPluginNetworkProxyRequestSubject(subject, "plugin_network_proxy_request_subject_invalid");
  const runtime = assertStrictRecord(
    subject.runtime,
    "plugin_network_proxy_request_subject_invalid",
  );
  const ownerId = stringRecordValue(
    runtime,
    "device_id",
    "plugin_network_proxy_request_subject_invalid",
  );
  const surface = getActiveSigningSurface("plugin_network_proxy_request", "none");

  return transcriptBase("plugin_network_proxy_request", surface, "device", ownerId, {
    subject_hash: blake3Base64Url(canonicalizeStrictBytes(subject)),
    subject_protocol: "refmd.plugin-network-proxy-request-subject",
    subject_version: CURRENT_PROTOCOL_VERSION,
    subject,
  });
}

export function verifyPluginNetworkProxyRequestSignature(
  params: VerifySurfaceSignatureParams,
): boolean {
  return verifySurfaceSignature("plugin_network_proxy_request", params);
}

export function signPluginNetworkProxyRequestSignature(
  params: SignSurfaceSignatureParams,
): HybridSignature {
  return signSurfaceSignature("plugin_network_proxy_request", params);
}

export function signRecoveryDeviceApprovalSignature(
  params: SignSurfaceSignatureParams,
): HybridSignature {
  return signSurfaceSignature("recovery_device_approval", params);
}

export function verifyRecoveryDeviceApprovalSignature(
  params: VerifySurfaceSignatureParams,
): boolean {
  return verifySurfaceSignature("recovery_device_approval", params);
}

export function createDeviceRevocationSignature(
  params: SignSurfaceSignatureParams,
): HybridSignature {
  return signSurfaceSignature("device_revocation", params);
}

export function verifyDeviceRevocationSignature(params: VerifySurfaceSignatureParams): boolean {
  return verifySurfaceSignature("device_revocation", params);
}

export function signDeviceKeyDeletionProofSignature(
  params: SignSurfaceSignatureParams,
): HybridSignature {
  return signSurfaceSignature("device_key_deletion_proof", params);
}

export function verifyDeviceKeyDeletionProofSignature(
  params: VerifySurfaceSignatureParams,
): boolean {
  return verifySurfaceSignature("device_key_deletion_proof", params);
}

export function signKeyDirectoryCheckpointSignature(
  params: SignSurfaceSignatureParams,
): HybridSignature {
  return signSurfaceSignature("key_directory_checkpoint", params);
}

export function verifyKeyDirectoryCheckpointSignature(
  params: VerifySurfaceSignatureParams,
): boolean {
  return verifySurfaceSignature("key_directory_checkpoint", params);
}

export function signKeyDirectoryEventSignature(
  params: SignSurfaceSignatureParams,
): HybridSignature {
  return signSurfaceSignature("key_directory_event", params);
}

export function verifyKeyDirectoryEventSignature(params: VerifySurfaceSignatureParams): boolean {
  return verifySurfaceSignature("key_directory_event", params);
}

export function signWorkspacePinBootstrapSignature(
  params: SignSurfaceSignatureParams,
): HybridSignature {
  return signSurfaceSignature("workspace_pin_bootstrap", params);
}

export function verifyWorkspacePinBootstrapSignature(
  params: VerifySurfaceSignatureParams,
): boolean {
  return verifySurfaceSignature("workspace_pin_bootstrap", params);
}

export function signPinGossipStatementSignature(
  params: SignSurfaceSignatureParams,
): HybridSignature {
  return signSurfaceSignature("pin_gossip_statement", params);
}

export function verifyPinGossipStatementSignature(params: VerifySurfaceSignatureParams): boolean {
  return verifySurfaceSignature("pin_gossip_statement", params);
}

export function signRecipientBoundAuthorizationSignature(
  params: SignSurfaceSignatureParams,
): HybridSignature {
  return signSurfaceSignature("recipient_bound_authorization", params);
}

export function verifyRecipientBoundAuthorizationSignature(
  params: VerifySurfaceSignatureParams,
): boolean {
  return verifySurfaceSignature("recipient_bound_authorization", params);
}

export function signRecoverySessionSignature(params: SignSurfaceSignatureParams): HybridSignature {
  return signSurfaceSignature("recovery_session", params);
}

export function verifyRecoverySessionSignature(params: VerifySurfaceSignatureParams): boolean {
  return verifySurfaceSignature("recovery_session", params);
}

export function signRecoveryAuthorizationProofSignature(
  params: SignSurfaceSignatureParams,
): HybridSignature {
  return signSurfaceSignature("recovery_authorization_proof", params);
}

export function verifyRecoveryAuthorizationProofSignature(
  params: VerifySurfaceSignatureParams,
): boolean {
  return verifySurfaceSignature("recovery_authorization_proof", params);
}

export function signPqWrapSignature(params: SignSurfaceSignatureParams): HybridSignature {
  return signSurfaceSignature("pq_wrap", params);
}

export function verifyPqWrapSignature(params: VerifySurfaceSignatureParams): boolean {
  return verifySurfaceSignature("pq_wrap", params);
}

export function signResponderPrekeySignature(params: SignSurfaceSignatureParams): HybridSignature {
  return signSurfaceSignature("responder_prekey", params);
}

export function verifyResponderPrekeySignature(params: VerifySurfaceSignatureParams): boolean {
  return verifySurfaceSignature("responder_prekey", params);
}

export function signInitiatorAkeCommitmentSignature(
  params: SignSurfaceSignatureParams,
): HybridSignature {
  return signSurfaceSignature("initiator_ake_commitment", params);
}

export function verifyInitiatorAkeCommitmentSignature(
  params: VerifySurfaceSignatureParams,
): boolean {
  return verifySurfaceSignature("initiator_ake_commitment", params);
}

export function signInitialKeyDeliverySignature(
  params: SignSurfaceSignatureParams,
): HybridSignature {
  return signSurfaceSignature("initial_key_delivery", params);
}

export function verifyInitialKeyDeliverySignature(params: VerifySurfaceSignatureParams): boolean {
  return verifySurfaceSignature("initial_key_delivery", params);
}

export function signShareCapabilityAuthorizationSignature(
  params: SignSurfaceSignatureParams,
): HybridSignature {
  return signSurfaceSignature("share_capability_authorization", params);
}

export function verifyShareCapabilityAuthorizationSignature(
  params: VerifySurfaceSignatureParams,
): boolean {
  return verifySurfaceSignature("share_capability_authorization", params);
}

export function signShareParticipantDeviceAuthorizationSignature(
  params: SignSurfaceSignatureParams,
): HybridSignature {
  return signSurfaceSignature("share_participant_device_authorization", params);
}

export function verifyShareParticipantDeviceAuthorizationSignature(
  params: VerifySurfaceSignatureParams,
): boolean {
  return verifySurfaceSignature("share_participant_device_authorization", params);
}

export function encodeHybridSignatureForTransport(signature: HybridSignature): string {
  assertSignatureShape(signature);
  return encodeBase64Url(canonicalizeStrictBytes(signature as unknown as StrictJsonValue));
}

export function decodeHybridSignatureFromTransport(encoded: string): HybridSignature {
  const decodedBytes = decodeBase64UrlStrict(encoded);
  const decoded = parseJsonStrictBytes(decodedBytes);
  if (!constantTimeEqual(decodedBytes, canonicalizeStrictBytes(decoded))) {
    throw new Error("non_canonical_signature_transport");
  }
  assertSignatureShape(decoded);
  return decoded;
}

export function assertHybridSigningPublicKeyMaterial(
  material: unknown,
): asserts material is AnyHybridSigningPublicKeyMaterial {
  assertPlainObject(material, "public_key_material_not_object");
  assertExactKeys(material, [
    "ed25519_public",
    "mldsa65_public",
    "owner_id",
    "owner_kind",
    "protocol",
    "suite_id",
    "suite_rank",
    "version",
  ]);
  assertLiteral(
    material.protocol,
    SIGNING_PUBLIC_KEY_MATERIAL_PROTOCOL,
    "public_key_protocol_invalid",
  );
  assertProtocolVersionField(material.version);
  assertOwnerKind(material.owner_kind);
  assertNonEmptyString(material.owner_id, "owner_id_invalid");
  assertSuiteFields(material.suite_id, material.suite_rank);
  assertNonEmptyString(material.ed25519_public, "ed25519_public_invalid");
  assertNonEmptyString(material.mldsa65_public, "mldsa65_public_invalid");
  decodeBase64UrlStrict(material.ed25519_public, HYBRID_SIGNATURE_LENGTHS.ED25519_PUBLIC);
  decodeBase64UrlStrict(material.mldsa65_public, HYBRID_SIGNATURE_LENGTHS.MLDSA65_PUBLIC);
}

export function assertHybridSigningPrivateKeyMaterial(
  material: unknown,
): asserts material is HybridSigningPrivateKeyMaterial {
  assertPlainObject(material, "private_key_material_not_object");
  assertExactKeys(material, [
    "ed25519_private",
    "ed25519_public",
    "mldsa65_private",
    "mldsa65_public",
    "owner_id",
    "owner_kind",
    "protocol",
    "suite_id",
    "suite_rank",
    "version",
  ]);
  assertLiteral(
    material.protocol,
    SIGNING_PRIVATE_KEY_MATERIAL_PROTOCOL,
    "private_key_protocol_invalid",
  );
  assertProtocolVersionField(material.version);
  assertOwnerKind(material.owner_kind);
  assertNonEmptyString(material.owner_id, "owner_id_invalid");
  assertSuiteFields(material.suite_id, material.suite_rank);
  assertNonEmptyString(material.ed25519_private, "ed25519_private_invalid");
  assertNonEmptyString(material.ed25519_public, "ed25519_public_invalid");
  assertNonEmptyString(material.mldsa65_private, "mldsa65_private_invalid");
  assertNonEmptyString(material.mldsa65_public, "mldsa65_public_invalid");

  const ed25519Private = decodeBase64UrlStrict(
    material.ed25519_private,
    HYBRID_SIGNATURE_LENGTHS.ED25519_PRIVATE,
  );
  const ed25519Public = decodeBase64UrlStrict(
    material.ed25519_public,
    HYBRID_SIGNATURE_LENGTHS.ED25519_PUBLIC,
  );
  const mldsa65Private = decodeBase64UrlStrict(
    material.mldsa65_private,
    HYBRID_SIGNATURE_LENGTHS.MLDSA65_PRIVATE,
  );
  const mldsa65Public = decodeBase64UrlStrict(
    material.mldsa65_public,
    HYBRID_SIGNATURE_LENGTHS.MLDSA65_PUBLIC,
  );

  if (!constantTimeEqual(ed25519.getPublicKey(ed25519Private), ed25519Public)) {
    throw new Error("ed25519_private_public_mismatch");
  }
  if (!constantTimeEqual(ml_dsa65.getPublicKey(mldsa65Private), mldsa65Public)) {
    throw new Error("mldsa65_private_public_mismatch");
  }
}

export function assertSignatureShape(signature: unknown): asserts signature is HybridSignature {
  assertPlainObject(signature, "signature_not_object");
  assertExactKeys(signature, [
    "ed25519",
    "mldsa65",
    "protocol",
    "signing_key_id",
    "suite_id",
    "suite_rank",
    "transcript_hash",
    "version",
  ]);
  assertLiteral(signature.protocol, SIGNATURE_PROTOCOL_ID, "signature_protocol_invalid");
  assertProtocolVersionField(signature.version);
  assertSuiteFields(signature.suite_id, signature.suite_rank);
  assertNonEmptyString(signature.signing_key_id, "signing_key_id_invalid");
  assertNonEmptyString(signature.transcript_hash, "transcript_hash_invalid");
  assertNonEmptyString(signature.ed25519, "ed25519_signature_invalid");
  assertNonEmptyString(signature.mldsa65, "mldsa65_signature_invalid");
  assertBlake3Base64Url(signature.signing_key_id);
  assertBlake3Base64Url(signature.transcript_hash);
  decodeBase64UrlStrict(signature.ed25519, HYBRID_SIGNATURE_LENGTHS.ED25519_SIGNATURE);
  decodeBase64UrlStrict(signature.mldsa65, HYBRID_SIGNATURE_LENGTHS.MLDSA65_SIGNATURE);
}

export function assertTranscript(
  transcript: StrictJsonValue,
  signingPurpose: string,
  ownerKind: SigningOwnerKind,
  ownerId: string,
): void {
  assertPlainObject(transcript, "transcript_not_object");
  if (transcript.protocol !== SIGNATURE_TRANSCRIPT_PROTOCOL) {
    throw new Error("transcript_protocol_invalid");
  }
  if (transcript.label !== SIGNATURE_TRANSCRIPT_LABEL) {
    throw new Error("transcript_label_invalid");
  }
  assertProtocolVersionField(transcript.version);
  if (transcript.signing_purpose !== signingPurpose) {
    throw new Error("signing_purpose_mismatch");
  }
  if (typeof transcript.surface_variant !== "string") {
    throw new Error("surface_variant_invalid");
  }
  const surface = getActiveSigningSurface(signingPurpose, transcript.surface_variant);
  assertSigningSurfaceOwner(surface, ownerKind);
  if (transcript.transcript_owner !== surface.transcript_owner) {
    throw new Error("transcript_owner_mismatch");
  }
  if (transcript.surface_id !== surface.surface_id) {
    throw new Error("surface_id_mismatch");
  }
  if (transcript.surface_variant !== surface.variant) {
    throw new Error("surface_variant_mismatch");
  }
  if (transcript.owner_kind !== ownerKind) {
    throw new Error("owner_kind_mismatch");
  }
  if (transcript.owner_id !== ownerId) {
    throw new Error("owner_id_mismatch");
  }
  assertCanonicalOwnerId(ownerKind, ownerId);
  assertSuiteFields(transcript.signature_suite_id, transcript.signature_suite_rank);
  assertOwnerExactTranscriptPayload(transcript, surface.signing_purpose, surface.variant);
  canonicalizeStrictBytes(transcript);
}

function assertOwnerExactTranscriptPayload(
  transcript: Record<string, unknown>,
  signingPurpose: string,
  variant: string,
): void {
  const payloadKeys = ownerExactPayloadKeys(signingPurpose, variant);
  assertExactKeys(transcript, [...COMMON_TRANSCRIPT_KEYS, ...payloadKeys]);
  assertTopLevelOwnerExactFieldValues(transcript, payloadKeys, signingPurpose, variant);

  if ("subject_hash" in transcript) {
    assertNonEmptyString(transcript.subject_hash, "subject_hash_invalid");
    assertBlake3Base64Url(transcript.subject_hash);
  }
  if ("subject_protocol" in transcript) {
    assertNonEmptyString(transcript.subject_protocol, "subject_protocol_invalid");
  }
  if ("subject_version" in transcript && transcript.subject_version !== CURRENT_PROTOCOL_VERSION) {
    throw new Error("subject_version_invalid");
  }
  if (signingPurpose === "plugin_network_proxy_request") {
    const subject = assertStrictRecord(
      transcript.subject as StrictJsonValue,
      "plugin_network_proxy_request_subject_invalid",
    );
    assertPluginNetworkProxyRequestSubject(subject, "plugin_network_proxy_request_subject_invalid");
  }
  if (signingPurpose === "pop_request") {
    assertNonEmptyString(transcript.challenge, "challenge_invalid");
    if (transcript.pop_variant !== variant) {
      throw new Error("pop_variant_mismatch");
    }
    const expectedTransport = variant.startsWith("channel_") ? "phoenix_channel" : "http";
    if (transcript.transport !== expectedTransport) {
      throw new Error("pop_transport_mismatch");
    }
  }
  assertNestedOwnerExactFields(transcript, signingPurpose, variant);
}

function assertTopLevelOwnerExactFieldValues(
  transcript: Record<string, unknown>,
  payloadKeys: readonly string[],
  signingPurpose: string,
  variant: string,
): void {
  const nested = nestedOwnerExactFields(signingPurpose, variant);
  const nestedFields = new Set(Object.keys(nested));

  for (const key of payloadKeys) {
    if (nestedFields.has(key)) continue;
    assertTopLevelOwnerExactFieldValue(key, transcript[key]);
  }
}

function assertTopLevelOwnerExactFieldValue(key: string, value: unknown): void {
  const error = `${key}_invalid`;

  if (key === "subject_protocol") {
    assertNonEmptyString(value, "subject_protocol_invalid");
    return;
  }
  if (key === "subject_version") {
    if (value !== CURRENT_PROTOCOL_VERSION) throw new Error("subject_version_invalid");
    return;
  }
  if (key === "password_protected") {
    if (typeof value !== "boolean") throw new Error(error);
    return;
  }
  if (key.endsWith("_hash")) {
    assertNonEmptyString(value, error);
    assertBlake3Base64Url(value);
    return;
  }
  if (key.endsWith("_sequence") || key.endsWith("_version") || key.endsWith("_rank")) {
    if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 1) {
      throw new Error(error);
    }
    return;
  }
  if (isPlainObject(value)) {
    canonicalizeStrictBytes(value as StrictJsonValue);
    return;
  }
  if (Array.isArray(value)) {
    canonicalizeStrictBytes({ value } as StrictJsonValue);
    return;
  }
  assertNonEmptyString(value, error);
}

function ownerExactPayloadKeys(signingPurpose: string, variant: string): readonly string[] {
  const payloadKeys = OWNER_EXACT_PAYLOAD_KEYS[`${signingPurpose}:${variant}`];
  if (payloadKeys) return payloadKeys;
  if (
    signingPurpose === "key_directory_event" &&
    KEY_DIRECTORY_EVENT_VARIANTS.includes(variant as (typeof KEY_DIRECTORY_EVENT_VARIANTS)[number])
  ) {
    return [
      "actor",
      "authority_boundary",
      "event",
      "subject_hash",
      "subject_protocol",
      "subject_version",
    ];
  }
  if (signingPurpose === "document_snapshot") {
    return [
      "actor",
      "authority_boundary",
      "ciphertext_hash",
      "document_id",
      "nonce",
      "public_data",
      "snapshot_id",
      "subject_hash",
      "subject_protocol",
      "subject_version",
    ];
  }
  if (signingPurpose === "document_update") {
    return [
      "actor",
      "authority_boundary",
      "ciphertext_hash",
      "document_id",
      "nonce",
      "public_data",
      "subject_hash",
      "subject_protocol",
      "subject_version",
    ];
  }
  if (signingPurpose === "editor_ephemeral") {
    return [
      "actor",
      "authority_boundary",
      "session",
      "subject_hash",
      "subject_protocol",
      "subject_version",
    ];
  }
  if (signingPurpose === "editor_ephemeral_session") {
    return [
      "actor",
      "capabilities",
      "session",
      "subject_hash",
      "subject_protocol",
      "subject_version",
    ];
  }
  throw new Error(`owner_exact_schema_missing:${signingPurpose}:${variant}`);
}

function assertNestedOwnerExactFields(
  transcript: Record<string, unknown>,
  signingPurpose: string,
  variant: string,
): void {
  const nested = nestedOwnerExactFields(signingPurpose, variant);

  for (const [field, keys] of Object.entries(nested)) {
    const value = transcript[field];
    assertPlainObject(value, `${field}_invalid`);
    assertExactKeys(value, nestedExpectedKeys(transcript, field, value, [...keys]));
    assertNestedFieldValues(field, value);
  }
}

function nestedOwnerExactFields(
  signingPurpose: string,
  variant: string,
): Record<string, readonly string[]> {
  return (
    NESTED_OWNER_EXACT_KEYS[`${signingPurpose}:${variant}`] ??
    NESTED_OWNER_EXACT_KEYS[`${signingPurpose}:*`] ??
    {}
  );
}

function nestedExpectedKeys(
  transcript: Record<string, unknown>,
  field: string,
  value: Record<string, unknown>,
  keys: string[],
): string[] {
  if (field === "scope" && isInitialKeyDirectoryCheckpoint(transcript)) {
    return keys.filter((key) => key !== "previous_checkpoint_hash");
  }
  if (field === "authority_boundary" && isInitialKeyDirectoryCheckpoint(transcript)) {
    return keys.filter(
      (key) => key !== "authorizing_checkpoint_sequence" && key !== "authorizing_checkpoint_hash",
    );
  }
  if (
    field === "authority_boundary" &&
    transcript.surface_id === "key_directory_checkpoint" &&
    value.required_authority === "invitation_redeem_authority"
  ) {
    return ["invitation_id", "required_authority"];
  }
  if (field === "event" && isInitialKeyDirectoryEvent(transcript)) {
    return keys.filter((key) => key !== "previous_event_hash");
  }
  if (
    field === "authority_boundary" &&
    isInitialKeyDirectoryEvent(transcript) &&
    value.required_authority === "tofu_root"
  ) {
    return ["required_authority"];
  }
  if (
    field === "authority_boundary" &&
    transcript.surface_id === "key_directory_event" &&
    value.required_authority === "invitation_redeem_authority"
  ) {
    return ["event_type", "invitation_id", "required_authority"];
  }
  if (
    field === "approval" &&
    transcript.surface_id === "plugin_bundle_approval" &&
    value.owner_scope_kind === "workspace"
  ) {
    return keys.filter((key) => key !== "owner_user_id");
  }
  if (
    field === "approval" &&
    transcript.surface_id === "plugin_bundle_approval" &&
    value.owner_scope_kind === "user"
  ) {
    return keys.filter(
      (key) =>
        key !== "application_scope_kind" && key !== "owner_workspace_id" && key !== "workspace_id",
    );
  }
  if (
    (field === "signer" || field === "actor") &&
    (transcript.surface_id === "key_directory_checkpoint" ||
      transcript.surface_id === "key_directory_event")
  ) {
    return keyDirectorySignerKeys(value);
  }
  return keys;
}

function keyDirectorySignerKeys(value: Record<string, unknown>): string[] {
  const checkpointKeys = [
    "key_scope_kind",
    "key_scope_id",
    "key_checkpoint_sequence",
    "key_checkpoint_hash",
    "authorizing_checkpoint_sequence",
    "authorizing_checkpoint_hash",
    "role_at_event",
  ].filter((key) => key in value);

  switch (value.signer_kind) {
    case "identity":
      return [...checkpointKeys, "signer_kind", "signing_key_id", "user_id"].sort();
    case "device":
      return [...checkpointKeys, "device_id", "signer_kind", "signing_key_id", "user_id"].sort();
    case "share_participant_device":
      if ("share_participant_device_id" in value || "share_participant_principal_id" in value) {
        return [
          ...checkpointKeys,
          "share_id",
          "share_participant_device_id",
          "share_participant_principal_id",
          "signer_kind",
          "signing_key_id",
        ].sort();
      }
      return [
        ...checkpointKeys,
        "device_id",
        "principal_id",
        "signer_kind",
        "signing_key_id",
      ].sort();
    case "invitation_redeem_authority":
      return [...checkpointKeys, "invitation_id", "signer_kind", "signing_key_id"].sort();
    default:
      throw new Error("signer_kind_invalid");
  }
}

function isInitialKeyDirectoryCheckpoint(transcript: Record<string, unknown>): boolean {
  if (transcript.surface_id !== "key_directory_checkpoint") return false;
  const scope = transcript.scope as Record<string, unknown> | undefined;
  return scope?.checkpoint_sequence === 1;
}

function isInitialKeyDirectoryEvent(transcript: Record<string, unknown>): boolean {
  if (transcript.surface_id !== "key_directory_event") return false;
  const event = transcript.event as Record<string, unknown> | undefined;
  return event?.sequence === 1;
}

function assertNestedFieldValues(field: string, value: Record<string, unknown>): void {
  for (const [key, nestedValue] of Object.entries(value)) {
    if ((field === "resource" || field === "request") && key === "canonical_query") {
      if (typeof nestedValue !== "string") {
        throw new Error(`${field}_${key}_invalid`);
      }
    } else if (key.startsWith("previous_") && key.endsWith("_hash") && nestedValue === "GENESIS") {
      continue;
    } else if (key === "source_url_hash" && nestedValue === "NO_SOURCE_URL") {
      continue;
    } else if (key.endsWith("_hash") || publicDataBlake3Field(field, key)) {
      assertNonEmptyString(nestedValue, `${field}_${key}_invalid`);
      assertBlake3Base64Url(nestedValue);
    } else if (
      key.endsWith("_sequence") ||
      key.endsWith("_epoch") ||
      key === "sequence" ||
      key === "counter" ||
      key.endsWith("_counter") ||
      key.endsWith("_version") ||
      key === "created_at_ms" ||
      key === "min_suite_rank" ||
      publicDataPositiveIntegerField(field, key)
    ) {
      if (typeof nestedValue !== "number") {
        throw new Error(`${field}_${key}_invalid`);
      }
      if (!Number.isSafeInteger(nestedValue) || nestedValue < 1) {
        throw new Error(`${field}_${key}_invalid`);
      }
    } else if (field === "public_data" && key === "clock") {
      if (typeof nestedValue !== "number") {
        throw new Error(`${field}_${key}_invalid`);
      }
      if (!Number.isSafeInteger(nestedValue) || nestedValue < 0) {
        throw new Error(`${field}_${key}_invalid`);
      }
    } else if (field === "public_data" && key === "parentSnapshotUpdateClocks") {
      assertPlainObject(nestedValue, `${field}_${key}_invalid`);
      canonicalizeStrictBytes(nestedValue as StrictJsonValue);
    } else if (field === "pin_gossip" && key === "statement") {
      assertPlainObject(nestedValue, `${field}_${key}_invalid`);
      canonicalizeStrictBytes(nestedValue as StrictJsonValue);
    } else if (key.endsWith("_material")) {
      assertPlainObject(nestedValue, `${field}_${key}_invalid`);
      canonicalizeStrictBytes(nestedValue as StrictJsonValue);
    } else if (key === "password_protected" || key === "is_recovery") {
      if (typeof nestedValue !== "boolean") {
        throw new Error(`${field}_${key}_invalid`);
      }
    } else {
      assertNonEmptyString(nestedValue, `${field}_${key}_invalid`);
    }
  }
}

function publicDataBlake3Field(field: string, key: string): boolean {
  return field === "public_data" && (key === "keyCheckpointHash" || key === "updateHash");
}

function publicDataPositiveIntegerField(field: string, key: string): boolean {
  return (
    field === "public_data" &&
    (key === "authorityPermissionVersion" ||
      key === "keyCheckpointSequence" ||
      key === "keyVersion" ||
      key === "minDekVersion" ||
      key === "writeSessionCounter" ||
      key === "timestamp")
  );
}

function assertSuiteFields(suiteId: unknown, suiteRank: unknown): void {
  if (suiteId !== SUITE_IDS.HYBRID_SIGNATURE) throw new Error("signature_suite_id_invalid");
  if (suiteRank !== CURRENT_SUITE_RANK) throw new Error("signature_suite_rank_invalid");
}

function assertProtocolVersionField(version: unknown): void {
  if (version !== CURRENT_PROTOCOL_VERSION) throw new Error("signature_protocol_version_invalid");
}

function assertOwnerKind(value: unknown): asserts value is SigningOwnerKind {
  if (
    value !== "identity" &&
    value !== "device" &&
    value !== "share_capability" &&
    value !== "share_participant_device" &&
    value !== "invitation_redeem_authority"
  ) {
    throw new Error("owner_kind_invalid");
  }
}

function assertCanonicalOwnerId(ownerKind: SigningOwnerKind, ownerId: string): void {
  if (
    (ownerKind === "identity" ||
      ownerKind === "device" ||
      ownerKind === "share_participant_device" ||
      ownerKind === "invitation_redeem_authority") &&
    !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(ownerId)
  ) {
    throw new Error("owner_id_invalid");
  }
}

function assertSigningPurpose(value: unknown): asserts value is string {
  if (typeof value !== "string") {
    throw new Error("signing_purpose_invalid");
  }
  if (!/^[a-z][a-z0-9_]{0,63}$/.test(value)) {
    throw new Error("signing_purpose_invalid");
  }
}

function assertNonEmptyString(value: unknown, error: string): asserts value is string {
  if (typeof value !== "string" || value.length === 0) throw new Error(error);
}

function assertLiteral(value: unknown, expected: string, error: string): void {
  if (value !== expected) throw new Error(error);
}

function assertPlainObject(
  value: unknown,
  error: string,
): asserts value is Record<string, unknown> {
  if (!isPlainObject(value)) {
    throw new Error(error);
  }
}

function assertStrictRecord(
  value: StrictJsonValue,
  error: string,
): Record<string, StrictJsonValue> {
  assertPlainObject(value, error);
  return value as Record<string, StrictJsonValue>;
}

function stringRecordValue(
  value: Record<string, StrictJsonValue>,
  key: string,
  error: string,
): string {
  const result = value[key];
  if (typeof result !== "string" || result.length === 0) throw new Error(error);
  return result;
}

function stringPresentRecordValue(
  value: Record<string, StrictJsonValue>,
  key: string,
  error: string,
): string {
  const result = value[key];
  if (typeof result !== "string") throw new Error(error);
  return result;
}

function positiveIntegerRecordValue(
  value: Record<string, StrictJsonValue>,
  key: string,
  error: string,
): number {
  const result = value[key];
  if (typeof result !== "number" || !Number.isSafeInteger(result) || result < 1) {
    throw new Error(error);
  }
  return result;
}

function booleanRecordValue(
  value: Record<string, StrictJsonValue>,
  key: string,
  error: string,
): boolean {
  const result = value[key];
  if (typeof result !== "boolean") throw new Error(error);
  return result;
}

function strictRecordValue(
  value: Record<string, StrictJsonValue>,
  key: string,
  error: string,
): Record<string, StrictJsonValue> {
  return assertStrictRecord(value[key], error);
}

function assertPluginActorWorkspaceScope(
  actor: Record<string, StrictJsonValue>,
  subject: Record<string, StrictJsonValue>,
  error: string,
): void {
  const workspaceId = stringRecordValue(subject, "workspace_id", error);
  if (actor.key_scope_kind !== "workspace" || actor.key_scope_id !== workspaceId) {
    throw new Error(error);
  }
}

function assertPluginConsentActorSubjectBinding(
  actor: Record<string, StrictJsonValue>,
  consent: Record<string, StrictJsonValue>,
  error: string,
): void {
  const actorUserId = stringRecordValue(actor, "user_id", error);
  const actorDeviceId = stringRecordValue(actor, "device_id", error);
  const consentUserId = stringRecordValue(consent, "user_id", error);
  const consentDeviceId = stringRecordValue(consent, "device_id", error);

  if (actorUserId !== consentUserId || actorDeviceId !== consentDeviceId) {
    throw new Error(error);
  }
}

function assertPluginNetworkProxyRequestSubject(
  subject: Record<string, StrictJsonValue>,
  error: string,
): void {
  assertExactRecordKeys(
    subject,
    ["endpoint", "protocol", "proxy", "request_id", "runtime", "target", "version"],
    error,
  );
  stringRecordValue(subject, "protocol", error);
  positiveIntegerRecordValue(subject, "version", error);
  stringRecordValue(subject, "request_id", error);

  const proxy = strictRecordValue(subject, "proxy", error);
  assertExactRecordKeys(proxy, ["id", "origin", "scope"], error);
  stringRecordValue(proxy, "id", error);
  stringRecordValue(proxy, "scope", error);
  stringRecordValue(proxy, "origin", error);

  const target = strictRecordValue(subject, "target", error);
  assertExactRecordKeys(target, ["body_text", "headers", "method", "url"], error);
  stringRecordValue(target, "url", error);
  stringRecordValue(target, "method", error);
  strictRecordValue(target, "headers", error);
  stringPresentRecordValue(target, "body_text", error);

  const endpoint = strictRecordValue(subject, "endpoint", error);
  assertExactRecordKeys(endpoint, pluginNetworkProxyEndpointKeys(endpoint), error);
  stringRecordValue(endpoint, "id", error);
  positiveIntegerRecordValue(endpoint, "max_request_bytes", error);
  positiveIntegerRecordValue(endpoint, "max_response_bytes", error);
  if (Object.hasOwn(endpoint, "credential_audience")) {
    stringRecordValue(endpoint, "credential_audience", error);
  }

  const runtime = strictRecordValue(subject, "runtime", error);
  assertExactRecordKeys(
    runtime,
    [
      "activation_id",
      "application_id",
      "capability_grant_id",
      "consent_epoch",
      "credential_handle_used",
      "device_id",
      "frame_generation",
      "owner_scope_kind",
      "package_id",
      "plugin_id",
      "request_id",
      "user_id",
      "workspace_id",
    ],
    error,
  );
  stringRecordValue(runtime, "workspace_id", error);
  stringRecordValue(runtime, "plugin_id", error);
  stringRecordValue(runtime, "package_id", error);
  stringRecordValue(runtime, "application_id", error);
  stringRecordValue(runtime, "activation_id", error);
  positiveIntegerRecordValue(runtime, "frame_generation", error);
  stringRecordValue(runtime, "user_id", error);
  stringRecordValue(runtime, "device_id", error);
  stringRecordValue(runtime, "owner_scope_kind", error);
  positiveIntegerRecordValue(runtime, "consent_epoch", error);
  stringRecordValue(runtime, "capability_grant_id", error);
  stringRecordValue(runtime, "request_id", error);
  booleanRecordValue(runtime, "credential_handle_used", error);
}

function pluginNetworkProxyEndpointKeys(endpoint: Record<string, StrictJsonValue>): string[] {
  const keys = ["id", "max_request_bytes", "max_response_bytes"];
  if (Object.hasOwn(endpoint, "credential_audience")) keys.push("credential_audience");
  return keys;
}

function assertPluginActorOwnerScope(
  actor: Record<string, StrictJsonValue>,
  subject: Record<string, StrictJsonValue>,
  error: string,
): void {
  const ownerScopeKind = stringRecordValue(subject, "owner_scope_kind", error);
  const ownerScopeId =
    ownerScopeKind === "workspace"
      ? stringRecordValue(subject, "owner_workspace_id", error)
      : ownerScopeKind === "user"
        ? stringRecordValue(subject, "owner_user_id", error)
        : null;
  if (
    !ownerScopeId ||
    actor.key_scope_kind !== ownerScopeKind ||
    actor.key_scope_id !== ownerScopeId
  ) {
    throw new Error(error);
  }
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return (
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    Object.getPrototypeOf(value) === Object.prototype
  );
}

function assertExactKeys(value: Record<string, unknown>, expectedKeys: string[]): void {
  const keys = Object.keys(value).sort();
  const expected = [...expectedKeys].sort();
  if (keys.length !== expected.length) throw new Error("unexpected_keys");
  for (let i = 0; i < keys.length; i += 1) {
    if (keys[i] !== expected[i]) throw new Error("unexpected_keys");
  }
}

function assertExactRecordKeys(
  value: Record<string, unknown>,
  expectedKeys: string[],
  error: string,
): void {
  try {
    assertExactKeys(value, expectedKeys);
  } catch {
    throw new Error(error);
  }
}

function mldsaContext(signingPurpose: string): Uint8Array {
  assertSigningPurpose(signingPurpose);
  const context = textEncoder.encode(`${MLDSA_CONTEXT_PREFIX}${signingPurpose}`);
  if (context.length > 255) throw new Error("mldsa_context_too_long");
  return context;
}

function constantStringEqual(a: string, b: string): boolean {
  return constantTimeEqual(textEncoder.encode(a), textEncoder.encode(b));
}
