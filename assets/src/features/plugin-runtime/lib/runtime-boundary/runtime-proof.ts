import { blake3Base64Url } from "@/shared/lib/crypto/hash";
import {
  canonicalizeStrictBytes,
  parseJsonStrictBytes,
  type StrictJsonValue,
} from "@/shared/lib/crypto/jcs";
import {
  buildPluginBundleApprovalTranscript,
  buildPluginConsentEventTranscript,
  verifyPluginBundleApprovalSignature,
  verifyPluginConsentEventSignature,
  type HybridSigningPublicKeyMaterial,
} from "@/shared/lib/crypto/signature";
import {
  assertActorMatchesSigner,
  assertSignerMatchesMaterial,
  findKeyEntryById,
  isRecord,
  numberField,
  signingKeyMaterialById,
  stringField,
} from "@/shared/lib/anti-rollback/key-directory-pin/primitives";
import {
  assertPluginManifestAuthorityHashes,
  derivePluginManifestAuthority,
} from "./manifest-authority";
import { verifyPluginRuntimeApprovalAuthorityFromKeyDirectory } from "./runtime-approval-authority";
import type {
  PluginRuntimeApprovalAuthorityVerifier,
  PluginRuntimeBundleEnvelope,
  PluginRuntimeApplicationDescriptor,
  PluginRuntimeLocalPins,
  PluginRuntimeSignatureProofEnvelope,
  PluginRuntimeSignerKeyResolver,
} from "./runtime-types";
import { assertRuntimeLocalPins } from "./runtime-pins";

export function assertRuntimeBundleManifestAuthority(envelope: PluginRuntimeBundleEnvelope): {
  manifestJsonBytes: Uint8Array;
  authority: ReturnType<typeof derivePluginManifestAuthority>;
} {
  const manifestJsonBytes = decodeBase64Bytes(envelope.manifest_json_bytes);
  const authority = derivePluginManifestAuthority(parseJsonStrictBytes(manifestJsonBytes));
  assertPluginManifestAuthorityHashes(authority, {
    permissionsHash: envelope.permissions_hash,
    endpointHash: envelope.endpoint_hash,
    rendererSlotsHash: envelope.renderer_slots_hash,
    documentScopeHash: envelope.document_scope_hash,
  });
  return { manifestJsonBytes, authority };
}

export function verifyRuntimeBundleProof(
  descriptor: PluginRuntimeApplicationDescriptor,
  envelope: PluginRuntimeBundleEnvelope,
  localPins: PluginRuntimeLocalPins,
  signerKeyResolver: PluginRuntimeSignerKeyResolver,
  approvalAuthorityVerifier: PluginRuntimeApprovalAuthorityVerifier = verifyPluginRuntimeApprovalAuthorityFromKeyDirectory,
): Promise<void> {
  return verifyRuntimeBundleProofInternal(
    descriptor,
    envelope,
    localPins,
    signerKeyResolver,
    approvalAuthorityVerifier,
  );
}

async function verifyRuntimeBundleProofInternal(
  descriptor: PluginRuntimeApplicationDescriptor,
  envelope: PluginRuntimeBundleEnvelope,
  localPins: PluginRuntimeLocalPins,
  signerKeyResolver: PluginRuntimeSignerKeyResolver,
  approvalAuthorityVerifier: PluginRuntimeApprovalAuthorityVerifier,
): Promise<void> {
  assertRuntimeLocalPins(descriptor, envelope, localPins);
  assertEqual(envelope.plugin_id, descriptor.pluginId, "plugin_id_mismatch");
  assertEqual(envelope.package_id, descriptor.packageId, "package_id_mismatch");
  assertEqual(envelope.application_id, descriptor.applicationId, "application_id_mismatch");
  assertEqual(envelope.workspace_id, descriptor.workspaceId, "workspace_id_mismatch");
  assertEqual(envelope.state_head_hash, localPins.state.latestEventHash, "state_head_mismatch");
  assertEqual(
    envelope.consent_event_hash,
    localPins.consent.latestEventHash,
    "consent_head_mismatch",
  );

  assertEqual(
    envelope.approval_proof.event_hash,
    localPins.state.approvalEventHash,
    "approval_pin_mismatch",
  );
  assertEqual(
    envelope.consent_proof.event_hash,
    envelope.consent_event_hash,
    "consent_pin_mismatch",
  );
  assertEqual(envelope.bundle_hash, localPins.state.bundleHash, "bundle_pin_mismatch");
  assertEqual(envelope.consent_epoch, localPins.consent.consentEpoch, "consent_epoch_mismatch");

  const approvalSubject = requireRecord(
    envelope.approval_proof.subject,
    "approval_subject_invalid",
  );
  assertApprovalSubjectScopeShape(descriptor, approvalSubject);
  const approvalAuthority = assertApprovalAuthorityShape(
    descriptor,
    envelope.approval_proof,
    approvalSubject,
  );
  await approvalAuthorityVerifier({
    descriptor,
    proof: envelope.approval_proof,
    approvalSubject,
    authority: approvalAuthority,
  });
  assertEqual(approvalSubject.bundle_hash, envelope.bundle_hash, "approval_bundle_hash_mismatch");
  assertEqual(
    approvalSubject.manifest_hash,
    envelope.manifest_hash,
    "approval_manifest_hash_mismatch",
  );
  assertEqual(
    approvalSubject.main_js_hash,
    envelope.main_js_hash,
    "approval_main_js_hash_mismatch",
  );
  assertEqual(
    approvalSubject.styles_css_hash,
    envelope.styles_css_hash,
    "approval_styles_css_hash_mismatch",
  );
  assertEqual(
    approvalSubject.permissions_hash,
    envelope.permissions_hash,
    "approval_permissions_hash_mismatch",
  );
  assertEqual(
    approvalSubject.endpoint_hash,
    envelope.endpoint_hash,
    "approval_endpoint_hash_mismatch",
  );
  assertEqual(
    approvalSubject.renderer_slots_hash,
    envelope.renderer_slots_hash,
    "approval_renderer_slots_hash_mismatch",
  );
  assertEqual(
    approvalSubject.document_scope_hash,
    envelope.document_scope_hash,
    "approval_document_scope_hash_mismatch",
  );
  assertSubjectHash(
    envelope.approval_proof.subject,
    envelope.approval_event_hash,
    "approval_hash_mismatch",
  );

  const consentSubject = requireRecord(envelope.consent_proof.subject, "consent_subject_invalid");
  assertEqual(consentSubject.bundle_hash, envelope.bundle_hash, "consent_bundle_hash_mismatch");
  assertEqual(
    consentSubject.manifest_hash,
    envelope.manifest_hash,
    "consent_manifest_hash_mismatch",
  );
  assertEqual(
    consentSubject.permissions_hash,
    envelope.permissions_hash,
    "consent_permissions_hash_mismatch",
  );
  assertEqual(
    consentSubject.endpoint_hash,
    envelope.endpoint_hash,
    "consent_endpoint_hash_mismatch",
  );
  assertEqual(
    consentSubject.document_scope_hash,
    envelope.document_scope_hash,
    "consent_document_scope_hash_mismatch",
  );
  assertEqual(consentSubject.decision, "allow", "consent_decision_mismatch");
  assertSubjectHash(
    envelope.consent_proof.subject,
    envelope.consent_event_hash,
    "consent_hash_mismatch",
  );
  assertConsentSubjectBinding(descriptor, envelope, envelope.consent_proof, consentSubject);

  await verifyApprovalSignature(signerKeyResolver, envelope);

  const consentTranscript = buildPluginConsentEventTranscript({
    actor: envelope.consent_proof.actor,
    consent: envelope.consent_proof.subject,
  });
  const consentSignerKey = await trustedSignerKey(
    signerKeyResolver,
    envelope.consent_proof,
    "consent",
    envelope,
  );
  if (
    !verifyPluginConsentEventSignature({
      transcript: consentTranscript,
      signature: envelope.consent_proof.hybrid_signature,
      publicKeyMaterial: consentSignerKey,
    })
  ) {
    throw new Error("consent_signature_invalid");
  }
}

function assertConsentSubjectBinding(
  descriptor: PluginRuntimeApplicationDescriptor,
  envelope: PluginRuntimeBundleEnvelope,
  proof: PluginRuntimeSignatureProofEnvelope,
  consentSubject: Record<string, StrictJsonValue>,
): void {
  const actor = requireRecord(proof.actor, "runtime_proof_actor_invalid");

  assertNoNullFields(consentSubject, "consent_subject_null_field");
  assertEqual(consentSubject.plugin_id, descriptor.pluginId, "consent_plugin_id_mismatch");
  assertEqual(consentSubject.package_id, descriptor.packageId, "consent_package_id_mismatch");
  assertEqual(
    consentSubject.application_id,
    descriptor.applicationId,
    "consent_application_id_mismatch",
  );
  assertEqual(
    consentSubject.activation_id,
    descriptor.activationId,
    "consent_activation_id_mismatch",
  );
  assertEqual(consentSubject.workspace_id, descriptor.workspaceId, "consent_workspace_id_mismatch");
  assertEqual(
    consentSubject.owner_scope_kind,
    descriptor.ownerScopeKind,
    "consent_owner_scope_mismatch",
  );
  assertEqual(
    consentSubject.owner_scope_kind,
    envelope.owner_scope_kind,
    "consent_owner_scope_mismatch",
  );
  assertEqual(consentSubject.user_id, descriptor.userId, "consent_user_id_mismatch");
  assertEqual(consentSubject.device_id, descriptor.deviceId, "consent_device_id_mismatch");
  assertEqual(consentSubject.consent_epoch, envelope.consent_epoch, "consent_epoch_mismatch");
  assertEqual(actor.user_id, consentSubject.user_id, "consent_actor_mismatch");
  assertEqual(actor.device_id, consentSubject.device_id, "consent_actor_mismatch");
}

async function verifyApprovalSignature(
  signerKeyResolver: PluginRuntimeSignerKeyResolver,
  envelope: PluginRuntimeBundleEnvelope,
): Promise<void> {
  const approvalTranscript = buildPluginBundleApprovalTranscript({
    actor: envelope.approval_proof.actor,
    approval: envelope.approval_proof.subject,
  });
  const approvalSignerKey = await trustedSignerKey(
    signerKeyResolver,
    envelope.approval_proof,
    "approval",
    envelope,
  );
  if (
    !verifyPluginBundleApprovalSignature({
      transcript: approvalTranscript,
      signature: envelope.approval_proof.hybrid_signature,
      publicKeyMaterial: approvalSignerKey,
    })
  ) {
    throw new Error("approval_signature_invalid");
  }
}

export function createTrustedPluginRuntimeSignerKeyResolver(
  checkpointPayload: (
    proof: PluginRuntimeSignatureProofEnvelope,
    purpose: "approval" | "consent",
    envelope: PluginRuntimeBundleEnvelope,
  ) => Promise<Record<string, unknown>>,
): PluginRuntimeSignerKeyResolver {
  return async (proof, purpose, envelope) => {
    const actor = requireRecord(proof.actor, "runtime_proof_actor_invalid");
    const payload = await checkpointPayload(proof, purpose, envelope);
    const material = signingKeyMaterialById(payload).get(proof.signing_key_id) ?? null;
    if (!material) return null;
    const entry = findKeyEntryById(payload, proof.signing_key_id);
    if (!entry || (purpose !== "approval" && isRecord(entry.revoked_at))) return null;
    assertActorMatchesSigner(actor, {
      ...actor,
      signing_key_id: proof.signing_key_id,
    });
    assertSignerMatchesMaterial(
      {
        ...actor,
        signing_key_id: proof.signing_key_id,
      },
      material,
    );
    return material;
  };
}

function assertApprovalAuthorityShape(
  descriptor: PluginRuntimeApplicationDescriptor,
  proof: PluginRuntimeSignatureProofEnvelope,
  approvalSubject: Record<string, StrictJsonValue>,
): Record<string, StrictJsonValue> {
  const actor = requireRecord(proof.actor, "runtime_proof_actor_invalid");
  if (proof.approval_authority === undefined) throw new Error("approval_authority_required");
  const authority = requireRecord(proof.approval_authority, "approval_authority_required");
  if (Object.prototype.hasOwnProperty.call(authority, "role")) {
    throw new Error("approval_authority_untrusted_role");
  }
  assertEqual(authority.kind, "key_directory_membership", "approval_authority_kind_mismatch");
  assertApprovalAuthorityScopeMatchesSubject(descriptor, authority, approvalSubject);
  assertEqual(actor.signer_kind, "device", "approval_authority_actor_mismatch");
  assertEqual(authority.user_id, actor.user_id, "approval_authority_actor_mismatch");
  assertEqual(authority.device_id, actor.device_id, "approval_authority_device_mismatch");
  assertEqual(
    authority.signing_key_id,
    proof.signing_key_id,
    "approval_authority_signing_key_mismatch",
  );
  assertEqual(
    approvalSubject.approver_user_id,
    authority.user_id,
    "approval_authority_approver_mismatch",
  );
  assertEqual(
    approvalSubject.approver_device_id,
    authority.device_id,
    "approval_authority_approver_mismatch",
  );
  nonNegativeIntegerField(
    authority.event_head_sequence,
    "approval_authority_event_head_sequence_invalid",
  );
  stringField(authority.event_head_hash, "approval_authority_event_head_hash_invalid");
  numberField(authority.checkpoint_sequence, "approval_authority_checkpoint_sequence_invalid");
  stringField(authority.checkpoint_hash, "approval_authority_checkpoint_hash_invalid");
  return authority;
}

function assertApprovalSubjectScopeShape(
  descriptor: PluginRuntimeApplicationDescriptor,
  approvalSubject: Record<string, StrictJsonValue>,
): void {
  assertNoNullFields(approvalSubject, "approval_subject_null_field");
  assertEqual(approvalSubject.package_id, descriptor.packageId, "approval_package_id_mismatch");
  assertEqual(
    approvalSubject.owner_scope_kind,
    descriptor.ownerScopeKind,
    "approval_owner_scope_mismatch",
  );

  if (approvalSubject.owner_scope_kind === "workspace") {
    assertEqual(
      approvalSubject.owner_workspace_id,
      descriptor.workspaceId,
      "approval_owner_workspace_mismatch",
    );
    assertEqual(
      approvalSubject.application_scope_kind,
      "workspace",
      "approval_application_scope_mismatch",
    );
    assertEqual(
      approvalSubject.workspace_id,
      descriptor.workspaceId,
      "approval_workspace_mismatch",
    );
    forbidField(approvalSubject, "owner_user_id", "approval_subject_forbidden_field");
  } else if (approvalSubject.owner_scope_kind === "user") {
    stringField(approvalSubject.owner_user_id, "approval_owner_user_invalid");
    forbidField(approvalSubject, "owner_workspace_id", "approval_subject_forbidden_field");
    forbidField(approvalSubject, "application_scope_kind", "approval_subject_forbidden_field");
    forbidField(approvalSubject, "workspace_id", "approval_subject_forbidden_field");
  } else {
    throw new Error("approval_owner_scope_mismatch");
  }
}

function assertApprovalAuthorityScopeMatchesSubject(
  descriptor: PluginRuntimeApplicationDescriptor,
  authority: Record<string, StrictJsonValue>,
  approvalSubject: Record<string, StrictJsonValue>,
): void {
  assertEqual(
    authority.scope_kind,
    approvalSubject.owner_scope_kind,
    "approval_authority_scope_mismatch",
  );

  if (authority.scope_kind === "workspace") {
    assertEqual(
      authority.workspace_id,
      descriptor.workspaceId,
      "approval_authority_workspace_mismatch",
    );
    forbidField(authority, "owner_user_id", "approval_authority_scope_mismatch");
  } else if (authority.scope_kind === "user") {
    assertEqual(
      authority.owner_user_id,
      approvalSubject.owner_user_id,
      "approval_authority_user_mismatch",
    );
    assertEqual(
      authority.user_id,
      approvalSubject.owner_user_id,
      "approval_authority_user_mismatch",
    );
    forbidField(authority, "workspace_id", "approval_authority_scope_mismatch");
  } else {
    throw new Error("approval_authority_scope_mismatch");
  }
}

function assertNoNullFields(record: Record<string, StrictJsonValue>, error: string): void {
  for (const value of Object.values(record)) {
    if (value === null) throw new Error(error);
  }
}

function forbidField(record: Record<string, StrictJsonValue>, field: string, error: string): void {
  if (Object.prototype.hasOwnProperty.call(record, field)) throw new Error(error);
}

async function trustedSignerKey(
  signerKeyResolver: PluginRuntimeSignerKeyResolver,
  proof: PluginRuntimeSignatureProofEnvelope,
  purpose: "approval" | "consent",
  envelope: PluginRuntimeBundleEnvelope,
): Promise<HybridSigningPublicKeyMaterial> {
  const actor = requireRecord(proof.actor, "runtime_proof_actor_invalid");
  assertEqual(actor.signing_key_id, proof.signing_key_id, "runtime_proof_signer_mismatch");
  const key = await signerKeyResolver(proof, purpose, envelope);
  if (!key) throw new Error("runtime_proof_signer_untrusted");
  return key;
}

function assertSubjectHash(subject: StrictJsonValue, expectedHash: string, error: string): void {
  assertEqual(blake3Base64Url(canonicalizeStrictBytes(subject)), expectedHash, error);
}

function requireRecord(value: StrictJsonValue, error: string): Record<string, StrictJsonValue> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new Error(error);
  return value as Record<string, StrictJsonValue>;
}

function assertEqual(actual: unknown, expected: unknown, error: string): void {
  if (actual !== expected) throw new Error(error);
}

function nonNegativeIntegerField(value: unknown, error: string): number {
  if (typeof value !== "number" || !Number.isInteger(value) || value < 0) {
    throw new Error(error);
  }
  return value;
}

function decodeBase64Bytes(value: string): Uint8Array {
  const binary = globalThis.atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index++) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes;
}
