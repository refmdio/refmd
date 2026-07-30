import {
  assertKeyEntryActiveAtSequence,
  checkpointHash,
  eventHash,
  numberField,
} from "./key-directory-pin/primitives";
import {
  AUDIT_CHECKPOINT_PIN_STORE_NAME,
  KEY_DIRECTORY_PIN_STORE_NAME,
  openSecurityDb,
} from "./security-db";
import {
  idbAtomicConditionalPuts,
  idbConditionalPutWithRequiredRecord,
  idbGet,
} from "@/shared/lib/storage/idb";
import { blake3Base64Url } from "@/shared/lib/crypto/hash";
import { canonicalizeStrictBytes, type StrictJsonValue } from "@/shared/lib/crypto/jcs";
import {
  assertAuditCheckpointPayload,
  assertHybridSigningPublicKeyMaterial,
  assertSignatureShape,
  auditCheckpointHash,
  buildAuditCheckpointTranscript,
  computeSigningKeyId,
  verifyAuditCheckpointSignature,
  type AnyHybridSigningPublicKeyMaterial,
  type AuditCheckpointVariant,
  type HybridSignature,
} from "@/shared/lib/crypto/signature";
import {
  lookupVerifiedKeyDirectoryCheckpointBodies,
  lookupVerifiedKeyDirectoryEventBodies,
} from "./key-directory-pin/pins";
import type { KeyDirectoryPin } from "./key-directory-pin/types";

export interface AuditCheckpointPin {
  protocol: "refmd.audit-checkpoint-pin";
  version: 1;
  chain_scope_kind: "user" | "workspace";
  chain_scope_id: string;
  checkpoint_sequence: number;
  checkpoint_hash: string;
  event_head_sequence: number;
  event_head_hash: string;
  checkpoint_variant: AuditCheckpointVariant;
  signer_owner_kind: "identity" | "device";
  signer_owner_id: string;
  signing_key_id: string;
  authorization_checkpoint_sequence: number;
  authorization_checkpoint_hash: string;
  trust_state: "anchored" | "recovery_unanchored";
  anchor_evidence_hash: string;
}

export interface AuditCheckpointPinSet {
  protocol: "refmd.audit-checkpoint-pin-set";
  version: 1;
  trust_transfer_id: string;
  source_device_id: string;
  target_device_id: string;
  transfer_scope_hash: string;
  pins: AuditCheckpointPin[];
}

interface SignedAuditCheckpointEnvelope {
  payload: Record<string, StrictJsonValue>;
  signature: HybridSignature;
  checkpoint_hash: string;
}

export interface GenesisAuditAuthority {
  userId: string;
  deviceId: string;
  workspaceId: string;
  userAuditCheckpointHash: string;
  workspaceAuditCheckpointHash: string;
  userKeyDirectoryCheckpointHash: string;
  workspaceKeyDirectoryCheckpointHash: string;
}

interface AuditVerificationOptions {
  acquisition?: "local" | "trust_transfer" | "recovery";
  genesisAuthority?: GenesisAuditAuthority;
}

const HIGH_RISK_EVENT_TYPES = new Set([
  "user.account.genesis",
  "user.device.genesis_bootstrapped",
  "user.device.approved",
  "user.device.recovery_approved",
  "user.device.revoked.security",
  "workspace.security_device_revocation.applied",
  "user.device.revoked.retire",
  "user.identity.key_added",
  "user.identity.signing_key_revoked",
  "user.identity.encryption_key_revoked",
  "user.identity.rotation_started",
  "user.identity.rotation_completed",
  "workspace.identity_self_envelope_rewrap.completed",
  "user.identity.old_key_deleted",
  "user.recovery_authorization.created",
  "user.recovery_authorization.replaced",
  "user.trust_transfer.completed",
  "user.suite_policy.changed",
  "workspace.genesis",
  "workspace.member.added",
  "workspace.member.removed",
  "workspace.member.role_changed",
  "workspace.invitation.created",
  "workspace.invitation.redeemed.known_recipient",
  "workspace.invitation.redeemed.unknown_recipient",
  "workspace.invitation.revoked",
  "workspace.guest_invitation.created",
  "workspace.guest_invitation.redeemed.known_recipient",
  "workspace.guest_invitation.redeemed.unknown_recipient",
  "workspace.guest_invitation.revoked",
  "workspace.guest_grant.revoked",
  "workspace.guest_device.revoked",
  "workspace.share.created",
  "workspace.share.metadata_updated",
  "workspace.share.key_scope_added",
  "workspace.share.key_scope_replaced",
  "workspace.share.key_scope_removed",
  "workspace.share.exclusion_changed",
  "workspace.share.revoked",
  "workspace.kek.rotation_started",
  "workspace.kek.rotation_completed",
  "workspace.kek.old_key_deleted",
  "workspace.dek.rotation_started",
  "workspace.dek.rotation_completed",
  "workspace.dek.old_key_deleted",
  "workspace.suite_policy.changed",
]);

const HIGH_RISK_RUNTIME_EVENT_TYPES = new Set([
  "plugin.ui.registration.accepted",
  "plugin.ui.invocation.accepted",
  "plugin.network.requested",
  "plugin.credential_handle.used",
  "plugin.plaintext.invoked",
  "document.sensitive_action.started",
  "share.sensitive_action.started",
  "publication.sensitive_action.started",
  "git.sync.started",
]);

const LOW_RISK_RUNTIME_EVENTS = new Map<string, { operations: string[]; result: string }>([
  ["plugin.ui.registration.rejected", { operations: ["register"], result: "denied" }],
  ["plugin.ui.invocation.rejected", { operations: ["invoke"], result: "denied" }],
  ["plugin.ui.owner_stale_frame_rejected", { operations: ["invoke"], result: "denied" }],
  ["plugin.ui.consent_stale_rejected", { operations: ["invoke"], result: "denied" }],
  ["plugin.ui.capability_mismatch_rejected", { operations: ["invoke"], result: "denied" }],
  ["plugin.ui.registry_entry_disposed", { operations: ["dispose"], result: "completed" }],
  ["plugin.ui.iframe.closed_with_live_entries", { operations: ["close"], result: "completed" }],
  [
    "plugin.ui.iframe.lifecycle",
    { operations: ["created", "ready", "closed", "crashed"], result: "completed" },
  ],
]);

const WORKSPACE_ADMIN_AUDIT_EVENTS = new Set([
  "workspace.member.added",
  "workspace.member.removed",
  "workspace.member.role_changed",
  "workspace.invitation.created",
  "workspace.invitation.revoked",
  "workspace.guest_invitation.created",
  "workspace.guest_invitation.revoked",
  "workspace.guest_grant.revoked",
  "workspace.guest_device.revoked",
  "workspace.kek.rotation_started",
  "workspace.kek.rotation_completed",
  "workspace.kek.old_key_deleted",
  "workspace.suite_policy.changed",
]);

const WORKSPACE_SHARE_MANAGEMENT_AUDIT_EVENTS = new Set([
  "workspace.share.created",
  "workspace.share.metadata_updated",
  "workspace.share.key_scope_added",
  "workspace.share.key_scope_replaced",
  "workspace.share.key_scope_removed",
  "workspace.share.exclusion_changed",
  "workspace.share.revoked",
]);

const WORKSPACE_DOCUMENT_ROTATION_AUDIT_EVENTS = new Set([
  "workspace.dek.rotation_started",
  "workspace.dek.rotation_completed",
  "workspace.dek.old_key_deleted",
]);

const WORKSPACE_ACTIVE_MEMBER_AUDIT_EVENTS = new Set([
  "workspace.security_device_revocation.applied",
  "workspace.identity_self_envelope_rewrap.completed",
]);

export async function getAuditCheckpointPin(
  scopeKind: "user" | "workspace",
  scopeId: string,
): Promise<AuditCheckpointPin | null> {
  requiredUuid(scopeId, "audit_checkpoint_scope_invalid");
  const db = await openSecurityDb();
  return (
    (await idbGet<AuditCheckpointPin>(db, AUDIT_CHECKPOINT_PIN_STORE_NAME, [scopeKind, scopeId])) ??
    null
  );
}

export function buildAuditCheckpointPinSet(params: {
  trustTransferId: string;
  sourceDeviceId: string;
  targetDeviceId: string;
  ownerUserId: string;
  pins: AuditCheckpointPin[];
}): { pinSet: AuditCheckpointPinSet; pinSetHash: string; transferScopeHash: string } {
  const pins = [...params.pins].sort(compareAuditPinScopes);
  assertAuditPinScopeOrder(pins);
  const transferScopeHash = auditTransferScopeHash(params.ownerUserId, pins);
  const pinSet: AuditCheckpointPinSet = {
    protocol: "refmd.audit-checkpoint-pin-set",
    version: 1,
    trust_transfer_id: requiredUuid(params.trustTransferId, "audit_checkpoint_pin_set_invalid"),
    source_device_id: requiredUuid(params.sourceDeviceId, "audit_checkpoint_pin_set_invalid"),
    target_device_id: requiredUuid(params.targetDeviceId, "audit_checkpoint_pin_set_invalid"),
    transfer_scope_hash: transferScopeHash,
    pins,
  };
  return {
    pinSet,
    pinSetHash: auditCheckpointPinSetHash(pinSet),
    transferScopeHash,
  };
}

export function assertAuditCheckpointPinSet(params: {
  value: unknown;
  ownerUserId: string;
  trustTransferId: string;
  sourceDeviceId: string;
  targetDeviceId: string;
  transferScopeHash: string;
  pinSetHash: string;
}): AuditCheckpointPinSet {
  const value = requiredRecord(params.value, "audit_checkpoint_pin_set_invalid");
  assertExactKeys(value, [
    "pins",
    "protocol",
    "source_device_id",
    "target_device_id",
    "transfer_scope_hash",
    "trust_transfer_id",
    "version",
  ]);
  if (value.protocol !== "refmd.audit-checkpoint-pin-set" || value.version !== 1) {
    throw new Error("audit_checkpoint_pin_set_invalid");
  }
  const pins = requiredArray(value.pins).map(assertAuditCheckpointPin);
  assertAuditPinScopeOrder(pins);
  const pinSet: AuditCheckpointPinSet = {
    protocol: "refmd.audit-checkpoint-pin-set",
    version: 1,
    trust_transfer_id: requiredUuid(value.trust_transfer_id, "audit_checkpoint_pin_set_invalid"),
    source_device_id: requiredUuid(value.source_device_id, "audit_checkpoint_pin_set_invalid"),
    target_device_id: requiredUuid(value.target_device_id, "audit_checkpoint_pin_set_invalid"),
    transfer_scope_hash: requiredHash(value.transfer_scope_hash),
    pins,
  };
  if (
    pinSet.trust_transfer_id !== params.trustTransferId ||
    pinSet.source_device_id !== params.sourceDeviceId ||
    pinSet.target_device_id !== params.targetDeviceId ||
    pinSet.transfer_scope_hash !== params.transferScopeHash ||
    pinSet.transfer_scope_hash !== auditTransferScopeHash(params.ownerUserId, pins) ||
    auditCheckpointPinSetHash(pinSet) !== params.pinSetHash
  ) {
    throw new Error("audit_checkpoint_pin_set_binding_mismatch");
  }
  return pinSet;
}

export async function installTransferredSecurityPinSet(params: {
  pinSet: AuditCheckpointPinSet;
  pinSetHash: string;
  keyDirectoryPins: KeyDirectoryPin[];
  verifiedAuditPins: AuditCheckpointPin[];
  authorizationCheckpoints: Array<{
    scopeKind: "user" | "workspace";
    scopeId: string;
    sequence: number;
    hash: string;
  }>;
}): Promise<void> {
  if (
    params.verifiedAuditPins.length !== params.pinSet.pins.length ||
    params.verifiedAuditPins.some(
      (pin, index) => !sameAuditCheckpointIdentity(pin, params.pinSet.pins[index]),
    )
  ) {
    throw new Error("audit_checkpoint_transfer_proof_mismatch");
  }
  const auditScopes = params.pinSet.pins.map(auditPinScopeKey);
  const keyDirectoryPins = [...params.keyDirectoryPins].sort((left, right) =>
    left.pinKey.localeCompare(right.pinKey),
  );
  const keyScopes = keyDirectoryPins.map((pin) => pin.pinKey);
  if (
    auditScopes.length !== keyScopes.length ||
    auditScopes.some((scope, index) => scope !== keyScopes[index])
  ) {
    throw new Error("trust_state_bundle_pin_scope_mismatch");
  }
  for (const pin of params.pinSet.pins) {
    if (
      pin.authorization_checkpoint_sequence === 0 &&
      pin.authorization_checkpoint_hash === "GENESIS"
    ) {
      continue;
    }
    const hasAuthorizationCheckpoint = params.authorizationCheckpoints.some(
      (checkpoint) =>
        checkpoint.scopeKind === pin.chain_scope_kind &&
        checkpoint.scopeId === pin.chain_scope_id &&
        checkpoint.sequence === pin.authorization_checkpoint_sequence &&
        checkpoint.hash === pin.authorization_checkpoint_hash,
    );
    if (!hasAuthorizationCheckpoint) {
      throw new Error("audit_checkpoint_authorization_proof_missing");
    }
  }

  const anchoredPins = params.verifiedAuditPins.map((pin) => ({
    ...pin,
    trust_state: "anchored" as const,
    anchor_evidence_hash: params.pinSetHash,
  }));
  const db = await openSecurityDb();
  await idbAtomicConditionalPuts(db, [
    ...keyDirectoryPins.map((pin) => ({
      storeName: KEY_DIRECTORY_PIN_STORE_NAME,
      key: pin.pinKey,
      value: pin,
      shouldWrite: (existing: unknown) => canMergeKeyDirectoryPin(existing, pin),
    })),
    ...anchoredPins.map((pin) => ({
      storeName: AUDIT_CHECKPOINT_PIN_STORE_NAME,
      key: [pin.chain_scope_kind, pin.chain_scope_id],
      value: pin,
      shouldWrite: (existing: unknown) => canMergeAuditPin(existing, pin),
    })),
  ]);
}

function sameAuditCheckpointIdentity(
  left: AuditCheckpointPin,
  right: AuditCheckpointPin | undefined,
): boolean {
  return (
    !!right &&
    left.chain_scope_kind === right.chain_scope_kind &&
    left.chain_scope_id === right.chain_scope_id &&
    left.checkpoint_sequence === right.checkpoint_sequence &&
    left.checkpoint_hash === right.checkpoint_hash &&
    left.event_head_sequence === right.event_head_sequence &&
    left.event_head_hash === right.event_head_hash &&
    left.checkpoint_variant === right.checkpoint_variant &&
    left.signer_owner_kind === right.signer_owner_kind &&
    left.signer_owner_id === right.signer_owner_id &&
    left.signing_key_id === right.signing_key_id &&
    left.authorization_checkpoint_sequence === right.authorization_checkpoint_sequence &&
    left.authorization_checkpoint_hash === right.authorization_checkpoint_hash
  );
}

export async function verifyAndPinAuditCheckpoint(
  value: unknown,
  options: AuditVerificationOptions = {},
): Promise<AuditCheckpointPin> {
  const pin = await verifyAuditCheckpointCandidate(value, options);
  const db = await openSecurityDb();
  const wrote = await idbConditionalPutWithRequiredRecord<AuditCheckpointPin, KeyDirectoryPin>({
    db,
    targetStoreName: AUDIT_CHECKPOINT_PIN_STORE_NAME,
    targetKey: [pin.chain_scope_kind, pin.chain_scope_id],
    targetValue: pin,
    requiredStoreName: KEY_DIRECTORY_PIN_STORE_NAME,
    requiredKey: `${pin.chain_scope_kind}:${pin.chain_scope_id}`,
    validateRequired: (keyPin) =>
      !!keyPin &&
      keyPin.scopeKind === pin.chain_scope_kind &&
      keyPin.scopeId === pin.chain_scope_id,
    shouldWrite: (existing) => {
      if (!existing) return true;
      if (pin.checkpoint_sequence < existing.checkpoint_sequence) return false;
      if (pin.checkpoint_sequence === existing.checkpoint_sequence) {
        return (
          pin.checkpoint_hash === existing.checkpoint_hash &&
          pin.event_head_hash === existing.event_head_hash
        );
      }
      return true;
    },
  }).catch((error: unknown) => {
    if (error instanceof Error && error.message === "required_record_missing_or_invalid") {
      throw new Error("audit_checkpoint_key_directory_pin_required");
    }
    throw error;
  });
  if (!wrote) throw new Error("audit_checkpoint_rollback_or_fork");
  return pin;
}

export async function verifyAuditCheckpointCandidate(
  value: unknown,
  options: AuditVerificationOptions = {},
): Promise<AuditCheckpointPin> {
  const response = requiredRecord(value, "audit_checkpoint_response_invalid");
  assertExactKeys(response, [
    "ancestry",
    "current_event_head",
    "signed_checkpoint",
    "unsigned_tail",
  ]);
  const envelope = assertSignedAuditCheckpointEnvelope(response.signed_checkpoint);
  const payload = envelope.payload;
  const variant = auditCheckpointVariant(payload);
  assertAuditCheckpointPayload(variant, payload);
  if (auditCheckpointHash(payload) !== envelope.checkpoint_hash) {
    throw new Error("audit_checkpoint_hash_mismatch");
  }

  const scopeKind = requiredString(payload.chain_scope_kind, "audit_checkpoint_scope_invalid") as
    | "user"
    | "workspace";
  const scopeId = requiredString(payload.chain_scope_id, "audit_checkpoint_scope_invalid");
  const sequence = requiredPositiveInteger(payload.sequence, "audit_checkpoint_sequence_invalid");
  const eventHash = requiredHash(payload.event_hash);
  const existing = await getAuditCheckpointPin(scopeKind, scopeId);
  assertSignedCheckpointAdvance(existing, payload, envelope.checkpoint_hash, eventHash);

  const ancestry = requiredRecordArray(response.ancestry, "audit_checkpoint_ancestry_invalid");
  const publicKeyMaterial = authoritySigningMaterial(
    scopeKind,
    scopeId,
    payload,
    envelope.checkpoint_hash,
    ancestry,
    options.genesisAuthority,
    existing,
  );
  const ownerKind = variant === "user_identity" ? "identity" : "device";
  const ownerId = requiredString(
    ownerKind === "identity" ? payload.signer_user_id : payload.signer_device_id,
    "audit_checkpoint_signer_invalid",
  );
  const transcript = buildAuditCheckpointTranscript({
    variant,
    ownerKind,
    ownerId,
    payload,
  });
  if (
    !verifyAuditCheckpointSignature({
      transcript,
      signature: envelope.signature,
      publicKeyMaterial,
    })
  ) {
    throw new Error("audit_checkpoint_signature_invalid");
  }

  verifyEventRange(
    ancestry,
    existing?.event_head_sequence ?? 0,
    existing?.event_head_hash ?? "GENESIS",
    sequence,
    eventHash,
    scopeKind,
    scopeId,
  );

  const unsignedTail = requiredRecordArray(response.unsigned_tail, "audit_checkpoint_tail_invalid");
  const currentHead = requiredRecord(response.current_event_head, "audit_checkpoint_head_invalid");
  const currentSequence = requiredPositiveInteger(
    currentHead.sequence,
    "audit_checkpoint_head_invalid",
  );
  const currentHash = requiredHash(currentHead.event_hash);
  verifyEventRange(
    unsignedTail,
    sequence,
    eventHash,
    currentSequence,
    currentHash,
    scopeKind,
    scopeId,
  );
  assertUnsignedTailLowRiskOnly(unsignedTail);

  const authoritySequence = requiredNonNegativeInteger(
    payload.authorization_checkpoint_sequence,
    "audit_checkpoint_authority_invalid",
  );
  const authorityHash = requiredString(
    payload.authorization_checkpoint_hash,
    "audit_checkpoint_authority_invalid",
  );
  const genesis = authoritySequence === 0 && authorityHash === "GENESIS";
  if (
    !existing &&
    !genesis &&
    options.acquisition !== "trust_transfer" &&
    options.acquisition !== "recovery"
  ) {
    throw new Error("audit_checkpoint_anchor_evidence_required");
  }

  return {
    protocol: "refmd.audit-checkpoint-pin",
    version: 1,
    chain_scope_kind: scopeKind,
    chain_scope_id: scopeId,
    checkpoint_sequence: sequence,
    checkpoint_hash: envelope.checkpoint_hash,
    event_head_sequence: sequence,
    event_head_hash: eventHash,
    checkpoint_variant: variant,
    signer_owner_kind: ownerKind,
    signer_owner_id: ownerId,
    signing_key_id: requiredHash(payload.signing_key_id),
    authorization_checkpoint_sequence: authoritySequence,
    authorization_checkpoint_hash: authorityHash,
    trust_state:
      existing?.trust_state ??
      (options.acquisition === "recovery" ? "recovery_unanchored" : "anchored"),
    anchor_evidence_hash:
      existing?.anchor_evidence_hash ??
      (options.acquisition === "recovery" ? "NONE" : envelope.checkpoint_hash),
  };
}

function assertSignedAuditCheckpointEnvelope(value: unknown): SignedAuditCheckpointEnvelope {
  const envelope = requiredRecord(value, "signed_audit_checkpoint_invalid");
  assertExactKeys(envelope, ["checkpoint_hash", "payload", "signature"]);
  const payload = requiredRecord(envelope.payload, "audit_checkpoint_payload_invalid") as Record<
    string,
    StrictJsonValue
  >;
  assertSignatureShape(envelope.signature);
  return {
    payload,
    signature: envelope.signature,
    checkpoint_hash: requiredHash(envelope.checkpoint_hash),
  };
}

function auditCheckpointVariant(payload: Record<string, StrictJsonValue>): AuditCheckpointVariant {
  if (payload.chain_scope_kind === "user") {
    return "signer_device_id" in payload ? "user_device" : "user_identity";
  }
  if (payload.chain_scope_kind === "workspace") {
    return requiredString(
      payload.covered_event_type,
      "audit_checkpoint_event_type_invalid",
    ).startsWith("workspace.guest_invitation.redeemed.")
      ? "workspace_guest_device"
      : "workspace_device";
  }
  throw new Error("audit_checkpoint_scope_invalid");
}

function authoritySigningMaterial(
  scopeKind: "user" | "workspace",
  scopeId: string,
  payload: Record<string, StrictJsonValue>,
  auditCheckpointHashValue: string,
  auditAncestry: Record<string, unknown>[],
  genesisAuthority: GenesisAuditAuthority | undefined,
  existing: AuditCheckpointPin | null,
): AnyHybridSigningPublicKeyMaterial {
  const authoritySequence = requiredNonNegativeInteger(
    payload.authorization_checkpoint_sequence,
    "audit_checkpoint_authority_invalid",
  );
  const authorityHash = requiredString(
    payload.authorization_checkpoint_hash,
    "audit_checkpoint_authority_invalid",
  );
  if (
    payload.authorization_checkpoint_scope_kind !== scopeKind ||
    payload.authorization_checkpoint_scope_id !== scopeId
  ) {
    throw new Error("audit_checkpoint_scope_mismatch");
  }
  const signingKeyId = requiredHash(payload.signing_key_id);
  const checkpoints = lookupVerifiedKeyDirectoryCheckpointBodies(scopeKind, scopeId);
  const checkpoint =
    authoritySequence === 0 && authorityHash === "GENESIS"
      ? checkpoints.find((candidate) => candidate.payload.sequence === 1)
      : checkpoints.find(
          (candidate) =>
            candidate.payload.sequence === authoritySequence &&
            checkpointHash(candidate) === authorityHash,
        );
  if (!checkpoint) throw new Error("audit_checkpoint_authority_unverified");
  const entries = [
    ...requiredArray(checkpoint.payload.identity_keys),
    ...requiredArray(checkpoint.payload.device_keys),
  ];
  const entry = entries.find(
    (candidate) =>
      requiredRecord(candidate, "audit_checkpoint_key_entry_invalid").key_id === signingKeyId,
  );
  assertKeyEntryActiveAtSequence(
    checkpoint.payload,
    signingKeyId,
    numberField(
      requiredRecord(checkpoint.payload.covered_event_head, "audit_checkpoint_authority_invalid")
        .head_sequence,
      "audit_checkpoint_authority_invalid",
    ),
  );
  const material = requiredRecord(
    requiredRecord(entry, "audit_checkpoint_signer_unknown").key_material,
    "audit_checkpoint_signer_unknown",
  );
  assertHybridSigningPublicKeyMaterial(material);
  if (computeSigningKeyId(material) !== signingKeyId) {
    throw new Error("audit_checkpoint_signer_key_id_mismatch");
  }
  const variant = auditCheckpointVariant(payload);
  const expectedOwnerKind = variant === "user_identity" ? "identity" : "device";
  const expectedOwnerId =
    variant === "user_identity"
      ? requiredString(payload.signer_user_id, "audit_checkpoint_signer_invalid")
      : requiredString(payload.signer_device_id, "audit_checkpoint_signer_invalid");
  if (material.owner_kind !== expectedOwnerKind || material.owner_id !== expectedOwnerId) {
    throw new Error("audit_checkpoint_signer_owner_mismatch");
  }
  if (authoritySequence === 0 && authorityHash === "GENESIS") {
    const alreadyPinned =
      existing?.checkpoint_hash === auditCheckpointHashValue &&
      existing.authorization_checkpoint_sequence === 0 &&
      existing.authorization_checkpoint_hash === "GENESIS";
    if (!alreadyPinned) {
      assertGenesisAuditAuthority(
        scopeKind,
        scopeId,
        payload,
        auditCheckpointHashValue,
        checkpoint,
        auditAncestry,
        genesisAuthority,
      );
    }
  } else {
    assertAuditSignerAuthority(scopeKind, scopeId, payload, checkpoint);
  }
  return material;
}

function assertGenesisAuditAuthority(
  scopeKind: "user" | "workspace",
  scopeId: string,
  payload: Record<string, StrictJsonValue>,
  auditCheckpointHashValue: string,
  checkpoint: { payload: Record<string, unknown> },
  auditAncestry: Record<string, unknown>[],
  authority: GenesisAuditAuthority | undefined,
): void {
  if (!authority || checkpoint.payload.sequence !== 1) {
    throw new Error("audit_checkpoint_authority_unverified");
  }
  const expectedAuditHash =
    scopeKind === "user"
      ? authority.userAuditCheckpointHash
      : authority.workspaceAuditCheckpointHash;
  const expectedKeyDirectoryHash =
    scopeKind === "user"
      ? authority.userKeyDirectoryCheckpointHash
      : authority.workspaceKeyDirectoryCheckpointHash;
  if (
    auditCheckpointHashValue !== expectedAuditHash ||
    checkpointHash(checkpoint as never) !== expectedKeyDirectoryHash
  ) {
    throw new Error("audit_checkpoint_authority_unverified");
  }

  const eventType = requiredString(
    payload.covered_event_type,
    "audit_checkpoint_authority_unverified",
  );
  if (scopeKind === "user") {
    if (
      scopeId !== authority.userId ||
      eventType !== "user.device.genesis_bootstrapped" ||
      "signer_device_id" in payload
    ) {
      throw new Error("audit_checkpoint_authority_unverified");
    }
    assertUserGenesisKeyDirectoryAuthority(checkpoint, authority, payload);
    assertUserGenesisAuditEvent(auditAncestry, authority, payload);
    return;
  }

  if (
    scopeId !== authority.workspaceId ||
    eventType !== "workspace.genesis" ||
    payload.signer_user_id !== authority.userId ||
    payload.signer_device_id !== authority.deviceId
  ) {
    throw new Error("audit_checkpoint_authority_unverified");
  }
  assertWorkspaceGenesisKeyDirectoryAuthority(checkpoint, authority, payload);
  assertWorkspaceGenesisAuditEvent(auditAncestry, authority, payload);
}

function assertUserGenesisKeyDirectoryAuthority(
  checkpoint: { payload: Record<string, unknown> },
  authority: GenesisAuditAuthority,
  auditPayload: Record<string, StrictJsonValue>,
): void {
  const events = lookupVerifiedKeyDirectoryEventBodies("user", authority.userId)
    .filter((event) => Number(event.payload.sequence) <= 4)
    .sort((left, right) => Number(left.payload.sequence) - Number(right.payload.sequence));
  const expectedTypes = [
    "identity_key_added",
    "identity_key_added",
    "suite_policy_changed",
    "device_key_added",
  ];
  if (
    events.length !== expectedTypes.length ||
    events.some(
      (event, index) =>
        event.payload.sequence !== index + 1 || event.payload.event_type !== expectedTypes[index],
    )
  ) {
    throw new Error("audit_checkpoint_authority_unverified");
  }
  const deviceBody = requiredRecord(
    events[3]!.payload.body,
    "audit_checkpoint_authority_unverified",
  );
  if (
    deviceBody.user_id !== authority.userId ||
    deviceBody.device_id !== authority.deviceId ||
    requiredRecord(checkpoint.payload.covered_event_head, "audit_checkpoint_authority_unverified")
      .head_hash !== eventHash(events[3] as never) ||
    auditPayload.signer_user_id !== authority.userId
  ) {
    throw new Error("audit_checkpoint_authority_unverified");
  }
}

function assertUserGenesisAuditEvent(
  ancestry: Record<string, unknown>[],
  authority: GenesisAuditAuthority,
  payload: Record<string, StrictJsonValue>,
): void {
  const event = ancestry.find((candidate) => candidate.event_hash === payload.event_hash);
  const body = requiredRecord(event?.event_body, "audit_checkpoint_authority_unverified");
  const actor = requiredRecord(body.actor, "audit_checkpoint_authority_unverified");
  if (
    event?.event_type !== "user.device.genesis_bootstrapped" ||
    body.chain_scope_kind !== "user" ||
    body.chain_scope_id !== authority.userId ||
    actor.kind !== "identity" ||
    actor.user_id !== authority.userId ||
    body.subject_kind !== "user_device" ||
    body.subject_id !== authority.deviceId
  ) {
    throw new Error("audit_checkpoint_authority_unverified");
  }
}

function assertWorkspaceGenesisKeyDirectoryAuthority(
  checkpoint: { payload: Record<string, unknown> },
  authority: GenesisAuditAuthority,
  auditPayload: Record<string, StrictJsonValue>,
): void {
  const events = lookupVerifiedKeyDirectoryEventBodies("workspace", authority.workspaceId)
    .filter((event) => Number(event.payload.sequence) <= 6)
    .sort((left, right) => Number(left.payload.sequence) - Number(right.payload.sequence));
  const expectedTypes = [
    "identity_key_added",
    "identity_key_added",
    "device_key_added",
    "member_added",
    "suite_policy_changed",
    "workspace_member_envelope_issued",
  ];
  if (
    events.length !== expectedTypes.length ||
    events.some(
      (event, index) =>
        event.payload.sequence !== index + 1 || event.payload.event_type !== expectedTypes[index],
    )
  ) {
    throw new Error("audit_checkpoint_authority_unverified");
  }
  const deviceBody = requiredRecord(
    events[2]!.payload.body,
    "audit_checkpoint_authority_unverified",
  );
  const memberBody = requiredRecord(
    events[3]!.payload.body,
    "audit_checkpoint_authority_unverified",
  );
  const envelopeBody = requiredRecord(
    events[5]!.payload.body,
    "audit_checkpoint_authority_unverified",
  );
  if (
    deviceBody.user_id !== authority.userId ||
    deviceBody.device_id !== authority.deviceId ||
    deviceBody.signing_key_id !== auditPayload.signing_key_id ||
    memberBody.workspace_id !== authority.workspaceId ||
    memberBody.user_id !== authority.userId ||
    memberBody.base_role !== "owner" ||
    envelopeBody.workspace_id !== authority.workspaceId ||
    envelopeBody.target_user_id !== authority.userId ||
    envelopeBody.sender_device_id !== authority.deviceId ||
    envelopeBody.workspace_member_envelope_hash !== memberBody.workspace_member_envelope_hash ||
    requiredRecord(checkpoint.payload.covered_event_head, "audit_checkpoint_authority_unverified")
      .head_hash !== eventHash(events[5] as never)
  ) {
    throw new Error("audit_checkpoint_authority_unverified");
  }
}

function assertWorkspaceGenesisAuditEvent(
  ancestry: Record<string, unknown>[],
  authority: GenesisAuditAuthority,
  payload: Record<string, StrictJsonValue>,
): void {
  const event = ancestry.find((candidate) => candidate.event_hash === payload.event_hash);
  const body = requiredRecord(event?.event_body, "audit_checkpoint_authority_unverified");
  const actor = requiredRecord(body.actor, "audit_checkpoint_authority_unverified");
  if (
    event?.event_type !== "workspace.genesis" ||
    body.chain_scope_kind !== "workspace" ||
    body.chain_scope_id !== authority.workspaceId ||
    body.subject_kind !== "workspace" ||
    body.subject_id !== authority.workspaceId ||
    actor.kind !== "device" ||
    actor.user_id !== authority.userId ||
    actor.device_id !== authority.deviceId
  ) {
    throw new Error("audit_checkpoint_authority_unverified");
  }
}

function assertAuditSignerAuthority(
  scopeKind: "user" | "workspace",
  scopeId: string,
  payload: Record<string, StrictJsonValue>,
  authorityCheckpoint: { payload: Record<string, unknown> },
): void {
  const signerUserId = requiredString(payload.signer_user_id, "audit_checkpoint_signer_invalid");
  if (scopeKind === "user") {
    if (signerUserId !== scopeId) throw new Error("audit_checkpoint_authority_unverified");
    return;
  }

  const coveredHead = requiredRecord(
    authorityCheckpoint.payload.covered_event_head,
    "audit_checkpoint_authority_unverified",
  );
  const headSequence = requiredPositiveInteger(
    coveredHead.head_sequence,
    "audit_checkpoint_authority_unverified",
  );
  const headHash = requiredHash(coveredHead.head_hash);
  const role = workspaceMemberAuthorityAt(scopeId, signerUserId, headSequence, headHash);
  const eventType = requiredString(
    payload.covered_event_type,
    "audit_checkpoint_event_type_invalid",
  );

  const authorized =
    (WORKSPACE_ADMIN_AUDIT_EVENTS.has(eventType) &&
      rolePermissionGranted(role, "workspace:admin")) ||
    (WORKSPACE_SHARE_MANAGEMENT_AUDIT_EVENTS.has(eventType) &&
      rolePermissionGranted(role, "document:manage_share")) ||
    (WORKSPACE_DOCUMENT_ROTATION_AUDIT_EVENTS.has(eventType) &&
      rolePermissionGranted(role, "document:archive")) ||
    (WORKSPACE_ACTIVE_MEMBER_AUDIT_EVENTS.has(eventType) && role !== null);

  if (!authorized) throw new Error("audit_checkpoint_authority_unverified");
}

interface WorkspaceMemberAuthority {
  baseRole: string;
  permissions: Set<string> | null;
}

function workspaceMemberAuthorityAt(
  workspaceId: string,
  signerUserId: string,
  headSequence: number,
  headHash: string,
): WorkspaceMemberAuthority | null {
  const members = new Map<string, WorkspaceMemberAuthority>();
  const events = lookupVerifiedKeyDirectoryEventBodies("workspace", workspaceId)
    .filter((event) => Number(event.payload.sequence) <= headSequence)
    .sort((left, right) => Number(left.payload.sequence) - Number(right.payload.sequence));
  if (
    events.length !== headSequence ||
    events.some((event, index) => Number(event.payload.sequence) !== index + 1) ||
    eventHash(events.at(-1)!) !== headHash
  ) {
    throw new Error("audit_checkpoint_authority_unverified");
  }

  for (const event of events) {
    const eventType = requiredString(
      event.payload.event_type,
      "audit_checkpoint_authority_unverified",
    );
    const body = requiredRecord(event.payload.body, "audit_checkpoint_authority_unverified");
    if (eventType === "member_added") {
      members.set(requiredString(body.user_id, "audit_checkpoint_authority_unverified"), {
        baseRole: requiredString(body.base_role, "audit_checkpoint_authority_unverified"),
        permissions: null,
      });
    } else if (eventType === "member_role_changed") {
      const permissions = requiredArray(body.effective_permissions).map((permission) =>
        requiredString(permission, "audit_checkpoint_authority_unverified"),
      );
      members.set(requiredString(body.user_id, "audit_checkpoint_authority_unverified"), {
        baseRole: requiredString(body.base_role, "audit_checkpoint_authority_unverified"),
        permissions: new Set(permissions),
      });
    } else if (eventType === "member_removed") {
      members.delete(requiredString(body.user_id, "audit_checkpoint_authority_unverified"));
    } else if (eventType === "workspace_invitation_redeemed") {
      members.set(requiredString(body.redeemed_user_id, "audit_checkpoint_authority_unverified"), {
        baseRole: requiredString(body.base_role, "audit_checkpoint_authority_unverified"),
        permissions: null,
      });
    }
  }
  return members.get(signerUserId) ?? null;
}

function rolePermissionGranted(role: WorkspaceMemberAuthority | null, permission: string): boolean {
  if (!role) return false;
  if (role.baseRole === "owner") return true;
  if (role.permissions) return role.permissions.has(permission);
  const defaults: Record<string, string[]> = {
    admin: ["workspace:admin", "document:manage_share", "document:archive"],
    editor: ["document:manage_share", "document:archive"],
    viewer: [],
    guest: [],
  };
  return (defaults[role.baseRole] ?? []).includes(permission);
}

function assertSignedCheckpointAdvance(
  existing: AuditCheckpointPin | null,
  payload: Record<string, StrictJsonValue>,
  candidateCheckpointHash: string,
  candidateEventHash: string,
): void {
  if (!existing) return;
  const sequence = Number(payload.sequence);
  if (sequence < existing.checkpoint_sequence) {
    throw new Error("audit_checkpoint_rollback_or_fork");
  }
  if (sequence === existing.checkpoint_sequence) {
    if (
      candidateCheckpointHash !== existing.checkpoint_hash ||
      candidateEventHash !== existing.event_head_hash
    ) {
      throw new Error("audit_checkpoint_rollback_or_fork");
    }
    return;
  }
  if (
    payload.previous_signed_checkpoint_sequence !== existing.checkpoint_sequence ||
    payload.previous_signed_checkpoint_hash !== existing.checkpoint_hash
  ) {
    throw new Error("audit_checkpoint_previous_mismatch");
  }
}

function verifyEventRange(
  events: Record<string, unknown>[],
  startSequence: number,
  startHash: string,
  targetSequence: number,
  targetHash: string,
  scopeKind: "user" | "workspace",
  scopeId: string,
): void {
  let sequence = startSequence;
  let previousHash = startHash;
  const canonicalEvents = events.map((event) =>
    assertCanonicalAuditChainEvent(event, scopeKind, scopeId),
  );
  if (canonicalEvents.some((event) => Number(event.sequence) > targetSequence)) {
    throw new Error("audit_checkpoint_ancestry_invalid");
  }
  const relevant = canonicalEvents.filter((event) => Number(event.sequence) > startSequence);
  if (relevant.length === 0 && targetSequence !== startSequence) {
    throw new Error("audit_checkpoint_ancestry_missing");
  }
  for (const event of relevant) {
    if (event.sequence !== sequence + 1 || event.previous_event_hash !== previousHash) {
      throw new Error("audit_checkpoint_ancestry_invalid");
    }
    const hash = requiredHash(event.event_hash);
    const preimage: Record<string, StrictJsonValue> = { ...event };
    delete preimage.event_hash;
    if (blake3Base64Url(canonicalizeStrictBytes(preimage)) !== hash) {
      throw new Error("audit_checkpoint_ancestry_invalid");
    }
    sequence += 1;
    previousHash = hash;
  }
  if (sequence !== targetSequence || previousHash !== targetHash) {
    throw new Error("audit_checkpoint_ancestry_invalid");
  }
}

function assertCanonicalAuditChainEvent(
  value: Record<string, unknown>,
  scopeKind: "user" | "workspace",
  scopeId: string,
): Record<string, StrictJsonValue> {
  assertExactKeys(value, [
    "chain_scope_id",
    "chain_scope_kind",
    "event_body",
    "event_hash",
    "event_id",
    "event_type",
    "previous_event_hash",
    "protocol",
    "sequence",
    "version",
  ]);
  if (value.protocol !== "refmd.audit.chain-event" || value.version !== 1) {
    throw new Error("audit_checkpoint_ancestry_invalid");
  }
  const eventId = requiredUuid(value.event_id, "audit_checkpoint_ancestry_invalid");
  if (value.chain_scope_kind !== scopeKind || value.chain_scope_id !== scopeId) {
    throw new Error("audit_checkpoint_scope_mismatch");
  }
  const eventType = requiredString(value.event_type, "audit_checkpoint_ancestry_invalid");
  const eventSequence = requiredPositiveInteger(
    value.sequence,
    "audit_checkpoint_ancestry_invalid",
  );
  if (eventSequence === 1) {
    if (value.previous_event_hash !== "GENESIS") {
      throw new Error("audit_checkpoint_ancestry_invalid");
    }
  } else {
    requiredHash(value.previous_event_hash);
  }
  const body = requiredRecord(value.event_body, "audit_checkpoint_ancestry_invalid");
  if (HIGH_RISK_EVENT_TYPES.has(eventType)) {
    assertHighRiskAuditBody(body, eventType, scopeKind, scopeId);
  } else if (
    HIGH_RISK_RUNTIME_EVENT_TYPES.has(eventType) ||
    LOW_RISK_RUNTIME_EVENTS.has(eventType)
  ) {
    assertSecurityRuntimeAuditBody(body, eventId, eventType);
  } else {
    throw new Error("unknown_security_audit_event");
  }
  requiredHash(value.event_hash);
  return value as Record<string, StrictJsonValue>;
}

function assertHighRiskAuditBody(
  body: Record<string, unknown>,
  eventType: string,
  scopeKind: "user" | "workspace",
  scopeId: string,
): void {
  assertExactKeys(body, [
    "actor",
    "canonical_request_hash",
    "chain_scope_id",
    "chain_scope_kind",
    "event_type",
    "key_directory_effects_hash",
    "mutation_id",
    "protocol",
    "subject_id",
    "subject_kind",
    "version",
  ]);
  if (
    body.protocol !== "refmd.audit.high-risk-mutation" ||
    body.version !== 1 ||
    body.event_type !== eventType ||
    body.chain_scope_kind !== scopeKind ||
    body.chain_scope_id !== scopeId
  ) {
    throw new Error("audit_checkpoint_ancestry_invalid");
  }
  requiredUuid(body.mutation_id, "audit_checkpoint_ancestry_invalid");
  requiredString(body.subject_kind, "audit_checkpoint_ancestry_invalid");
  requiredString(body.subject_id, "audit_checkpoint_ancestry_invalid");
  requiredHash(body.canonical_request_hash);
  requiredHash(body.key_directory_effects_hash);
  const actor = requiredRecord(body.actor, "audit_checkpoint_ancestry_invalid");
  if (actor.kind === "identity") {
    assertExactKeys(actor, ["kind", "user_id"]);
    requiredUuid(actor.user_id, "audit_checkpoint_ancestry_invalid");
  } else if (actor.kind === "device") {
    assertExactKeys(actor, ["device_id", "kind", "user_id"]);
    requiredUuid(actor.user_id, "audit_checkpoint_ancestry_invalid");
    requiredUuid(actor.device_id, "audit_checkpoint_ancestry_invalid");
  } else {
    throw new Error("audit_checkpoint_ancestry_invalid");
  }
}

function assertSecurityRuntimeAuditBody(
  body: Record<string, unknown>,
  eventId: string,
  eventType: string,
): void {
  assertExactKeys(body, [
    "action",
    "actor",
    "class",
    "correlation",
    "created_at",
    "event_id",
    "protocol",
    "resource",
    "scope",
    "sensitivity",
    "type",
    "version",
  ]);
  if (
    body.protocol !== "refmd.security-audit-event" ||
    body.version !== 1 ||
    body.event_id !== eventId ||
    body.type !== eventType ||
    body.class !== "security_runtime"
  ) {
    throw new Error("audit_checkpoint_ancestry_invalid");
  }
  requiredString(body.created_at, "audit_checkpoint_ancestry_invalid");
  assertNullableRecord(
    body.actor,
    ["device_id", "principal_id", "session_id", "user_id"],
    ["principal_kind"],
  );
  assertNullableRecord(body.scope, ["document_id", "share_id", "workspace_id"], []);
  assertNullableRecord(body.resource, ["version_hash"], ["id", "kind"]);
  assertNullableRecord(body.action, ["reason_code"], ["operation", "result"]);
  assertNullableRecord(
    body.correlation,
    ["authority_event_ref", "capability_id", "execution_context_id", "request_id"],
    [],
  );
  const sensitivity = requiredRecord(body.sensitivity, "audit_checkpoint_ancestry_invalid");
  assertExactKeys(sensitivity, [
    "egress_bytes",
    "plaintext_bytes",
    "plaintext_scope_kind",
    "storage_bytes",
  ]);
  requiredString(sensitivity.plaintext_scope_kind, "audit_checkpoint_ancestry_invalid");
  requiredNonNegativeInteger(sensitivity.plaintext_bytes, "audit_checkpoint_ancestry_invalid");
  requiredNonNegativeInteger(sensitivity.egress_bytes, "audit_checkpoint_ancestry_invalid");
  requiredNonNegativeInteger(sensitivity.storage_bytes, "audit_checkpoint_ancestry_invalid");
}

function assertNullableRecord(
  value: unknown,
  nullableKeys: string[],
  requiredStringKeys: string[],
): void {
  const record = requiredRecord(value, "audit_checkpoint_ancestry_invalid");
  assertExactKeys(record, [...nullableKeys, ...requiredStringKeys]);
  for (const key of nullableKeys) {
    if (record[key] !== null) requiredString(record[key], "audit_checkpoint_ancestry_invalid");
  }
  for (const key of requiredStringKeys) {
    requiredString(record[key], "audit_checkpoint_ancestry_invalid");
  }
}

function assertAuditCheckpointPin(value: unknown): AuditCheckpointPin {
  const record = requiredRecord(value, "audit_checkpoint_pin_invalid");
  assertExactKeys(record, [
    "anchor_evidence_hash",
    "authorization_checkpoint_hash",
    "authorization_checkpoint_sequence",
    "chain_scope_id",
    "chain_scope_kind",
    "checkpoint_hash",
    "checkpoint_sequence",
    "checkpoint_variant",
    "event_head_hash",
    "event_head_sequence",
    "protocol",
    "signer_owner_id",
    "signer_owner_kind",
    "signing_key_id",
    "trust_state",
    "version",
  ]);
  if (record.protocol !== "refmd.audit-checkpoint-pin" || record.version !== 1) {
    throw new Error("audit_checkpoint_pin_invalid");
  }
  const chainScopeKind = record.chain_scope_kind;
  if (chainScopeKind !== "user" && chainScopeKind !== "workspace") {
    throw new Error("audit_checkpoint_pin_invalid");
  }
  const trustState = record.trust_state;
  if (trustState !== "anchored" && trustState !== "recovery_unanchored") {
    throw new Error("audit_checkpoint_pin_invalid");
  }
  const anchorEvidenceHash = requiredString(
    record.anchor_evidence_hash,
    "audit_checkpoint_pin_invalid",
  );
  if (trustState === "recovery_unanchored") {
    if (anchorEvidenceHash !== "NONE") throw new Error("audit_checkpoint_pin_invalid");
  } else {
    requiredHash(anchorEvidenceHash);
  }
  return {
    protocol: "refmd.audit-checkpoint-pin",
    version: 1,
    chain_scope_kind: chainScopeKind,
    chain_scope_id: requiredUuid(record.chain_scope_id, "audit_checkpoint_pin_invalid"),
    checkpoint_sequence: requiredPositiveInteger(
      record.checkpoint_sequence,
      "audit_checkpoint_pin_invalid",
    ),
    checkpoint_hash: requiredHash(record.checkpoint_hash),
    event_head_sequence: requiredPositiveInteger(
      record.event_head_sequence,
      "audit_checkpoint_pin_invalid",
    ),
    event_head_hash: requiredHash(record.event_head_hash),
    checkpoint_variant: assertAuditVariant(record.checkpoint_variant),
    signer_owner_kind: assertSignerOwnerKind(record.signer_owner_kind),
    signer_owner_id: requiredUuid(record.signer_owner_id, "audit_checkpoint_pin_invalid"),
    signing_key_id: requiredHash(record.signing_key_id),
    authorization_checkpoint_sequence: requiredNonNegativeInteger(
      record.authorization_checkpoint_sequence,
      "audit_checkpoint_pin_invalid",
    ),
    authorization_checkpoint_hash:
      record.authorization_checkpoint_sequence === 0 &&
      record.authorization_checkpoint_hash === "GENESIS"
        ? "GENESIS"
        : requiredHash(record.authorization_checkpoint_hash),
    trust_state: trustState,
    anchor_evidence_hash: anchorEvidenceHash,
  };
}

function assertUnsignedTailLowRiskOnly(events: Record<string, unknown>[]): void {
  for (const event of events) {
    const eventType = requiredString(event.event_type, "unknown_security_audit_event");
    if (HIGH_RISK_EVENT_TYPES.has(eventType) || HIGH_RISK_RUNTIME_EVENT_TYPES.has(eventType)) {
      throw new Error("audit_checkpoint_high_risk_unsigned_tail");
    }
    const contract = LOW_RISK_RUNTIME_EVENTS.get(eventType);
    if (!contract) throw new Error("unknown_security_audit_event");
    const body = requiredRecord(event.event_body, "unknown_security_audit_event");
    const action = requiredRecord(body.action, "unknown_security_audit_event");
    const sensitivity = requiredRecord(body.sensitivity, "unknown_security_audit_event");
    const correlation = requiredRecord(body.correlation, "unknown_security_audit_event");
    const resource = requiredRecord(body.resource, "unknown_security_audit_event");
    if (
      body.class !== "security_runtime" ||
      resource.kind !== "plugin" ||
      !contract.operations.includes(String(action.operation)) ||
      action.result !== contract.result ||
      sensitivity.plaintext_scope_kind !== "none" ||
      sensitivity.plaintext_bytes !== 0 ||
      sensitivity.egress_bytes !== 0 ||
      sensitivity.storage_bytes !== 0 ||
      correlation.authority_event_ref !== null
    ) {
      throw new Error("unknown_security_audit_event");
    }
  }
}

function auditCheckpointPinSetHash(pinSet: AuditCheckpointPinSet): string {
  return blake3Base64Url(canonicalizeStrictBytes(pinSet as unknown as StrictJsonValue));
}

function auditTransferScopeHash(ownerUserId: string, pins: AuditCheckpointPin[]): string {
  return blake3Base64Url(
    canonicalizeStrictBytes({
      protocol: "refmd.trust-transfer-scope-set",
      version: 1,
      owner_user_id: requiredUuid(ownerUserId, "audit_checkpoint_pin_set_invalid"),
      scope_keys: pins.map(auditPinScopeKey),
    }),
  );
}

function auditPinScopeKey(pin: AuditCheckpointPin): string {
  return `${pin.chain_scope_kind}:${pin.chain_scope_id}`;
}

function compareAuditPinScopes(left: AuditCheckpointPin, right: AuditCheckpointPin): number {
  if (left.chain_scope_kind !== right.chain_scope_kind) {
    return left.chain_scope_kind === "user" ? -1 : 1;
  }
  return left.chain_scope_id.localeCompare(right.chain_scope_id);
}

function assertAuditPinScopeOrder(pins: AuditCheckpointPin[]): void {
  if (pins.length === 0) throw new Error("audit_checkpoint_pin_set_invalid");
  const scopes = pins.map(auditPinScopeKey);
  if (new Set(scopes).size !== scopes.length) {
    throw new Error("audit_checkpoint_pin_set_invalid");
  }
  const sorted = [...pins].sort(compareAuditPinScopes).map(auditPinScopeKey);
  if (scopes.some((scope, index) => scope !== sorted[index])) {
    throw new Error("audit_checkpoint_pin_set_invalid");
  }
}

function sameAuditPin(existing: unknown, candidate: AuditCheckpointPin): boolean {
  try {
    const pin = assertAuditCheckpointPin(existing);
    return (
      pin.checkpoint_sequence === candidate.checkpoint_sequence &&
      pin.checkpoint_hash === candidate.checkpoint_hash &&
      pin.event_head_sequence === candidate.event_head_sequence &&
      pin.event_head_hash === candidate.event_head_hash
    );
  } catch {
    return false;
  }
}

function canMergeAuditPin(existing: unknown, candidate: AuditCheckpointPin): boolean {
  if (existing === undefined) return true;
  try {
    const pin = assertAuditCheckpointPin(existing);
    if (pin.checkpoint_sequence > candidate.checkpoint_sequence) return false;
    if (pin.checkpoint_sequence === candidate.checkpoint_sequence) {
      return sameAuditPin(pin, candidate);
    }
    return true;
  } catch {
    return false;
  }
}

function sameKeyDirectoryPin(existing: unknown, candidate: KeyDirectoryPin): boolean {
  if (typeof existing !== "object" || existing === null) return false;
  const pin = existing as KeyDirectoryPin;
  return (
    pin.pinKey === candidate.pinKey &&
    pin.checkpointSequence === candidate.checkpointSequence &&
    pin.checkpointHash === candidate.checkpointHash &&
    pin.eventHeadSequence === candidate.eventHeadSequence &&
    pin.eventHeadHash === candidate.eventHeadHash
  );
}

function canMergeKeyDirectoryPin(existing: unknown, candidate: KeyDirectoryPin): boolean {
  if (existing === undefined) return true;
  if (typeof existing !== "object" || existing === null) return false;
  const pin = existing as KeyDirectoryPin;
  if (pin.checkpointSequence > candidate.checkpointSequence) return false;
  if (pin.checkpointSequence === candidate.checkpointSequence) {
    return sameKeyDirectoryPin(pin, candidate);
  }
  return true;
}

function assertAuditVariant(value: unknown): AuditCheckpointVariant {
  if (
    value === "user_identity" ||
    value === "user_device" ||
    value === "workspace_device" ||
    value === "workspace_guest_device"
  ) {
    return value;
  }
  throw new Error("audit_checkpoint_pin_invalid");
}

function assertSignerOwnerKind(value: unknown): "identity" | "device" {
  if (value === "identity" || value === "device") return value;
  throw new Error("audit_checkpoint_pin_invalid");
}

function assertExactKeys(record: Record<string, unknown>, keys: string[]): void {
  if (Object.keys(record).sort().join("\0") !== [...keys].sort().join("\0")) {
    throw new Error("unexpected_keys");
  }
}

function requiredRecord(value: unknown, code: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(code);
  return value as Record<string, unknown>;
}

function requiredRecordArray(value: unknown, code: string): Record<string, unknown>[] {
  if (!Array.isArray(value)) throw new Error(code);
  return value.map((entry) => requiredRecord(entry, code));
}

function requiredArray(value: unknown): unknown[] {
  if (!Array.isArray(value)) throw new Error("audit_checkpoint_authority_invalid");
  return value;
}

function requiredHash(value: unknown): string {
  const hash = requiredString(value, "audit_checkpoint_hash_invalid");
  if (!/^[A-Za-z0-9_-]{43}$/.test(hash)) throw new Error("audit_checkpoint_hash_invalid");
  return hash;
}

function requiredString(value: unknown, code: string): string {
  if (typeof value !== "string" || value.length === 0) throw new Error(code);
  return value;
}

function requiredUuid(value: unknown, code: string): string {
  const uuid = requiredString(value, code);
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(uuid)) {
    throw new Error(code);
  }
  return uuid;
}

function requiredPositiveInteger(value: unknown, code: string): number {
  if (!Number.isSafeInteger(value) || Number(value) <= 0) throw new Error(code);
  return Number(value);
}

function requiredNonNegativeInteger(value: unknown, code: string): number {
  if (!Number.isSafeInteger(value) || Number(value) < 0) throw new Error(code);
  return Number(value);
}
