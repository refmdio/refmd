import type { components } from "@/shared/api";
import { hashKeyDirectoryCheckpointEnvelope } from "@/shared/lib/anti-rollback/key-directory-pin/pins";
import { base64UrlEncode } from "@/shared/lib/crypto/encoding";
import { blake3Base64Url } from "@/shared/lib/crypto/hash";
import { computeHybridEncryptionKeyId } from "@/shared/lib/crypto/hybrid-encryption";
import { canonicalizeStrictBytes, type StrictJsonValue } from "@/shared/lib/crypto/jcs";
import {
  activeDeviceSigningKeyId,
  actorWithCheckpointAuthority,
  appendKeyEntryIfMissing,
  checkpointShareParticipantKeys,
  deviceActor,
  eventHash,
  eventHead,
  eventRef,
  keyDirectoryCheckpoint,
  keyDirectoryEvent,
  keyEntry,
  numberField,
  signCheckpoint,
  signEvent,
  stringField,
} from "@/shared/lib/crypto/key-directory/primitives";
import { wrapIssuedKeyDirectoryEventFromRecord } from "@/shared/lib/crypto/key-directory/wrap-events";
import type { KeyDirectoryEnvelope } from "@/shared/lib/crypto/key-directory/types";
import { computeSigningKeyId } from "@/shared/lib/crypto/signature";
import type { SignedPqWrapRecord } from "@/shared/lib/crypto/signed-pq-wrap";
import { getCryptoWorker } from "@/shared/lib/crypto/worker/client";
import type { WorkspacePinBootstrapEnvelope } from "@/shared/lib/key-directory/workspace-pin-bootstrap";

type DeliveryAttempt = components["schemas"]["InvitationDeliveryAttemptResponse"];
type TargetRegistration = components["schemas"]["InvitationDeliveryTargetRegistration"];

export interface MemberGossipStatement {
  payload: Record<string, unknown>;
  transcript: Record<string, unknown>;
  signature: Record<string, unknown>;
  signing_key_id: string;
  hybrid_signing_public_key_material: Record<string, unknown>;
}

export interface WorkspaceRecipientDeliveryApproval {
  authorization: Record<string, unknown>;
  redeem_freshness_proof: Record<string, unknown>;
  workspace_pin_bootstrap: WorkspacePinBootstrapEnvelope;
  delivery_wrap: SignedPqWrapRecord;
  member_envelope: SignedPqWrapRecord & {
    target_user_id: string;
    sender_device_id: string;
    key_version: number;
  };
  workspace_key_directory_events: KeyDirectoryEnvelope[];
  workspace_key_directory_checkpoint: KeyDirectoryEnvelope;
}

export interface GuestRecipientDeliveryApproval {
  authorization: Record<string, unknown>;
  redeem_freshness_proof: Record<string, unknown>;
  workspace_pin_bootstrap: WorkspacePinBootstrapEnvelope;
  delivery_wrap: SignedPqWrapRecord;
  workspace_key_directory_events: KeyDirectoryEnvelope[];
  workspace_key_directory_intermediate_checkpoint: KeyDirectoryEnvelope;
  workspace_key_directory_checkpoint: KeyDirectoryEnvelope;
}

export async function buildWorkspaceRecipientDeliveryApproval(params: {
  attempt: DeliveryAttempt;
  checkpointEnvelope: KeyDirectoryEnvelope;
  workspacePinBootstrap: WorkspacePinBootstrapEnvelope;
  workspacePinBootstrapHash: string;
  actorUserId: string;
  actorDeviceId: string;
  memberGossipStatements?: MemberGossipStatement[];
}): Promise<WorkspaceRecipientDeliveryApproval> {
  const { attempt } = params;
  if (attempt.context_kind !== "workspace_invitation") {
    throw new Error("invitation_delivery_context_invalid");
  }
  const context = attempt.context_snapshot as Record<string, unknown>;
  const target = plainTargetRegistration(attempt.target_registration as TargetRegistration);
  const checkpointPayload = params.checkpointEnvelope.payload as Record<string, unknown>;
  const coveredHead = checkpointPayload.covered_event_head as Record<string, unknown>;
  const baseOperationCheckpoint = operationCheckpointFromEnvelope(params.checkpointEnvelope);
  const actorSigningKeyId = activeDeviceSigningKeyId(checkpointPayload, params.actorDeviceId);
  const freshnessProof = redeemFreshnessProof({
    attempt,
    checkpointEnvelope: params.checkpointEnvelope,
    actorUserId: params.actorUserId,
    actorDeviceId: params.actorDeviceId,
    memberGossipStatements: params.memberGossipStatements,
  });
  const authorizationPayload = {
    protocol: "refmd.recipient-bound-authorization",
    version: 1,
    authorization_id: crypto.randomUUID(),
    redeem_attempt_id: attempt.redeem_attempt_id,
    workspace_id: attempt.workspace_id,
    context_kind: attempt.context_kind,
    context_id: attempt.context_id,
    resource_hash: attempt.resource_hash,
    recipient: {
      recipient_kind: "invitee",
      recipient_principal_id: attempt.target_user_id,
      recipient_device_id: attempt.target_device_id,
      encryption_key_id: attempt.target_encryption_key_id,
    },
    workspace_pin_bootstrap_hash: params.workspacePinBootstrapHash,
    current_checkpoint_sequence: numberField(checkpointPayload.sequence),
    current_checkpoint_hash: hashKeyDirectoryCheckpointEnvelope(params.checkpointEnvelope),
    current_event_head_sequence: numberField(coveredHead.head_sequence),
    current_event_head_hash: stringField(coveredHead.head_hash),
    redeem_authority_signing_key_id: actorSigningKeyId,
    recipient_redeem_nonce: attempt.recipient_redeem_nonce,
    recipient_nonce_state_hash: attempt.recipient_nonce_state_hash,
    live_redeem_challenge_hash: attempt.live_redeem_challenge_hash,
    redeem_freshness_proof_hash: hash(freshnessProof),
    not_after_event_sequence: numberField(coveredHead.head_sequence) + 1,
  };
  const signedAuthorization = await getCryptoWorker().signRecipientBoundAuthorization({
    authorizationPayload,
  });
  const authorization = {
    payload: authorizationPayload,
    transcript: signedAuthorization.transcript,
    signature: signedAuthorization.signature,
    signing_key_id: signedAuthorization.signing_key_id,
    hybrid_signing_public_key_material: signedAuthorization.hybrid_signing_public_key_material,
  };
  const authorizationHash = hash(authorizationPayload);
  const recipientHash = hash(authorizationPayload.recipient);
  const admissionEvent = keyDirectoryEvent({
    scopeKind: "workspace",
    scopeId: attempt.workspace_id,
    sequence: numberField(coveredHead.head_sequence) + 1,
    eventType: "recipient_bound_delivery_admitted",
    actor: actorWithCheckpointAuthority(
      deviceActor(params.actorUserId, params.actorDeviceId, actorSigningKeyId),
      "workspace",
      attempt.workspace_id,
      checkpointPayload,
    ),
    previousEventHash: stringField(coveredHead.head_hash),
    body: {
      event_type: "recipient_bound_delivery_admitted",
      authorization_id: authorizationPayload.authorization_id,
      redeem_attempt_id: attempt.redeem_attempt_id,
      authorization_hash: authorizationHash,
      workspace_id: attempt.workspace_id,
      context_kind: attempt.context_kind,
      context_id: attempt.context_id,
      recipient_hash: recipientHash,
      recipient_device_id: attempt.target_device_id,
      permission: "NOT_APPLICABLE",
      share_session_id: "NOT_APPLICABLE",
      share_session_binding_hash: "NOT_APPLICABLE",
      recipient_nonce_state_hash: attempt.recipient_nonce_state_hash,
      live_redeem_challenge_hash: attempt.live_redeem_challenge_hash,
      redeem_freshness_proof_hash: authorizationPayload.redeem_freshness_proof_hash,
      previous_workspace_event_sequence: numberField(coveredHead.head_sequence),
      previous_workspace_event_hash: stringField(coveredHead.head_hash),
      admission_nonce: randomBase64Url32(),
    },
  });
  const signedAdmissionEvent = await signEvent("device", admissionEvent);

  let memberWrap = await getCryptoWorker().createSignedPqKekWrap({
    purpose: "workspace_member_kek_wrap",
    workspaceId: attempt.workspace_id,
    keyVersion: numberField(context.kek_version),
    recipientPublicKeyMaterial: target.identity_hybrid_encryption_public_key_material,
    senderUserId: params.actorUserId,
    senderDeviceId: params.actorDeviceId,
    resource: {
      workspace_id: attempt.workspace_id,
      target_user_id: attempt.target_user_id,
      kek_version: numberField(context.kek_version),
    },
    eventScope: { scope_kind: "workspace", scope_id: attempt.workspace_id },
    operationCheckpoint: baseOperationCheckpoint,
    eventPrevious: {
      sequence: numberField(admissionEvent.sequence),
      hash: eventHash(admissionEvent),
    },
    recipientKeyCheckpoint: {
      scopeKind: "user",
      scopeId: attempt.recipient_user_id,
      sequence: numberField(attempt.target_key_checkpoint_sequence),
      checkpointHash: stringField(attempt.target_key_checkpoint_hash),
    },
  });
  const memberWrapEvent = wrapIssuedKeyDirectoryEventFromRecord({
    scopeKind: "workspace",
    scopeId: attempt.workspace_id,
    coveredHead: eventHead(admissionEvent),
    wrapRecord: memberWrap,
  });
  const signedMemberWrapEvent = await signEvent("device", memberWrapEvent);

  const redeemedEvent = keyDirectoryEvent({
    scopeKind: "workspace",
    scopeId: attempt.workspace_id,
    sequence: numberField(memberWrapEvent.sequence) + 1,
    eventType: "workspace_invitation_redeemed",
    actor: actorWithCheckpointAuthority(
      deviceActor(params.actorUserId, params.actorDeviceId, actorSigningKeyId),
      "workspace",
      attempt.workspace_id,
      checkpointPayload,
    ),
    previousEventHash: eventHash(memberWrapEvent),
    body: {
      workspace_id: attempt.workspace_id,
      invitation_id: attempt.context_id,
      redeemed_user_id: attempt.target_user_id,
      redeemed_device_id: attempt.target_device_id,
      redeemed_encryption_key_id: attempt.target_encryption_key_id,
      member_envelope_key_version: numberField(context.kek_version),
      member_envelope_hash: memberWrap.event.wrap_event_body_hash,
      redeemed_at_event_sequence: numberField(memberWrapEvent.sequence) + 1,
    },
  });
  const signedRedeemedEvent = await signEvent("device", redeemedEvent);
  const redeemedEventHash = eventHash(redeemedEvent);

  let deliveryWrap = await getCryptoWorker().createSignedPqKekWrap({
    purpose: "workspace_invitation_kek_wrap",
    workspaceId: attempt.workspace_id,
    keyVersion: numberField(context.kek_version),
    recipientPublicKeyMaterial: target.device_hybrid_encryption_public_key_material,
    senderUserId: params.actorUserId,
    senderDeviceId: params.actorDeviceId,
    resource: {
      workspace_id: attempt.workspace_id,
      invitation_id: attempt.context_id,
      redeemed_user_id: attempt.target_user_id,
      redeemed_device_id: attempt.target_device_id,
      recipient_encryption_key_id: attempt.target_encryption_key_id,
      role_id: stringField(context.role_id),
      kek_version: numberField(context.kek_version),
      workspace_invitation_redeemed_event_hash: redeemedEventHash,
    },
    eventScope: { scope_kind: "workspace", scope_id: attempt.workspace_id },
    operationCheckpoint: baseOperationCheckpoint,
    eventPrevious: {
      sequence: numberField(redeemedEvent.sequence),
      hash: redeemedEventHash,
    },
    recipientKeyCheckpoint: {
      scopeKind: "user",
      scopeId: attempt.recipient_user_id,
      sequence: numberField(attempt.target_key_checkpoint_sequence),
      checkpointHash: stringField(attempt.target_key_checkpoint_hash),
    },
  });
  const deliveryWrapEvent = wrapIssuedKeyDirectoryEventFromRecord({
    scopeKind: "workspace",
    scopeId: attempt.workspace_id,
    coveredHead: eventHead(redeemedEvent),
    wrapRecord: deliveryWrap,
  });
  const signedDeliveryWrapEvent = await signEvent("device", deliveryWrapEvent);
  const finalCheckpointPayload = keyDirectoryCheckpoint({
    scopeKind: "workspace",
    scopeId: attempt.workspace_id,
    sequence: numberField(checkpointPayload.sequence) + 1,
    issuedAt: new Date().toISOString(),
    previousCheckpointHash: hashKeyDirectoryCheckpointEnvelope(params.checkpointEnvelope),
    coveredEventHead: eventHead(deliveryWrapEvent),
    identityKeys: appendKeyEntryIfMissing(
      (checkpointPayload.identity_keys as Record<string, unknown>[] | undefined) ?? [],
      keyEntry(
        computeHybridEncryptionKeyId(target.identity_hybrid_encryption_public_key_material),
        target.identity_hybrid_encryption_public_key_material,
        eventRef("workspace", attempt.workspace_id, redeemedEvent),
      ),
    ),
    deviceKeys: appendKeyEntryIfMissing(
      appendKeyEntryIfMissing(
        (checkpointPayload.device_keys as Record<string, unknown>[] | undefined) ?? [],
        keyEntry(
          computeSigningKeyId(target.device_hybrid_signing_public_key_material),
          target.device_hybrid_signing_public_key_material,
          eventRef("workspace", attempt.workspace_id, redeemedEvent),
        ),
      ),
      keyEntry(
        attempt.target_encryption_key_id,
        target.device_hybrid_encryption_public_key_material,
        eventRef("workspace", attempt.workspace_id, redeemedEvent),
      ),
    ),
    shareParticipantKeys: checkpointShareParticipantKeys(checkpointPayload),
    revokedKeyIds: (checkpointPayload.revoked_key_ids as string[] | undefined) ?? [],
  });
  const finalCheckpoint = await signCheckpoint(
    "device",
    "workspace_authorized",
    finalCheckpointPayload,
  );
  const finalOperationCheckpoint = operationCheckpointFromEnvelope(finalCheckpoint);
  memberWrap = await getCryptoWorker().finalizeSignedPqWrapOperationCheckpoint({
    record: memberWrap,
    operationCheckpoint: finalOperationCheckpoint,
  });
  deliveryWrap = await getCryptoWorker().finalizeSignedPqWrapOperationCheckpoint({
    record: deliveryWrap,
    operationCheckpoint: finalOperationCheckpoint,
  });

  return {
    authorization,
    redeem_freshness_proof: freshnessProof,
    workspace_pin_bootstrap: params.workspacePinBootstrap,
    delivery_wrap: deliveryWrap,
    member_envelope: {
      target_user_id: attempt.target_user_id,
      sender_device_id: params.actorDeviceId,
      key_version: numberField(context.kek_version),
      ...memberWrap,
    },
    workspace_key_directory_events: [
      signedAdmissionEvent,
      signedMemberWrapEvent,
      signedRedeemedEvent,
      signedDeliveryWrapEvent,
    ],
    workspace_key_directory_checkpoint: finalCheckpoint,
  };
}

export async function buildGuestRecipientDeliveryApproval(params: {
  attempt: DeliveryAttempt;
  checkpointEnvelope: KeyDirectoryEnvelope;
  workspacePinBootstrap: WorkspacePinBootstrapEnvelope;
  workspacePinBootstrapHash: string;
  actorUserId: string;
  actorDeviceId: string;
  shareSlug?: string;
  memberGossipStatements?: MemberGossipStatement[];
}): Promise<GuestRecipientDeliveryApproval> {
  const { attempt } = params;
  if (attempt.context_kind !== "guest_invitation") {
    throw new Error("invitation_delivery_context_invalid");
  }
  const context = attempt.context_snapshot as Record<string, unknown>;
  const scopeKind = stringField(context.scope_kind);
  const scopeId = stringField(context.scope_id);
  const permission = stringField(context.permission);
  const workspaceScope = scopeKind === "workspace";
  if (
    (workspaceScope && (scopeId !== "none" || context.kek_version == null)) ||
    (!workspaceScope &&
      (!(["document", "folder", "share"] as string[]).includes(scopeKind) ||
        context.kek_version != null ||
        !params.shareSlug))
  ) {
    throw new Error("guest_invitation_key_context_invalid");
  }
  const target = plainTargetRegistration(attempt.target_registration as TargetRegistration);
  const checkpointPayload = params.checkpointEnvelope.payload as Record<string, unknown>;
  const coveredHead = checkpointPayload.covered_event_head as Record<string, unknown>;
  const baseOperationCheckpoint = operationCheckpointFromEnvelope(params.checkpointEnvelope);
  const actorSigningKeyId = activeDeviceSigningKeyId(checkpointPayload, params.actorDeviceId);
  const freshnessProof = redeemFreshnessProof({
    attempt,
    checkpointEnvelope: params.checkpointEnvelope,
    actorUserId: params.actorUserId,
    actorDeviceId: params.actorDeviceId,
    memberGossipStatements: params.memberGossipStatements,
  });
  const authorizationPayload = {
    protocol: "refmd.recipient-bound-authorization",
    version: 1,
    authorization_id: crypto.randomUUID(),
    redeem_attempt_id: attempt.redeem_attempt_id,
    workspace_id: attempt.workspace_id,
    context_kind: attempt.context_kind,
    context_id: attempt.context_id,
    resource_hash: attempt.resource_hash,
    recipient: {
      recipient_kind: "guest",
      recipient_principal_id: attempt.target_user_id,
      recipient_device_id: attempt.target_device_id,
      encryption_key_id: attempt.target_encryption_key_id,
    },
    workspace_pin_bootstrap_hash: params.workspacePinBootstrapHash,
    current_checkpoint_sequence: numberField(checkpointPayload.sequence),
    current_checkpoint_hash: hashKeyDirectoryCheckpointEnvelope(params.checkpointEnvelope),
    current_event_head_sequence: numberField(coveredHead.head_sequence),
    current_event_head_hash: stringField(coveredHead.head_hash),
    redeem_authority_signing_key_id: actorSigningKeyId,
    recipient_redeem_nonce: attempt.recipient_redeem_nonce,
    recipient_nonce_state_hash: attempt.recipient_nonce_state_hash,
    live_redeem_challenge_hash: attempt.live_redeem_challenge_hash,
    redeem_freshness_proof_hash: hash(freshnessProof),
    not_after_event_sequence: numberField(coveredHead.head_sequence) + 1,
  };
  const signedAuthorization = await getCryptoWorker().signRecipientBoundAuthorization({
    authorizationPayload,
  });
  const authorization = {
    payload: authorizationPayload,
    transcript: signedAuthorization.transcript,
    signature: signedAuthorization.signature,
    signing_key_id: signedAuthorization.signing_key_id,
    hybrid_signing_public_key_material: signedAuthorization.hybrid_signing_public_key_material,
  };
  const admissionEvent = keyDirectoryEvent({
    scopeKind: "workspace",
    scopeId: attempt.workspace_id,
    sequence: numberField(coveredHead.head_sequence) + 1,
    eventType: "recipient_bound_delivery_admitted",
    actor: actorWithCheckpointAuthority(
      deviceActor(params.actorUserId, params.actorDeviceId, actorSigningKeyId),
      "workspace",
      attempt.workspace_id,
      checkpointPayload,
    ),
    previousEventHash: stringField(coveredHead.head_hash),
    body: {
      event_type: "recipient_bound_delivery_admitted",
      authorization_id: authorizationPayload.authorization_id,
      redeem_attempt_id: attempt.redeem_attempt_id,
      authorization_hash: hash(authorizationPayload),
      workspace_id: attempt.workspace_id,
      context_kind: attempt.context_kind,
      context_id: attempt.context_id,
      recipient_hash: hash(authorizationPayload.recipient),
      recipient_device_id: attempt.target_device_id,
      permission: "NOT_APPLICABLE",
      share_session_id: "NOT_APPLICABLE",
      share_session_binding_hash: "NOT_APPLICABLE",
      recipient_nonce_state_hash: attempt.recipient_nonce_state_hash,
      live_redeem_challenge_hash: attempt.live_redeem_challenge_hash,
      redeem_freshness_proof_hash: authorizationPayload.redeem_freshness_proof_hash,
      previous_workspace_event_sequence: numberField(coveredHead.head_sequence),
      previous_workspace_event_hash: stringField(coveredHead.head_hash),
      admission_nonce: randomBase64Url32(),
    },
  });
  const signedAdmissionEvent = await signEvent("device", admissionEvent);
  const guestGrantId = crypto.randomUUID();
  const redeemedEvent = keyDirectoryEvent({
    scopeKind: "workspace",
    scopeId: attempt.workspace_id,
    sequence: numberField(admissionEvent.sequence) + 1,
    eventType: "guest_invitation_redeemed",
    actor: actorWithCheckpointAuthority(
      deviceActor(params.actorUserId, params.actorDeviceId, actorSigningKeyId),
      "workspace",
      attempt.workspace_id,
      checkpointPayload,
    ),
    previousEventHash: eventHash(admissionEvent),
    body: {
      workspace_id: attempt.workspace_id,
      guest_invitation_id: attempt.context_id,
      guest_grant_id: guestGrantId,
      guest_user_id: attempt.target_user_id,
      guest_device_id: attempt.target_device_id,
      guest_encryption_key_id: attempt.target_encryption_key_id,
      guest_signing_key_id: computeSigningKeyId(target.device_hybrid_signing_public_key_material),
      scope_kind: scopeKind,
      scope_id: scopeId,
      permission,
      recipient_account_user_id: attempt.recipient_user_id,
      recipient_account_device_id: attempt.recipient_device_id,
      redeemed_at_event_sequence: numberField(admissionEvent.sequence) + 1,
    },
  });
  const signedRedeemedEvent = await signEvent("device", redeemedEvent);
  const guestIdentityEncryptionKeyId = computeHybridEncryptionKeyId(
    target.identity_hybrid_encryption_public_key_material,
  );
  const guestDeviceSigningKeyId = computeSigningKeyId(
    target.device_hybrid_signing_public_key_material,
  );
  const intermediateCheckpointPayload = keyDirectoryCheckpoint({
    scopeKind: "workspace",
    scopeId: attempt.workspace_id,
    sequence: numberField(checkpointPayload.sequence) + 1,
    issuedAt: new Date().toISOString(),
    previousCheckpointHash: hashKeyDirectoryCheckpointEnvelope(params.checkpointEnvelope),
    coveredEventHead: eventHead(redeemedEvent),
    identityKeys: appendKeyEntryIfMissing(
      (checkpointPayload.identity_keys as Record<string, unknown>[] | undefined) ?? [],
      keyEntry(
        guestIdentityEncryptionKeyId,
        target.identity_hybrid_encryption_public_key_material,
        eventRef("workspace", attempt.workspace_id, redeemedEvent),
      ),
    ),
    deviceKeys: appendKeyEntryIfMissing(
      appendKeyEntryIfMissing(
        (checkpointPayload.device_keys as Record<string, unknown>[] | undefined) ?? [],
        keyEntry(
          guestDeviceSigningKeyId,
          target.device_hybrid_signing_public_key_material,
          eventRef("workspace", attempt.workspace_id, redeemedEvent),
        ),
      ),
      keyEntry(
        attempt.target_encryption_key_id,
        target.device_hybrid_encryption_public_key_material,
        eventRef("workspace", attempt.workspace_id, redeemedEvent),
      ),
    ),
    shareParticipantKeys: checkpointShareParticipantKeys(checkpointPayload),
    revokedKeyIds: (checkpointPayload.revoked_key_ids as string[] | undefined) ?? [],
  });
  const intermediateCheckpoint = await signCheckpoint(
    "device",
    "workspace_authorized",
    intermediateCheckpointPayload,
  );
  const redeemedEventHash = eventHash(redeemedEvent);
  const commonWrapParams = {
    recipientPublicKeyMaterial: target.device_hybrid_encryption_public_key_material,
    senderUserId: params.actorUserId,
    senderDeviceId: params.actorDeviceId,
    eventScope: { scope_kind: "workspace", scope_id: attempt.workspace_id },
    operationCheckpoint: baseOperationCheckpoint,
    eventPrevious: {
      sequence: numberField(redeemedEvent.sequence),
      hash: redeemedEventHash,
    },
    recipientKeyCheckpoint: {
      scopeKind: "workspace" as const,
      scopeId: attempt.workspace_id,
      sequence: numberField(intermediateCheckpointPayload.sequence),
      checkpointHash: hashKeyDirectoryCheckpointEnvelope(intermediateCheckpoint),
    },
  };
  let deliveryWrap = workspaceScope
    ? await getCryptoWorker().createSignedPqKekWrap({
        ...commonWrapParams,
        purpose: "guest_invitation_workspace_kek_wrap",
        workspaceId: attempt.workspace_id,
        keyVersion: numberField(context.kek_version),
        resource: {
          workspace_id: attempt.workspace_id,
          guest_invitation_id: attempt.context_id,
          guest_user_id: attempt.target_user_id,
          guest_device_id: attempt.target_device_id,
          recipient_encryption_key_id: attempt.target_encryption_key_id,
          guest_grant_id: guestGrantId,
          scope_kind: "workspace",
          scope_id: "none",
          permission,
          kek_version: numberField(context.kek_version),
          guest_invitation_redeemed_event_hash: redeemedEventHash,
        },
      })
    : await getCryptoWorker().createSignedPqGuestInvitationShareKeyWrap({
        ...commonWrapParams,
        shareSlug: params.shareSlug!,
        resource: {
          workspace_id: attempt.workspace_id,
          guest_invitation_id: attempt.context_id,
          guest_user_id: attempt.target_user_id,
          guest_device_id: attempt.target_device_id,
          recipient_encryption_key_id: attempt.target_encryption_key_id,
          share_id: stringField(context.share_id),
          scope_kind: stringField(context.resource_scope_kind),
          scope_id: stringField(context.resource_scope_id),
          permission,
          document_scope_hash: stringField(context.document_scope_hash),
          share_key_version: numberField(context.share_key_version),
          dek_version: numberField(context.dek_version),
          guest_invitation_redeemed_event_hash: redeemedEventHash,
        },
      });
  const deliveryWrapEvent = wrapIssuedKeyDirectoryEventFromRecord({
    scopeKind: "workspace",
    scopeId: attempt.workspace_id,
    coveredHead: eventHead(redeemedEvent),
    wrapRecord: deliveryWrap,
  });
  const signedDeliveryWrapEvent = await signEvent("device", deliveryWrapEvent);
  const finalCheckpointPayload = keyDirectoryCheckpoint({
    scopeKind: "workspace",
    scopeId: attempt.workspace_id,
    sequence: numberField(intermediateCheckpointPayload.sequence) + 1,
    issuedAt: new Date().toISOString(),
    previousCheckpointHash: hashKeyDirectoryCheckpointEnvelope(intermediateCheckpoint),
    coveredEventHead: eventHead(deliveryWrapEvent),
    identityKeys: intermediateCheckpointPayload.identity_keys as Record<string, unknown>[],
    deviceKeys: intermediateCheckpointPayload.device_keys as Record<string, unknown>[],
    shareParticipantKeys: checkpointShareParticipantKeys(intermediateCheckpointPayload),
    revokedKeyIds: (intermediateCheckpointPayload.revoked_key_ids as string[] | undefined) ?? [],
  });
  const finalCheckpoint = await signCheckpoint(
    "device",
    "workspace_authorized",
    finalCheckpointPayload,
  );
  deliveryWrap = await getCryptoWorker().finalizeSignedPqWrapOperationCheckpoint({
    record: deliveryWrap,
    operationCheckpoint: operationCheckpointFromEnvelope(finalCheckpoint),
  });

  return {
    authorization,
    redeem_freshness_proof: freshnessProof,
    workspace_pin_bootstrap: params.workspacePinBootstrap,
    delivery_wrap: deliveryWrap,
    workspace_key_directory_events: [
      signedAdmissionEvent,
      signedRedeemedEvent,
      signedDeliveryWrapEvent,
    ],
    workspace_key_directory_intermediate_checkpoint: intermediateCheckpoint,
    workspace_key_directory_checkpoint: finalCheckpoint,
  };
}

export function redeemFreshnessProof(params: {
  attempt: DeliveryAttempt;
  checkpointEnvelope: KeyDirectoryEnvelope;
  actorUserId: string;
  actorDeviceId: string;
  memberGossipStatements?: MemberGossipStatement[];
}): Record<string, unknown> {
  const payload = params.checkpointEnvelope.payload as Record<string, unknown>;
  const coveredHead = payload.covered_event_head as Record<string, unknown>;
  const common = {
    protocol: "refmd.redeem-freshness-proof",
    version: 1,
    workspace_id: params.attempt.workspace_id,
    current_event_head_sequence: numberField(coveredHead.head_sequence),
    current_event_head_hash: stringField(coveredHead.head_hash),
    current_checkpoint_hash: hashKeyDirectoryCheckpointEnvelope(params.checkpointEnvelope),
    recipient_redeem_nonce: params.attempt.recipient_redeem_nonce,
    live_redeem_challenge_hash: params.attempt.live_redeem_challenge_hash,
  };

  if (!params.memberGossipStatements) {
    return {
      ...common,
      proof_kind: "authoritative_device_live",
      authoritative_device: {
        user_id: params.actorUserId,
        device_id: params.actorDeviceId,
      },
    };
  }

  const statements = params.memberGossipStatements;
  const userIds = statements.map((statement) => stringField(statement.payload.user_id));
  if (statements.length < 2 || new Set(userIds).size !== userIds.length) {
    throw new Error("member_gossip_quorum_invalid");
  }
  const proofHashes = statements.map((statement) => hash(statement.payload)).sort();
  if (new Set(proofHashes).size !== proofHashes.length) {
    throw new Error("member_gossip_quorum_invalid");
  }

  return {
    ...common,
    proof_kind: "member_gossip_quorum",
    proof_hashes: proofHashes,
    gossip_statements: statements,
  };
}

function plainTargetRegistration(target: TargetRegistration): TargetRegistration {
  return {
    identity_hybrid_encryption_public_key_material: {
      ...target.identity_hybrid_encryption_public_key_material,
    },
    identity_hybrid_signing_public_key_material: {
      ...target.identity_hybrid_signing_public_key_material,
    },
    device_hybrid_encryption_public_key_material: {
      ...target.device_hybrid_encryption_public_key_material,
    },
    device_hybrid_signing_public_key_material: {
      ...target.device_hybrid_signing_public_key_material,
    },
  };
}

function operationCheckpointFromEnvelope(envelope: KeyDirectoryEnvelope) {
  const payload = envelope.payload as Record<string, unknown>;
  const coveredHead = payload.covered_event_head as Record<string, unknown>;
  return {
    sequence: numberField(payload.sequence),
    checkpointHash: hashKeyDirectoryCheckpointEnvelope(envelope),
    coveredHeadSequence: numberField(coveredHead.head_sequence),
    coveredHeadHash: stringField(coveredHead.head_hash),
  };
}

function hash(value: unknown): string {
  return blake3Base64Url(canonicalizeStrictBytes(value as StrictJsonValue));
}

function randomBase64Url32(): string {
  return base64UrlEncode(crypto.getRandomValues(new Uint8Array(32)));
}
