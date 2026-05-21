import { decodeBase64UrlStrict } from "./encoding";
import { blake3Base64Url } from "./hash";
import { canonicalizeStrictBytes, type StrictJsonValue } from "./jcs";
import { getActiveSigningSurface } from "./signing-surface";
import { CURRENT_PROTOCOL_VERSION } from "./suite";
import {
  collaborationVariant,
  transcriptBase,
  type SigningOwnerKind,
} from "./signature-transcript-core";

export function buildDocumentUpdateTranscript(params: {
  ownerKind: SigningOwnerKind;
  ownerId: string;
  workspaceId: string;
  actorUserId: string;
  actorDeviceId: string;
  signingKeyId: string;
  publicData: Record<string, unknown>;
  authorityBoundary: Record<string, unknown>;
  ciphertext: string;
  nonce: string;
}): StrictJsonValue {
  const surface = getActiveSigningSurface(
    "document_update",
    collaborationVariant(params.ownerKind),
  );
  const subject = canonicalizeStrictBytes({
    ciphertext: params.ciphertext,
    nonce: params.nonce,
    publicData: params.publicData,
  } as unknown as StrictJsonValue);

  return transcriptBase("document_update", surface, params.ownerKind, params.ownerId, {
    document_id: params.publicData.docId,
    ciphertext_hash: blake3Base64Url(decodeBase64UrlStrict(params.ciphertext)),
    nonce: params.nonce,
    public_data: params.publicData,
    subject_protocol: "refmd.ws.document_update",
    subject_version: CURRENT_PROTOCOL_VERSION,
    subject_hash: blake3Base64Url(subject),
    actor: collaborationActor(params),
    authority_boundary: params.authorityBoundary,
  });
}

export function buildDocumentSnapshotTranscript(params: {
  ownerKind: SigningOwnerKind;
  ownerId: string;
  workspaceId: string;
  actorUserId: string;
  actorDeviceId: string;
  signingKeyId: string;
  publicData: Record<string, unknown>;
  authorityBoundary: Record<string, unknown>;
  ciphertext: string;
  nonce: string;
}): StrictJsonValue {
  const surface = getActiveSigningSurface(
    "document_snapshot",
    collaborationVariant(params.ownerKind),
  );
  const publicDataForSubject = normalizeSnapshotPublicDataForSubject(params.publicData);
  const subject = canonicalizeStrictBytes({
    ciphertext: params.ciphertext,
    nonce: params.nonce,
    publicData: publicDataForSubject,
  } as unknown as StrictJsonValue);

  return transcriptBase("document_snapshot", surface, params.ownerKind, params.ownerId, {
    document_id: params.publicData.docId,
    snapshot_id: params.publicData.snapshotId,
    ciphertext_hash: blake3Base64Url(decodeBase64UrlStrict(params.ciphertext)),
    nonce: params.nonce,
    public_data: publicDataForSubject,
    subject_protocol: "refmd.ws.document_snapshot",
    subject_version: CURRENT_PROTOCOL_VERSION,
    subject_hash: blake3Base64Url(subject),
    actor: collaborationActor(params),
    authority_boundary: params.authorityBoundary,
  });
}

function collaborationActor(params: {
  ownerKind: SigningOwnerKind;
  actorUserId: string;
  actorDeviceId: string;
  signingKeyId: string;
  workspaceId: string;
  publicData: Record<string, unknown>;
}): StrictJsonValue {
  if (params.ownerKind === "share_participant_device") {
    return {
      signer_kind: "share_participant_device",
      share_id: params.publicData.authorityId,
      share_participant_principal_id: params.actorUserId,
      share_participant_device_id: params.actorDeviceId,
      signing_key_id: params.signingKeyId,
      key_scope_kind: "workspace",
      key_scope_id: params.workspaceId,
      key_checkpoint_sequence: params.publicData.keyCheckpointSequence,
      key_checkpoint_hash: params.publicData.keyCheckpointHash,
    } as StrictJsonValue;
  }

  return {
    signer_kind: "workspace_device",
    device_id: params.actorDeviceId,
    signing_key_id: params.signingKeyId,
    user_id: params.actorUserId,
    key_scope_kind: "workspace",
    key_scope_id: params.workspaceId,
    key_checkpoint_sequence: params.publicData.keyCheckpointSequence,
    key_checkpoint_hash: params.publicData.keyCheckpointHash,
  } as StrictJsonValue;
}

function normalizeSnapshotPublicDataForSubject(
  publicData: Record<string, unknown>,
): Record<string, unknown> {
  return {
    ...publicData,
    parentSnapshotId: publicData.parentSnapshotId ?? "GENESIS",
  };
}

export function buildEditorEphemeralTranscript(params: {
  ownerKind: SigningOwnerKind;
  ownerId: string;
  workspaceId: string;
  actorUserId: string;
  actorDeviceId: string;
  signingKeyId: string;
  publicData: Record<string, unknown>;
  authorityBoundary: Record<string, unknown>;
  ciphertext: string;
  nonce: string;
}): StrictJsonValue {
  const surface = getActiveSigningSurface(
    "editor_ephemeral",
    collaborationVariant(params.ownerKind),
  );
  const subject = canonicalizeStrictBytes({
    ciphertext: params.ciphertext,
    nonce: params.nonce,
    publicData: params.publicData,
  } as unknown as StrictJsonValue);

  return transcriptBase("editor_ephemeral", surface, params.ownerKind, params.ownerId, {
    subject_hash: blake3Base64Url(subject),
    subject_protocol: "refmd.editor-ephemeral",
    subject_version: CURRENT_PROTOCOL_VERSION,
    actor: collaborationActor(params),
    session: {
      workspace_id: params.workspaceId,
      document_id: params.publicData.docId,
      channel_id: params.publicData.docId,
      message_nonce: params.nonce,
    },
    authority_boundary: params.authorityBoundary,
  });
}

export function buildEditorEphemeralSessionTranscript(params: {
  ownerKind: SigningOwnerKind;
  ownerId: string;
  workspaceId: string;
  documentId: string;
  channelId: string;
  actorUserId: string;
  actorDeviceId: string;
  signingKeyId: string;
  sessionId: string;
  proofDirection: string;
  proofType: string;
  sessionNonce: string;
  counter: number;
  expiresEventSequence: number;
  keyCheckpointSequence: number;
  keyCheckpointHash: string;
  authorityBoundary: Record<string, unknown>;
}): StrictJsonValue {
  const surface = getActiveSigningSurface(
    "editor_ephemeral_session",
    collaborationVariant(params.ownerKind),
  );
  const session = {
    workspace_id: params.workspaceId,
    document_id: params.documentId,
    channel_id: params.channelId,
    session_id: params.sessionId,
    proof_direction: params.proofDirection,
    proof_type: params.proofType,
    session_nonce: params.sessionNonce,
    counter: params.counter,
    expires_event_sequence: params.expiresEventSequence,
  };
  const subject = canonicalizeStrictBytes(session as unknown as StrictJsonValue);

  return transcriptBase("editor_ephemeral_session", surface, params.ownerKind, params.ownerId, {
    subject_hash: blake3Base64Url(subject),
    subject_protocol: "refmd.editor-ephemeral-session",
    subject_version: CURRENT_PROTOCOL_VERSION,
    actor: ephemeralSessionActor(params),
    session,
    authority_boundary: params.authorityBoundary as StrictJsonValue,
  });
}

function ephemeralSessionActor(params: {
  ownerKind: SigningOwnerKind;
  actorUserId: string;
  actorDeviceId: string;
  signingKeyId: string;
  workspaceId: string;
  keyCheckpointSequence: number;
  keyCheckpointHash: string;
}): StrictJsonValue {
  if (params.ownerKind === "share_participant_device") {
    return {
      signer_kind: "share_participant_device",
      share_participant_principal_id: params.actorUserId,
      share_participant_device_id: params.actorDeviceId,
      signing_key_id: params.signingKeyId,
      key_scope_kind: "workspace",
      key_scope_id: params.workspaceId,
      key_checkpoint_sequence: params.keyCheckpointSequence,
      key_checkpoint_hash: params.keyCheckpointHash,
    } as StrictJsonValue;
  }

  return {
    signer_kind: "workspace_device",
    device_id: params.actorDeviceId,
    signing_key_id: params.signingKeyId,
    user_id: params.actorUserId,
    key_scope_kind: "workspace",
    key_scope_id: params.workspaceId,
    key_checkpoint_sequence: params.keyCheckpointSequence,
    key_checkpoint_hash: params.keyCheckpointHash,
  } as StrictJsonValue;
}
