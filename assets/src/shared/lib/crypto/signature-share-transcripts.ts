import { blake3Base64Url } from "./hash";
import { canonicalizeStrictBytes, type StrictJsonValue } from "./jcs";
import { getActiveSigningSurface } from "./signing-surface";
import { CURRENT_PROTOCOL_VERSION } from "./suite";
import { transcriptBase } from "./signature-transcript-core";

export function buildShareCapabilityAuthorizationTranscript(params: {
  shareTokenHash: string;
  workspacePinBootstrapHash: string;
  shareId: string;
  scopeKind: "document" | "folder";
  scopeId: string;
  permission: "view" | "edit";
  passwordProtected: boolean;
  createdEventHash: string;
  latestBootstrapEventHash: string;
  capabilityContextHash: string;
  shareCapabilitySecretCommitment: string;
  passwordCapabilitySecretCommitment: string;
}): StrictJsonValue {
  const surface = getActiveSigningSurface("share_capability_authorization", "none");
  const subject = canonicalizeStrictBytes({
    authorization: {
      token_hash: params.shareTokenHash,
      workspace_pin_bootstrap_hash: params.workspacePinBootstrapHash,
    },
    share_state: {
      share_id: params.shareId,
      scope_kind: params.scopeKind,
      scope_id: params.scopeId,
      permission: params.permission,
      password_protected: params.passwordProtected,
      created_event_hash: params.createdEventHash,
      latest_bootstrap_event_hash: params.latestBootstrapEventHash,
      capability_context_hash: params.capabilityContextHash,
      share_capability_secret_commitment: params.shareCapabilitySecretCommitment,
      password_capability_secret_commitment: params.passwordCapabilitySecretCommitment,
    },
  } as unknown as StrictJsonValue);

  return transcriptBase(
    "share_capability_authorization",
    surface,
    "share_capability",
    params.shareTokenHash,
    {
      subject_hash: blake3Base64Url(subject),
      subject_protocol: "refmd.share.capability_authorization",
      subject_version: CURRENT_PROTOCOL_VERSION,
      authorization: {
        token_hash: params.shareTokenHash,
        workspace_pin_bootstrap_hash: params.workspacePinBootstrapHash,
      },
      share_state: {
        share_id: params.shareId,
        scope_kind: params.scopeKind,
        scope_id: params.scopeId,
        permission: params.permission,
        password_protected: params.passwordProtected,
        created_event_hash: params.createdEventHash,
        latest_bootstrap_event_hash: params.latestBootstrapEventHash,
        capability_context_hash: params.capabilityContextHash,
        share_capability_secret_commitment: params.shareCapabilitySecretCommitment,
        password_capability_secret_commitment: params.passwordCapabilitySecretCommitment,
      },
    },
  );
}

export function buildShareParticipantDeviceAuthorizationTranscript(params: {
  shareId: string;
  shareSessionId: string;
  shareParticipantPrincipalId: string;
  shareParticipantDeviceId: string;
  participantSigningKeyId: string;
  participantEncryptionKeyId: string;
  capabilityContextHash: string;
  shareCreatedEventHash: string;
  latestBootstrapEventHash: string;
  scopeKind: "document" | "folder";
  scopeId: string;
  permission: "view" | "edit";
}): StrictJsonValue {
  const surface = getActiveSigningSurface("share_participant_device_authorization", "none");

  return transcriptBase(
    "share_participant_device_authorization",
    surface,
    "share_participant_device",
    params.shareParticipantDeviceId,
    {
      share_id: params.shareId,
      share_session_id: params.shareSessionId,
      share_participant_principal_id: params.shareParticipantPrincipalId,
      share_participant_device_id: params.shareParticipantDeviceId,
      participant_signing_key_id: params.participantSigningKeyId,
      participant_encryption_key_id: params.participantEncryptionKeyId,
      capability_context_hash: params.capabilityContextHash,
      share_created_event_hash: params.shareCreatedEventHash,
      latest_bootstrap_event_hash: params.latestBootstrapEventHash,
      scope_kind: params.scopeKind,
      scope_id: params.scopeId,
      permission: params.permission,
    },
  );
}
