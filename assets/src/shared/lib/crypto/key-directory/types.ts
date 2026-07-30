import type { components } from "@/shared/api/schema";
import type { HybridEncryptionPublicKeyMaterial } from "../hybrid-encryption";
import type { HybridSigningPublicKeyMaterial } from "../signature-types";
import type { SignedPqWrapRecord } from "../signed-pq-wrap";

export type KeyDirectoryEnvelope = components["schemas"]["KeyDirectoryEnvelope"];

export function keyDirectoryEnvelope(
  payload: KeyDirectoryEnvelope["payload"],
  signatures: KeyDirectoryEnvelope["signatures"],
): KeyDirectoryEnvelope {
  return { payload, signatures };
}

export function assertKeyDirectoryEnvelope(value: unknown, code: string): KeyDirectoryEnvelope {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error(code);
  }
  const record = value as Record<string, unknown>;
  if (
    typeof record.payload !== "object" ||
    record.payload === null ||
    Array.isArray(record.payload)
  ) {
    throw new Error(code);
  }
  if (!Array.isArray(record.signatures)) {
    throw new Error(code);
  }
  return value as KeyDirectoryEnvelope;
}

export interface InitialKeyDirectoryInput {
  userId: string;
  workspaceId: string;
  workspaceOwnerRoleId: string;
  deviceId: string;
  identityHybridSigningPublicKeyMaterial: HybridSigningPublicKeyMaterial;
  identityHybridEncryptionPublicKeyMaterial: HybridEncryptionPublicKeyMaterial;
  deviceHybridSigningPublicKeyMaterial: HybridSigningPublicKeyMaterial;
  deviceHybridEncryptionPublicKeyMaterial: HybridEncryptionPublicKeyMaterial;
}

export interface InitialKeyDirectoryBootstrap {
  userEvents: KeyDirectoryEnvelope[];
  userCheckpoint: KeyDirectoryEnvelope;
  workspaceEvents: KeyDirectoryEnvelope[];
  workspaceCheckpoint: KeyDirectoryEnvelope;
}

export interface InitialUserKeyDirectoryBootstrap {
  userEvents: KeyDirectoryEnvelope[];
  userCheckpoint: KeyDirectoryEnvelope;
}

export interface InitialWorkspaceKeyDirectoryBootstrap {
  workspaceEvents: KeyDirectoryEnvelope[];
  workspaceCheckpoint: KeyDirectoryEnvelope;
}

export interface DeviceKeyDirectoryAppendInput {
  scopeKind: "user" | "workspace";
  scopeId: string;
  userId: string;
  recipientUserId?: string;
  actorDeviceId?: string;
  checkpointEnvelope: KeyDirectoryEnvelope;
  recipientDeviceId: string;
  recipientHybridSigningPublicKeyMaterial: HybridSigningPublicKeyMaterial;
  recipientHybridEncryptionPublicKeyMaterial: HybridEncryptionPublicKeyMaterial;
}

export interface RecoveryWorkspaceDeviceKeyDirectoryAppendInput {
  workspaceId: string;
  userId: string;
  actorIdentitySigningKeyId: string;
  checkpointEnvelope: KeyDirectoryEnvelope;
  recipientDeviceId: string;
  recipientHybridSigningPublicKeyMaterial: HybridSigningPublicKeyMaterial;
  recipientHybridEncryptionPublicKeyMaterial: HybridEncryptionPublicKeyMaterial;
}

export interface IdentityKeyDirectoryAppendInput {
  scopeKind: "workspace";
  scopeId: string;
  userId: string;
  actorDeviceId: string;
  checkpointEnvelope: KeyDirectoryEnvelope;
  recipientHybridEncryptionPublicKeyMaterial: HybridEncryptionPublicKeyMaterial;
  recipientHybridSigningPublicKeyMaterial?: HybridSigningPublicKeyMaterial;
}

export interface IdentityRotationKeyDirectoryAppendInput {
  userId: string;
  checkpointEnvelope: KeyDirectoryEnvelope;
  successorHybridEncryptionPublicKeyMaterial: HybridEncryptionPublicKeyMaterial;
  successorHybridSigningPublicKeyMaterial: HybridSigningPublicKeyMaterial;
  oldKeyVersion: number;
  newKeyVersion: number;
}

export interface DeviceRevocationKeyDirectoryAppendInput {
  scopeKind: "user" | "workspace";
  scopeId: string;
  userId: string;
  actorDeviceId?: string;
  checkpointEnvelope: KeyDirectoryEnvelope;
  revokedSigningKeyId: string;
  revokedEncryptionKeyId: string;
  reason: "security" | "retire";
}

export interface WorkspaceMemberRemovalKeyDirectoryAppendInput {
  workspaceId: string;
  actorUserId: string;
  actorDeviceId: string;
  removedUserId: string;
  currentKekVersion: number;
  documents: Array<{ id: string; minDekVersion: number }>;
  checkpointEnvelope: KeyDirectoryEnvelope;
}

export interface WorkspaceMemberRoleChangeKeyDirectoryAppendInput {
  workspaceId: string;
  actorUserId: string;
  actorDeviceId: string;
  changes: Array<{
    targetUserId: string;
    previousRoleId: string;
    previousBaseRole: string;
    roleId: string;
    baseRole: string;
  }>;
  checkpointEnvelope: KeyDirectoryEnvelope;
}

export interface WrapIssuedKeyDirectoryAppendInput {
  scopeKind: "user" | "workspace";
  scopeId: string;
  checkpointEnvelope: KeyDirectoryEnvelope;
  wrapRecord: SignedPqWrapRecord;
}

export interface ShareCreatedKeyDirectoryAppendInput {
  workspaceId: string;
  actorUserId: string;
  actorDeviceId: string;
  checkpointEnvelope: KeyDirectoryEnvelope;
  body: Record<string, unknown>;
}

export interface ShareManagementKeyDirectoryAppendInput {
  workspaceId: string;
  actorUserId: string;
  actorDeviceId: string;
  checkpointEnvelope: KeyDirectoryEnvelope;
  eventType:
    | "share_metadata_updated"
    | "share_revoked"
    | "share_exclusion_changed"
    | "share_key_scope_added"
    | "share_key_scope_replaced"
    | "share_key_scope_removed";
  body: Record<string, unknown>;
}

export interface KekRotationCompletionKeyDirectoryAppendInput {
  workspaceId: string;
  actorUserId: string;
  actorDeviceId: string;
  checkpointEnvelope: KeyDirectoryEnvelope;
  oldKeyVersion: number;
  newKeyVersion: number;
  completionManifestHash: string;
  deletionManifestHash: string;
}

export interface KekRotationStartKeyDirectoryAppendInput {
  workspaceId: string;
  actorUserId: string;
  actorDeviceId: string;
  checkpointEnvelope: KeyDirectoryEnvelope;
  oldKeyVersion: number;
  newKeyVersion: number;
  reason: "manual" | "security" | "membership_change" | "scheduled";
}

export interface DekRotationStartKeyDirectoryAppendInput {
  workspaceId: string;
  documentId: string;
  actorUserId: string;
  actorDeviceId: string;
  checkpointEnvelope: KeyDirectoryEnvelope;
  oldKeyVersion: number;
  newKeyVersion: number;
  reason: "time_based" | "manual" | "security" | "membership_change";
}

export interface DekRotationCompletionKeyDirectoryAppendInput {
  workspaceId: string;
  documentId: string;
  actorUserId: string;
  actorDeviceId: string;
  checkpointEnvelope: KeyDirectoryEnvelope;
  oldKeyVersion: number;
  newKeyVersion: number;
  completionManifestHash: string;
  deletionManifestHash: string;
}

export interface KeyDirectoryAppendArtifacts {
  events: KeyDirectoryEnvelope[];
  checkpoint: KeyDirectoryEnvelope;
}

export interface DocumentAdmissionKeyDirectoryAppendInput {
  workspaceId: string;
  documentId: string;
  shareId?: string;
  shareSessionId?: string;
  shareSlug?: string;
  checkpointEnvelope: KeyDirectoryEnvelope;
  actor:
    | {
        kind?: "device";
        userId: string;
        deviceId: string;
      }
    | {
        kind: "share_participant_device";
        principalId: string;
        deviceId: string;
        signingKeyId: string;
        hybridSigningPublicKeyMaterial: HybridSigningPublicKeyMaterial;
      };
  eventType: "document_snapshot_accepted" | "document_write_session_admitted";
  operationHash?: string;
  operationSignatureHash?: string;
  dekVersion?: number;
  minDekVersion: number;
  admissionNonce?: string;
  documentPermissionProofHash: string;
  sessionId?: string;
  sessionNonce?: string;
  issuedAtMs?: number;
  expiresAtMs?: number;
  maxUpdateCount?: number;
  maxCiphertextBytes?: number;
}

export interface DocumentWriteStateKeyDirectoryAppendInput {
  workspaceId: string;
  actorUserId: string;
  actorDeviceId: string;
  checkpointEnvelope: KeyDirectoryEnvelope;
  changes: Array<{
    documentId: string;
    previousWriteState: "writable" | "read_only" | "archived" | "write_disabled";
    writeState: "writable" | "read_only" | "archived" | "write_disabled";
  }>;
  reason: "archive" | "unarchive" | "read_only_enabled" | "read_only_disabled" | "policy";
}

export interface WorkspaceInvitationCreatedKeyDirectoryAppendInput {
  workspaceId: string;
  actorUserId: string;
  actorDeviceId: string;
  checkpointEnvelope: KeyDirectoryEnvelope;
  invitationId: string;
  roleId: string;
  baseRole: string;
  kekVersion: number;
  invitedEmail: string;
  deliveryMode: "unknown_fragment" | "known_recipient";
  recipientUserId: string | null;
  recipientDeviceIds: string[];
  expiresEventSequence: number;
  redeemAuthority: {
    signingKeyId: string;
    hybridSigningPublicKeyMaterial: HybridSigningPublicKeyMaterial;
  };
  bootstrapKeyCommitment: string;
  bootstrapPackageHash: string;
  bootstrapSuiteId: string;
  capabilityContextHash: string;
}

export interface WorkspaceInvitationRevokedKeyDirectoryAppendInput {
  workspaceId: string;
  actorUserId: string;
  actorDeviceId: string;
  checkpointEnvelope: KeyDirectoryEnvelope;
  invitationId: string;
  reason?: string;
}

export interface GuestInvitationCreatedKeyDirectoryAppendInput {
  workspaceId: string;
  actorUserId: string;
  actorDeviceId: string;
  checkpointEnvelope: KeyDirectoryEnvelope;
  invitationId: string;
  scopeKind: "workspace" | "document" | "folder" | "share";
  scopeId: string;
  permission: "view" | "edit";
  deliveryMode: "unknown_fragment" | "known_recipient";
  recipientUserId: string | null;
  recipientDeviceIds: string[];
  keyVersionContext: {
    workspaceKekVersion: number | "NOT_APPLICABLE";
    shareKeyVersion: number | "NOT_APPLICABLE";
    dekVersion: number | "NOT_APPLICABLE";
  };
  allowedShareIds: string[];
  expiresEventSequence: number;
  redeemAuthority: {
    signingKeyId: string;
    hybridSigningPublicKeyMaterial: HybridSigningPublicKeyMaterial;
  };
  bootstrapKeyCommitment: string;
  bootstrapPackageHash: string;
  bootstrapSuiteId: string;
  capabilityContextHash: string;
}

export interface GuestInvitationRevokedKeyDirectoryAppendInput {
  workspaceId: string;
  actorUserId: string;
  actorDeviceId: string;
  checkpointEnvelope: KeyDirectoryEnvelope;
  invitationId: string;
  reason?: string;
}

export interface WorkspaceInvitationRedeemedKeyDirectoryAppendInput {
  workspaceId: string;
  checkpointEnvelope: KeyDirectoryEnvelope;
  invitationId: string;
  redeemAuthoritySigningKeyId: string;
  memberEnvelopeWrap: SignedPqWrapRecord;
  redeemedUserId: string;
  redeemedDeviceId: string;
  redeemedIdentityHybridEncryptionPublicKeyMaterial: HybridEncryptionPublicKeyMaterial;
  redeemedDeviceHybridSigningPublicKeyMaterial: HybridSigningPublicKeyMaterial;
  redeemedDeviceHybridEncryptionPublicKeyMaterial: HybridEncryptionPublicKeyMaterial;
  redeemedEncryptionKeyId: string;
  memberEnvelopeKeyVersion: number;
  memberEnvelopeHash: string;
}

export interface GuestInvitationRedeemedKeyDirectoryAppendInput {
  workspaceId: string;
  checkpointEnvelope: KeyDirectoryEnvelope;
  invitationId: string;
  guestGrantId: string;
  redeemAuthoritySigningKeyId: string;
  guestUserId: string;
  guestDeviceId: string;
  guestIdentityHybridEncryptionPublicKeyMaterial: HybridEncryptionPublicKeyMaterial;
  guestDeviceHybridSigningPublicKeyMaterial: HybridSigningPublicKeyMaterial;
  guestDeviceHybridEncryptionPublicKeyMaterial: HybridEncryptionPublicKeyMaterial;
  guestEncryptionKeyId: string;
  guestSigningKeyId: string;
  scopeKind: "workspace" | "document" | "folder" | "share";
  scopeId: string;
  permission: "view" | "edit";
  recipientAccountUserId: string | null;
  recipientAccountDeviceId: string | null;
}
