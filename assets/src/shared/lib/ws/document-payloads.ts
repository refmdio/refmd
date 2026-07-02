import type { HybridSignature } from "@/shared/lib/crypto/signature-types";

export interface SnapshotProofChainEntry {
  protocol: "refmd.snapshot-proof-link";
  version: 1;
  document_id: string;
  snapshot_id: string;
  parent_snapshot_id: string;
  parent_proof_hash: string;
  ciphertext_hash: string;
  snapshot_signature_hash: string;
  snapshot_admission_event_hash: string;
  proof_chain_hash: string;
}
interface SnapshotPublicData {
  docId: string;
  snapshotId: string;
  signingKeyId: string;
  ownerKind: "device" | "share_participant_device";
  ownerId: string;
  authorityKind: "workspace_device" | "share_participant_device";
  authorityId: string;
  authorityContextKey: string;
  authorityScopeId: string;
  authorityPermissionVersion: number;
  keyCheckpointSequence: number;
  keyCheckpointHash: string;
  keyVersion: number;
  parentSnapshotId: string;
  parentProofHash: string;
  parentSnapshotUpdateClocks: Record<string, number>;
}
interface UpdatePublicData {
  docId: string;
  signingKeyId: string;
  ownerKind: "device" | "share_participant_device";
  ownerId: string;
  authorityKind: "workspace_device" | "share_participant_device";
  authorityId: string;
  authorityContextKey: string;
  authorityScopeId: string;
  authorityPermissionVersion: number;
  keyCheckpointSequence: number;
  keyCheckpointHash: string;
  keyVersion: number;
  refSnapshotId: string;
  clock: number;
  timestamp: number;
  updateHash: string;
  minDekVersion: number;
  writeSessionEventHash: string;
  writeSessionId: string;
  writeSessionCounter: number;
}
interface WriteSessionPublicData {
  docId: string;
  signingKeyId: string;
  ownerKind: "device" | "share_participant_device";
  ownerId: string;
  authorityKind: "workspace_device" | "share_participant_device";
  authorityId: string;
  authorityContextKey: string;
  authorityScopeId: string;
  authorityPermissionVersion: number;
  keyCheckpointSequence: number;
  keyCheckpointHash: string;
  keyVersion: number;
  minDekVersion: number;
  writeSessionEventHash: string;
  writeSessionId: string;
  writeSessionCounter: number;
}
interface EphemeralPublicData {
  docId: string;
  ownerKind: "device" | "share_participant_device";
  ownerId: string;
  authorityKind: "workspace_device" | "share_participant_device";
  authorityId: string;
  authorityContextKey: string;
  authorityScopeId: string;
  authorityPermissionVersion: number;
  keyCheckpointSequence: number;
  keyCheckpointHash: string;
  workspaceEventHeadSequence: number;
  workspaceEventHeadHash: string;
  signingKeyId: string;
}
interface SnapshotPayload {
  ciphertext: string;
  nonce: string;
  signature: HybridSignature;
  admission: DocumentOperationAdmission;
  publicData: SnapshotPublicData;
}
export interface UpdatePayload {
  ciphertext: string;
  nonce: string;
  signature: HybridSignature;
  admission: DocumentOperationAdmission;
  version: number;
  publicData: UpdatePublicData;
}
export interface WriteSessionPayload {
  admission: DocumentOperationAdmission;
  publicData: WriteSessionPublicData;
}
export interface EphemeralPayload {
  ciphertext: string;
  nonce: string;
  signature: HybridSignature;
  publicData: EphemeralPublicData;
}
export interface RemoteSnapshotPayload {
  snapshotId: string;
  snapshot: SnapshotPayload;
  proofChainHash?: string;
  ciphertextHash?: string;
  snapshotAdmissionEventHash?: string;
}
export interface DocumentPayload {
  snapshot: SnapshotPayload | null;
  updates: UpdatePayload[];
  snapshotProofChain: SnapshotProofChainEntry[];
  proofChainHash?: string;
  ciphertextHash?: string;
  snapshotAdmissionEventHash?: string;
  latestVersion: number;
  authorityPermissionVersion?: number;
  readOnly?: boolean;
  archived?: boolean;
  publicState?: {
    is_published: boolean;
    updated_at: string | null;
    can_sync: boolean;
  };
}
export interface PublicStatusChangedPayload {
  is_published: boolean;
  updated_at: string | null;
}
export interface UpdateSavedPayload {
  snapshotId: string;
  clock: number;
  updateHash: string;
  version: number;
}
export interface UpdateSaveFailedPayload {
  snapshotId: string;
  clock: number;
  reason?: string;
  requiresNewSnapshot: boolean;
}
export interface SnapshotSavedPayload {
  snapshotId: string;
  latestVersion?: number;
  proofChainHash: string;
  ciphertextHash: string;
  snapshotAdmissionEventHash: string;
}
export interface SnapshotSaveFailedPayload {
  snapshot: SnapshotPayload | null;
  updates: UpdatePayload[];
  snapshotProofChain: SnapshotProofChainEntry[];
}
export interface PeerLeftPayload {
  signingKeyId: string;
}

export interface DocumentOperationAdmission {
  workspaceKeyDirectoryEvents: Record<string, unknown>[];
  workspaceKeyDirectoryCheckpoint: Record<string, unknown>;
  workspaceKeyDirectoryCheckpointAncestry?: Record<string, unknown>[];
  workspaceKeyDirectoryEventAncestry?: Record<string, unknown>[];
}
