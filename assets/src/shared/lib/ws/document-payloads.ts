export interface SnapshotProofChainEntry {
  [key: string]: unknown;
  snapshotId: string;
  ciphertextHash: string;
  parentSnapshotProof: string;
}
interface SnapshotPublicData {
  [key: string]: unknown;
  docId: string;
  snapshotId: string;
  deviceId: string;
  signingPubKey: string;
  keyVersion: number;
  parentSnapshotId: string | null;
  parentSnapshotProof: string;
  parentSnapshotUpdateClocks: Record<string, number>;
}
interface UpdatePublicData {
  [key: string]: unknown;
  docId: string;
  deviceId: string;
  signingPubKey: string;
  keyVersion: number;
  refSnapshotId: string;
  clock: number;
  timestamp: number;
  updateHash: string;
}
interface EphemeralPublicData {
  [key: string]: unknown;
  docId: string;
  deviceId: string;
  signingPubKey: string;
}
interface SnapshotPayload {
  [key: string]: unknown;
  ciphertext: string;
  nonce: string;
  signature: string;
  publicData: SnapshotPublicData;
}
export interface UpdatePayload {
  [key: string]: unknown;
  ciphertext: string;
  nonce: string;
  signature: string;
  version: number;
  publicData: UpdatePublicData;
}
export interface EphemeralPayload {
  [key: string]: unknown;
  ciphertext: string;
  nonce: string;
  signature: string;
  publicData: EphemeralPublicData;
}
export interface RemoteSnapshotPayload {
  [key: string]: unknown;
  snapshotId: string;
  snapshot: SnapshotPayload;
}
export interface DocumentPayload {
  [key: string]: unknown;
  snapshot: SnapshotPayload | null;
  updates: UpdatePayload[];
  snapshotProofChain: SnapshotProofChainEntry[];
  latestVersion: number;
  archived?: boolean;
  publicState?: {
    is_published: boolean;
    updated_at: string | null;
    can_sync: boolean;
  };
}
export interface PublicStatusChangedPayload {
  [key: string]: unknown;
  is_published: boolean;
  updated_at: string | null;
}
export interface UpdateSavedPayload {
  [key: string]: unknown;
  snapshotId: string;
  clock: number;
  updateHash: string;
  version: number;
}
export interface UpdateSaveFailedPayload {
  [key: string]: unknown;
  snapshotId: string;
  clock: number;
  requiresNewSnapshot: boolean;
}
export interface SnapshotSavedPayload {
  [key: string]: unknown;
  snapshotId: string;
  latestVersion?: number;
}
export interface SnapshotSaveFailedPayload {
  [key: string]: unknown;
  snapshot: SnapshotPayload | null;
  updates: UpdatePayload[];
  snapshotProofChain: SnapshotProofChainEntry[];
}
export interface PeerLeftPayload {
  [key: string]: unknown;
  signingPubKey: string;
}
