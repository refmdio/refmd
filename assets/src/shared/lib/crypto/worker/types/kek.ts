export interface KekForDeviceParams {
  workspaceId: string;
  userId: string;
  senderDeviceId: string;
  targetDeviceId: string;
  targetDeviceEcdhPublic: Uint8Array;
  keyVersion: number;
}

export interface KekFromDeviceEnvelopeParams {
  workspaceId: string;
  userId: string;
  senderDeviceId: string;
  targetDeviceId: string;
  senderEcdhPublic: Uint8Array;
  encryptedKek: Uint8Array;
  nonce: Uint8Array;
  keyVersion: number;
}

export interface KekForMemberParams {
  workspaceId: string;
  targetUserId: string;
  targetIdentityEcdhPublic: Uint8Array;
  senderDeviceId: string;
  keyVersion: number;
}

export interface KekFromMemberEnvelopeParams {
  workspaceId: string;
  targetUserId: string;
  senderDeviceId: string;
  senderIdentityEcdhPublic: Uint8Array;
  encryptedKek: Uint8Array;
  nonce: Uint8Array;
  keyVersion: number;
}

export interface KekBackupParams {
  workspaceId: string;
  userId: string;
  keyVersion: number;
}

export interface KekFromBackupParams {
  workspaceId: string;
  userId: string;
  encryptedKek: Uint8Array;
  nonce: Uint8Array;
  keyVersion: number;
}

export interface KekForInvitationParams {
  workspaceId: string;
  invitationId: string;
  token: Uint8Array;
  keyVersion: number;
}

export interface KekFromInvitationParams {
  workspaceId: string;
  invitationId: string;
  token: Uint8Array;
  encryptedKek: Uint8Array;
  nonce: Uint8Array;
  keyVersion: number;
}
