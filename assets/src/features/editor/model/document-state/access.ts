import type { ShareVerificationDirectory } from "@/shared/lib/document/share-verification-directory";
export type {
  ShareVerificationDirectory,
  ShareVerificationParticipantDevice,
  ShareVerificationWorkspaceDevice,
} from "@/shared/lib/document/share-verification-directory";

export interface SharedDocumentAccess {
  kind: "share";
  source: "raw" | "mounted";
  documentToken: string;
  mountId?: string;
  shareId: string;
  shareSlug: string;
  participantPrincipalId: string;
  participantDisplayName: string;
  participantDeviceId: string;
  participantSigningPublicKey: string;
  participantEncryptionPublicKey: string;
  permission: "view" | "edit";
  passwordProtected: boolean;
  workspaceId: string;
  keyVersion: number;
  encryptedDek: string;
  nonce: string | null;
  verificationDirectory: ShareVerificationDirectory;
}

export interface WorkspaceDocumentAccess {
  kind: "workspace";
}

export type DocumentAccess = WorkspaceDocumentAccess | SharedDocumentAccess;

const documentAccessRegistry = new Map<string, DocumentAccess>();

export function registerSharedDocumentAccess(
  stateKey: string,
  access: Omit<SharedDocumentAccess, "kind" | "source"> & {
    source?: SharedDocumentAccess["source"];
  },
): void {
  documentAccessRegistry.set(stateKey, {
    kind: "share",
    source: access.source ?? "raw",
    ...access,
  });
}

export function isRawSharedDocumentAccess(access: DocumentAccess): access is SharedDocumentAccess {
  return access.kind === "share" && access.source === "raw";
}

export function isMountedSharedDocumentAccess(
  access: DocumentAccess,
): access is SharedDocumentAccess {
  return access.kind === "share" && access.source === "mounted";
}

export function getRegisteredDocumentAccess(stateKey: string): DocumentAccess | null {
  return documentAccessRegistry.get(stateKey) ?? null;
}

export function clearRegisteredDocumentAccess(stateKey: string): void {
  documentAccessRegistry.delete(stateKey);
}
