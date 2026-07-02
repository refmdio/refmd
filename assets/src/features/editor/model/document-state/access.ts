import type { ShareVerificationDirectory } from "@/shared/lib/document/share-verification-directory";
import type { ShareSessionTrustAnchor } from "@/shared/lib/auth/share-participant-session-store";
import type { HybridSigningPublicKeyMaterial } from "@/shared/lib/crypto/signature-types";
import type { DocumentPayload } from "@/shared/lib/ws/document-payloads";
import {
  assertKeyDirectoryEnvelope,
  type KeyDirectoryEnvelope,
} from "@/shared/lib/crypto/key-directory/types";
import {
  assertWorkspacePinBootstrapEnvelope,
  type WorkspacePinBootstrapEnvelope,
} from "@/shared/lib/key-directory/workspace-pin-bootstrap";
export type {
  ShareVerificationDirectory,
  ShareVerificationParticipantDevice,
  ShareVerificationWorkspaceDevice,
} from "@/shared/lib/document/share-verification-directory";

export interface SharedDocumentAccess {
  kind: "share";
  source: "link" | "mounted";
  documentToken: string;
  mountId?: string;
  shareId: string;
  authorizationShareId?: string;
  shareSlug: string;
  participantPrincipalId: string;
  participantDisplayName: string;
  participantDeviceId: string;
  participantSessionId?: string;
  participantSigningKeyId: string;
  participantHybridSigningPublicKeyMaterial?: HybridSigningPublicKeyMaterial;
  participantEncryptionPublicKey: string;
  permission: "view" | "edit";
  passwordProtected: boolean;
  workspaceId: string;
  workspacePinBootstrapHash?: string | null;
  workspacePinBootstrap?: WorkspacePinBootstrapEnvelope | null;
  keyVersion: number;
  encryptedKeyRefs: string[];
  workspaceKeyDirectoryCheckpoint?: KeyDirectoryEnvelope | null;
  workspaceKeyDirectoryLatestCheckpoint?: KeyDirectoryEnvelope | null;
  workspaceKeyDirectoryCheckpointAncestry?: KeyDirectoryEnvelope[];
  workspaceKeyDirectoryEventAncestry?: KeyDirectoryEnvelope[];
  workspacePinReady?: Promise<void>;
  shareDekReady?: Promise<void>;
  verificationDirectory: ShareVerificationDirectory;
  shareTrustAnchor?: ShareSessionTrustAnchor | null;
  initialDocument?: DocumentPayload | null;
}

export interface WorkspaceDocumentAccess {
  kind: "workspace";
}

export type DocumentAccess = WorkspaceDocumentAccess | SharedDocumentAccess;

const documentAccessRegistry = new Map<string, DocumentAccess>();

type SharedDocumentAccessInput = Omit<
  SharedDocumentAccess,
  | "kind"
  | "source"
  | "workspacePinBootstrap"
  | "workspaceKeyDirectoryCheckpoint"
  | "workspaceKeyDirectoryLatestCheckpoint"
  | "workspaceKeyDirectoryCheckpointAncestry"
  | "workspaceKeyDirectoryEventAncestry"
> & {
  source?: SharedDocumentAccess["source"];
  workspacePinBootstrap?: unknown;
  workspaceKeyDirectoryCheckpoint?: unknown;
  workspaceKeyDirectoryLatestCheckpoint?: unknown;
  workspaceKeyDirectoryCheckpointAncestry?: unknown;
  workspaceKeyDirectoryEventAncestry?: unknown;
};

export function registerSharedDocumentAccess(
  stateKey: string,
  access: SharedDocumentAccessInput,
): void {
  documentAccessRegistry.set(stateKey, {
    kind: "share",
    source: access.source ?? "link",
    ...access,
    workspacePinBootstrap: optionalWorkspacePinBootstrapEnvelope(
      access.workspacePinBootstrap,
      "workspace_pin_bootstrap_invalid",
    ),
    workspaceKeyDirectoryCheckpoint: optionalKeyDirectoryEnvelope(
      access.workspaceKeyDirectoryCheckpoint,
      "workspace_key_directory_checkpoint_invalid",
    ),
    workspaceKeyDirectoryLatestCheckpoint: optionalKeyDirectoryEnvelope(
      access.workspaceKeyDirectoryLatestCheckpoint,
      "workspace_key_directory_latest_checkpoint_invalid",
    ),
    workspaceKeyDirectoryCheckpointAncestry: optionalKeyDirectoryEnvelopeArray(
      access.workspaceKeyDirectoryCheckpointAncestry,
      "workspace_key_directory_checkpoint_ancestry_invalid",
    ),
    workspaceKeyDirectoryEventAncestry: optionalKeyDirectoryEnvelopeArray(
      access.workspaceKeyDirectoryEventAncestry,
      "workspace_key_directory_event_ancestry_invalid",
    ),
  });
}

function optionalKeyDirectoryEnvelope(
  value: unknown,
  code: string,
): KeyDirectoryEnvelope | null | undefined {
  if (value === undefined || value === null) return value;
  return assertKeyDirectoryEnvelope(value, code);
}

function optionalWorkspacePinBootstrapEnvelope(
  value: unknown,
  code: string,
): WorkspacePinBootstrapEnvelope | null | undefined {
  if (value === undefined || value === null) return value;
  return assertWorkspacePinBootstrapEnvelope(value, code);
}

function optionalKeyDirectoryEnvelopeArray(
  value: unknown,
  code: string,
): KeyDirectoryEnvelope[] | undefined {
  if (value === undefined || value === null) return undefined;
  if (!Array.isArray(value)) throw new Error(code);
  return value.map((entry) => assertKeyDirectoryEnvelope(entry, code));
}

export function isLinkSharedDocumentAccess(access: DocumentAccess): access is SharedDocumentAccess {
  return access.kind === "share" && access.source === "link";
}

export function isMountedSharedDocumentAccess(
  access: DocumentAccess,
): access is SharedDocumentAccess {
  return access.kind === "share" && access.source === "mounted";
}

export function canSharedAccessWriteDurably(access: SharedDocumentAccess): boolean {
  return access.permission === "edit";
}

export function getRegisteredDocumentAccess(stateKey: string): DocumentAccess | null {
  return documentAccessRegistry.get(stateKey) ?? null;
}

export function clearRegisteredDocumentAccess(stateKey: string): void {
  documentAccessRegistry.delete(stateKey);
}
