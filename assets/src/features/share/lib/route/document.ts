import { resolveSharedDocumentBootstrap } from "../bootstrap/document";
import { resolveShareTitle } from "./title";
import type { ShareSessionTrustAnchor } from "@/shared/lib/auth/share-participant-session-store";
import {
  normalizeShareVerificationDirectory,
  type ShareVerificationDirectory,
} from "@/shared/lib/document/share-verification-directory";
import type { HybridSigningPublicKeyMaterial } from "@/shared/lib/crypto/signature-types";
import {
  assertKeyDirectoryEnvelope,
  type KeyDirectoryEnvelope,
} from "@/shared/lib/crypto/key-directory/types";
import { ensureShareWorkspaceKeyDirectoryPin } from "./workspace-pin";
import {
  assertWorkspacePinBootstrapEnvelope,
  type WorkspacePinBootstrapEnvelope,
} from "@/shared/lib/key-directory/workspace-pin-bootstrap";

export type ResolvedShareDocumentRoute =
  | {
      kind: "bootstrap-required";
      shareSlug: string;
    }
  | {
      kind: "ready";
      target: {
        documentToken: string;
        documentId: string;
        title: string;
        workspaceId: string;
      };
      access: {
        documentToken: string;
        shareId: string;
        authorizationShareId?: string;
        shareSlug: string;
        participantPrincipalId: string;
        participantDisplayName: string;
        participantDeviceId: string;
        participantSessionId: string;
        participantSigningKeyId: string;
        participantHybridSigningPublicKeyMaterial: HybridSigningPublicKeyMaterial;
        participantEncryptionPublicKey: string;
        permission: "view" | "edit";
        passwordProtected: boolean;
        workspaceId: string;
        workspacePinBootstrapHash?: string | null;
        workspacePinBootstrap?: WorkspacePinBootstrapEnvelope | null;
        keyVersion: number;
        encryptedKeyRefs: string[];
        workspaceKeyDirectoryCheckpoint?: KeyDirectoryEnvelope | null;
        verificationDirectory: ShareVerificationDirectory;
        shareTrustAnchor?: ShareSessionTrustAnchor | null;
      };
    };

export async function resolveShareDocumentRoute(
  documentToken: string,
): Promise<ResolvedShareDocumentRoute> {
  const resolved = await resolveSharedDocumentBootstrap(documentToken);
  if (resolved.kind === "bootstrap-required") {
    return {
      kind: "bootstrap-required",
      shareSlug: resolved.shareSlug,
    };
  }

  const trustAnchor = resolved.trustAnchor;
  const workspacePinBootstrap =
    resolved.response.workspace_pin_bootstrap === null
      ? null
      : assertWorkspacePinBootstrapEnvelope(
          resolved.response.workspace_pin_bootstrap,
          "share_workspace_pin_bootstrap_invalid",
        );
  await ensureShareWorkspaceKeyDirectoryPin({
    workspaceId: resolved.response.workspace_id,
    workspacePinBootstrapHash: trustAnchor.workspacePinBootstrapHash,
    workspacePinBootstrap,
    workspaceKeyDirectoryCheckpoint: assertKeyDirectoryEnvelope(
      resolved.response.workspace_key_directory_checkpoint,
      "share_workspace_key_directory_checkpoint_invalid",
    ),
    mismatchCode: "share_workspace_pin_bootstrap_hash_mismatch",
  });
  const title = await resolveShareTitle(
    {
      ...resolved.response,
      document_id: resolved.response.document_id,
    },
    {
      passwordProtected: resolved.response.password_protected,
      passwordKey: resolved.response.share_slug,
      fallback: "Shared document",
      workspaceId: resolved.response.workspace_id,
      workspacePinBootstrapHash: trustAnchor.workspacePinBootstrapHash,
      workspacePinBootstrap,
    },
  );

  return {
    kind: "ready",
    target: {
      documentToken,
      documentId: resolved.response.document_id,
      title,
      workspaceId: resolved.response.workspace_id,
    },
    access: {
      documentToken,
      shareId: resolved.response.share_id,
      authorizationShareId: resolved.response.authorization_share_id ?? resolved.response.share_id,
      shareSlug: resolved.response.share_slug,
      participantPrincipalId: resolved.session.principalId,
      participantDisplayName: resolved.session.displayName,
      participantDeviceId: resolved.session.deviceId,
      participantSessionId: resolved.session.sessionId,
      participantSigningKeyId: resolved.session.signingKeyId,
      participantHybridSigningPublicKeyMaterial: resolved.session.hybridSigningPublicKeyMaterial,
      participantEncryptionPublicKey: resolved.session.encryptionPublicKey,
      permission: resolved.response.permission,
      passwordProtected: resolved.response.password_protected,
      workspaceId: resolved.response.workspace_id,
      workspacePinBootstrapHash: trustAnchor.workspacePinBootstrapHash,
      workspacePinBootstrap,
      keyVersion: resolved.response.key_version,
      encryptedKeyRefs: resolved.response.encrypted_key_refs,
      workspaceKeyDirectoryCheckpoint: assertKeyDirectoryEnvelope(
        resolved.response.workspace_key_directory_checkpoint,
        "share_workspace_key_directory_checkpoint_invalid",
      ),
      verificationDirectory: normalizeShareVerificationDirectory(
        resolved.response.verification_directory,
      ),
      shareTrustAnchor: trustAnchor.anchor,
    },
  };
}
