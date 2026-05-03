import { resolveSharedDocumentBootstrap } from "./document-bootstrap";
import { resolveShareTitle } from "./title";
import {
  normalizeShareVerificationDirectory,
  type ShareVerificationDirectory,
} from "@/shared/lib/document/share-verification-directory";

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

  const title = await resolveShareTitle(
    {
      ...resolved.response,
      document_id: resolved.response.document_id,
    },
    {
      passwordProtected: resolved.response.password_protected,
      passwordKey: resolved.response.share_slug,
      fallback: "Shared document",
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
      shareSlug: resolved.response.share_slug,
      participantPrincipalId: resolved.session.principalId,
      participantDisplayName: resolved.session.displayName,
      participantDeviceId: resolved.session.deviceId,
      participantSigningPublicKey: resolved.session.signingPublicKey,
      participantEncryptionPublicKey: resolved.session.encryptionPublicKey,
      permission: resolved.response.permission,
      passwordProtected: resolved.response.password_protected,
      workspaceId: resolved.response.workspace_id,
      keyVersion: resolved.response.key_version,
      encryptedDek: resolved.response.encrypted_dek,
      nonce: resolved.response.nonce,
      verificationDirectory: normalizeShareVerificationDirectory(
        resolved.response.verification_directory,
      ),
    },
  };
}
