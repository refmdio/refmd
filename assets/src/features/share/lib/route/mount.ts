import type { ShareMountDocument, ShareMountDetail } from "@/entities/mount";
import { loadMountTrustAnchor } from "@/entities/mount";
import { sharesApi } from "@/shared/api";
import { base64UrlEncode } from "@/shared/lib/crypto/encoding";
import { blake3Base64Url } from "@/shared/lib/crypto/hash";
import type { HybridSigningPublicKeyMaterial } from "@/shared/lib/crypto/signature-types";
import { getShareParticipantCryptoWorker } from "@/shared/lib/crypto/worker/scoped";
import { assertKeyDirectoryEnvelope } from "@/shared/lib/crypto/key-directory/types";
import { assertWorkspacePinBootstrapEnvelope } from "@/shared/lib/key-directory/workspace-pin-bootstrap";
import { normalizeShareVerificationDirectory } from "@/shared/lib/document/share-verification-directory";
import { ensureShareParticipantDeviceReady } from "../session/session";
import { resolveShareTitle } from "./title";
import { ensureShareWorkspaceKeyDirectoryPin } from "./workspace-pin";

export interface MountedShareParticipantContext {
  principalId: string;
  displayName: string;
  deviceId: string;
  signingKeyId: string;
  sessionId?: string;
  hybridSigningPublicKeyMaterial?: HybridSigningPublicKeyMaterial;
  encryptionPublicKey: Uint8Array;
}

export async function respondShareMountPasswordChallenge(mountId: string, password?: string) {
  const challenge = await sharesApi.getShareMountChallenge(mountId);
  const anchor = await loadMountTrustAnchor(mountId);
  if (!anchor) throw new Error("mount_trust_anchor_unavailable");
  const mountSessionKey = anchor.shareSessionKey;
  const participantSession = await ensureShareParticipantDeviceReady({
    requiredShareSlug: mountSessionKey,
  });
  if (!participantSession) throw new Error("share_participant_session_unavailable");

  const challengeParams: Parameters<
    ReturnType<typeof getShareParticipantCryptoWorker>["preparePasswordShareChallenge"]
  >[0] = {
    shareSlug: mountSessionKey,
    challenge: challenge.challenge,
    ...(password
      ? {
          password,
          salt: challenge.salt,
          kdfParams: challenge.kdf_params,
        }
      : {}),
  };

  const { response } =
    await getShareParticipantCryptoWorker(mountSessionKey).preparePasswordShareChallenge(
      challengeParams,
    );

  const result = await sharesApi.respondShareMountChallenge(mountId, {
    response,
    password_challenge_hash: blake3Base64Url(new TextEncoder().encode(`mount:${mountId}`)),
  } as Parameters<typeof sharesApi.respondShareMountChallenge>[1]);

  if (password) {
    await getShareParticipantCryptoWorker(mountSessionKey).persistShareSecretsWithDsk({
      shareSlug: mountSessionKey,
      principalId: participantSession.principalId,
      deviceId: participantSession.deviceId,
    });
  }

  return result;
}

export async function resolveMountedShareTitle(
  mountId: string,
  document: ShareMountDocument,
): Promise<string> {
  const anchor = await loadMountTrustAnchor(mountId);
  if (!anchor) throw new Error("mount_trust_anchor_unavailable");
  const shareSessionKey = anchor.shareSessionKey;

  return resolveShareTitle(document, {
    passwordProtected: document.password_protected,
    passwordKey: shareSessionKey,
    fallback: "Mounted document",
    workspaceId: document.workspace_id,
    workspacePinBootstrapHash: anchor.workspacePinBootstrapHash,
    workspacePinBootstrap:
      document.workspace_pin_bootstrap === null
        ? null
        : assertWorkspacePinBootstrapEnvelope(
            document.workspace_pin_bootstrap,
            "mount_workspace_pin_bootstrap_invalid",
          ),
  });
}

export async function resolveMountedShareOpen(
  mountId: string,
  detail: ShareMountDetail,
  document: ShareMountDocument,
  participant: MountedShareParticipantContext,
) {
  const anchor = await loadMountTrustAnchor(mountId);
  const shareSessionKey = anchor?.shareSessionKey;
  if (!shareSessionKey) throw new Error("mount_trust_anchor_unavailable");
  const workspacePinBootstrap =
    document.workspace_pin_bootstrap === null
      ? null
      : assertWorkspacePinBootstrapEnvelope(
          document.workspace_pin_bootstrap,
          "mount_workspace_pin_bootstrap_invalid",
        );
  await ensureShareWorkspaceKeyDirectoryPin({
    workspaceId: document.workspace_id,
    workspacePinBootstrapHash: anchor.workspacePinBootstrapHash,
    workspacePinBootstrap,
    workspaceKeyDirectoryCheckpoint: assertKeyDirectoryEnvelope(
      (document as Record<string, unknown>).workspace_key_directory_checkpoint,
      "mount_workspace_key_directory_checkpoint_invalid",
    ),
    mismatchCode: "mount_workspace_pin_bootstrap_hash_mismatch",
  });

  return {
    title: await resolveMountedShareTitle(mountId, document),
    access: {
      source: "mounted" as const,
      documentToken: document.document_token,
      mountId,
      shareId: document.share_id,
      authorizationShareId: document.authorization_share_id,
      shareSlug: shareSessionKey,
      participantPrincipalId: participant.principalId,
      participantDisplayName: participant.displayName,
      participantDeviceId: participant.deviceId,
      participantSessionId: participant.sessionId,
      participantSigningKeyId: participant.signingKeyId,
      participantHybridSigningPublicKeyMaterial: participant.hybridSigningPublicKeyMaterial,
      participantEncryptionPublicKey: base64UrlEncode(participant.encryptionPublicKey),
      permission: detail.mount.share.permission,
      passwordProtected: document.password_protected,
      workspaceId: document.workspace_id,
      workspacePinBootstrapHash: anchor.workspacePinBootstrapHash,
      workspacePinBootstrap,
      keyVersion: document.key_version,
      encryptedKeyRefs: document.encrypted_key_refs,
      verificationDirectory: normalizeShareVerificationDirectory(document.verification_directory),
    },
  };
}
