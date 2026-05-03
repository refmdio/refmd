import type { ShareMountAdmission, ShareMountDetail } from "@/entities/mount";
import { sharesApi } from "@/shared/api";
import { base64UrlDecode, base64UrlEncode } from "@/shared/lib/crypto/encoding";
import { deriveAuthKeys } from "@/shared/lib/crypto/kdf";
import { setShareDekEncryptionKey } from "@/shared/lib/crypto/share-dek";
import { normalizeShareVerificationDirectory } from "@/shared/lib/document/share-verification-directory";
import { resolveShareTitle } from "./title";

export interface MountedShareParticipantContext {
  principalId: string;
  displayName: string;
  deviceId: string;
  signingPublicKey: Uint8Array;
  encryptionPublicKey: Uint8Array;
}

export function mountPasswordKey(mountId: string): string {
  return `mount:${mountId}`;
}

export async function respondShareMountPasswordChallenge(
  mountId: string,
  password: string,
  options?: { shareId?: string | null },
) {
  const challenge = await sharesApi.getShareMountChallenge(mountId);
  const { shareAuthKeyBase64, shareDekEncryptionKeyBase64 } = await deriveAuthKeys(
    password,
    challenge.salt,
    challenge.kdf_params,
  );
  const authKey = new Uint8Array(base64UrlDecode(shareAuthKeyBase64));
  const challengeBytes = new Uint8Array(base64UrlDecode(challenge.challenge));
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    authKey,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const signature = await crypto.subtle.sign("HMAC", cryptoKey, challengeBytes);
  const result = await sharesApi.respondShareMountChallenge(mountId, {
    response: base64UrlEncode(new Uint8Array(signature)),
    ...(options?.shareId ? { share_id: options.shareId } : {}),
  });

  setShareDekEncryptionKey(mountPasswordKey(mountId), base64UrlDecode(shareDekEncryptionKeyBase64));
  return result;
}

export async function resolveMountedShareTitle(
  mountId: string,
  detail: ShareMountDetail,
  admission: ShareMountAdmission,
): Promise<string> {
  const fallback =
    admission.document_id === detail.mount.target_document_id
      ? (detail.mount.title ?? detail.mount.target.title ?? admission.title ?? "Mounted document")
      : (admission.title ?? "Mounted document");

  return resolveShareTitle(admission, {
    passwordProtected: admission.password_protected,
    passwordKey: mountPasswordKey(mountId),
    fallback,
  });
}

export async function resolveMountedShareOpen(
  mountId: string,
  detail: ShareMountDetail,
  admission: ShareMountAdmission,
  participant: MountedShareParticipantContext,
) {
  return {
    title: await resolveMountedShareTitle(mountId, detail, admission),
    access: {
      source: "mounted" as const,
      documentToken: mountPasswordKey(mountId),
      mountId,
      shareId: admission.share_id,
      shareSlug: mountPasswordKey(mountId),
      participantPrincipalId: participant.principalId,
      participantDisplayName: participant.displayName,
      participantDeviceId: participant.deviceId,
      participantSigningPublicKey: base64UrlEncode(participant.signingPublicKey),
      participantEncryptionPublicKey: base64UrlEncode(participant.encryptionPublicKey),
      permission: admission.permission,
      passwordProtected: admission.password_protected,
      workspaceId: admission.workspace_id,
      keyVersion: admission.key_version,
      encryptedDek: admission.encrypted_dek,
      nonce: admission.nonce,
      verificationDirectory: normalizeShareVerificationDirectory(admission.verification_directory),
    },
  };
}
