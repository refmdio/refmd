import {
  loadMountTrustAnchor,
  type ShareMountDocument,
  type ShareMountDetail,
} from "@/entities/mount";
import { base64UrlDecode } from "@/shared/lib/crypto/encoding";
import { ensureShareParticipantDeviceReady } from "../../lib/session/session";
import { resolveMountedShareOpen } from "../../lib/route/mount";

export async function openMountedShareDocument(
  mountId: string,
  detail: ShareMountDetail,
  document: ShareMountDocument,
) {
  const anchor = await loadMountTrustAnchor(mountId);
  const shareSessionKey = anchor?.shareSessionKey;
  if (!shareSessionKey) throw new Error("mount_trust_anchor_unavailable");
  if (document.authorization_share_id !== anchor.shareId) {
    throw new Error("mount_trust_anchor_document_mismatch");
  }

  const participantSession = await ensureShareParticipantDeviceReady({
    requiredShareSlug: shareSessionKey,
  });
  if (!participantSession) throw new Error("share_participant_session_unavailable");

  return resolveMountedShareOpen(mountId, detail, document, {
    principalId: participantSession.principalId,
    displayName: participantSession.displayName,
    deviceId: participantSession.deviceId,
    sessionId: participantSession.sessionId,
    signingKeyId: participantSession.signingKeyId,
    hybridSigningPublicKeyMaterial: participantSession.hybridSigningPublicKeyMaterial,
    encryptionPublicKey: base64UrlDecode(participantSession.encryptionPublicKey),
  });
}
