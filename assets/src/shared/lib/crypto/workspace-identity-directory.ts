import { encryptionApi } from "@/shared/api";
import { fetchVerifiedKeyDirectory } from "@/shared/lib/key-directory/fetch";
import { buildIdentityKeyDirectoryAppend } from "./key-directory/device-events";
import type { KeyDirectoryEnvelope } from "./key-directory/types";
import {
  computeHybridEncryptionKeyId,
  type HybridEncryptionPublicKeyMaterial,
} from "./hybrid-encryption";
import { computeSigningKeyId } from "./signature";
import type { HybridSigningPublicKeyMaterial } from "./signature-types";

export async function ensureWorkspaceIdentityKey(params: {
  workspaceId: string;
  ownerUserId: string;
  ownerDeviceId: string;
  targetUserId: string;
  targetIdentityHybridEncryptionPublicKeyMaterial: HybridEncryptionPublicKeyMaterial;
  targetIdentityHybridSigningPublicKeyMaterial: HybridSigningPublicKeyMaterial;
}): Promise<{ checkpoint: KeyDirectoryEnvelope }> {
  const directory = await fetchVerifiedKeyDirectory({
    scopeKind: "workspace",
    scopeId: params.workspaceId,
    rrpDeviceId: params.ownerDeviceId,
  });
  const targetKeyId = computeHybridEncryptionKeyId(
    params.targetIdentityHybridEncryptionPublicKeyMaterial,
  );
  const targetSigningKeyId = computeSigningKeyId(
    params.targetIdentityHybridSigningPublicKeyMaterial,
  );
  if (
    checkpointHasIdentityKey(directory.checkpoint, targetKeyId) &&
    checkpointHasIdentityKey(directory.checkpoint, targetSigningKeyId)
  ) {
    return directory;
  }

  const append = await buildIdentityKeyDirectoryAppend({
    scopeKind: "workspace",
    scopeId: params.workspaceId,
    userId: params.ownerUserId,
    actorDeviceId: params.ownerDeviceId,
    checkpointEnvelope: directory.checkpoint,
    recipientHybridEncryptionPublicKeyMaterial:
      params.targetIdentityHybridEncryptionPublicKeyMaterial,
    recipientHybridSigningPublicKeyMaterial: params.targetIdentityHybridSigningPublicKeyMaterial,
  });
  await encryptionApi.appendWorkspaceKeyDirectory(
    params.workspaceId,
    { events: append.events, checkpoint: append.checkpoint },
    { rrpDeviceId: params.ownerDeviceId, ignoreConflict: true },
  );
  return { checkpoint: append.checkpoint };
}

function checkpointHasIdentityKey(
  checkpointEnvelope: KeyDirectoryEnvelope,
  keyId: string,
): boolean {
  const payload = checkpointEnvelope.payload as Record<string, unknown> | undefined;
  const identityKeys = payload?.identity_keys as Array<Record<string, unknown>> | undefined;
  return identityKeys?.some((entry) => entry.key_id === keyId && !entry["revoked_at"]) ?? false;
}
