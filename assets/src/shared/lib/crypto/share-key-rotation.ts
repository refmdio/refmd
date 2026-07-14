import { encryptionApi, workspacesApi, type components } from "@/shared/api";
import { getKeyDirectoryPin } from "@/shared/lib/anti-rollback/key-directory-pin/pins";
import { base64UrlDecode, base64UrlEncode } from "@/shared/lib/crypto/encoding";
import { blake3Base64Url } from "@/shared/lib/crypto/hash";
import { canonicalizeStrictBytes } from "@/shared/lib/crypto/jcs";
import { buildShareManagementKeyDirectoryAppend } from "@/shared/lib/crypto/key-directory/share-events";
import type { KeyDirectoryEnvelope } from "@/shared/lib/crypto/key-directory/types";
import type { HybridSigningPublicKeyMaterial } from "@/shared/lib/crypto/signature-types";
import { signedPqWrapRecordFromEnvelope } from "@/shared/lib/crypto/signed-pq-wrap";
import { getCryptoWorker } from "@/shared/lib/crypto/worker/client";
import { fetchVerifiedKeyDirectory } from "@/shared/lib/key-directory/fetch";
import { verifyWorkspaceSignedPqWrapOperation } from "@/shared/lib/anti-rollback/key-directory-pin/wrap-operation-proof";

type RotationTarget = components["schemas"]["DocumentKeyRotationTarget"];
type RotationReplacement = components["schemas"]["DocumentShareKeyRotationReplacement"];

export async function prepareDocumentShareKeyRotation(params: {
  documentId: string;
  workspaceId: string;
  nextKeyVersion: number;
  actorUserId: string;
  actorDeviceId: string;
  checkpointEnvelope?: KeyDirectoryEnvelope;
}): Promise<{
  share_key_replacements: RotationReplacement[];
  workspace_key_directory_events?: KeyDirectoryEnvelope[];
  workspace_key_directory_checkpoint?: KeyDirectoryEnvelope;
}> {
  const manifest = await encryptionApi.getDocumentKeyRotationTargets(params.documentId);
  if (manifest.current_key_version + 1 !== params.nextKeyVersion) {
    throw new Error("share_key_rotation_version_mismatch");
  }
  if (manifest.targets.length === 0) return { share_key_replacements: [] };

  const worker = getCryptoWorker();
  const shareSlugs = new Map<string, string>();
  for (const target of manifest.targets) {
    if (!shareSlugs.has(target.root_share_id)) {
      shareSlugs.set(
        target.root_share_id,
        await restoreShareSlugFromBackup(params.workspaceId, target),
      );
    }
  }

  const replacements = await Promise.all(
    manifest.targets.map(async (target) => {
      const shareSlug = shareSlugs.get(target.root_share_id);
      if (!shareSlug) throw new Error("share_key_rotation_secret_unavailable");
      const wrapped = await worker.wrapPreparedShareDek({
        shareSlug,
        documentId: params.documentId,
        shareId: target.target_share_id,
        keyVersion: params.nextKeyVersion,
      });
      return {
        root_share_id: target.root_share_id,
        share_id: target.target_share_id,
        document_id: params.documentId,
        key_version: params.nextKeyVersion,
        encrypted_dek: base64UrlEncode(wrapped.encryptedDek),
        nonce: base64UrlEncode(wrapped.nonce),
      } satisfies RotationReplacement;
    }),
  );

  const directory = await buildRotationDirectory(
    params.workspaceId,
    params.actorUserId,
    params.actorDeviceId,
    manifest.targets,
    replacements,
    params.checkpointEnvelope,
  );
  return { share_key_replacements: replacements, ...directory };
}

async function restoreShareSlugFromBackup(
  workspaceId: string,
  target: RotationTarget,
): Promise<string> {
  const worker = getCryptoWorker();
  const signingMaterialByKey = new Map<string, HybridSigningPublicKeyMaterial>();
  const failures: string[] = [];

  for (const rawWrap of target.share_link_secret_backup_wraps) {
    const wrap = signedPqWrapRecordFromEnvelope(rawWrap);
    const sender = wrap.sender as Record<string, unknown>;
    const senderUserId = sender.user_id;
    const senderSigningKeyId = sender.signing_key_id;
    if (typeof senderUserId !== "string" || typeof senderSigningKeyId !== "string") {
      failures.push("sender_invalid");
      continue;
    }

    let senderMaterial = signingMaterialByKey.get(senderSigningKeyId);
    if (!senderMaterial) {
      const devices = await workspacesApi.listMemberDevices(workspaceId, senderUserId, true);
      const senderDevice = devices.devices.find(
        (candidate) => candidate.signing_key_id === senderSigningKeyId,
      );
      if (!senderDevice) {
        failures.push("sender_device_unavailable");
        continue;
      }
      senderMaterial =
        senderDevice.hybrid_signing_public_key_material as unknown as HybridSigningPublicKeyMaterial;
      signingMaterialByKey.set(senderSigningKeyId, senderMaterial);
    }

    try {
      await verifyWorkspaceSignedPqWrapOperation(workspaceId, rawWrap);
      const opened = await worker.openSignedPqShareLinkSecretBackupWrap({
        operationProof: rawWrap,
        senderSigningPublicKeyMaterial: senderMaterial,
        expectedShareId: target.root_share_id,
      });
      const match = opened.sharePathWithFragment.match(/^\/share\/([^#/?]+)/);
      if (match?.[1]) return match[1];
    } catch (error) {
      failures.push(error instanceof Error ? error.message : "backup_wrap_open_failed");
      // Try the next recipient wrap.
    }
  }

  throw new Error(
    `share_key_rotation_secret_unavailable:${failures.join(",") || "no_recipient_wrap"}`,
  );
}

async function buildRotationDirectory(
  workspaceId: string,
  actorUserId: string,
  actorDeviceId: string,
  targets: RotationTarget[],
  replacements: RotationReplacement[],
  checkpointEnvelope?: KeyDirectoryEnvelope,
): Promise<{
  workspace_key_directory_events: KeyDirectoryEnvelope[];
  workspace_key_directory_checkpoint: KeyDirectoryEnvelope;
}> {
  const pin = await getKeyDirectoryPin("workspace", workspaceId);
  if (!pin) throw new Error("workspace_key_directory_pin_required");
  const directory = await fetchVerifiedKeyDirectory({
    scopeKind: "workspace",
    scopeId: workspaceId,
    rrpDeviceId: actorDeviceId,
  });
  let checkpoint = checkpointEnvelope ?? directory.checkpoint;
  const events: KeyDirectoryEnvelope[] = [];
  const targetsByShare = new Map(targets.map((target) => [target.target_share_id, target]));

  for (const replacement of replacements) {
    const target = targetsByShare.get(replacement.share_id);
    if (!target) throw new Error("share_key_rotation_target_missing");
    const sequence = nextEventSequence(checkpoint);
    const append = await buildShareManagementKeyDirectoryAppend({
      workspaceId,
      actorUserId,
      actorDeviceId,
      checkpointEnvelope: checkpoint,
      eventType: "share_key_scope_replaced",
      body: {
        workspace_id: workspaceId,
        share_id: replacement.share_id,
        scope_kind: "document",
        scope_id: replacement.document_id,
        document_scope_hash: scopeHash(workspaceId, replacement.document_id),
        share_metadata_hash: replacementHash(replacement),
        share_key_version: replacement.key_version,
        previous_share_key_version: target.current_key_version,
        replaced_at_event_sequence: sequence,
      },
    });
    events.push(...append.events);
    checkpoint = append.checkpoint;
  }

  return {
    workspace_key_directory_events: events,
    workspace_key_directory_checkpoint: checkpoint,
  };
}

function nextEventSequence(checkpoint: KeyDirectoryEnvelope): number {
  const payload = checkpoint.payload as Record<string, unknown>;
  const covered = payload.covered_event_head as Record<string, unknown>;
  if (typeof covered.head_sequence !== "number") {
    throw new Error("workspace_key_directory_checkpoint_invalid");
  }
  return covered.head_sequence + 1;
}

function scopeHash(workspaceId: string, documentId: string): string {
  return blake3Base64Url(
    canonicalizeStrictBytes({ workspace_id: workspaceId, document_id: documentId }),
  );
}

function replacementHash(replacement: RotationReplacement): string {
  return blake3Base64Url(
    canonicalizeStrictBytes({
      share_id: replacement.share_id,
      encrypted_dek_hash: blake3Base64Url(base64UrlDecode(replacement.encrypted_dek)),
      nonce_hash: blake3Base64Url(base64UrlDecode(replacement.nonce)),
    }),
  );
}
