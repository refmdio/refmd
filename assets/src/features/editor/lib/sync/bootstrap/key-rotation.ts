import { getCryptoWorker } from "@/shared/lib/crypto/worker/client";
import { base64UrlDecode, base64UrlEncode } from "@/shared/lib/crypto/encoding";
import { getKekResolverSession } from "@/entities/session";
import { resolveActiveKek, resolveKekByVersion } from "@/shared/lib/crypto/kek-resolver";
import { encryptionApi } from "@/shared/api/encryption";
import { documentsApi } from "@/shared/api/documents";
import { workspacesApi } from "@/shared/api/workspaces";
import type { DocumentState } from "../../../model/document-state/types";

/**
 * Detect needs_dek_rotation and complete rotation if needed.
 * device.md step 8: other workspace members (document:write + KEK)
 * detect the flag on document access and auto-complete the rotation.
 * Errors are caught silently — rotation failure must not block document viewing.
 */
export async function completeDekRotationIfNeeded(
  documentId: string,
  workspaceId: string,
  state: DocumentState,
): Promise<void> {
  try {
    await doCompleteDekRotation(documentId, workspaceId, state);
  } catch (err) {
    console.error("[sync] DEK rotation completion failed (non-blocking):", err);
    // Another client may have completed the rotation. Refresh active DEK version.
    try {
      const worker = getCryptoWorker();
      const refreshed = await encryptionApi.getDocumentKeys(documentId);
      const refreshedActive = refreshed.keys.find((key) => key.is_active);
      if (refreshedActive && refreshedActive.key_version !== state.keyVersion) {
        await resolveKekByVersion(
          workspaceId,
          refreshedActive.kek_version,
          getKekResolverSession(),
        );
        await worker.unwrapDek({
          encryptedDek: base64UrlDecode(refreshedActive.encrypted_dek),
          nonce: base64UrlDecode(refreshedActive.nonce),
          documentId,
          workspaceId,
          keyVersion: refreshedActive.key_version,
          isActive: true,
          kekVersion: refreshedActive.kek_version,
        });
        state.keyVersion = refreshedActive.key_version;
      }
    } catch {
      // Best-effort refresh
    }
  }
}

async function doCompleteDekRotation(
  documentId: string,
  workspaceId: string,
  state: DocumentState,
): Promise<void> {
  const doc = await documentsApi.get(documentId);
  if (!doc?.needs_dek_rotation) return;

  // Step 5 must complete before step 6 (device.md)
  const workspace = await workspacesApi.get(workspaceId);
  if (workspace.needs_kek_rotation) return;

  // Re-resolve active KEK (may have changed since init if KEK rotation just completed)
  await resolveActiveKek(workspaceId, getKekResolverSession());

  const worker = getCryptoWorker();
  const nextKeyVersion = state.keyVersion + 1;

  // Generate new DEK without setting it as active (setActive: false).
  // Active version is only updated after successful server save.
  const {
    encryptedDek,
    nonce,
    keyVersion: kekVersion,
  } = await worker.generateDek(documentId, workspaceId, nextKeyVersion, false);

  // Save to server (also clears needs_dek_rotation flag and updates min_dek_version)
  try {
    await encryptionApi.createDocumentKey(documentId, {
      encrypted_dek: base64UrlEncode(encryptedDek),
      nonce: base64UrlEncode(nonce),
      key_version: nextKeyVersion,
      kek_version: kekVersion,
    });
  } catch (err) {
    // POST failed: evict the speculative DEK from cache
    await worker.evictDek(documentId, nextKeyVersion).catch(() => {});
    throw err;
  }

  // POST succeeded: now activate the new DEK
  await worker.unwrapDek({
    encryptedDek,
    nonce,
    documentId,
    workspaceId,
    keyVersion: nextKeyVersion,
    isActive: true,
    kekVersion,
  });

  // Don't advance state.keyVersion yet — peers still have the old DEK.
  // The rotation snapshot is the cutover point; keyVersion advances in handleSnapshotSaved.
  // Ephemeral messages continue using the old DEK until all peers have the new one.
  state.pendingRotationKeyVersion = nextKeyVersion;

  // Immediate title re-encryption uses the new key directly via nextKeyVersion
  try {
    await reEncryptTitleIfNeeded(documentId, workspaceId, state, nextKeyVersion);
  } catch (err) {
    console.error("[sync] Title re-encryption failed (will retry on next open):", err);
  }

  // Set snapshot trigger (post-rotation snapshot requirement)
  state.pendingRotationSnapshot = true;
}

/**
 * Re-encrypt document title if its key version doesn't match the active DEK.
 * Executed immediately after DEK rotation (not deferred to Snapshot).
 * Also handles crash recovery: stale title detected on document open.
 */
export async function reEncryptTitleIfNeeded(
  documentId: string,
  _workspaceId: string,
  state: DocumentState,
  targetKeyVersion?: number,
  docMeta?: Awaited<ReturnType<typeof documentsApi.get>>,
): Promise<void> {
  const worker = getCryptoWorker();
  const newKeyVersion = targetKeyVersion ?? state.keyVersion;

  const doc =
    docMeta ??
    (await documentsApi.get(documentId).catch(() => {
      return null;
    }));
  if (!doc) return;

  if (!doc.encrypted_title || !doc.encrypted_title_nonce || !doc.encrypted_title_key_version) {
    return;
  }

  // Only re-encrypt if title is on an older DEK version
  if (doc.encrypted_title_key_version >= newKeyVersion) return;

  const oldKeyVersion = doc.encrypted_title_key_version;
  const title = await worker.decryptTitle({
    encrypted: base64UrlDecode(doc.encrypted_title),
    nonce: base64UrlDecode(doc.encrypted_title_nonce),
    documentId,
    keyVersion: oldKeyVersion,
  });

  const { encrypted, nonce } = await worker.encryptTitle({
    title,
    documentId,
    keyVersion: newKeyVersion,
  });

  await documentsApi.update(documentId, {
    encrypted_title: base64UrlEncode(encrypted),
    encrypted_title_nonce: base64UrlEncode(nonce),
    encrypted_title_key_version: newKeyVersion,
  });
}
