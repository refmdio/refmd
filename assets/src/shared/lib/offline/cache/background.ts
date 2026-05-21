import { getCryptoWorker } from "@/shared/lib/crypto/worker/client";
import { buildChannelPopResource, getChannelPopParams } from "@/shared/lib/auth/pop";
import { clientWarn } from "@/shared/lib/logger";
import {
  hasTrackedDocumentChannel,
  joinTemporaryDocument,
  type DocumentChannelCallbacks,
} from "@/shared/lib/ws/phoenix-channel";
import { ensurePhoenixWsToken } from "@/shared/lib/ws/socket";
import { documentsApi } from "@/shared/api/documents";
import { encryptionApi } from "@/shared/api/encryption";
import { resolveActiveKek, type KekResolverSession } from "@/shared/lib/crypto/kek-resolver";
import { base64UrlDecode, base64UrlEncode } from "@/shared/lib/crypto/encoding";
import type { HybridSigningPublicKeyMaterial } from "@/shared/lib/crypto/signature-types";
import {
  documentOperationAuthorityBoundary,
  verifyDocumentOperationAdmission,
  verifyDocumentOperationAdmissionAncestry,
} from "@/shared/lib/document/document-operation-admission";
import { documentClockKey } from "@/shared/lib/anti-rollback/clock-observations";
import * as Y from "yjs";
import {
  getOfflineDocumentMeta,
  getAllOfflineDocumentMetas,
  getDocumentCache,
  putDocumentCache,
  putOfflineDocumentMeta,
  type DocumentCacheEntry,
} from "../storage/store";
import { cacheDek, cacheKek } from "./manager/keys";
import { offlineMode } from "../offline-state";
import { checkAndEvict } from "./eviction";
import type { components } from "@/shared/api";
import { waitForForegroundIdle } from "./foreground-busy";
const BACKGROUND_CACHE_INTERVAL_MS = 2000;
const MAX_BACKGROUND_CACHE_BROWSER = 50;
const MAX_BACKGROUND_CACHE_DESKTOP = 200;
type DeviceKeyCacheResult =
  | {
      status: "ok";
      signingKeys: Map<string, HybridSigningPublicKeyMaterial>;
      signingKeyOwners: Map<string, string>;
    }
  | {
      status: "key_changed";
    };
type BuildDeviceKeyCaches = (
  workspaceId: string,
  signal?: AbortSignal,
) => Promise<DeviceKeyCacheResult>;
type DocumentListEntry = Awaited<ReturnType<typeof documentsApi.list>>["documents"][number];
type DocumentKey = components["schemas"]["DocumentKeyResponse"];

function isTauri(): boolean {
  return typeof window !== "undefined" && "__TAURI__" in window;
}
function getMaxBackgroundCache(): number {
  return isTauri() ? MAX_BACKGROUND_CACHE_DESKTOP : MAX_BACKGROUND_CACHE_BROWSER;
}
let activeCachingWorkspace: string | null = null;

export function startBackgroundCaching(
  workspaceId: string,
  buildDeviceKeyCaches: BuildDeviceKeyCaches,
  getKekResolverSession: () => KekResolverSession,
): () => void {
  let cancelled = false;
  const run = async () => {
    if (activeCachingWorkspace === workspaceId) return;
    activeCachingWorkspace = workspaceId;
    try {
      const result = await documentsApi.list(workspaceId);
      if (cancelled || offlineMode()) return;
      // Sort by lastAccessedAt from offline-documents (local access history),
      // falling back to server updated_at for documents not yet accessed locally
      const offlineMetas = await getAllOfflineDocumentMetas().catch(() => []);
      const accessMap = new Map(offlineMetas.map((m) => [m.documentId, m.lastAccessedAt]));
      const sortedDocs = [...result.documents]
        .filter((d) => d.doc_type === "document")
        .sort((a, b) => {
          const aAccess = accessMap.get(a.id) ?? 0;
          const bAccess = accessMap.get(b.id) ?? 0;
          if (aAccess !== bAccess) {
            return bAccess - aAccess;
          }
          const aUpdatedAt = Date.parse(a.updated_at ?? "") || 0;
          const bUpdatedAt = Date.parse(b.updated_at ?? "") || 0;
          return bUpdatedAt - aUpdatedAt;
        })
        .slice(0, getMaxBackgroundCache());
      for (const doc of sortedDocs) {
        if (cancelled || offlineMode()) break;
        // Pause while user is actively opening a document
        await waitForForegroundIdle(() => cancelled);
        if (cancelled || offlineMode()) break;
        if (hasTrackedDocumentChannel(doc.id)) continue;
        const existing = await getDocumentCache(doc.id);
        if (existing) continue;
        try {
          await cacheDocumentSilently(
            doc.id,
            workspaceId,
            buildDeviceKeyCaches,
            getKekResolverSession,
            doc,
          );
        } catch {
          // Skip failures
        }
        if (cancelled) break;
        await new Promise((r) => setTimeout(r, BACKGROUND_CACHE_INTERVAL_MS));
      }
      checkAndEvict().catch(() => {});
    } catch {
      // Document list fetch failed
    } finally {
      activeCachingWorkspace = null;
    }
  };
  // Start after a short delay to not interfere with initial page load
  const timer = setTimeout(run, 5000);
  return () => {
    cancelled = true;
    clearTimeout(timer);
  };
}
async function cacheDocumentSilently(
  documentId: string,
  workspaceId: string,
  buildDeviceKeyCaches: BuildDeviceKeyCaches,
  getKekResolverSession: () => KekResolverSession,
  docInfo?: DocumentListEntry,
): Promise<void> {
  await ensurePhoenixWsToken("user");
  const worker = getCryptoWorker();
  // Build member signing key set for signature verification
  const keyCaches = await buildDeviceKeyCaches(workspaceId);
  if (keyCaches.status === "key_changed") throw new Error("TOFU key change detected");
  const validSigningKeys = keyCaches.signingKeys;
  const resolveSigningKey = (
    signingKeyId: string,
  ): { key: HybridSigningPublicKeyMaterial; ownerId: string } | null => {
    const key = validSigningKeys.get(signingKeyId);
    const ownerId = keyCaches.signingKeyOwners.get(signingKeyId);
    return key && ownerId ? { key, ownerId } : null;
  };
  // Resolve KEK and cache to offline-kek-cache
  const { kekVersion } = await resolveActiveKek(workspaceId, getKekResolverSession());
  await cacheKek(workspaceId, kekVersion).catch(() => {});
  const dekResp = await encryptionApi.getDocumentKeys(documentId);
  const activeDek = dekResp.keys.find((key: DocumentKey) => key.is_active);
  if (!activeDek) return;
  // Resolve version-specific KEK if DEK was wrapped by an older KEK version
  if (activeDek.kek_version && activeDek.kek_version !== kekVersion) {
    const { resolveKekByVersion } = await import("@/shared/lib/crypto/kek-resolver");
    await resolveKekByVersion(workspaceId, activeDek.kek_version, getKekResolverSession());
  }
  await worker.unwrapDek({
    encryptedDek: base64UrlDecode(activeDek.encrypted_dek),
    nonce: base64UrlDecode(activeDek.nonce),
    documentId,
    workspaceId,
    keyVersion: activeDek.key_version,
    isActive: true,
    kekVersion: activeDek.kek_version,
  });
  // Get pin before entering Promise executor (which cannot use await)
  const { getDocumentStatePin: getPin, hasCompleteSnapshotPin } =
    await import("@/shared/lib/anti-rollback/document-state-pins");
  const bgPin = await getPin(documentId).catch(() => null);
  const joinParams: Record<string, unknown> = {
    mode: "complete",
    silent: true,
  };
  if (hasCompleteSnapshotPin(bgPin)) {
    joinParams.knownSnapshotId = bgPin.latestSnapshotId;
  }
  const popParams = await getChannelPopParams(
    undefined,
    undefined,
    "user",
    undefined,
    buildChannelPopResource(documentId, "user", undefined, joinParams),
  );
  Object.assign(joinParams, popParams);
  return new Promise<void>((resolve, reject) => {
    let resolved = false;
    let disposeChannel: (() => void) | null = null;
    const cleanup = () => {
      clearTimeout(timeout);
      disposeChannel?.();
      disposeChannel = null;
    };
    const timeout = setTimeout(() => {
      if (!resolved) {
        resolved = true;
        cleanup();
        reject(new Error("Timeout"));
      }
    }, 30000);
    const callbacks: DocumentChannelCallbacks = {
      onDocument: async (payload) => {
        try {
          const yDoc = new Y.Doc();
          // Verify and decrypt snapshot
          if (payload.snapshot) {
            const snap = payload.snapshot;
            const spk = snap.publicData.signingKeyId;
            const signingKey = resolveSigningKey(spk);
            if (!signingKey) throw new Error("Snapshot signer is not foreground-verifiable");
            const sigValid = await worker.verifyDocumentSnapshotSignature({
              publicKeyMaterial: signingKey.key,
              signature: snap.signature,
              actorUserId: signingKey.ownerId,
              workspaceId,
              publicData: snap.publicData,
              authorityBoundary: documentOperationAuthorityBoundary(
                snap.admission,
                "document_snapshot_accepted",
              ),
              ciphertext: snap.ciphertext,
              nonce: snap.nonce,
            });
            if (!sigValid) throw new Error("Snapshot signature verification failed");
            if (!payload.snapshotAdmissionEventHash) {
              throw new Error("Snapshot admission event hash missing");
            }
            const snapshotCiphertextHash = base64UrlEncode(
              await worker.blake3Hash(base64UrlDecode(snap.ciphertext)),
            );
            await verifyDocumentOperationAdmission({
              admission: snap.admission,
              eventType: "document_snapshot_accepted",
              publicData: snap.publicData,
              workspaceId,
              documentId,
              operationHash: snapshotCiphertextHash,
              signature: snap.signature,
              actorUserId: signingKey.ownerId,
              expectedAdmissionEventHash: payload.snapshotAdmissionEventHash,
            });
            await verifyDocumentOperationAdmissionAncestry({
              admission: snap.admission,
              workspaceId,
            });
            const decrypted = await worker.decryptSnapshot({
              ciphertext: base64UrlDecode(snap.ciphertext),
              nonce: base64UrlDecode(snap.nonce),
              documentId,
              keyVersion: snap.publicData.keyVersion,
            });
            Y.applyUpdateV2(yDoc, decrypted, "remote");
          }
          // Verify and decrypt updates
          if (payload.updates) {
            for (const update of payload.updates) {
              const upk = update.publicData.signingKeyId;
              const signingKey = resolveSigningKey(upk);
              if (!signingKey) throw new Error("Update signer is not foreground-verifiable");
              const sigValid = await worker.verifyDocumentUpdateSignature({
                publicKeyMaterial: signingKey.key,
                signature: update.signature,
                actorUserId: signingKey.ownerId,
                workspaceId,
                publicData: update.publicData,
                authorityBoundary: documentOperationAuthorityBoundary(
                  update.admission,
                  "document_update_accepted",
                ),
                ciphertext: update.ciphertext,
                nonce: update.nonce,
              });
              if (!sigValid) throw new Error("Update signature verification failed");
              const updateHash = await worker.computeUpdateHash({
                clock: update.publicData.clock,
                signing_key_id: update.publicData.signingKeyId,
                document_id: documentId,
                encrypted_content: update.ciphertext,
                key_version: update.publicData.keyVersion,
                nonce: update.nonce,
                ref_snapshot_id: update.publicData.refSnapshotId,
                timestamp: update.publicData.timestamp,
              });
              if (updateHash !== update.publicData.updateHash) {
                throw new Error("Update hash verification failed");
              }
              await verifyDocumentOperationAdmission({
                admission: update.admission,
                eventType: "document_update_accepted",
                publicData: update.publicData,
                workspaceId,
                documentId,
                operationHash: updateHash,
                signature: update.signature,
                actorUserId: signingKey.ownerId,
              });
              await verifyDocumentOperationAdmissionAncestry({
                admission: update.admission,
                workspaceId,
              });
              const decrypted = await worker.decryptContent({
                ciphertext: base64UrlDecode(update.ciphertext),
                nonce: base64UrlDecode(update.nonce),
                documentId,
                keyVersion: update.publicData.keyVersion,
              });
              Y.applyUpdate(yDoc, decrypted, "remote");
            }
          }
          // Encrypt and cache
          const yjsState = Y.encodeStateAsUpdate(yDoc);
          const { ciphertext, nonce } = await worker.encryptOfflineCache({
            plaintext: yjsState,
            documentId,
            keyVersion: activeDek.key_version,
          });
          const snapshotId = payload.snapshot?.publicData.snapshotId ?? "";
          // Build confirmed sync metadata from payload
          let confirmedVersion = payload.latestVersion ?? 0;
          const confirmedClocks: Record<string, number> = {};
          if (payload.updates) {
            for (const update of payload.updates) {
              const key = documentClockKey(update.publicData);
              const clock = update.publicData.clock;
              if (clock > (confirmedClocks[key] ?? -1)) {
                confirmedClocks[key] = clock;
              }
              if (update.version > confirmedVersion) {
                confirmedVersion = update.version;
              }
            }
          }
          const entry: DocumentCacheEntry = {
            documentId,
            workspaceId,
            encryptedState: ciphertext,
            stateNonce: nonce,
            keyVersion: activeDek.key_version,
            confirmedStateVector: Y.encodeStateVector(yDoc),
            confirmedSnapshotId: snapshotId,
            confirmedVersion,
            confirmedClocks,
            cachedAt: Date.now(),
            updatedAt: Date.now(),
          };
          // Cache DEK first (design: offline-dek-cache before document-cache for crash safety)
          await cacheDek(documentId, activeDek.key_version);
          // Validate against anti-rollback pin before caching. Background cache does not advance
          // the durable pin because its signer context is best-effort and must not outrank
          // foreground verification.
          try {
            const { validateDocumentPayloadAgainstPin } =
              await import("@/shared/lib/anti-rollback/validate-document-payload");
            const validation = await validateDocumentPayloadAgainstPin(
              documentId,
              payload as import("@/shared/lib/anti-rollback/validate-document-payload").DocumentPayloadForValidation,
            );
            if (validation.rollbackWarnings.length > 0) {
              // Skip pin update and document cache for rollback-detected documents.
              // These require user approval which background cache cannot provide.
              clientWarn("background_cache_rollback_detected", { documentId });
              throw new Error("Rollback detected during background cache");
            }
            await putDocumentCache(entry);
          } catch (pinErr) {
            // Pin validation failure in background cache: skip this document
            clientWarn("background_cache_pin_validation_failed", { documentId, error: pinErr });
            yDoc.destroy();
            cleanup();
            resolved = true;
            reject(pinErr);
            return;
          }
          // Store metadata with DSK-encrypted title
          let encTitle: Uint8Array = new Uint8Array(0);
          let encTitleNonce: Uint8Array = new Uint8Array(0);
          if (
            docInfo?.encrypted_title &&
            docInfo?.encrypted_title_nonce &&
            docInfo?.encrypted_title_key_version != null
          ) {
            try {
              const titlePlain = await worker.decryptTitle({
                encrypted: base64UrlDecode(docInfo.encrypted_title),
                nonce: base64UrlDecode(docInfo.encrypted_title_nonce),
                documentId,
                keyVersion: docInfo.encrypted_title_key_version,
              });
              const { wrapTitleWithDsk } = await import("./manager/keys");
              const wrapped = await wrapTitleWithDsk(documentId, titlePlain);
              encTitle = wrapped.encryptedTitle;
              encTitleNonce = wrapped.encryptedTitleNonce;
            } catch {
              // Title encryption failed, keep empty
            }
          }
          const existingMeta = await getOfflineDocumentMeta(documentId).catch(() => null);
          await putOfflineDocumentMeta({
            documentId,
            workspaceId,
            encryptedTitle:
              encTitle.length > 0 ? encTitle : (existingMeta?.encryptedTitle ?? encTitle),
            encryptedTitleNonce:
              encTitleNonce.length > 0
                ? encTitleNonce
                : (existingMeta?.encryptedTitleNonce ?? encTitleNonce),
            lastAccessedAt: existingMeta?.lastAccessedAt ?? 0,
            cacheSize: ciphertext.byteLength,
          });
          yDoc.destroy();
          cleanup();
          resolved = true;
          resolve();
        } catch (err) {
          cleanup();
          resolved = true;
          reject(err);
        }
      },
      onUpdate: () => {},
      onSnapshot: () => {},
      onUpdateSaved: () => {},
      onUpdateSaveFailed: () => {},
      onSnapshotSaved: () => {},
      onSnapshotSaveFailed: () => {},
      onEphemeralMessage: () => {},
      onPeerLeft: () => {},
      onPublicStatusChanged: () => {},
      onUnauthorized: () => {
        cleanup();
        resolved = true;
        reject(new Error("Unauthorized"));
      },
      onError: (reason) => {
        cleanup();
        resolved = true;
        reject(new Error(String(reason)));
      },
      onClose: () => {
        if (!resolved) {
          cleanup();
          resolved = true;
          reject(new Error("Connection closed"));
        }
      },
    };
    joinTemporaryDocument(documentId, joinParams, callbacks, "user")
      .then(({ dispose }) => {
        disposeChannel = dispose;
      })
      .catch((err) => {
        cleanup();
        resolved = true;
        reject(err);
      });
  });
}
