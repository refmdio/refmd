import { getCryptoWorker } from "@/shared/lib/crypto/worker/client";
import { base64UrlDecode } from "@/shared/lib/crypto/encoding";
import { authState, deviceState, getKekResolverSession } from "@/entities/session";
import { resolveKekByVersion } from "@/shared/lib/crypto/kek-resolver";
import { encryptionApi } from "@/shared/api/encryption";
import { documentsApi } from "@/shared/api/documents";
import { queryClient } from "@/shared/lib/query/client";
import { getChannelState } from "@/shared/lib/ws/phoenix-channel";
import { getDocumentState } from "../../model/document-state/store";
import { notifyAwarenessReady } from "../../model/document-state/signals";
import type { DocumentState } from "../../model/document-state/types";
import {
  createEphemeralSession,
  encodeEphemeralPayload,
  MSG_INITIALIZE,
} from "./ephemeral-session";
import { sendEphemeralEnvelope } from "./ephemeral-send";
import { assignUserColor } from "../presence/user-colors";
import { setupAwarenessRelay } from "./ephemeral-awareness-relay";
import { cacheDocumentState, startPeriodicFlush } from "@/shared/lib/offline/cache/manager/write";
import { runDocumentOfflineWrite } from "@/shared/lib/crypto/document-key-write-barrier";
import { cacheDek, cacheKek } from "@/shared/lib/offline/cache/manager/keys";
import { checkAndEvict } from "@/shared/lib/offline/cache/eviction";
import { reEncryptTitleIfNeeded } from "./bootstrap-key-rotation";
import { getLocalIdentity } from "./share-identity";
import { getDocumentDekCacheKey } from "./share-access";
import { getDocumentCryptoWorker } from "./crypto-worker";

const INIT_RETRY_DELAY_MS = 5_000;
const MAX_INIT_RETRIES = 3;

function getCachedDocumentMeta(
  documentId: string,
  workspaceId: string,
): Awaited<ReturnType<typeof documentsApi.get>> | null {
  const cached = queryClient.getQueryData<Awaited<ReturnType<typeof documentsApi.list>>>([
    "documents",
    workspaceId,
  ]);
  return cached?.documents.find((doc) => doc.id === documentId) ?? null;
}

export async function primeHistoricalDeks(
  documentId: string,
  workspaceId: string,
  keys: Awaited<ReturnType<typeof encryptionApi.getDocumentKeys>>["keys"],
  activeKekVersion: number,
  activeKeyVersion: number,
  signal?: AbortSignal,
): Promise<void> {
  const worker = getCryptoWorker();

  for (const key of keys) {
    if (signal?.aborted) return;
    if (key.key_version === activeKeyVersion) continue;
    try {
      if (key.kek_version !== activeKekVersion) {
        await resolveKekByVersion(workspaceId, key.kek_version, getKekResolverSession(), signal);
      }
      await worker.unwrapDek({
        encryptedDek: base64UrlDecode(key.encrypted_dek),
        nonce: base64UrlDecode(key.nonce),
        documentId,
        workspaceId,
        keyVersion: key.key_version,
        kekVersion: key.kek_version,
      });
    } catch {
      // Historical DEKs are best-effort; ensureDekCached handles on-demand recovery.
    }
  }
}

export async function runPostInitializationTasks(
  documentId: string,
  workspaceId: string,
  state: DocumentState,
  localDeviceSigningKeyId?: string,
): Promise<void> {
  const isCurrentState = () => getDocumentState(state.stateKey) === state;

  const documentMetaTask = async () => {
    if (state.pendingRotationSnapshot) return;

    try {
      const docMeta = getCachedDocumentMeta(documentId, workspaceId);
      if (!docMeta || !isCurrentState()) return;

      if (docMeta.needs_rotation_snapshot) {
        state.pendingRotationSnapshot = true;
        state.autoSync?.notifyLocalEdit();
      }
      if (
        docMeta.encrypted_title_key_version &&
        docMeta.encrypted_title_key_version < state.keyVersion
      ) {
        await reEncryptTitleIfNeeded(documentId, workspaceId, state, state.keyVersion, docMeta);
      }
    } catch {
      // Best-effort
    }
  };

  const offlineCacheTask = async () => {
    await runDocumentOfflineWrite(documentId, async () => {
      try {
        const cacheOptions =
          state.access.kind === "share"
            ? {
                worker: getDocumentCryptoWorker(state),
                cacheKey: getDocumentDekCacheKey(state, documentId),
              }
            : undefined;
        if (state.access.kind !== "share") {
          const resolvedKek = await getCryptoWorker().resolveKek(workspaceId);
          await cacheDek(documentId, state.keyVersion).catch(() => {
            // Offline DEK cache is best-effort; the online editor keeps the active key in memory.
          });
          if (resolvedKek.found && resolvedKek.keyVersion !== undefined) {
            await cacheKek(workspaceId, resolvedKek.keyVersion).catch(() => {
              // Offline KEK cache is best-effort and will be retried after the next open/sync.
            });
          }
        }
        if (!isCurrentState()) return;
        cacheDocumentState(documentId, workspaceId, state, cacheOptions).catch(() => {
          // Offline document state cache is rebuilt from the current server/session state.
        });
        state.offlineFlushCleanup = startPeriodicFlush(
          documentId,
          workspaceId,
          state,
          cacheOptions,
        );
        checkAndEvict().catch(() => {
          // Cache eviction is opportunistic; quota pressure triggers another cleanup pass later.
        });
      } catch {
        // Best-effort
      }
    });
  };

  const awarenessTask = async () => {
    if (!localDeviceSigningKeyId || !isCurrentState() || state.ephemeralSession) return;

    const auth = state.access.kind === "share" ? null : authState();
    const currentDevice = state.access.kind === "share" ? null : deviceState();
    const shareIdentity = getLocalIdentity(state);
    if (!shareIdentity && (!auth || !currentDevice)) return;

    state.awareness.setLocalStateField("user", {
      userId: shareIdentity?.id ?? auth!.user.id,
      name: shareIdentity?.name ?? auth!.user.name,
      color: assignUserColor(shareIdentity?.colorSeed ?? auth!.user.id, state.awareness),
      signingKeyId: localDeviceSigningKeyId,
    });

    const session = createEphemeralSession();
    state.ephemeralSession = session;

    sendInitialize(session, state, documentId, localDeviceSigningKeyId);
    setupAwarenessRelay(state, documentId, localDeviceSigningKeyId);
    notifyAwarenessReady(state.stateKey);
  };

  if (state.access.kind === "share") {
    await Promise.allSettled([offlineCacheTask(), awarenessTask()]);
    return;
  }

  await Promise.allSettled([documentMetaTask(), offlineCacheTask(), awarenessTask()]);
}

// ── Ephemeral initialize with handshake fallback ─────────────

export function sendInitialize(
  session: ReturnType<typeof createEphemeralSession>,
  state: DocumentState,
  documentId: string,
  signingKeyId: string,
  attempt = 0,
): void {
  const payload = encodeEphemeralPayload(session, MSG_INITIALIZE, new Uint8Array(0));
  sendEphemeralEnvelope(
    payload,
    documentId,
    state,
    signingKeyId,
    state.stateKey,
    getDocumentDekCacheKey(state, documentId),
    getDocumentCryptoWorker(state),
  )
    .then(() => {
      session.initializeSent = true;
    })
    .catch(() => {
      // Initialize is retried below while the channel/session remains current.
    });

  if (attempt < MAX_INIT_RETRIES) {
    setTimeout(() => {
      if (
        state.ephemeralSession !== session ||
        !state.channel ||
        getChannelState(state.channel) !== "joined"
      ) {
        return;
      }
      sendInitialize(session, state, documentId, signingKeyId, attempt + 1);
    }, INIT_RETRY_DELAY_MS);
  }
}
