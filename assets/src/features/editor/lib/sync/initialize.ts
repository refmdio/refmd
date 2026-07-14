import {
  notifyForegroundDocumentOpen,
  notifyForegroundDocumentClose,
} from "@/shared/lib/offline/cache/foreground-busy";
import type { DocumentState } from "../../model/document-state/types";
import { DocumentSyncError } from "./error";

const INITIAL_SYNC_TIMEOUT_MS = 45_000;

function withInitializationTimeout<T>(
  promise: Promise<T>,
  abortController: AbortController,
): Promise<T> {
  let timeout: ReturnType<typeof setTimeout> | null = null;
  const timeoutPromise = new Promise<never>((_, reject) => {
    timeout = setTimeout(() => {
      abortController.abort();
      reject(
        new DocumentSyncError("server_unreachable", "Timed out while initializing document sync"),
      );
    }, INITIAL_SYNC_TIMEOUT_MS);
  });

  return Promise.race([promise, timeoutPromise]).finally(() => {
    if (timeout) clearTimeout(timeout);
  });
}

export async function initializeDocumentSync(
  documentId: string,
  workspaceId: string,
  state: DocumentState,
  options: { skipDocumentWipeAcknowledgement?: boolean } = {},
): Promise<void> {
  const abortController = new AbortController();
  state._initAbortController?.abort();
  state._initAbortController = abortController;
  notifyForegroundDocumentOpen();
  try {
    const { doInitializeDocumentSync } = await import("./bootstrap-initialize");
    const { normalizeDocumentSyncError } = await import("./bootstrap-initialize");
    const initPromise = doInitializeDocumentSync(
      documentId,
      workspaceId,
      state,
      abortController.signal,
      options,
    );
    void initPromise.catch(() => {});
    try {
      await withInitializationTimeout(initPromise, abortController);
      return;
    } catch (err) {
      const normalized = normalizeDocumentSyncError(err);
      throw normalized;
    }
  } catch (err) {
    state.initPromise = null;
    throw err;
  } finally {
    if (state._initAbortController === abortController) {
      state._initAbortController = null;
    }
    notifyForegroundDocumentClose();
  }
}
