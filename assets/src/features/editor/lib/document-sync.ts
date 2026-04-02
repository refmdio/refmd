import {
  notifyForegroundDocumentOpen,
  notifyForegroundDocumentClose,
} from "@/shared/lib/offline/background-cache";
import type { DocumentState } from "./document-state-cache";

export async function initializeDocumentSync(
  documentId: string,
  workspaceId: string,
  state: DocumentState,
): Promise<void> {
  const abortController = new AbortController();
  state._initAbortController?.abort();
  state._initAbortController = abortController;
  notifyForegroundDocumentOpen();
  try {
    const { doInitializeDocumentSync } = await import("./document-sync-init");
    await doInitializeDocumentSync(documentId, workspaceId, state, abortController.signal);
  } catch (err) {
    state.initPromise = null;
    const { normalizeDocumentSyncError } = await import("./document-sync-init");
    throw normalizeDocumentSyncError(err);
  } finally {
    if (state._initAbortController === abortController) {
      state._initAbortController = null;
    }
    notifyForegroundDocumentClose();
  }
}
