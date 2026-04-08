import {
  notifyForegroundDocumentOpen,
  notifyForegroundDocumentClose,
} from "@/shared/lib/offline/cache/foreground-busy";
import type { DocumentState } from "../../model/document-state/types";

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
    const { doInitializeDocumentSync } = await import("./bootstrap/initialize");
    await doInitializeDocumentSync(documentId, workspaceId, state, abortController.signal);
  } catch (err) {
    state.initPromise = null;
    const { normalizeDocumentSyncError } = await import("./bootstrap/initialize");
    throw normalizeDocumentSyncError(err);
  } finally {
    if (state._initAbortController === abortController) {
      state._initAbortController = null;
    }
    notifyForegroundDocumentClose();
  }
}
