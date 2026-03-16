import { createSignal } from "solid-js";

const DOCUMENT_STORAGE_KEY = "refmd_selected_document";

function loadDocumentId(): string | null {
  try {
    return localStorage.getItem(DOCUMENT_STORAGE_KEY);
  } catch {
    return null;
  }
}

const [selectedDocumentId, _setSelectedDocumentId] = createSignal<string | null>(loadDocumentId());

export function setSelectedDocumentId(id: string | null) {
  _setSelectedDocumentId(id);
  try {
    if (id) {
      localStorage.setItem(DOCUMENT_STORAGE_KEY, id);
    } else {
      localStorage.removeItem(DOCUMENT_STORAGE_KEY);
    }
  } catch {
    // Ignore storage errors
  }
}

export { selectedDocumentId };
