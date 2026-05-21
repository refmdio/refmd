import { createSignal } from "solid-js";

const DOCUMENT_STORAGE_KEY = "refmd_selected_document";

globalThis.localStorage?.removeItem(DOCUMENT_STORAGE_KEY);

const [selectedDocumentId, setSelectedDocumentId] = createSignal<string | null>(null);

export { selectedDocumentId, setSelectedDocumentId };
