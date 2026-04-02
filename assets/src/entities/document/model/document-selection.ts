import { createPersistedSignal } from "@/shared/lib/persisted-signal";

const DOCUMENT_STORAGE_KEY = "refmd_selected_document";

const [selectedDocumentId, setSelectedDocumentId] = createPersistedSignal(DOCUMENT_STORAGE_KEY);

export { selectedDocumentId, setSelectedDocumentId };
