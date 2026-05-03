export interface DocumentPublicationState {
  isPublished: boolean;
  updatedAt: string | null;
  contentHash?: string | null;
}

const publicationStates = new Map<string, DocumentPublicationState>();

export function getDocumentPublicationState(documentId: string): DocumentPublicationState | null {
  return publicationStates.get(documentId) ?? null;
}

export function setDocumentPublicationState(
  documentId: string,
  state: DocumentPublicationState,
): void {
  publicationStates.set(documentId, state);
}
