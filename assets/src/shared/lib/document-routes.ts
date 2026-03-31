export function buildDocumentPath(documentId: string | null | undefined): string {
  return documentId ? `/document/${documentId}` : "/dashboard";
}
