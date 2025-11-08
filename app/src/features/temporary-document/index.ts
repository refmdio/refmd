export { useTemporaryDocument } from './hooks/useTemporaryDocument'
export type { TemporaryDocumentState } from './hooks/useTemporaryDocument'
export {
  listTemporaryDocuments,
  createTemporaryDocumentEntry,
  deleteTemporaryDocumentEntry,
  updateTemporaryDocumentEntry,
  touchTemporaryDocumentEntry,
  getTemporaryDocumentEntry,
  type TemporaryDocumentMeta,
  TEMPORARY_DOCUMENT_TTL_MS,
  TEMPORARY_DOCUMENT_PERSISTENCE_PREFIX,
} from './lib/storage'
