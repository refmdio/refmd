import { createContext, useContext } from 'react'
import type { DocumentResponse } from '@/shared/api'

export interface DocumentsData {
  documents: DocumentResponse[]
  documentsLoading: boolean
}

export const DocumentsDataContext = createContext<DocumentsData | null>(null)

export function useDocumentsData(): DocumentsData | null {
  return useContext(DocumentsDataContext)
}
