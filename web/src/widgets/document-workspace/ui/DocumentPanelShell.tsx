/**
 * Document Panel Shell
 *
 * Shared wrapper for document panels that handles metadata sync,
 * loading, error, key-change warnings, and not-found states.
 */

import { useEffect } from 'react'
import { Loader2, AlertCircle } from 'lucide-react'
import { useDocumentEdit, type UseDocumentEditResult } from '@/features/document-edit'
import { KeyChangeGuard } from '@/shared/ui/KeyChangeGuard'
import { useDocumentWorkspace } from '../model/DocumentWorkspaceContext'

interface DocumentPanelShellProps {
  documentId: string
  children: (result: UseDocumentEditResult & { document: NonNullable<UseDocumentEditResult['document']> }) => React.ReactNode
}

export function DocumentPanelShell({ documentId, children }: DocumentPanelShellProps) {
  const result = useDocumentEdit(documentId)
  const { upsertDocumentMetadata } = useDocumentWorkspace()

  useEffect(() => {
    if (!result.document) return
    upsertDocumentMetadata({
      id: result.document.id,
      title: result.document.title,
      workspaceId: result.document.workspace_id,
    })
  }, [result.document, upsertDocumentMetadata])

  if (result.error) {
    return (
      <div className="flex flex-col items-center justify-center h-full bg-background">
        <AlertCircle className="w-6 h-6 text-destructive" />
        <p className="mt-2 text-sm text-destructive">{result.error.message}</p>
      </div>
    )
  }

  if (result.isLoading) {
    return (
      <div className="flex items-center justify-center h-full bg-background">
        <Loader2 className="w-6 h-6 animate-spin text-muted-foreground" />
      </div>
    )
  }

  return (
    <KeyChangeGuard dialogProps={result.keyChangeDialogProps}>
      {!result.document ? (
        <div className="flex items-center justify-center h-full bg-background text-muted-foreground">
          Document not found
        </div>
      ) : (
        <>{children({ ...result, document: result.document })}</>
      )}
    </KeyChangeGuard>
  )
}
