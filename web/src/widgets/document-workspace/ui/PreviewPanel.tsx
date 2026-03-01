/**
 * Preview Panel (WYSIWYG)
 *
 * ProseMirror WYSIWYG editor panel for use within mosaic workspace.
 * Replaces the old read-only Markdown preview with a rich-text editor
 * backed by Y.Doc for real-time collaboration.
 */

import { ProseMirrorEditor } from '@/features/document-edit'
import { DocumentPanelShell } from './DocumentPanelShell'

interface PreviewPanelProps {
  documentId: string
}

export function PreviewPanel({ documentId }: PreviewPanelProps) {
  return (
    <DocumentPanelShell documentId={documentId}>
      {({ document, yDoc, awareness }) =>
        yDoc && awareness ? (
          <ProseMirrorEditor
            yDoc={yDoc}
            awareness={awareness}
            readOnly={document.is_archived}
            className="h-full p-4"
          />
        ) : (
          <div className="flex items-center justify-center h-full bg-background text-muted-foreground">
            Loading editor...
          </div>
        )
      }
    </DocumentPanelShell>
  )
}
