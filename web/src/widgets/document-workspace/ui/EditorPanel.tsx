/**
 * Editor Panel
 *
 * CodeMirror editor panel for use within mosaic workspace.
 */

import { DocumentPanelShell } from './DocumentPanelShell'
import { CodeMirrorEditor } from '@/features/document-edit'

interface EditorPanelProps {
  documentId: string
}

export function EditorPanel({ documentId }: EditorPanelProps) {
  return (
    <DocumentPanelShell documentId={documentId}>
      {({ document, yDoc, awareness, onLocalEdit }) =>
        yDoc ? (
          <CodeMirrorEditor
            documentId={documentId}
            yDoc={yDoc}
            awareness={awareness}
            onLocalEdit={onLocalEdit}
            readOnly={document.is_archived}
          />
        ) : (
          <div className="flex items-center justify-center h-full bg-background text-muted-foreground">
            Document not found
          </div>
        )
      }
    </DocumentPanelShell>
  )
}
