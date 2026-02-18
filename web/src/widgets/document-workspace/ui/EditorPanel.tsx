/**
 * Editor Panel
 *
 * CodeMirror editor panel for use within mosaic workspace.
 */

import { DocumentPanelShell } from './DocumentPanelShell'
import { DocumentEditor } from './DocumentEditor'

interface EditorPanelProps {
  documentId: string
}

export function EditorPanel({ documentId }: EditorPanelProps) {
  return (
    <DocumentPanelShell documentId={documentId}>
      {({ document, yDoc, save }) =>
        yDoc ? (
          <DocumentEditor
            documentId={documentId}
            yDoc={yDoc}
            onSave={save}
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
