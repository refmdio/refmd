/**
 * Preview Panel
 *
 * Markdown preview panel for use within mosaic workspace.
 */

import { DocumentPanelShell } from './DocumentPanelShell'
import { MarkdownPreview } from './MarkdownPreview'

interface PreviewPanelProps {
  documentId: string
}

export function PreviewPanel({ documentId }: PreviewPanelProps) {
  return (
    <DocumentPanelShell documentId={documentId}>
      {({ content }) => <MarkdownPreview content={content} className="h-full" />}
    </DocumentPanelShell>
  )
}
