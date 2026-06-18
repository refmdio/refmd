export const OPEN_DOCUMENT_PLUGIN_PANE_EVENT = 'refmd:document-workspace:open-plugin-pane'

export type OpenDocumentPluginPaneDetail = {
  documentId: string
  paneKey?: string
}

export function dispatchOpenDocumentPluginPane(documentId: string, paneKey?: string) {
  if (typeof window === 'undefined') return
  const id = (documentId || '').trim()
  if (!id) return
  window.dispatchEvent(
    new CustomEvent<OpenDocumentPluginPaneDetail>(OPEN_DOCUMENT_PLUGIN_PANE_EVENT, {
      detail: paneKey ? { documentId: id, paneKey } : { documentId: id },
    }),
  )
}
