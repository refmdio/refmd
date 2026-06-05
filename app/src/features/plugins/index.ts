export * from './model/usePluginManifest'
export * from './model/usePluginExecutor'
export * from './model/usePluginDocumentRedirect'
export * from './model/useDocumentEditorPlugins'
export {
  matchesMount,
  resolvePluginForRoute,
  resolvePluginForDocument,
  resolvePluginForDocumentById,
  resolveDocumentEditorPlugins,
  mountResolvedPlugin,
  mountRoutePlugin,
} from '@/features/plugins/lib/resolution'
export { renderDocumentPaneIcon } from '@/features/plugins/lib/pane-icons'

export type { RoutePluginMatch, DocumentPluginMatch } from '@/features/plugins/lib/resolution'
export type {
  DocumentEditorActivationContext,
  DocumentEditorApi,
  DocumentEditorDocumentApi,
  DocumentEditorDecorationInput,
  DocumentEditorEditInput,
  DocumentEditorHiddenRangeInput,
  DocumentEditorKvApi,
  DocumentEditorPaneContribution,
  DocumentEditorPaneRegistration,
  DocumentEditorPaneRenderContext,
  DocumentEditorPluginMatch,
  DocumentEditorRange,
  DocumentEditorRecordApi,
  DocumentEditorSelection,
} from '@/features/plugins/lib/document-editor'
