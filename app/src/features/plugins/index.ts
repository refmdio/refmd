export * from './model/usePluginManifest'
export * from './model/usePluginExecutor'
export * from './model/usePluginDocumentRedirect'
export { useDocumentEditorPlugins } from './model/useDocumentEditorPlugins'
export {
  matchesMount,
  resolvePluginForRoute,
  resolvePluginForDocument,
  resolvePluginForDocumentById,
  resolveDocumentEditorPlugins,
  mountResolvedPlugin,
  mountRoutePlugin,
} from '@/features/plugins/lib/resolution'

export type { RoutePluginMatch, DocumentPluginMatch } from '@/features/plugins/lib/resolution'
export type {
  DocumentEditorActionApi,
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
  DocumentEditorUserApi,
} from '@/features/plugins/lib/document-editor'
