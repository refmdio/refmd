export * from './model/usePluginManifest'
export * from './model/usePluginExecutor'
export * from './model/usePluginDocumentRedirect'
export {
  matchesMount,
  resolvePluginForRoute,
  resolvePluginForDocument,
  resolvePluginForDocumentById,
  mountResolvedPlugin,
  mountRoutePlugin,
} from '@/features/plugins/lib/resolution'

export type { RoutePluginMatch, DocumentPluginMatch } from '@/features/plugins/lib/resolution'
