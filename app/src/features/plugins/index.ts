export * from './model/usePluginManifest'
export * from './model/usePluginExecutor'
export * from './model/usePluginDocumentRedirect'
export {
  matchesMount,
  resolvePluginForRoute,
  resolvePluginForDocument,
  mountResolvedPlugin,
  mountRoutePlugin,
} from './lib/resolution'

export type { RoutePluginMatch, DocumentPluginMatch } from './lib/resolution'
