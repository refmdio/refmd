export { default as ShareDialog } from './ShareDialog'
export { default as DocumentShareCard } from './ui/DocumentShareCard'
export { default as FolderShareTree } from './ui/FolderShareTree'
export type { ActiveShareItem } from './types'

// Share Context for E2EE key management
export {
  ShareProvider,
  useShareContext,
  useShareContextOptional,
  type ShareContextValue,
} from './model/share-context'
