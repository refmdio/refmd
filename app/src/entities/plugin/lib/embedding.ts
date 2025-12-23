export type PluginEmbedding = 'none' | 'full' | 'preview'

export function getPluginEmbeddingKind(pluginId: string): PluginEmbedding {
  const id = pluginId.trim()
  if (!id) return 'none'
  // Currently only Marp is a "preview-only override" in the built-in plugins.
  if (id === 'marp') return 'preview'
  return 'full'
}

