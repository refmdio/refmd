import { useQuery } from '@tanstack/react-query'
import { useCallback, useMemo } from 'react'

import { pluginManifestQuery, type PluginManifestItem } from '../api'

export type PluginCommand = {
  pluginId: string
  pluginName?: string
  title: string
  action: string
  scope?: string
}

export type PluginRule = {
  pluginId: string
  icon: string
  identify?: { type: 'kvFlag'; key: string; path?: string; equals?: any }
}

type State = {
  plugins: PluginManifestItem[]
  commands: PluginCommand[]
  rules: PluginRule[]
}

const initialState: State = { plugins: [], commands: [], rules: [] }

export function usePluginManifest(options: { enabled?: boolean } = {}) {
  const { enabled = true } = options

  const query = useQuery({
    ...pluginManifestQuery(),
    enabled,
  })

  const manifest = (query.data ?? []) as PluginManifestItem[]

  const derived = useMemo((): State => {
    if (!enabled || manifest.length === 0) {
      return initialState
    }

    const sortedManifest = [...manifest].sort((a, b) => {
      const scopeA = (a as any)?.scope ?? 'global'
      const scopeB = (b as any)?.scope ?? 'global'
      if (scopeA !== scopeB) return scopeA.localeCompare(scopeB)
      return String(a.id).localeCompare(String(b.id))
    })

    const commands: PluginCommand[] = []
    const rules: PluginRule[] = []
    const seenRulePlugins = new Set<string>()

    for (const item of sortedManifest) {
      const toolbar = (item as any)?.ui?.toolbar
      if (Array.isArray(toolbar)) {
        for (const cmd of toolbar) {
          if (cmd?.action) {
            commands.push({
              pluginId: String(item.id),
              pluginName: typeof item.name === 'string' ? item.name : undefined,
              title: String(cmd.title || 'Command'),
              action: String(cmd.action),
              scope: typeof (item as any)?.scope === 'string' ? String((item as any).scope) : undefined,
            })
          }
        }
      }

      const fileTree = (item as any)?.ui?.fileTree
      if (
        fileTree &&
        typeof fileTree === 'object' &&
        typeof fileTree.icon === 'string' &&
        !seenRulePlugins.has(String(item.id))
      ) {
        const identify = fileTree.identify && typeof fileTree.identify === 'object' ? fileTree.identify : undefined
        if (!identify || (identify.type === 'kvFlag' && typeof identify.key === 'string')) {
          rules.push({
            pluginId: String(item.id),
            icon: String(fileTree.icon),
            identify: identify
              ? {
                  type: 'kvFlag' as const,
                  key: String(identify.key),
                  path: typeof identify.path === 'string' ? identify.path : undefined,
                  equals: identify.equals,
                }
              : undefined,
          })
        }
        seenRulePlugins.add(String(item.id))
      }
    }

    return { plugins: sortedManifest, commands, rules }
  }, [enabled, manifest])

  const refresh = useCallback(async () => {
    if (!enabled) return
    await query.refetch()
  }, [enabled, query])

  if (!enabled) {
    return {
      ...initialState,
      loading: false,
      refresh,
    }
  }

  return {
    plugins: derived.plugins,
    commands: derived.commands,
    rules: derived.rules,
    loading: query.isPending || query.isFetching,
    refresh,
  }
}
