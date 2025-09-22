import { useCallback, useEffect, useState } from 'react'

import type { PluginManifestItem } from '../api'
import { getPluginManifest } from '../api'

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
  const [state, setState] = useState<State>(initialState)
  const [loading, setLoading] = useState<boolean>(false)

  const load = useCallback(async () => {
    if (!enabled) {
      return
    }
    setLoading(true)
    try {
      const manifest = await getPluginManifest()
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

      setState({ plugins: sortedManifest, commands, rules })
    } catch (err) {
      console.warn('[plugins] failed to load manifest', err)
      setState(initialState)
    } finally {
      setLoading(false)
    }
  }, [enabled])

  useEffect(() => {
    if (!enabled) {
      setState(initialState)
      setLoading(false)
      return
    }
    void load()
  }, [enabled, load])

  return {
    plugins: state.plugins,
    commands: state.commands,
    rules: state.rules,
    loading,
    refresh: load,
  }
}
