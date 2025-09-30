import { useCallback, useMemo } from 'react'
import { toast } from 'sonner'

import {
  createDocument as createDocumentApi,
  deleteDocument as deleteDocumentApi,
  updateDocumentParent,
  updateDocumentTitle,
} from '@/entities/document'
import { usePluginExecutor, usePluginManifest, type PluginCommand } from '@/entities/plugin'

import type { DocumentNode } from '@/features/file-tree/model/types'

export type PluginMenuItem = {
  title: string
  onClick?: () => void
  icon?: string
  disabled?: boolean
}

type NavigateFn = (options: { to: string; params?: Record<string, unknown>; search?: any }) => void

type UseFileTreeInteractionsOptions = {
  shareToken: string
  documents: DocumentNode[]
  getSelectedDocumentId: () => string | null
  setSelectedDocumentId: (id: string | null) => void
  refreshDocuments: () => void
  expandFolder: (id: string) => void
  updateDocuments: (docs: DocumentNode[]) => void
  requestRename: (id: string) => void
  requestDocumentId: () => Promise<string | null>
  navigate: NavigateFn
}

function buildPluginMenu(
  items: PluginCommand[],
  runner: (pluginId: string, action: string) => void,
  iconByPlugin: Map<string, string>,
): PluginMenuItem[] {
  const scopePriority = (scope?: string) => (scope === 'user' ? 0 : 1)
  const grouped = new Map<
    string,
    { name?: string; priority: number; commands: Array<{ title: string; action: string }> }
  >()

  for (const item of items) {
    const priority = scopePriority(item.scope)
    const existing = grouped.get(item.pluginId)
    if (!existing || priority < existing.priority) {
      grouped.set(item.pluginId, {
        name: item.pluginName,
        priority,
        commands: [{ title: item.title, action: item.action }],
      })
    } else if (priority === existing.priority) {
      existing.commands.push({ title: item.title, action: item.action })
    }
  }

  const menu: PluginMenuItem[] = []
  const multiPlugin = grouped.size > 1
  for (const [pluginId, group] of grouped.entries()) {
    const icon = iconByPlugin.get(pluginId)
    for (const command of group.commands) {
      const label = multiPlugin && group.name ? `${group.name}: ${command.title}` : command.title
      menu.push({
        title: label,
        icon,
        onClick: () => runner(pluginId, command.action),
      })
    }
  }

  return menu
}

export function useFileTreeInteractions({
  shareToken,
  documents,
  getSelectedDocumentId,
  setSelectedDocumentId,
  refreshDocuments,
  expandFolder,
  updateDocuments,
  requestRename,
  requestDocumentId,
  navigate,
}: UseFileTreeInteractionsOptions) {
  const isShare = !!shareToken
  const { plugins, commands, rules } = usePluginManifest({ enabled: !isShare })

  const { runPluginCommand, resolveDocRoute } = usePluginExecutor({
    plugins,
    shareToken,
    refreshDocuments,
    navigate: (to) => navigate({ to }),
    getCurrentDocumentId: getSelectedDocumentId,
    requestDocumentId,
  })

  const iconByPlugin = useMemo(() => {
    const map = new Map<string, string>()
    for (const plugin of plugins) {
      const icon = (plugin as any)?.ui?.fileTree?.icon
      if (typeof icon === 'string' && icon.trim().length > 0) {
        map.set(String(plugin.id), icon)
      }
    }
    return map
  }, [plugins])

  const pluginMenu = useMemo(
    () => buildPluginMenu(commands, runPluginCommand, iconByPlugin),
    [commands, runPluginCommand, iconByPlugin],
  )

  const selectableDocuments = useMemo(() => {
    const result: Array<{ id: string; title: string; path: string }> = []
    const visit = (nodes: DocumentNode[], parents: string[]) => {
      for (const node of nodes) {
        const nextParents = [...parents, node.title || 'Untitled']
        if (node.type !== 'folder') {
          result.push({ id: node.id, title: node.title || 'Untitled', path: nextParents.join(' / ') })
        }
        if (node.children?.length) {
          visit(node.children, nextParents)
        }
      }
    }
    visit(documents, [])
    return result
  }, [documents])

  const createDocument = useCallback(
    async (parentId?: string | null) => {
      const parent = parentId ?? null
      try {
        const doc = await createDocumentApi({ title: 'Untitled', parent_id: parent })
        requestRename(doc.id)
        refreshDocuments()
        if (parent) expandFolder(parent)
        navigate({ to: '/document/$id', params: { id: doc.id } })
        toast.success('Document created')
        return doc
      } catch (error) {
        console.error('[file-tree] create document failed', error)
        toast.error('Failed to create document')
        return null
      }
    },
    [expandFolder, refreshDocuments, requestRename],
  )

  const createFolder = useCallback(
    async (parentId?: string | null) => {
      const parent = parentId ?? null
      try {
        const folder = await createDocumentApi({ title: 'New Folder', parent_id: parent, type: 'folder' })
        requestRename(folder.id)
        refreshDocuments()
        const expandId = parent ?? folder.id
        expandFolder(expandId)
        toast.success('Folder created')
        return folder
      } catch (error) {
        console.error('[file-tree] create folder failed', error)
        toast.error('Failed to create folder')
        return null
      }
    },
    [expandFolder, refreshDocuments, requestRename],
  )

  const renameDocument = useCallback(
    async (id: string, title: string) => {
      const cloneTree = (nodes: DocumentNode[]): DocumentNode[] =>
        nodes.map((node) => ({
          ...node,
          children: node.children ? cloneTree(node.children) : undefined,
        }))

      const updatedTree = cloneTree(documents)
      const apply = (nodes: DocumentNode[]): boolean => {
        for (const node of nodes) {
          if (node.id === id) {
            node.title = title
            return true
          }
          if (node.children && apply(node.children)) return true
        }
        return false
      }
      apply(updatedTree)
      updateDocuments(updatedTree)

      try {
        await updateDocumentTitle(id, title)
        refreshDocuments()
        toast.success('Renamed')
      } catch (error) {
        console.error('[file-tree] rename failed', error)
        refreshDocuments()
        toast.error('Failed to rename')
      }
    },
    [documents, refreshDocuments, updateDocuments],
  )

  const deleteDocument = useCallback(
    async (id: string) => {
      const wasSelected = getSelectedDocumentId() === id
      try {
        await deleteDocumentApi(id)
        if (wasSelected) {
          setSelectedDocumentId(null)
          if (!isShare) {
            navigate({ to: '/dashboard' })
          }
        }
        refreshDocuments()
        toast.success('Deleted')
      } catch (error) {
        console.error('[file-tree] delete failed', error)
        toast.error('Failed to delete')
      }
    },
    [getSelectedDocumentId, isShare, navigate, refreshDocuments, setSelectedDocumentId],
  )

  const navigateToDocument = useCallback(
    async (id: string) => {
      setSelectedDocumentId(id)
      const target = await resolveDocRoute(id)
      if (target.startsWith('/document/')) {
        const match = target.match(/\/document\/(.+?)(?:\?|$)/)
        const docId = match?.[1] || id
        if (isShare) {
          const tokenForNav = shareToken
          if (tokenForNav) {
            if (typeof window !== 'undefined') {
              const params = new URL(target, window.location.origin)
              const searchData = Object.fromEntries(params.searchParams.entries())
              if (!searchData.token) searchData.token = tokenForNav
              navigate({
                to: '/document/$id',
                params: { id: docId },
                search: (prev: Record<string, unknown>) => ({ ...prev, ...searchData }),
              })
            } else {
              navigate({
                to: '/document/$id',
                params: { id: docId },
                search: (prev: Record<string, unknown>) => ({ ...prev, token: tokenForNav }),
              })
            }
          } else {
            navigate({
              to: '/document/$id',
              params: { id: docId },
            })
          }
        } else {
          navigate({
            to: '/document/$id',
            params: { id: docId },
          })
        }
        return
      }

      const routerNav = (window as any)?.router?.navigate
      if (typeof routerNav === 'function') {
        try {
          routerNav({ to: target })
          return
        } catch (error) {
          console.warn('[file-tree] router navigate failed', error)
        }
      }
      if (typeof window !== 'undefined') {
        window.location.href = target
      }
    },
    [isShare, navigate, resolveDocRoute, setSelectedDocumentId, shareToken],
  )

  const moveDocument = useCallback(
    async (nodeId: string, targetId?: string) => {
      if (targetId === nodeId) return
      const parentId = targetId === undefined || targetId === '' ? null : targetId
      try {
        await updateDocumentParent(nodeId, parentId ?? null)
        refreshDocuments()
        toast.success('Moved')
        if (parentId) expandFolder(parentId)
      } catch (error) {
        console.error('[file-tree] move failed', error)
        toast.error('Failed to move')
      }
    },
    [expandFolder, refreshDocuments],
  )

  return {
    pluginMenu,
    pluginRules: rules,
    runPluginCommand,
    selectableDocuments,
    createDocument,
    createFolder,
    renameDocument,
    deleteDocument,
    navigateToDocument,
    moveDocument,
    resolveDocRoute,
  }
}
