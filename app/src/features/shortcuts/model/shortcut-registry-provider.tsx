import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react'

import { SHORTCUT_ACTIONS } from '@/shared/config/shortcuts'
import {
  ShortcutRegistryContext,
  type ShortcutHandlerOptions,
  type ShortcutProfileState,
  type ShortcutRegistryValue,
} from '@/shared/contexts/shortcut-context'
import {
  detectPlatform,
  formatBinding as formatShortcutBinding,
  isTextInputEvent,
  matchBinding,
  normalizeAssignments,
  resolveBindings,
  serializeAssignments,
  type ShortcutPlatform,
} from '@/shared/lib/shortcuts'
import type { KeyBinding, ShortcutAssignmentMap, ShortcutAction } from '@/shared/types/shortcuts'

import { shortcutKeys, shortcutProfileQuery, updateUserShortcuts } from '@/entities/shortcuts'

type HandlerEntry = {
  handler: (event: KeyboardEvent) => void
  options?: ShortcutHandlerOptions
}

const defaultProfile: ShortcutProfileState = {
  assignments: {},
  leaderKey: null,
  updatedAt: undefined,
}

type ShortcutRegistryProviderProps = {
  children: React.ReactNode
  currentUserId?: string | null
}

export function ShortcutRegistryProvider({ children, currentUserId }: ShortcutRegistryProviderProps) {
  const queryClient = useQueryClient()
  const [profile, setProfile] = useState<ShortcutProfileState>(defaultProfile)
  const [platform, setPlatform] = useState<ShortcutPlatform>('windows')
  const dispatchSuspendedCountRef = useRef(0)

  useEffect(() => {
    setPlatform(detectPlatform())
  }, [])

  const queryEnabled = Boolean(currentUserId)
  const shortcutsQuery = useQuery({
    ...shortcutProfileQuery(),
    enabled: queryEnabled,
  })

  useEffect(() => {
    if (!currentUserId) {
      setProfile(defaultProfile)
      return
    }
    if (shortcutsQuery.data) {
      setProfile({
        assignments: normalizeAssignments(shortcutsQuery.data.bindings),
        leaderKey: shortcutsQuery.data.leader_key ?? null,
        updatedAt: shortcutsQuery.data.updated_at ?? undefined,
      })
    }
  }, [shortcutsQuery.data, currentUserId])

  const actionMap = useMemo(() => {
    const map = new Map<string, ShortcutAction>()
    for (const action of SHORTCUT_ACTIONS) {
      map.set(action.id, action)
    }
    return map
  }, [])

  const resolvedBindings = useMemo(() => {
    const map: Record<string, KeyBinding[]> = {}
    for (const action of SHORTCUT_ACTIONS) {
      map[action.id] = resolveBindings(action, profile.assignments, platform)
    }
    return map
  }, [profile.assignments, platform])

  const resolvedRef = useRef(resolvedBindings)
  useEffect(() => {
    resolvedRef.current = resolvedBindings
  }, [resolvedBindings])

  const handlersRef = useRef<Map<string, Set<HandlerEntry>>>(new Map())

  const handleKeyDown = useCallback(
    (event: KeyboardEvent) => {
      if (event.defaultPrevented) return
      if (dispatchSuspendedCountRef.current > 0) return
      const resolved = resolvedRef.current
      for (const [actionId, bindings] of Object.entries(resolved)) {
        if (!bindings.some((binding) => matchBinding(binding, event))) continue
        const action = actionMap.get(actionId)
        if (!action) continue
        if (!action.allowInInputs && isTextInputEvent(event)) {
          const target = event.target as HTMLElement | null
          const insideMonaco = target?.closest('.monaco-editor')
          if (!insideMonaco) {
            continue
          }
        }
        const handlers = handlersRef.current.get(actionId)
        if (!handlers || handlers.size === 0) continue
        let prevented = false
        for (const entry of handlers) {
          if (entry.options?.preventDefault !== false && !prevented) {
            event.preventDefault()
            prevented = true
          }
          entry.handler(event)
        }
        break
      }
    },
    [actionMap],
  )

  useEffect(() => {
    if (typeof window === 'undefined') return undefined
    window.addEventListener('keydown', handleKeyDown, true)
    return () => {
      window.removeEventListener('keydown', handleKeyDown, true)
    }
  }, [handleKeyDown])

  const registerHandler = useCallback(
    (actionId: string, handler: HandlerEntry['handler'], options?: ShortcutHandlerOptions) => {
      const entry: HandlerEntry = { handler, options }
      const existing = handlersRef.current.get(actionId)
      if (existing) {
        existing.add(entry)
      } else {
        handlersRef.current.set(actionId, new Set([entry]))
      }
      return () => {
        const set = handlersRef.current.get(actionId)
        if (!set) return
        set.delete(entry)
        if (set.size === 0) {
          handlersRef.current.delete(actionId)
        }
      }
    },
    [],
  )

  const mutation = useMutation({
    mutationFn: (payload: { assignments: ShortcutAssignmentMap; leaderKey: string | null }) =>
      updateUserShortcuts({
        bindings: serializeAssignments(payload.assignments),
        leader_key: payload.leaderKey ?? undefined,
      }),
    onSuccess: (data) => {
      queryClient.setQueryData(shortcutKeys.profile(), data)
      setProfile({
        assignments: normalizeAssignments(data.bindings),
        leaderKey: data.leader_key ?? null,
        updatedAt: data.updated_at ?? undefined,
      })
    },
  })

  const saveProfile = useCallback(
    async (assignments: ShortcutAssignmentMap, leaderKey: string | null) => {
      if (!currentUserId) return
      await mutation.mutateAsync({ assignments, leaderKey })
    },
    [mutation, currentUserId],
  )

  const suspendDispatch = useCallback(() => {
    dispatchSuspendedCountRef.current += 1
    let released = false
    return () => {
      if (released) return
      released = true
      dispatchSuspendedCountRef.current = Math.max(0, dispatchSuspendedCountRef.current - 1)
    }
  }, [])

  const value = useMemo<ShortcutRegistryValue>(
    () => ({
      actions: SHORTCUT_ACTIONS,
      platform,
      profile,
      resolved: resolvedBindings,
      loading: shortcutsQuery.isLoading || shortcutsQuery.isFetching,
      formatBinding: (binding: KeyBinding) => formatShortcutBinding(binding, platform),
      registerHandler,
      saveProfile,
      suspendDispatch,
    }),
    [
      platform,
      profile,
      registerHandler,
      resolvedBindings,
      saveProfile,
      suspendDispatch,
      shortcutsQuery.isFetching,
      shortcutsQuery.isLoading,
    ],
  )

  return <ShortcutRegistryContext.Provider value={value}>{children}</ShortcutRegistryContext.Provider>
}
