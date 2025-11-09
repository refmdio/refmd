import { createContext, useContext } from 'react'

import type { ShortcutPlatform } from '@/shared/lib/shortcuts'
import type { KeyBinding, ShortcutAction, ShortcutAssignmentMap } from '@/shared/types/shortcuts'

export type ShortcutProfileState = {
  assignments: ShortcutAssignmentMap
  leaderKey: string | null
  updatedAt?: string
}

export type ShortcutHandlerOptions = {
  preventDefault?: boolean
}

export type ShortcutRegistryValue = {
  actions: ShortcutAction[]
  platform: ShortcutPlatform
  profile: ShortcutProfileState
  resolved: Record<string, KeyBinding[]>
  loading: boolean
  formatBinding: (binding: KeyBinding) => string
  registerHandler: (actionId: string, handler: (event: KeyboardEvent) => void, options?: ShortcutHandlerOptions) => () => void
  saveProfile: (assignments: ShortcutAssignmentMap, leaderKey: string | null) => Promise<void>
  suspendDispatch: () => () => void
}

export const ShortcutRegistryContext = createContext<ShortcutRegistryValue | null>(null)

export function useShortcutRegistry() {
  const ctx = useContext(ShortcutRegistryContext)
  if (!ctx) throw new Error('useShortcutRegistry must be used within ShortcutRegistryProvider')
  return ctx
}
