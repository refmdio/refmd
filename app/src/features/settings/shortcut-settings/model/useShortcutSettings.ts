import { useCallback, useEffect, useMemo, useRef, useState } from 'react'

import { useShortcutRegistry } from '@/shared/contexts/shortcut-context'
import type { KeyBinding, ShortcutAssignmentMap } from '@/shared/types/shortcuts'

const cloneAssignments = (source: ShortcutAssignmentMap): ShortcutAssignmentMap => {
  const next: ShortcutAssignmentMap = {}
  for (const [actionId, modes] of Object.entries(source)) {
    const modeCopy: Record<string, KeyBinding[]> = {}
    for (const [modeKey, bindings] of Object.entries(modes)) {
      if (!bindings) continue
      modeCopy[modeKey] = bindings.map((binding) => binding.map((chord) => ({ ...chord })))
    }
    if (Object.keys(modeCopy).length > 0) {
      next[actionId] = modeCopy
    }
  }
  return next
}

export function useShortcutSettings() {
  const registry = useShortcutRegistry()
  const [draft, setDraft] = useState<ShortcutAssignmentMap>(() => cloneAssignments(registry.profile.assignments))
  const [saving, setSaving] = useState(false)
  const hasLocalChangesRef = useRef(false)

  const resetDraft = useCallback(() => {
    hasLocalChangesRef.current = false
    setDraft(cloneAssignments(registry.profile.assignments))
  }, [registry.profile.assignments])

  useEffect(() => {
    if (hasLocalChangesRef.current) return
    setDraft(cloneAssignments(registry.profile.assignments))
  }, [registry.profile.assignments])

  const dirty = useMemo(() => JSON.stringify(draft) !== JSON.stringify(registry.profile.assignments), [draft, registry.profile.assignments])

  const handleChange = useCallback(
    (actionId: string, binding: KeyBinding | null) => {
      hasLocalChangesRef.current = true
      setDraft((prev) => {
        const next: ShortcutAssignmentMap = { ...prev }
        const modes = { ...(next[actionId] ?? {}) }
        if (binding) {
          modes.default = [binding]
          next[actionId] = modes
        } else {
          delete modes.default
          if (Object.keys(modes).length > 0) {
            next[actionId] = modes
          } else {
            delete next[actionId]
          }
        }
        return next
      })
    },
    [],
  )

  const save = useCallback(async () => {
    setSaving(true)
    try {
      await registry.saveProfile(draft, registry.profile.leaderKey ?? null)
      resetDraft()
    } finally {
      setSaving(false)
    }
  }, [draft, registry, resetDraft])

  return {
    actions: registry.actions,
    platform: registry.platform,
    formatBinding: registry.formatBinding,
    draft,
    dirty,
    saving,
    handleBindingChange: handleChange,
    resetDraft,
    save,
  }
}
