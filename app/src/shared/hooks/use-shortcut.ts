import { useEffect } from 'react'

import { useShortcutRegistry } from '@/shared/contexts/shortcut-context'

type ShortcutOptions = {
  preventDefault?: boolean
}

export function useShortcut(actionId: string, handler: (event: KeyboardEvent) => void, options?: ShortcutOptions) {
  const registry = useShortcutRegistry()
  const preventDefault = options?.preventDefault

  useEffect(() => {
    if (!handler) return
    return registry.registerHandler(
      actionId,
      handler,
      preventDefault === undefined ? undefined : { preventDefault },
    )
  }, [actionId, handler, preventDefault, registry])
}
