import { useEffect } from 'react'
import type { Awareness } from 'y-protocols/awareness'

type Options = {
  userId?: string
  userName?: string
}

/**
 * Syncs local user metadata to Yjs awareness and injects remote cursor styles.
 */
export function useAwarenessStyles(awareness: Awareness | null | undefined, { userId, userName }: Options) {
  useEffect(() => {
    if (!awareness || (awareness as any)?._destroyed) return

    const info = {
      name: userName || `User-${awareness.clientID}`,
      color: generateUserColor(userId),
      colorLight: generateUserColor(userId, true),
      id: userId || String(awareness.clientID),
    }
    awareness.setLocalStateField('user', info)

    const style = document.createElement('style')
    style.id = 'y-remote-cursor-styles'
    document.head.appendChild(style)

    const update = () => {
      const states = awareness.getStates()
      let css = ''
      states.forEach((state: any, clientId: number) => {
        if (state?.user && clientId !== awareness.clientID) {
          const c = state.user.color || '#000'
          const cl = state.user.colorLight || c
          css += `
            .yRemoteSelection-${clientId} { background-color: ${cl}; opacity: .5; }
            .yRemoteSelectionHead-${clientId} { border-color: ${c}; border-width: 2px; }
            .yRemoteSelectionHead-${clientId}::after {
              content: '';
              position: absolute;
              left: -1px;
              top: 0;
              bottom: 0;
              border-left: 2px solid ${c};
            }
            .yRemoteCursorLabel-${clientId} {
              background-color: ${c};
              color: #fff;
              opacity: 1;
              padding: 2px 4px;
              border-radius: 2px;
              font-size: 11px;
              position: absolute;
              z-index: 100;
            }
          `
        }
      })
      style.textContent = css
    }

    update()
    const handler = () => update()
    awareness.on('update', handler)

    return () => {
      try { awareness.off('update', handler) } catch {}
      style.remove()
    }
  }, [awareness, userId, userName])
}

function generateUserColor(userId?: string, light = false): string {
  let hash = 0
  const str = userId || Math.random().toString()
  for (let i = 0; i < str.length; i++) {
    const char = str.charCodeAt(i)
    hash = ((hash << 5) - hash) + char
    hash = hash & hash
  }
  const hue = Math.abs(hash) % 360
  const saturation = light ? 30 : 70
  const lightness = light ? 80 : 50
  return `hsl(${hue}, ${saturation}%, ${lightness}%)`
}

export default useAwarenessStyles
