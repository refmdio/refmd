/**
 * Presence Avatars
 *
 * Shows connected users as colored avatar circles in the editor toolbar.
 * Subscribes to Awareness state changes and renders remote clients.
 * Deduplicates by userId so multiple devices of the same user show one avatar.
 */

import { useState, useEffect } from 'react'
import type { Awareness } from 'y-protocols/awareness'

interface AwarenessUser {
  userId?: string
  name?: string
  color?: string
}

interface RemoteUser {
  clientId: number
  name: string
  color: string
}

export function PresenceAvatars({ awareness }: { awareness: Awareness | null }) {
  const [remoteUsers, setRemoteUsers] = useState<RemoteUser[]>([])

  useEffect(() => {
    if (!awareness) {
      setRemoteUsers([])
      return
    }

    const update = () => {
      const localId = awareness.clientID
      const localState = awareness.getLocalState()
      const localUserId = (localState?.user as AwarenessUser | undefined)?.userId

      const seen = new Set<string>()
      const users: RemoteUser[] = []
      awareness.getStates().forEach((state, clientId) => {
        if (clientId === localId) return
        const user = state.user as AwarenessUser | undefined
        if (!user?.name) return
        // Skip same user on different devices
        if (localUserId && user.userId === localUserId) return
        // Dedup by userId (multiple devices of same remote user → one avatar)
        if (user.userId) {
          if (seen.has(user.userId)) return
          seen.add(user.userId)
        }
        users.push({
          clientId,
          name: user.name,
          color: user.color ?? '#888',
        })
      })
      setRemoteUsers(users)
    }

    update()
    awareness.on('change', update)
    return () => { awareness.off('change', update) }
  }, [awareness])

  if (remoteUsers.length === 0) return null

  return (
    <div className="flex items-center gap-0.5 mr-1">
      {remoteUsers.map((user) => (
        <div
          key={user.clientId}
          className="w-6 h-6 rounded-full flex items-center justify-center text-[10px] font-medium text-white cursor-default"
          style={{ backgroundColor: user.color }}
          title={user.name}
        >
          {user.name.charAt(0).toUpperCase()}
        </div>
      ))}
    </div>
  )
}
