import { useEffect, useState } from 'react'
import type { Awareness } from 'y-protocols/awareness'

type CursorInfo = {
  clientId: number
  user: {
    name: string
    color: string
    colorLight: string
  }
  selection?: {
    anchor: any
    head: any
  }
  isActive: boolean
}

type Props = { awareness: Awareness | null; className?: string }

export default function CursorDisplay({ awareness, className }: Props) {
  const [users, setUsers] = useState<Map<number, CursorInfo>>(new Map())

  useEffect(() => {
    if (!awareness || (awareness as any)?._destroyed) return

    const updateUsers = () => {
      const states = awareness.getStates()
      const next = new Map<number, CursorInfo>()
      states.forEach((state: any, clientId: number) => {
        if (clientId !== awareness.clientID && state?.user) {
          const hasSelection = state.selection?.anchor && state.selection?.head
          if (state.user && (!state.user.name || state.user.name === 'User')) {
            state.user.name = `User-${clientId}`
          }
          next.set(clientId, {
            clientId,
            user: state.user,
            selection: state.selection,
            isActive: !!hasSelection
          })
        }
      })
      setUsers(next)
    }

    updateUsers()
    const handler = () => updateUsers()
    awareness.on('update', handler)
    return () => {
      try { awareness.off('update', handler) } catch {}
    }
  }, [awareness])

  if (users.size === 0) return null

  return (
    <div className={`absolute top-2 right-2 p-2 bg-background border rounded shadow-sm ${className || ''}`}>
      <div className="flex flex-col gap-1">
        {Array.from(users.values()).map((u) => (
          <div key={u.clientId} className="flex items-center gap-2">
            <div 
              className={`w-2 h-2 rounded-full ${u.isActive ? 'animate-pulse' : ''}`} 
              style={{ backgroundColor: u.user.color }} 
            />
            <span className="text-xs">
              {u.user.name}
              {u.isActive && <span className="ml-1 text-muted-foreground">(editing)</span>}
            </span>
          </div>
        ))}
      </div>
    </div>
  )
}
