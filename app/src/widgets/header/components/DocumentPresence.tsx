import { Wifi, WifiOff, Users } from 'lucide-react'
import { memo } from 'react'

import { overlayMenuClass } from '@/shared/lib/overlay-classes'
import { cn } from '@/shared/lib/utils'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/shared/ui/dropdown-menu'

import type { HeaderRealtimeState } from '@/widgets/header/Header'

type OnlineUser = HeaderRealtimeState['onlineUsers'][number]

type DocumentPresenceProps = {
  realtime: HeaderRealtimeState
  onCollaboratorSelect?: (clientId?: number) => void
  showTitle?: boolean
}

function DocumentPresenceComponent({ realtime, onCollaboratorSelect, showTitle = true }: DocumentPresenceProps) {
  const title = realtime.documentTitle || 'Untitled Document'
  const onlineUsers = realtime.onlineUsers || []
  const collaboratorCount = Array.isArray(onlineUsers) ? onlineUsers.length : 0
  const hasRealtime = realtime.documentId != null
  const connected = hasRealtime && realtime.connected

  return (
    <>
      {showTitle && <span className="hidden xl:inline text-muted-foreground">{title}</span>}
      {hasRealtime && (
        connected ? (
          <span className="inline-flex items-center gap-1">
            <Wifi
              className={cn(
                'h-3 w-3 text-green-600 dark:text-green-400',
                !showTitle && 'h-4 w-4',
              )}
              aria-hidden
            />
            <span className="sr-only">Connected</span>
          </span>
        ) : (
          <span className="inline-flex items-center gap-1">
            <WifiOff
              className={cn(
                'h-3 w-3 text-red-600 dark:text-red-400',
                !showTitle && 'h-4 w-4',
              )}
              aria-hidden
            />
            <span className="sr-only">Disconnected</span>
          </span>
        )
      )}
      {hasRealtime && collaboratorCount > 1 && (
        <CollaboratorDropdown
          users={onlineUsers}
          onSelect={onCollaboratorSelect}
          count={collaboratorCount}
          compact={!showTitle}
        />
      )}
    </>
  )
}

type CollaboratorDropdownProps = {
  users: OnlineUser[]
  count: number
  onSelect?: (clientId?: number) => void
  compact?: boolean
}

function CollaboratorDropdown({ users, count, onSelect, compact }: CollaboratorDropdownProps) {
  const triggerClass = compact
    ? 'flex items-center justify-center gap-1 rounded-full border border-border/50 bg-muted/20 px-1.5 py-1 text-muted-foreground transition-colors hover:bg-muted/40 hover:text-foreground'
    : 'flex items-center gap-1 text-xs underline-offset-2 hover:underline text-blue-600 dark:text-blue-400'

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <button className={cn(triggerClass, compact ? 'no-underline text-xs' : '')}>
          <Users className={cn('h-3 w-3', compact && 'h-4 w-4')} />
          {compact ? (
            <>
              {count > 0 && <span className="text-[10px] font-medium tabular-nums text-muted-foreground/70">{count}</span>}
              <span className="sr-only">{count} people online</span>
            </>
          ) : (
            <span>{count} people online</span>
          )}
        </button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="center" className={overlayMenuClass}>
        <DropdownMenuLabel className="text-xs">Online collaborators</DropdownMenuLabel>
        <DropdownMenuSeparator />
        {users.map((user) => (
          <DropdownMenuItem
            key={`${user.id}-${user.clientId ?? 'c'}`}
            className="text-xs cursor-pointer"
            onClick={() => onSelect?.(user.clientId)}
          >
            <span
              className="inline-block h-2 w-2 rounded-full mr-2"
              style={{ backgroundColor: user.color || '#3b82f6' }}
            />
            <span className="truncate max-w-[180px]">{user.name}</span>
          </DropdownMenuItem>
        ))}
      </DropdownMenuContent>
    </DropdownMenu>
  )
}

export const DocumentPresence = memo(DocumentPresenceComponent)
