/**
 * Workspace Events State Management
 *
 * Manages workspace SSE subscriptions and notification state.
 * Follows the same pattern as usePendingDevices.
 */

import { useState, useCallback, createContext, useContext } from 'react'
import { sseUrls, routeWorkspaceSSEEvent, type WorkspaceSSEEvent, type InvitationAcceptedEvent } from '@/shared/api'
import { useEventSource } from '@/shared/hooks'

export interface WorkspaceNotification {
  id: string
  type: 'invitation_accepted'
  workspaceId: string
  email: string
  timestamp: number
}

export interface WorkspaceEventsContextValue {
  /** Active workspace notifications */
  notifications: WorkspaceNotification[]
  /** Number of workspace notifications */
  notificationCount: number
  /** Dismiss a notification */
  dismiss: (id: string) => void
  /** Timestamp of the last invitation_accepted event (for triggering list refetches) */
  lastInvitationAcceptedAt: number
}

export const WorkspaceEventsContext = createContext<WorkspaceEventsContextValue | null>(null)

export function useWorkspaceEvents() {
  const context = useContext(WorkspaceEventsContext)
  if (!context) {
    throw new Error('useWorkspaceEvents must be used within WorkspaceEventProvider')
  }
  return context
}

export function useWorkspaceEventsModel(): WorkspaceEventsContextValue {
  const [notifications, setNotifications] = useState<WorkspaceNotification[]>([])
  const [lastInvitationAcceptedAt, setLastInvitationAcceptedAt] = useState(0)

  const dismiss = useCallback((id: string) => {
    setNotifications((prev) => prev.filter((n) => n.id !== id))
  }, [])

  const handleSSEMessage = useCallback((data: unknown) => {
    if (typeof data !== 'object' || data === null || !('type' in data)) return
    routeWorkspaceSSEEvent(data as WorkspaceSSEEvent, {
      onInvitationAccepted: (event: InvitationAcceptedEvent) => {
        const notification: WorkspaceNotification = {
          id: event.invitation_id,
          type: 'invitation_accepted',
          workspaceId: event.workspace_id,
          email: event.accepted_by_email,
          timestamp: Date.now(),
        }
        setNotifications((prev) => {
          if (prev.some((n) => n.id === event.invitation_id)) return prev
          return [...prev, notification]
        })
        setLastInvitationAcceptedAt(Date.now())
      },
    })
  }, [])

  useEventSource({
    url: sseUrls.workspaceEvents(),
    onMessage: handleSSEMessage,
  })

  return {
    notifications,
    notificationCount: notifications.length,
    dismiss,
    lastInvitationAcceptedAt,
  }
}
