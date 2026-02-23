/**
 * Workspace Event Provider
 *
 * Wraps children with WorkspaceEventsContext to provide
 * workspace SSE event notifications.
 */

import type { ReactNode } from 'react'
import {
  WorkspaceEventsContext,
  useWorkspaceEventsModel,
} from '../model/useWorkspaceEvents'

interface WorkspaceEventProviderProps {
  children: ReactNode
}

export function WorkspaceEventProvider({ children }: WorkspaceEventProviderProps) {
  const contextValue = useWorkspaceEventsModel()

  return (
    <WorkspaceEventsContext.Provider value={contextValue}>
      {children}
    </WorkspaceEventsContext.Provider>
  )
}
