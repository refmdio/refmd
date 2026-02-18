import { createContext, useContext } from 'react'
import type { WorkspaceWithMembership } from '@/shared/api'

export const WorkspacesDataContext = createContext<WorkspaceWithMembership[] | null>(null)

export function useWorkspacesData(): WorkspaceWithMembership[] | null {
  return useContext(WorkspacesDataContext)
}
