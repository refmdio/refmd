import { createContext, useContext, useState, useCallback, type ReactNode } from 'react'

interface WorkspaceSelectionContextValue {
  currentWorkspaceId: string | null
  setCurrentWorkspaceId: (id: string | null) => void
}

const WorkspaceSelectionContext = createContext<WorkspaceSelectionContextValue | null>(null)

export function WorkspaceSelectionProvider({ children }: { children: ReactNode }) {
  const [currentWorkspaceId, setCurrentWorkspaceIdState] = useState<string | null>(null)

  const setCurrentWorkspaceId = useCallback((id: string | null) => {
    setCurrentWorkspaceIdState(id)
  }, [])

  return (
    <WorkspaceSelectionContext.Provider value={{ currentWorkspaceId, setCurrentWorkspaceId }}>
      {children}
    </WorkspaceSelectionContext.Provider>
  )
}

export function useWorkspaceSelection(): WorkspaceSelectionContextValue {
  const context = useContext(WorkspaceSelectionContext)
  if (!context) {
    throw new Error('useWorkspaceSelection must be used within a WorkspaceSelectionProvider')
  }
  return context
}
