import { createContext, useContext, useState, useCallback, type ReactNode } from 'react'

export const WORKSPACE_STORAGE_KEY = 'refmd_current_workspace'

interface WorkspaceSelectionContextValue {
  currentWorkspaceId: string | null
  setCurrentWorkspaceId: (id: string | null) => void
}

const WorkspaceSelectionContext = createContext<WorkspaceSelectionContextValue | null>(null)

export function WorkspaceSelectionProvider({ children }: { children: ReactNode }) {
  const [currentWorkspaceId, setCurrentWorkspaceIdState] = useState<string | null>(() => {
    try {
      return typeof window !== 'undefined' ? localStorage.getItem(WORKSPACE_STORAGE_KEY) : null
    } catch {
      return null
    }
  })

  const setCurrentWorkspaceId = useCallback((id: string | null) => {
    setCurrentWorkspaceIdState(id)
    try {
      if (id) {
        localStorage.setItem(WORKSPACE_STORAGE_KEY, id)
      } else {
        localStorage.removeItem(WORKSPACE_STORAGE_KEY)
      }
    } catch {
      // localStorage unavailable (e.g. private browsing quota exceeded)
    }
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
