import React, { createContext, useContext } from 'react'

const ShareTokenContext = createContext<string | undefined>(undefined)

export function ShareTokenProvider({ token, children }: { token?: string; children: React.ReactNode }) {
  return <ShareTokenContext.Provider value={token}>{children}</ShareTokenContext.Provider>
}

export function useShareToken() {
  return useContext(ShareTokenContext)
}
