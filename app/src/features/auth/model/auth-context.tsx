import { useQueryClient } from '@tanstack/react-query'
import { useNavigate } from '@tanstack/react-router'
import React, { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react'

import type { UserResponse } from '@/shared/api'
import { setClientWorkspaceId } from '@/shared/api/client.config'

import {
  login as loginApi,
  register as registerApi,
  me as meApi,
  deleteAccount as deleteAccountApi,
  logout as logoutApi,
  switchWorkspace as switchWorkspaceApi,
  oauthLogin as oauthLoginApi,
  userKeys,
} from '@/entities/user'

const WORKSPACE_STORAGE_KEY = 'refmd.activeWorkspaceId'

type AuthState = {
  user: UserResponse | null
  workspaces: UserResponse['workspaces']
  activeWorkspaceId: string | null
  activeWorkspace: UserResponse['workspaces'][number] | null
  permissions: string[]
  loading: boolean
  signIn: (email: string, password: string, options?: SignInOptions) => Promise<UserResponse>
  signInWithProvider: (provider: string, payload: OAuthPayload) => Promise<UserResponse>
  signUp: (email: string, name: string, password: string) => Promise<void>
  signOut: () => Promise<void>
  deleteAccount: () => Promise<void>
  switchWorkspace: (workspaceId: string) => Promise<void>
}

type OAuthPayload = {
  credential?: string
  code?: string
  redirect_uri?: string
  remember_me?: boolean
  state?: string
}

type SignInOptions = {
  remember?: boolean
}

const Ctx = createContext<AuthState | null>(null)

function readStoredWorkspaceId() {
  if (typeof window === 'undefined') return null
  try {
    const stored = window.localStorage.getItem(WORKSPACE_STORAGE_KEY)
    return stored && stored.trim().length > 0 ? stored : null
  } catch {
    return null
  }
}

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const meState = queryClient.getQueryState(userKeys.me())
  const initialUser = ((meState?.data as UserResponse | null | undefined) ?? null) as UserResponse | null
  const hasInitialData = meState?.status === 'success'
  const [user, setUser] = useState<UserResponse | null>(initialUser)
  const [loading, setLoading] = useState(() => !hasInitialData)
  const [preferredWorkspaceId, setPreferredWorkspaceId] = useState<string | null>(() => {
    const stored = readStoredWorkspaceId()
    if (stored) {
      setClientWorkspaceId(stored)
    }
    return stored
  })

  useEffect(() => {
    if (hasInitialData) {
      setUser(initialUser)
      setLoading(false)
      return
    }

    let cancelled = false

    const init = async () => {
      try {
        const me = await meApi()
        if (cancelled) return
        setUser(me)
        queryClient.setQueryData(userKeys.me(), me)
      } catch {
        if (cancelled) return
        setUser(null)
      } finally {
        if (!cancelled) {
          setLoading(false)
        }
      }
    }

    void init()

    return () => {
      cancelled = true
    }
  }, [hasInitialData, initialUser, queryClient])

  useEffect(() => {
    const unsubscribe = queryClient.getQueryCache().subscribe((event) => {
      const typed = event as {
        type: string
        query?: { queryKey: readonly unknown[]; state: { status: string; data?: unknown } }
      }

      if (typed.type !== 'updated' || !typed.query) return
      if (typed.query.queryKey?.[0] !== userKeys.me()[0]) return

      const status = typed.query.state.status
      if (status === 'pending') {
        setLoading(true)
        return
      }

      if (status === 'success') {
        const data = typed.query.state.data as UserResponse | undefined
        setUser(data ?? null)
        setLoading(false)
        return
      }

      if (status === 'error') {
        setUser(null)
        setLoading(false)
      }
    })

    return () => {
      unsubscribe()
    }
  }, [queryClient])

  const signIn = useCallback(
    async (email: string, password: string, options?: SignInOptions) => {
      const res = await loginApi(email, password, options)
      queryClient.clear()
      queryClient.setQueryData(userKeys.me(), res.user)
      setUser(res.user)
      return res.user
    },
    [queryClient],
  )

  const signInWithProvider = useCallback(
    async (provider: string, payload: OAuthPayload) => {
      const res = await oauthLoginApi(provider, payload)
      queryClient.clear()
      queryClient.setQueryData(userKeys.me(), res.user)
      setUser(res.user)
      return res.user
    },
    [queryClient],
  )

  const signUp = useCallback(async (email: string, name: string, password: string) => {
    await registerApi(email, name, password)
  }, [])

  const signOut = useCallback(async () => {
    try {
      await logoutApi()
    } catch (error) {
      console.warn('[auth] logout failed', error)
    }
    queryClient.clear()
    setUser(null)
    navigate({ to: '/auth/signin' })
  }, [navigate])

  const deleteAccount = useCallback(async () => {
    await deleteAccountApi()
    queryClient.clear()
    setUser(null)
    navigate({ to: '/auth/signin' })
  }, [navigate])

  const workspaces = useMemo(() => user?.workspaces ?? [], [user])
  const activeWorkspace = useMemo(() => {
    if (!user) return null
    if (preferredWorkspaceId) {
      const preferred = workspaces.find((ws) => ws.id === preferredWorkspaceId)
      if (preferred) return preferred
    }
    if (user.active_workspace) {
      return user.active_workspace
    }
    if (user.active_workspace_id) {
      return workspaces.find((ws) => ws.id === user.active_workspace_id) ?? null
    }
    return workspaces.find((ws) => ws.is_default) ?? workspaces[0] ?? null
  }, [user, workspaces, preferredWorkspaceId])
  const activeWorkspaceId = useMemo(() => activeWorkspace?.id ?? null, [activeWorkspace])
  const permissions = useMemo(() => user?.active_workspace_permissions ?? [], [user])

  useEffect(() => {
    if (typeof window === 'undefined') return
    setClientWorkspaceId(activeWorkspaceId)
    try {
      if (!activeWorkspaceId) {
        window.localStorage.removeItem(WORKSPACE_STORAGE_KEY)
        if (preferredWorkspaceId !== null) {
          setPreferredWorkspaceId(null)
        }
      } else {
        window.localStorage.setItem(WORKSPACE_STORAGE_KEY, activeWorkspaceId)
        if (preferredWorkspaceId !== activeWorkspaceId) {
          setPreferredWorkspaceId(activeWorkspaceId)
        }
      }
    } catch {
      /* noop */
    }
  }, [activeWorkspaceId, preferredWorkspaceId])

  const switchWorkspace = useCallback(
    async (workspaceId: string) => {
      const previousWorkspaceId = activeWorkspaceId
      setPreferredWorkspaceId(workspaceId)
      setClientWorkspaceId(workspaceId)
      try {
        await switchWorkspaceApi(workspaceId)
        queryClient.clear()
        const updated = await meApi()
        queryClient.setQueryData(userKeys.me(), updated)
        setUser(updated)
        navigate({ to: '/dashboard' })
      } catch (error) {
        if (previousWorkspaceId !== workspaceId) {
          setPreferredWorkspaceId(previousWorkspaceId)
          setClientWorkspaceId(previousWorkspaceId)
        }
        throw error
      }
    },
    [navigate, queryClient, activeWorkspaceId],
  )

  const value = useMemo(
    () => ({
      user,
      workspaces,
      activeWorkspaceId,
      activeWorkspace,
      permissions,
      loading,
      signIn,
      signInWithProvider,
      signUp,
      signOut,
      deleteAccount,
      switchWorkspace,
    }),
    [
      user,
      workspaces,
      activeWorkspaceId,
      activeWorkspace,
      permissions,
      loading,
      signIn,
      signInWithProvider,
      signUp,
      signOut,
      deleteAccount,
      switchWorkspace,
    ],
  )
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>
}

export function useAuthContext() {
  const v = useContext(Ctx)
  if (!v) throw new Error('useAuthContext must be used within AuthProvider')
  return v
}
