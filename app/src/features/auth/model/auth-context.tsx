import { useQueryClient } from '@tanstack/react-query'
import { useNavigate } from '@tanstack/react-router'
import { getGlobalStartContext } from '@tanstack/start-client-core'
import React, { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from 'react'

import { ApiError } from '@/shared/api'
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

import { updateRuntimeAuthContext } from '@/features/auth/lib/runtime-context'
import type { AuthMiddlewareContext } from '@/features/auth/lib/types'

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

function readInitialAuthContext(): AuthMiddlewareContext | null {
  if (typeof window === 'undefined') return null
  try {
    const context = getGlobalStartContext() as { auth?: AuthMiddlewareContext } | undefined
    return context?.auth ?? null
  } catch {
    return null
  }
}

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
  const initialAuthContext = useMemo(() => readInitialAuthContext(), [])
  const ssrUser = initialAuthContext?.user ?? null
  const [runtimeHasRefreshToken, setRuntimeHasRefreshToken] = useState<boolean>(
    initialAuthContext?.hasRefreshToken ?? false,
  )
  const runtimeRefreshRef = useRef(runtimeHasRefreshToken)

  const updateAuthContext = useCallback(
    (partial: Partial<AuthMiddlewareContext>) => {
      const normalized: Partial<AuthMiddlewareContext> = { ...partial }
      if ('deferUntil' in normalized) {
        normalized.deferDurationMs = undefined
      }
      if (initialAuthContext) {
        Object.assign(initialAuthContext, normalized)
      }
      updateRuntimeAuthContext((ctx) => {
        Object.assign(ctx, normalized)
      })
    },
    [initialAuthContext],
  )

  useEffect(() => {
    runtimeRefreshRef.current = runtimeHasRefreshToken
  }, [runtimeHasRefreshToken])

  if (ssrUser) {
    const existingUser = queryClient.getQueryData(userKeys.me()) as UserResponse | undefined
    if (!existingUser) {
      queryClient.setQueryData(userKeys.me(), ssrUser)
    }
  }

  const meState = queryClient.getQueryState(userKeys.me())
  const initialUser = ((meState?.data as UserResponse | null | undefined) ?? ssrUser ?? null) as UserResponse | null
  const hasInitialData = meState?.status === 'success' || Boolean(ssrUser)
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
      updateAuthContext({
        user: initialUser,
        isAuthenticated: Boolean(initialUser),
        authResolved: true,
        hasRefreshToken: runtimeRefreshRef.current,
        deferUntil: undefined,
      })
      return
    }

    let cancelled = false
    let retryTimer: ReturnType<typeof setTimeout> | null = null
    const maxAttempts = 3
    const baseDelay = 2000

    const attemptFetch = async (attempt: number) => {
      if (cancelled) return
      const delay = baseDelay * Math.max(1, attempt + 1)
      updateAuthContext({
        authResolved: false,
        deferUntil: Date.now() + delay,
        hasRefreshToken: runtimeRefreshRef.current,
      })
      setLoading(true)
      try {
        const me = await meApi()
        if (cancelled) return
        queryClient.setQueryData(userKeys.me(), me)
        setUser(me)
        setRuntimeHasRefreshToken(true)
        runtimeRefreshRef.current = true
        updateAuthContext({
          user: me,
          isAuthenticated: true,
          authResolved: true,
          hasRefreshToken: true,
          deferUntil: undefined,
        })
        setLoading(false)
      } catch (error) {
        if (cancelled) return
        const isApiError = error instanceof ApiError
        if (!isApiError && attempt < maxAttempts - 1) {
          retryTimer = setTimeout(() => {
            retryTimer = null
            void attemptFetch(attempt + 1)
          }, delay)
          return
        }

        let nextHasRefresh = runtimeRefreshRef.current
        if (isApiError && error.status === 401) {
          nextHasRefresh = false
          setRuntimeHasRefreshToken(false)
          runtimeRefreshRef.current = false
        }
        setUser(null)
        updateAuthContext({
          user: null,
          isAuthenticated: false,
          authResolved: true,
          hasRefreshToken: nextHasRefresh,
          deferUntil: undefined,
        })
        setLoading(false)
      }
    }

    void attemptFetch(0)

    return () => {
      cancelled = true
      if (retryTimer) {
        clearTimeout(retryTimer)
      }
    }
  }, [hasInitialData, initialUser, queryClient, updateAuthContext])

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
        updateAuthContext({
          authResolved: false,
          deferUntil: Date.now() + 5000,
          hasRefreshToken: runtimeRefreshRef.current,
        })
        return
      }

      if (status === 'success') {
        const data = typed.query.state.data as UserResponse | undefined
        setUser(data ?? null)
        updateAuthContext({
          user: data ?? null,
          isAuthenticated: Boolean(data),
          authResolved: true,
          hasRefreshToken: runtimeRefreshRef.current,
          deferUntil: undefined,
        })
        setLoading(false)
        return
      }

      if (status === 'error') {
        setUser(null)
        updateAuthContext({
          user: null,
          isAuthenticated: false,
          authResolved: true,
          deferUntil: undefined,
        })
        setLoading(false)
      }
    })

    return () => {
      unsubscribe()
    }
  }, [queryClient, updateAuthContext])

  const signIn = useCallback(
    async (email: string, password: string, options?: SignInOptions) => {
      const res = await loginApi(email, password, options)
      queryClient.clear()
      queryClient.setQueryData(userKeys.me(), res.user)
      setUser(res.user)
      setRuntimeHasRefreshToken(true)
      runtimeRefreshRef.current = true
      updateAuthContext({
        user: res.user,
        isAuthenticated: true,
        authResolved: true,
        hasRefreshToken: true,
        deferUntil: undefined,
      })
      return res.user
    },
    [queryClient, updateAuthContext],
  )

  const signInWithProvider = useCallback(
    async (provider: string, payload: OAuthPayload) => {
      const res = await oauthLoginApi(provider, payload)
      queryClient.clear()
      queryClient.setQueryData(userKeys.me(), res.user)
      setUser(res.user)
      setRuntimeHasRefreshToken(true)
      runtimeRefreshRef.current = true
      updateAuthContext({
        user: res.user,
        isAuthenticated: true,
        authResolved: true,
        hasRefreshToken: true,
        deferUntil: undefined,
      })
      return res.user
    },
    [queryClient, updateAuthContext],
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
    setRuntimeHasRefreshToken(false)
    runtimeRefreshRef.current = false
    updateAuthContext({
      user: null,
      isAuthenticated: false,
      authResolved: true,
      hasRefreshToken: false,
      deferUntil: undefined,
    })
    navigate({ to: '/auth/signin' })
  }, [navigate, queryClient, updateAuthContext])

  const deleteAccount = useCallback(async () => {
    await deleteAccountApi()
    queryClient.clear()
    setUser(null)
    setRuntimeHasRefreshToken(false)
    runtimeRefreshRef.current = false
    updateAuthContext({
      user: null,
      isAuthenticated: false,
      authResolved: true,
      hasRefreshToken: false,
      deferUntil: undefined,
    })
    navigate({ to: '/auth/signin' })
  }, [navigate, queryClient, updateAuthContext])

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
        await queryClient.cancelQueries({
          predicate: (query) => query.queryKey?.[0] !== userKeys.me()[0],
        })
        queryClient.removeQueries({
          predicate: (query) => query.queryKey?.[0] !== userKeys.me()[0],
          type: 'inactive',
        })
        void queryClient.invalidateQueries({
          // Refresh everything except the user record we are about to overwrite
          predicate: (query) => query.queryKey?.[0] !== userKeys.me()[0],
          type: 'active',
          refetchType: 'active',
        })
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
