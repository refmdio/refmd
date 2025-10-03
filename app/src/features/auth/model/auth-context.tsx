import { useQueryClient } from '@tanstack/react-query'
import { useNavigate } from '@tanstack/react-router'
import React, { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react'

import type { UserResponse } from '@/shared/api'

import { login as loginApi, register as registerApi, me as meApi, deleteAccount as deleteAccountApi, AuthService, userKeys } from '@/entities/user'

type AuthState = {
  user: UserResponse | null
  loading: boolean
  signIn: (email: string, password: string) => Promise<void>
  signUp: (email: string, name: string, password: string) => Promise<void>
  signOut: () => Promise<void>
  deleteAccount: () => Promise<void>
}

const Ctx = createContext<AuthState | null>(null)

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const meState = queryClient.getQueryState(userKeys.me())
  const initialUser = ((meState?.data as UserResponse | null | undefined) ?? null) as UserResponse | null
  const hasInitialData = meState?.status === 'success'
  const [user, setUser] = useState<UserResponse | null>(initialUser)
  const [loading, setLoading] = useState(() => !hasInitialData)

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

  const signIn = useCallback(async (email: string, password: string) => {
    const res = await loginApi(email, password)
    // Cookie is set by server; ignore access_token in response
    queryClient.clear()
    queryClient.setQueryData(userKeys.me(), res.user)
    setUser(res.user)
  }, [])

  const signUp = useCallback(async (email: string, name: string, password: string) => {
    await registerApi(email, name, password)
  }, [])

  const signOut = useCallback(async () => {
    try {
      await AuthService.logout()
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

  const value = useMemo(
    () => ({ user, loading, signIn, signUp, signOut, deleteAccount }),
    [user, loading, signIn, signUp, signOut, deleteAccount],
  )
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>
}

export function useAuthContext() {
  const v = useContext(Ctx)
  if (!v) throw new Error('useAuthContext must be used within AuthProvider')
  return v
}
