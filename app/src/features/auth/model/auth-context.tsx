import { useNavigate } from '@tanstack/react-router'
import React, { createContext, useContext, useEffect, useMemo, useState, useCallback } from 'react'

import type { UserResponse } from '@/shared/api'
import { queryClient } from '@/shared/lib/queryClient'

import { login as loginApi, register as registerApi, me as meApi, AuthService, userKeys } from '@/entities/user'

type AuthState = {
  user: UserResponse | null
  loading: boolean
  signIn: (email: string, password: string) => Promise<void>
  signUp: (email: string, name: string, password: string) => Promise<void>
  signOut: () => Promise<void>
}

const Ctx = createContext<AuthState | null>(null)

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const navigate = useNavigate()
  const [user, setUser] = useState<UserResponse | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    const init = async () => {
      try {
        const me = await meApi()
        setUser(me)
      } catch {
        // not signed in
      } finally {
        setLoading(false)
      }
    }
    init()
  }, [])

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

  const value = useMemo(
    () => ({ user, loading, signIn, signUp, signOut }),
    [user, loading, signIn, signUp, signOut],
  )
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>
}

export function useAuthContext() {
  const v = useContext(Ctx)
  if (!v) throw new Error('useAuthContext must be used within AuthProvider')
  return v
}
