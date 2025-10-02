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
  const [user, setUser] = useState<UserResponse | null>(null)
  const [loading, setLoading] = useState(true)
  const queryClient = useQueryClient()

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
