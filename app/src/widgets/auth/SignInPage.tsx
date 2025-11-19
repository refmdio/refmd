import { Link, useNavigate } from '@tanstack/react-router'
import { useCallback, useEffect, useRef, useState } from 'react'

import { Button } from '@/shared/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/shared/ui/card'
import { Input } from '@/shared/ui/input'
import { Label } from '@/shared/ui/label'

import { GOOGLE_CLIENT_ID } from '@/shared/lib/config'
import { useAuthContext } from '@/features/auth'

type Props = {
  redirect?: string
  redirectSearch?: string
}

type GoogleCredentialResponse = {
  credential?: string
}

declare global {
  interface Window {
    google?: {
      accounts: {
        id: {
          initialize(config: Record<string, unknown>): void
          renderButton(element: HTMLElement, options?: Record<string, unknown>): void
        }
      }
    }
  }
}

const GOOGLE_SCRIPT_SRC = 'https://accounts.google.com/gsi/client'

export function SignInPage({ redirect, redirectSearch }: Props) {
  const navigate = useNavigate()
  const { signIn, signInWithProvider } = useAuthContext()
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [socialLoading, setSocialLoading] = useState(false)
  const googleClientId = GOOGLE_CLIENT_ID
  const isGoogleEnabled = Boolean(googleClientId)
  const googleButtonRef = useRef<HTMLDivElement | null>(null)

  const finishSignIn = useCallback(() => {
    const redirectTo = redirect || '/dashboard'
    const parsedRedirectSearch = parseRedirectSearch(redirectSearch)
    if (parsedRedirectSearch) navigate({ to: redirectTo, search: () => parsedRedirectSearch })
    else navigate({ to: redirectTo })
  }, [navigate, redirect, redirectSearch])

  const handleGoogleCredential = useCallback(
    async (credential: string) => {
      setSocialLoading(true)
      setError(null)
      try {
        await signInWithProvider('google', { credential })
        finishSignIn()
      } catch (err: any) {
        setError(err?.message || 'Googleでのサインインに失敗しました')
      } finally {
        setSocialLoading(false)
      }
    },
    [finishSignIn, signInWithProvider],
  )

  const onSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setLoading(true)
    setError(null)
    try {
      await signIn(email, password)
      finishSignIn()
    } catch (err: any) {
      setError(err?.message || 'Failed to sign in')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    if (!isGoogleEnabled) return
    if (typeof window === 'undefined') return
    let cancelled = false
    let script = document.querySelector<HTMLScriptElement>('script[data-google-identity]')

    const initialize = () => {
      if (cancelled) return
      if (!window.google || !googleButtonRef.current) return
      window.google.accounts.id.initialize({
        client_id: googleClientId,
        callback: (response: GoogleCredentialResponse) => {
          if (response?.credential) {
            void handleGoogleCredential(response.credential)
          } else {
            setError('Google認証に失敗しました')
          }
        },
      })
      googleButtonRef.current.innerHTML = ''
      window.google.accounts.id.renderButton(googleButtonRef.current, {
        theme: 'outline',
        size: 'large',
        width: '100%',
        text: 'continue_with',
        shape: 'rectangular',
      })
    }

    if (script && (script.dataset.loaded === 'true')) {
      initialize()
      return
    }

    if (!script) {
      script = document.createElement('script')
      script.src = GOOGLE_SCRIPT_SRC
      script.async = true
      script.defer = true
      script.dataset.googleIdentity = 'true'
      document.head.appendChild(script)
    }

    const handleLoad = () => {
      if (!script) return
      script.dataset.loaded = 'true'
      initialize()
    }

    script.addEventListener('load', handleLoad)

    return () => {
      cancelled = true
      script?.removeEventListener('load', handleLoad)
    }
  }, [googleClientId, handleGoogleCredential, isGoogleEnabled])

  return (
    <div className="min-h-svh flex items-center justify-center bg-gradient-to-br from-gray-50 to-gray-100 dark:from-gray-900 dark:to-gray-800 px-4">
      <Card className="w-full max-w-md">
        <CardHeader className="text-center">
          <CardTitle className="text-2xl font-bold">Welcome Back</CardTitle>
          <CardDescription>Sign in to your RefMD account</CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={onSubmit} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="email">Email</Label>
              <Input id="email" name="email" type="email" placeholder="Enter your email" value={email} onChange={(e) => setEmail(e.target.value)} required />
            </div>
            <div className="space-y-2">
              <Label htmlFor="password">Password</Label>
              <Input id="password" name="password" type="password" placeholder="Enter your password" value={password} onChange={(e) => setPassword(e.target.value)} required autoComplete="current-password" />
            </div>
            {error && <div className="text-sm text-red-600">{error}</div>}
            <Button type="submit" className="w-full" disabled={loading}>
              {loading ? 'Signing in…' : 'Sign In'}
            </Button>
          </form>
          {isGoogleEnabled && (
            <div className="mt-6">
              <div className="relative mb-4">
                <div className="absolute inset-0 flex items-center">
                  <span className="w-full border-t border-muted-foreground/30" />
                </div>
                <div className="relative flex justify-center text-xs uppercase text-muted-foreground">
                  <span className="bg-white px-2 dark:bg-gray-900">or continue with</span>
                </div>
              </div>
              <div ref={googleButtonRef} className="flex justify-center" />
              {socialLoading && (
                <p className="mt-2 text-center text-xs text-muted-foreground">Signing in with Google…</p>
              )}
            </div>
          )}
          <div className="mt-6 text-center">
            <p className="text-sm text-gray-600 dark:text-gray-400">
              Don’t have an account?{' '}
              <Link to="/auth/signup" className="font-medium text-blue-600 hover:text-blue-500 dark:text-blue-400 dark:hover:text-blue-300">
                Sign up
              </Link>
            </p>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}

function parseRedirectSearch(search?: string) {
  if (!search) return undefined

  try {
    const params = new URLSearchParams(search)
    if (!params.toString()) return undefined

    const result: Record<string, string | string[]> = {}
    params.forEach((value, key) => {
      if (result[key] === undefined) result[key] = value
      else if (Array.isArray(result[key])) (result[key] as string[]).push(value)
      else result[key] = [result[key] as string, value]
    })

    return result
  } catch {
    return undefined
  }
}
