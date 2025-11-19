import { Link, useNavigate } from '@tanstack/react-router'
import { useCallback, useEffect, useRef, useState } from 'react'

import { GOOGLE_CLIENT_ID } from '@/shared/lib/config'
import { Button } from '@/shared/ui/button'
import { Input } from '@/shared/ui/input'
import { Label } from '@/shared/ui/label'

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
    <div className="min-h-svh flex items-center justify-center bg-background px-4 py-12">
      <div className="w-full max-w-md space-y-6">
        <div className="text-center space-y-2">
          <p className="text-sm font-medium text-muted-foreground">Welcome back</p>
          <h1 className="text-3xl font-semibold tracking-tight">Sign in to RefMD</h1>
          <p className="text-sm text-muted-foreground">
            Access your workspaces, documents, and shortcuts without missing a beat.
          </p>
        </div>
        <form onSubmit={onSubmit} className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="email">Email</Label>
            <Input
              id="email"
              name="email"
              type="email"
              placeholder="you@example.com"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              required
            />
          </div>
          <div className="space-y-2">
            <Label htmlFor="password">Password</Label>
            <Input
              id="password"
              name="password"
              type="password"
              placeholder="••••••••"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
              autoComplete="current-password"
            />
          </div>
          {error && <div className="text-sm text-red-600">{error}</div>}
          <Button type="submit" className="w-full" disabled={loading}>
            {loading ? 'Signing in…' : 'Sign In'}
          </Button>
        </form>
        {isGoogleEnabled && (
          <div className="space-y-4">
            <div className="flex items-center gap-3 text-xs uppercase tracking-wide text-muted-foreground">
              <span className="h-px flex-1 bg-muted" />
              <span>or continue with</span>
              <span className="h-px flex-1 bg-muted" />
            </div>
            <div ref={googleButtonRef} className="flex justify-center" />
            {socialLoading && (
              <p className="text-center text-xs text-muted-foreground">Signing in with Google…</p>
            )}
          </div>
        )}
        <div className="text-center text-sm text-muted-foreground">
          Don’t have an account?{' '}
          <Link to="/auth/signup" className="font-medium text-primary hover:underline">
            Sign up
          </Link>
        </div>
      </div>
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
