import { Link, useNavigate } from '@tanstack/react-router'
import { GithubIcon } from 'lucide-react'
import { useCallback, useEffect, useMemo, useRef, useState } from 'react'

import { GITHUB_CLIENT_ID, GITHUB_REDIRECT_URI, GOOGLE_CLIENT_ID } from '@/shared/lib/config'
import { Button } from '@/shared/ui/button'
import { Input } from '@/shared/ui/input'
import { Label } from '@/shared/ui/label'

import { useAuthContext } from '@/features/auth'

import {
  buildRedirectSearchString,
  clearGithubOAuthState,
  parseRedirectSearch,
  readGithubOAuthState,
  type RedirectSearchParams,
  writeGithubOAuthState,
} from './github-oauth-state'

type Props = {
  redirect?: string
  redirectSearch?: string
  oauthProvider?: string
  oauthCode?: string
  oauthState?: string
  oauthError?: string
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
function buildGithubState() {
  if (typeof window !== 'undefined' && window.crypto?.randomUUID) {
    return window.crypto.randomUUID()
  }
  return Math.random().toString(36).slice(2)
}

export function SignInPage({
  redirect,
  redirectSearch,
  oauthProvider,
  oauthCode,
  oauthState,
  oauthError,
}: Props) {
  const navigate = useNavigate()
  const { signIn, signInWithProvider } = useAuthContext()
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [rememberMe, setRememberMe] = useState(true)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [socialLoading, setSocialLoading] = useState(false)
  const googleClientId = GOOGLE_CLIENT_ID
  const isGoogleEnabled = Boolean(googleClientId)
  const isGithubEnabled = Boolean(GITHUB_CLIENT_ID)
  const googleButtonRef = useRef<HTMLDivElement | null>(null)

  const sanitizedRedirectSearch = useMemo<RedirectSearchParams | undefined>(
    () => parseRedirectSearch(redirectSearch),
    [redirectSearch],
  )

  const finishSignIn = useCallback(
    (override?: { redirect?: string; redirectSearch?: RedirectSearchParams }) => {
      const redirectTo = override?.redirect || redirect || '/dashboard'
      const searchPayload = override?.redirectSearch ?? sanitizedRedirectSearch
      if (searchPayload) {
        navigate({ to: redirectTo, search: () => searchPayload })
      } else {
        navigate({ to: redirectTo })
      }
      clearGithubOAuthState()
    },
    [navigate, redirect, sanitizedRedirectSearch],
  )

  const clearOauthSearch = useCallback(
    (override?: { redirect?: string; redirectSearch?: RedirectSearchParams }) => {
      navigate({
        to: '/auth/signin',
        search: () => {
          const nextSearch: { redirect?: string; redirectSearch?: string } = {}
          const nextRedirect = override?.redirect ?? redirect
          if (nextRedirect !== undefined) {
            nextSearch.redirect = nextRedirect
          }
          const nextRedirectSearch = override?.redirectSearch
            ? buildRedirectSearchString(override.redirectSearch)
            : redirectSearch
          if (nextRedirectSearch !== undefined) {
            nextSearch.redirectSearch = nextRedirectSearch
          }
          return nextSearch
        },
        replace: true,
      })
    },
    [navigate, redirect, redirectSearch],
  )

  const resolveGithubRedirectUri = useCallback(() => {
    const ensureProviderParam = (uri: string) => {
      if (!uri) return uri
      try {
        const parsed = new URL(uri)
        if (!parsed.searchParams.has('provider')) {
          parsed.searchParams.set('provider', 'github')
        }
        return parsed.toString()
      } catch {
        if (uri.includes('provider=')) {
          return uri
        }
        const separator = uri.includes('?') ? '&' : '?'
        return `${uri}${separator}provider=github`
      }
    }

    if (GITHUB_REDIRECT_URI && GITHUB_REDIRECT_URI.trim().length > 0) {
      return ensureProviderParam(GITHUB_REDIRECT_URI)
    }
    if (typeof window !== 'undefined') {
      return ensureProviderParam(`${window.location.origin}/auth/signin`)
    }
    return ''
  }, [])

  const handleGoogleCredential = useCallback(
    async (credential: string) => {
      setSocialLoading(true)
      setError(null)
      try {
        await signInWithProvider('google', { credential, remember_me: rememberMe })
        finishSignIn()
      } catch (err: any) {
        setError(err?.message || 'Failed to sign in with Google')
      } finally {
        setSocialLoading(false)
      }
    },
    [finishSignIn, rememberMe, signInWithProvider],
  )

  const onSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setLoading(true)
    setError(null)
    try {
      await signIn(email, password, { remember: rememberMe })
      finishSignIn()
    } catch (err: any) {
      setError(err?.message || 'Failed to sign in')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    if (oauthProvider !== 'github') return
    const storedState = readGithubOAuthState()
    const storedOverride = storedState
      ? {
          redirect: storedState.redirect,
          redirectSearch: storedState.redirectSearch,
        }
      : undefined
    if (storedState?.rememberMe !== undefined) {
      setRememberMe(storedState.rememberMe)
    }
    if (oauthError) {
      setError(`GitHub authentication error: ${oauthError}`)
      clearOauthSearch(storedOverride)
      clearGithubOAuthState()
      return
    }
    if (!oauthCode) return
    if (!storedState || storedState.nonce !== oauthState) {
      setError('GitHub authentication state mismatch')
      clearOauthSearch(storedOverride)
      clearGithubOAuthState()
      return
    }
    const redirectUri = resolveGithubRedirectUri()
    if (!redirectUri) {
      setError('GitHub redirect URL is not configured')
      clearOauthSearch(storedOverride)
      clearGithubOAuthState()
      return
    }
    let cancelled = false
    const exchange = async () => {
      setSocialLoading(true)
      setError(null)
      try {
        await signInWithProvider('github', {
          code: oauthCode,
          redirect_uri: redirectUri,
          remember_me: storedState.rememberMe ?? rememberMe,
        })
        if (!cancelled) {
          clearOauthSearch()
          finishSignIn({
            redirect: storedState.redirect,
            redirectSearch: storedState.redirectSearch,
          })
        }
      } catch (err: any) {
        if (!cancelled) {
          setError(err?.message || 'Failed to sign in with GitHub')
          clearOauthSearch(storedOverride)
        }
      } finally {
        if (!cancelled) {
          setSocialLoading(false)
        }
        clearGithubOAuthState()
      }
    }
    void exchange()
    return () => {
      cancelled = true
    }
  }, [
    oauthProvider,
    oauthCode,
    oauthState,
    oauthError,
    clearOauthSearch,
    finishSignIn,
    rememberMe,
    resolveGithubRedirectUri,
    signInWithProvider,
  ])

  const startGithubSignIn = useCallback(() => {
    if (!isGithubEnabled || typeof window === 'undefined') return
    setError(null)
    const redirectUri = resolveGithubRedirectUri()
    if (!redirectUri) {
      setError('GitHub redirect URL is not configured')
      return
    }
    const state = buildGithubState()
    const stored = {
      nonce: state,
      redirect: redirect || undefined,
      redirectSearch: sanitizedRedirectSearch,
      rememberMe,
    }
    if (!writeGithubOAuthState(stored)) {
      setError('Unable to start GitHub sign in. Please enable site data storage and try again.')
      return
    }
    const url = new URL('https://github.com/login/oauth/authorize')
    url.searchParams.set('client_id', GITHUB_CLIENT_ID)
    url.searchParams.set('redirect_uri', redirectUri)
    url.searchParams.set('scope', 'read:user user:email')
    url.searchParams.set('state', state)
    url.searchParams.set('allow_signup', 'true')
    window.location.href = url.toString()
  }, [isGithubEnabled, redirect, rememberMe, resolveGithubRedirectUri, sanitizedRedirectSearch])

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
            setError('Failed to sign in with Google')
          }
        },
      })
      googleButtonRef.current.innerHTML = ''
      window.google.accounts.id.renderButton(googleButtonRef.current, {
        theme: 'outline',
        size: 'large',
        width: 320,
        text: 'continue_with',
        shape: 'rectangular',
      })
    }

    if (script && script.dataset.loaded === 'true') {
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

  const showSocial = isGithubEnabled || isGoogleEnabled
  const socialButtonWidth = 320

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
          <div className="flex items-center justify-between">
            <Label
              htmlFor="remember"
              className="flex cursor-pointer items-center gap-2 text-sm font-normal text-muted-foreground"
            >
              <input
                id="remember"
                name="remember"
                type="checkbox"
                checked={rememberMe}
                onChange={(event) => setRememberMe(event.target.checked)}
                className="md-checkbox"
              />
              Keep me signed in
            </Label>
          </div>
          {error && <div className="text-sm text-red-600">{error}</div>}
          <Button type="submit" className="w-full" disabled={loading}>
            {loading ? 'Signing in…' : 'Sign In'}
          </Button>
        </form>
        {showSocial && (
          <div className="space-y-4">
            <div className="flex items-center gap-3 text-xs uppercase tracking-wide text-muted-foreground">
              <span className="h-px flex-1 bg-muted" />
              <span>or continue with</span>
              <span className="h-px flex-1 bg-muted" />
            </div>
            <div className="flex flex-col items-center gap-3">
              {isGithubEnabled && (
                <button
                  type="button"
                  onClick={startGithubSignIn}
                  style={{ width: socialButtonWidth }}
                  className="flex items-center justify-center gap-2 rounded-md border border-input bg-background py-2 text-sm font-medium text-foreground shadow-sm outline-none transition-colors hover:bg-accent focus-visible:ring-2 focus-visible:ring-ring"
                >
                  <GithubIcon className="h-4 w-4" />
                  Continue with GitHub
                </button>
              )}
              {isGoogleEnabled && (
                <div
                  ref={googleButtonRef}
                  className="flex justify-center"
                  style={{ width: socialButtonWidth }}
                />
              )}
            </div>
            {socialLoading && (
              <p className="text-center text-xs text-muted-foreground">
                Signing in with {oauthProvider === 'github' ? 'GitHub' : 'Google'}…
              </p>
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
