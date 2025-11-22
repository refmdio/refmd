import { Link, useNavigate } from '@tanstack/react-router'
import { GithubIcon } from 'lucide-react'
import { useCallback, useEffect, useMemo, useRef, useState } from 'react'

import type { AuthProvidersResponse } from '@/shared/api'
import { Button } from '@/shared/ui/button'
import { Input } from '@/shared/ui/input'
import { Label } from '@/shared/ui/label'

import { createOauthState } from '@/entities/user'

import { useAuthContext } from '@/features/auth'

import {
  buildRedirectSearchString,
  clearOauthState,
  parseRedirectSearch,
  readOauthState,
  type RedirectSearchParams,
  writeOauthState,
} from './oauth-state'

type AuthProviderInfo = AuthProvidersResponse['providers'][number]

type Props = {
  redirect?: string
  redirectSearch?: string
  oauthProvider?: string
  oauthCode?: string
  oauthState?: string
  oauthError?: string
  providers?: AuthProviderInfo[]
  providerLoadFailed?: boolean
  providersLoading?: boolean
  onRetryProviders?: () => void | Promise<unknown>
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

export function SignInPage({
  redirect,
  redirectSearch,
  oauthProvider,
  oauthCode,
  oauthState,
  oauthError,
  providers,
  providerLoadFailed = false,
  providersLoading = false,
  onRetryProviders,
}: Props) {
  const navigate = useNavigate()
  const { signIn, signInWithProvider } = useAuthContext()
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [rememberMe, setRememberMe] = useState(true)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [socialLoading, setSocialLoading] = useState(false)
  const [activeSocialProvider, setActiveSocialProvider] = useState<string | null>(null)
  const pickClientId = useCallback((provider?: AuthProviderInfo | null) => {
    if (!provider) return ''
    for (const value of provider.client_ids ?? []) {
      if (typeof value === 'string') {
        const trimmed = value.trim()
        if (trimmed.length > 0) {
          return trimmed
        }
      }
    }
    return ''
  }, [])
  const providerList = providers ?? []
  const providerMap = useMemo(() => new Map(providerList.map((provider) => [provider.id, provider])), [providerList])
  const googleProvider = useMemo(
    () => providerList.find((provider) => provider.id === 'google'),
    [providerList],
  )
  const codeProviders = useMemo(
    () =>
      providerList.filter((provider) => {
        if (!provider.requires_state) return false
        const authUrl = provider.authorization_url?.trim()
        if (!authUrl) return false
        return Boolean(pickClientId(provider))
      }),
    [pickClientId, providerList],
  )
  const getProviderLabel = useCallback(
    (providerId?: string | null) => {
      if (!providerId) return 'provider'
      const provider = providerMap.get(providerId)
      return provider?.name?.trim() || provider?.id || providerId
    },
    [providerMap],
  )
  const clearAllOauthState = useCallback(() => {
    clearOauthState('github')
    providerList.forEach((provider) => {
      if (provider.requires_state && provider.id !== 'github') {
        clearOauthState(provider.id)
      }
    })
  }, [providerList])
  const resolveRedirectUri = useCallback((providerId: string, provider?: AuthProviderInfo | null) => {
    const ensureProviderParam = (uri: string) => {
      if (!uri) return uri
      try {
        const parsed = new URL(uri)
        if (!parsed.searchParams.has('provider')) {
          parsed.searchParams.set('provider', providerId)
        }
        return parsed.toString()
      } catch {
        if (uri.includes('provider=')) {
          return uri
        }
        const separator = uri.includes('?') ? '&' : '?'
        return `${uri}${separator}provider=${providerId}`
      }
    }

    const configured = provider?.redirect_uri?.trim()
    if (configured && configured.length > 0) {
      return ensureProviderParam(configured)
    }
    if (typeof window !== 'undefined') {
      return ensureProviderParam(`${window.location.origin}/auth/signin`)
    }
    return ''
  }, [])

  const googleClientId = useMemo(() => pickClientId(googleProvider), [googleProvider, pickClientId])
  const isGoogleEnabled = Boolean(googleProvider && googleClientId)
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
      clearAllOauthState()
    },
    [clearAllOauthState, navigate, redirect, sanitizedRedirectSearch],
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

  const handleGoogleCredential = useCallback(
    async (credential: string) => {
      setSocialLoading(true)
      setActiveSocialProvider('google')
      setError(null)
      try {
        await signInWithProvider('google', { credential, remember_me: rememberMe })
        finishSignIn()
      } catch (err: any) {
        setError(err?.message || 'Failed to sign in with Google')
      } finally {
        setSocialLoading(false)
        setActiveSocialProvider(null)
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
    if (!oauthProvider) return
    if (!providerMap.size) return
    const provider = providerMap.get(oauthProvider)
    if (!provider) {
      if (providersLoading) return
      setError('Requested OAuth provider is not available. Please try again or use another sign-in method.')
      clearOauthSearch()
      clearOauthState(oauthProvider)
      return
    }
    if (!provider.requires_state) return
    const providerLabel = provider.name?.trim() || provider.id
    const storedState = readOauthState(oauthProvider)
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
      setError(`${providerLabel} authentication error: ${oauthError}`)
      clearOauthSearch(storedOverride)
      clearOauthState(oauthProvider)
      return
    }
    if (!oauthCode) return
    if (!storedState || storedState.nonce !== oauthState) {
      setError(`${providerLabel} authentication state mismatch`)
      clearOauthSearch(storedOverride)
      clearOauthState(oauthProvider)
      return
    }
    const redirectUri = resolveRedirectUri(oauthProvider, provider)
    if (!redirectUri) {
      setError(`${providerLabel} redirect URL is not configured`)
      clearOauthSearch(storedOverride)
      clearOauthState(oauthProvider)
      return
    }
    let cancelled = false
    setActiveSocialProvider(oauthProvider)
    const exchange = async () => {
      setSocialLoading(true)
      setError(null)
      try {
        await signInWithProvider(oauthProvider, {
          code: oauthCode,
          redirect_uri: redirectUri,
          remember_me: storedState.rememberMe ?? rememberMe,
          state: oauthState,
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
          setError(err?.message || `Failed to sign in with ${providerLabel}`)
          clearOauthSearch(storedOverride)
        }
      } finally {
        if (!cancelled) {
          setSocialLoading(false)
          setActiveSocialProvider(null)
        }
        clearOauthState(oauthProvider)
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
    resolveRedirectUri,
    signInWithProvider,
    providerMap,
    providersLoading,
  ])

  const startOauthSignIn = useCallback(
    async (providerId: string) => {
      if (typeof window === 'undefined') return
      const provider = providerMap.get(providerId)
      if (!provider || !provider.requires_state) return
      const clientId = pickClientId(provider)
      const authorizationUrl = provider.authorization_url?.trim()
      const label = provider.name?.trim() || provider.id
      if (!clientId) {
        setError(`${label} client ID is not configured`)
        return
      }
      if (!authorizationUrl) {
        setError(`${label} authorization URL is not configured`)
        return
      }
      const redirectUri = resolveRedirectUri(providerId, provider)
      if (!redirectUri) {
        setError(`${label} redirect URL is not configured`)
        return
      }
      setError(null)
      setSocialLoading(true)
      setActiveSocialProvider(providerId)
      try {
        const stateResponse = await createOauthState(providerId)
        const state = stateResponse.state
        const stored = {
          nonce: state,
          redirect: redirect || undefined,
          redirectSearch: sanitizedRedirectSearch,
          rememberMe,
        }
        if (!writeOauthState(providerId, stored)) {
          setError(
            `Unable to start ${label} sign in. Please enable site data storage and try again.`,
          )
          setSocialLoading(false)
          setActiveSocialProvider(null)
          return
        }
        const url = new URL(authorizationUrl)
        url.searchParams.set('client_id', clientId)
        url.searchParams.set('redirect_uri', redirectUri)
        url.searchParams.set('response_type', 'code')
        const scopeParam =
          provider.scopes && provider.scopes.length > 0
            ? provider.scopes.join(' ')
            : 'openid profile email'
        url.searchParams.set('scope', scopeParam)
        url.searchParams.set('state', state)
        if (providerId === 'github') {
          url.searchParams.set('allow_signup', 'true')
        }
        window.location.href = url.toString()
      } catch (err: any) {
        setError(err?.message || `Unable to start ${label} sign in`)
        setSocialLoading(false)
        setActiveSocialProvider(null)
      }
    },
    [pickClientId, providerMap, redirect, rememberMe, resolveRedirectUri, sanitizedRedirectSearch],
  )

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

  const showSocial = isGoogleEnabled || codeProviders.length > 0
  const socialButtonWidth = 320
  const retryProviderFetch = useCallback(() => {
    if (!onRetryProviders) return
    void onRetryProviders()
  }, [onRetryProviders])

  const providerErrorNotice = providerLoadFailed ? (
    <div className="text-center text-xs text-amber-600 space-y-2">
      <p>
        Social sign-in is temporarily unavailable.{' '}
        {showSocial ? 'Please try again later.' : 'Use email and password or retry fetching providers.'}
      </p>
      {onRetryProviders && (
        <Button
          type="button"
          variant="outline"
          size="sm"
          onClick={retryProviderFetch}
          disabled={providersLoading}
          className="mx-auto"
        >
          {providersLoading ? 'Retrying…' : 'Retry fetching providers'}
        </Button>
      )}
    </div>
  ) : null

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
              {codeProviders.map((provider) => (
                <button
                  key={provider.id}
                  type="button"
                  onClick={() => startOauthSignIn(provider.id)}
                  style={{ width: socialButtonWidth }}
                  className="flex items-center justify-center gap-2 rounded-md border border-input bg-background py-2 text-sm font-medium text-foreground shadow-sm outline-none transition-colors hover:bg-accent focus-visible:ring-2 focus-visible:ring-ring"
                >
                  {provider.id === 'github' && <GithubIcon className="h-4 w-4" />}
                  Continue with {provider.name ?? provider.id}
                </button>
              ))}
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
                Signing in with {getProviderLabel(activeSocialProvider ?? oauthProvider)}…
              </p>
            )}
            {providerErrorNotice}
          </div>
        )}
        {!showSocial && providerErrorNotice}
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
