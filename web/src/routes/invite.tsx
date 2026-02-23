/**
 * Invite Accept Page
 *
 * Handles invitation link acceptance:
 * 1. Extract token from URL fragment and persist to sessionStorage
 * 2. Clear fragment from URL (security)
 * 3. Restore session if not authenticated (this route is outside _authenticated layout)
 * 4. If still not authenticated, show landing page with Create Account / Sign In options
 * 5. Accept invitation via API (sends raw token, server hashes)
 * 6. Decrypt KEK from response using token
 * 7. Save KEK for device and UMK backup
 * 8. Navigate to workspace
 *
 * Uses module-level dedup flags to prevent double-execution under React Strict Mode.
 */

import { Link, createFileRoute, useNavigate } from '@tanstack/react-router'
import { useEffect, useRef, useState } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { Button } from '@/shared/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/shared/ui/card'
import { Spinner } from '@/shared/ui/spinner'
import { useAuthContext } from '@/shared/context'
import { invitationApi } from '@/shared/api'
import { base64UrlDecode } from '@/shared/lib/crypto'
import { restoreSession } from '@/features/auth'
import { buildAuthState, buildDeviceState } from '@/shared/model/session-hydration'
import {
  decryptKekFromInvitation,
  encryptAndSaveKekForDevice,
  wrapAndSaveKekBackup,
} from '@/entities/workspace'

export const Route = createFileRoute('/invite')({
  component: InviteAcceptPage,
})

const TOKEN_SESSION_KEY = 'refmd_invite_token'

// Module-level dedup flags — survive React Strict Mode remounts
let restoreInFlight = false
let acceptInFlight = false

type AcceptState =
  | { step: 'restoring' }
  | { step: 'need_auth' }
  | { step: 'accepting' }
  | { step: 'saving_keys' }
  | { step: 'success'; workspaceId: string }
  | { step: 'error'; message: string; retryable: boolean }

/** Extract invite token from URL fragment and persist to sessionStorage. */
function extractAndPersistToken(): string | null {
  let tokenBase64: string | null = null

  const hash = window.location.hash
  if (hash.includes('token=')) {
    tokenBase64 = hash.split('token=')[1]?.split('&')[0] ?? null
    // Immediately clear fragment from URL (security)
    window.history.replaceState(null, '', window.location.pathname + window.location.search)
  }

  if (tokenBase64) {
    sessionStorage.setItem(TOKEN_SESSION_KEY, tokenBase64)
  } else {
    tokenBase64 = sessionStorage.getItem(TOKEN_SESSION_KEY)
  }

  return tokenBase64
}

function InviteAcceptPage() {
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const { auth, device, isAuthenticated, setFullSession } = useAuthContext()
  const [state, setState] = useState<AcceptState>({ step: 'restoring' })
  const redirectTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null)
  const [retryCount, setRetryCount] = useState(0)

  // Extract token on mount (before any async work)
  const tokenRef = useRef<string | null>(null)
  if (tokenRef.current === null) {
    tokenRef.current = extractAndPersistToken() ?? ''
  }
  const tokenBase64 = tokenRef.current || null

  // Cleanup on unmount
  useEffect(() => {
    return () => {
      if (redirectTimerRef.current) clearTimeout(redirectTimerRef.current)
      // Reset module-level flags so re-mounting (e.g. navigate away and back) works
      restoreInFlight = false
      acceptInFlight = false
    }
  }, [])

  // Phase 1: Session restore (runs once on mount)
  useEffect(() => {
    if (isAuthenticated) return // Already authenticated (e.g. navigated from register)
    if (restoreInFlight) return
    restoreInFlight = true

    if (!tokenBase64) {
      setState({ step: 'error', message: 'No invitation token found in URL.', retryable: false })
      return
    }

    let cancelled = false

    async function tryRestore() {
      try {
        const result = await restoreSession()

        if (cancelled) return

        if (result && !('type' in result) && result.deviceData) {
          setFullSession(
            buildAuthState(result),
            buildDeviceState(result.deviceData),
          )
          // Auth state updated — Phase 2 will trigger via the next useEffect
          return
        }
      } catch (e) {
        console.warn('[invite] Session restore failed:', e)
      }

      if (!cancelled) {
        setState({ step: 'need_auth' })
      }
    }

    tryRestore()
    return () => { cancelled = true }
  }, []) // eslint-disable-line react-hooks/exhaustive-deps -- intentionally run once

  // Phase 2: Accept invitation (runs when authenticated)
  useEffect(() => {
    if (!isAuthenticated || !auth || !device) return
    if (acceptInFlight) return
    if (!tokenBase64) return
    acceptInFlight = true

    // Capture current auth/device values for the async closure
    const currentAuth = auth
    const currentDevice = device

    let cancelled = false

    async function acceptInvitation() {
      setState({ step: 'accepting' })

      // Validate token format
      let tokenBytes: Uint8Array
      try {
        tokenBytes = base64UrlDecode(tokenBase64!)
        if (tokenBytes.length !== 32) {
          throw new Error('Invalid token length')
        }
      } catch {
        sessionStorage.removeItem(TOKEN_SESSION_KEY)
        if (!cancelled) setState({ step: 'error', message: 'Invalid invitation token format.', retryable: false })
        return
      }

      // Accept invitation via API
      let result
      try {
        result = await invitationApi.accept({ token: tokenBase64! })
      } catch (err) {
        if (cancelled) return
        const message = err instanceof Error ? err.message : 'Failed to accept invitation'
        const status = (err as { status?: number })?.status
        const is410 = status === 410
        const is409 = status === 409
        const retryable = is409 || !status
        if (!retryable) {
          sessionStorage.removeItem(TOKEN_SESSION_KEY)
        }
        setState({
          step: 'error',
          message: is410 ? 'This invitation link is no longer valid.'
                 : is409 ? 'Workspace key rotation in progress. Please try again later.'
                 : message,
          retryable,
        })
        return
      }

      if (cancelled) return

      // Decrypt KEK from response
      setState({ step: 'saving_keys' })

      let kek: Uint8Array
      try {
        const encryptedKek = base64UrlDecode(result.encrypted_kek)
        const nonce = base64UrlDecode(result.kek_nonce)

        kek = decryptKekFromInvitation(
          encryptedKek,
          nonce,
          tokenBytes,
          result.workspace_id,
          result.invitation_id,
          result.kek_version
        )
      } catch {
        sessionStorage.removeItem(TOKEN_SESSION_KEY)
        if (!cancelled) {
          setState({
            step: 'error',
            message: 'Failed to decrypt workspace key. The invitation link may be corrupted. Please request a new one.',
            retryable: false,
          })
        }
        return
      }

      // Save KEK for device and UMK backup
      try {
        await encryptAndSaveKekForDevice(
          kek,
          currentDevice.deviceKeys.ecdhPrivateKey,
          currentDevice.deviceKeys.ecdhPublicKey,
          currentDevice.deviceId,
          result.workspace_id,
          currentAuth.userId,
          currentDevice.deviceId,
          result.kek_version
        )

        if (currentAuth.umk) {
          await wrapAndSaveKekBackup(
            kek,
            currentAuth.umk,
            result.workspace_id,
            currentAuth.userId,
            result.kek_version
          )
        }
      } catch (err) {
        console.error('Failed to save KEK:', err)
        if (!cancelled) {
          setState({
            step: 'error',
            message: 'Joined the workspace but failed to save encryption keys. Please retry.',
            retryable: true,
          })
        }
        return
      }

      if (cancelled) return

      // Done
      sessionStorage.removeItem(TOKEN_SESSION_KEY)
      setState({ step: 'success', workspaceId: result.workspace_id })

      await queryClient.invalidateQueries({ queryKey: ['workspaces'] })

      redirectTimerRef.current = setTimeout(() => {
        navigate({ to: '/workspace/$workspaceId', params: { workspaceId: result.workspace_id } })
      }, 1500)
    }

    acceptInvitation()
    return () => { cancelled = true; acceptInFlight = false }
  }, [isAuthenticated, auth, device, retryCount]) // eslint-disable-line react-hooks/exhaustive-deps

  // Landing page for unauthenticated users
  if (state.step === 'need_auth') {
    return (
      <main className="min-h-screen flex items-center justify-center p-4">
        <Card className="w-full max-w-md">
          <CardHeader className="space-y-1 text-center">
            <CardTitle className="text-2xl font-bold">
              You've been invited
            </CardTitle>
            <CardDescription>
              Someone invited you to collaborate on a workspace.
              Create an account or sign in to accept.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            <Button
              className="w-full"
              onClick={() => navigate({ to: '/auth/register', search: { redirect: '/invite' } })}
            >
              Create Account
            </Button>
            <Button
              variant="outline"
              className="w-full"
              onClick={() => navigate({ to: '/auth/login', search: { redirect: '/invite' } })}
            >
              Sign In
            </Button>
            <p className="text-center text-xs text-muted-foreground pt-2">
              Your data is end-to-end encrypted.{' '}
              <Link to="/auth/recovery" className="text-primary hover:underline">
                Lost access?
              </Link>
            </p>
          </CardContent>
        </Card>
      </main>
    )
  }

  return (
    <div className="flex h-screen items-center justify-center">
      <div className="w-full max-w-sm space-y-4 text-center">
        {state.step === 'restoring' && (
          <>
            <Spinner size="lg" />
            <p className="text-muted-foreground">Processing invitation...</p>
          </>
        )}

        {state.step === 'accepting' && (
          <>
            <Spinner size="lg" />
            <p className="text-muted-foreground">Accepting invitation...</p>
          </>
        )}

        {state.step === 'saving_keys' && (
          <>
            <Spinner size="lg" />
            <p className="text-muted-foreground">Setting up workspace encryption...</p>
          </>
        )}

        {state.step === 'success' && (
          <>
            <div className="text-3xl">&#10003;</div>
            <p className="text-foreground font-medium">You've joined the workspace!</p>
            <p className="text-sm text-muted-foreground">Redirecting to workspace...</p>
          </>
        )}

        {state.step === 'error' && (
          <>
            <p className="text-destructive font-medium">{state.message}</p>
            <div className="flex gap-2 justify-center">
              {state.retryable && (
                <Button onClick={() => {
                  acceptInFlight = false
                  setState({ step: 'accepting' })
                  setRetryCount((c) => c + 1)
                }}>
                  Retry
                </Button>
              )}
              <Button
                variant="outline"
                onClick={() => {
                  sessionStorage.removeItem(TOKEN_SESSION_KEY)
                  navigate({ to: '/workspace' })
                }}
              >
                Go to workspace
              </Button>
            </div>
          </>
        )}
      </div>
    </div>
  )
}
