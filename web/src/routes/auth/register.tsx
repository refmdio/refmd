import { Link, createFileRoute, useNavigate, useRouter } from '@tanstack/react-router'
import { useState } from 'react'
import { Button } from '@/shared/ui/button'
import { FormField } from '@/shared/ui/form-field'
import { AuthLayout } from './-components/AuthLayout'
import { EmailField, PasswordField } from './-components/AuthFields'
import { register, login } from '@/features/auth'
import { getApiErrorMessage } from '@/shared/api'
import { ErrorAlert } from '@/shared/ui/error-alert'
import { useAsyncAction } from '@/shared/hooks'
import { formatRecoveryKeyFile } from '@/shared/lib/recovery-key-format'
import { sanitizeRedirect } from '@/shared/lib/redirect'
import { useAuthContext } from '@/shared/context'
import { buildAuthState, buildDeviceState } from '@/shared/model/session-hydration'
import { WORKSPACE_STORAGE_KEY } from '@/entities/workspace'

export const Route = createFileRoute('/auth/register')({
  component: RegisterPage,
  validateSearch: (search: Record<string, unknown>): { redirect?: string } => ({
    redirect: sanitizeRedirect(search.redirect),
  }),
})

function RegisterPage() {
  const navigate = useNavigate()
  const router = useRouter()
  const { redirect } = Route.useSearch()
  const { setFullSession, clearAuthState } = useAuthContext()
  const [name, setName] = useState('')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const { error, setError, loading, execute } = useAsyncAction(getApiErrorMessage)
  const [recoveryMnemonic, setRecoveryMnemonic] = useState<string | null>(null)
  const [mnemonicConfirmed, setMnemonicConfirmed] = useState(false)
  const [showMnemonic, setShowMnemonic] = useState(false)
  const [loggingIn, setLoggingIn] = useState(false)

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()

    if (password !== confirmPassword) {
      setError('Passwords do not match')
      return
    }

    if (password.length < 8) {
      setError('Password must be at least 8 characters')
      return
    }

    await execute(async () => {
      const result = await register(email, password, name)
      setRecoveryMnemonic(result.recoveryMnemonic)
    })
  }

  const handleCopyRecoveryKey = async () => {
    if (!recoveryMnemonic) return
    try {
      await navigator.clipboard.writeText(recoveryMnemonic)
      setMnemonicConfirmed(true)
    } catch {
      // Clipboard write may fail (permissions, insecure context).
      // User can use the Download button as fallback.
    }
  }

  const handleDownloadRecoveryKey = () => {
    if (!recoveryMnemonic) return

    const content = formatRecoveryKeyFile(recoveryMnemonic)

    const blob = new Blob([content], { type: 'text/plain' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = 'refmd-recovery-key.txt'
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    URL.revokeObjectURL(url)

    setMnemonicConfirmed(true)
  }

  const handleConfirmMnemonic = async () => {
    setLoggingIn(true)
    setError(null)

    // Capture credentials and clear from state to reduce exposure window
    const loginEmail = email
    const loginPassword = password
    setPassword('')
    setConfirmPassword('')

    try {
      const result = await login(loginEmail, loginPassword, false)
      await router.invalidate()

      if (result.type === 'device_required') {
        // Should not happen for fresh registration, but handle gracefully
        navigate({ to: '/auth/login', search: { redirect } })
        return
      }

      if (!result.deviceKeys) {
        clearAuthState()
        navigate({ to: '/auth/login', search: { redirect } })
        return
      }

      setFullSession(
        buildAuthState(result),
        buildDeviceState({ deviceId: result.deviceId, deviceKeys: result.deviceKeys }),
      )

      if (redirect) {
        navigate({ to: redirect })
      } else {
        const workspaceId = localStorage.getItem(WORKSPACE_STORAGE_KEY)
        if (workspaceId) {
          navigate({ to: '/workspace/$workspaceId', params: { workspaceId } })
        } else {
          navigate({ to: '/workspace' })
        }
      }
    } catch {
      // Auto-login failed — fall back to manual login
      navigate({ to: '/auth/login', search: { redirect } })
    }
  }

  // Show recovery mnemonic after successful registration
  if (recoveryMnemonic) {
    const words = recoveryMnemonic.split(' ')

    return (
      <AuthLayout
        title="Recovery Key"
        maxWidth="lg"
        description={<>
          Save this recovery key in a safe place. You will need it for{' '}
          <Link to="/auth/recovery" className="text-primary hover:underline">
            account recovery
          </Link>{' '}
          if you lose access to all your devices.
        </>}
      >
        <div className="space-y-4">
          <div className="p-4 border rounded">
            <div className="flex items-center justify-between mb-3">
              <span className="text-sm text-muted-foreground">24 words</span>
              <Button
                variant="ghost"
                size="sm"
                onClick={() => setShowMnemonic(!showMnemonic)}
              >
                {showMnemonic ? 'Hide' : 'Show'}
              </Button>
            </div>
            <div className="grid grid-cols-3 gap-2 text-sm">
              {words.map((word, index) => (
                <div key={index} className="flex items-center gap-2">
                  <span className="text-muted-foreground w-5 text-right">{index + 1}.</span>
                  <span>{showMnemonic ? word : '••••••'}</span>
                </div>
              ))}
            </div>
          </div>

          <div className="flex gap-2">
            <Button
              onClick={handleCopyRecoveryKey}
              variant="outline"
              className="flex-1"
            >
              Copy
            </Button>
            <Button
              onClick={handleDownloadRecoveryKey}
              variant="outline"
              className="flex-1"
            >
              Download
            </Button>
          </div>

          <ErrorAlert>
            <strong>Warning:</strong> If you lose this recovery key and forget your password, you
            will permanently lose access to your encrypted data.
          </ErrorAlert>

          <Button
            onClick={handleConfirmMnemonic}
            className="w-full"
            disabled={!mnemonicConfirmed || loggingIn}
          >
            {loggingIn ? 'Signing in...' : 'Continue'}
          </Button>
        </div>
      </AuthLayout>
    )
  }

  return (
    <AuthLayout title="Create Account" description="Enter your details to create a new account">
      <form onSubmit={handleSubmit} className="space-y-4">
        {error && (
          <ErrorAlert>{error}</ErrorAlert>
        )}

        <FormField
          id="name"
          label="Name"
          placeholder="John Doe"
          value={name}
          onChange={setName}
          required
          disabled={loading}
          autoComplete="name"
        />

        <EmailField value={email} onChange={setEmail} disabled={loading} />
        <PasswordField value={password} onChange={setPassword} disabled={loading} autoComplete="new-password" />
        <PasswordField id="confirmPassword" label="Confirm Password" value={confirmPassword} onChange={setConfirmPassword} disabled={loading} autoComplete="new-password" />

        <Button type="submit" className="w-full" disabled={loading}>
          {loading ? 'Creating account...' : 'Create Account'}
        </Button>

        <p className="text-center text-sm text-muted-foreground">
          Already have an account?{' '}
          <Link to="/auth/login" search={{ redirect }} className="text-primary hover:underline">
            Sign in
          </Link>
        </p>
      </form>
    </AuthLayout>
  )
}
