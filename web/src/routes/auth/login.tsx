import { Link, createFileRoute, useNavigate, useRouter } from '@tanstack/react-router'
import { useState } from 'react'
import { Button } from '@/shared/ui/button'
import { Checkbox } from '@/shared/ui/checkbox'
import { Label } from '@/shared/ui/label'
import { AuthLayout } from './-components/AuthLayout'
import { EmailField, PasswordField } from './-components/AuthFields'
import { login } from '@/features/auth'
import { getApiErrorMessage } from '@/shared/api'
import { ErrorAlert } from '@/shared/ui/error-alert'
import { useAuthContext } from '@/shared/context'
import { useAsyncAction } from '@/shared/hooks'
import { buildAuthState, buildDeviceState } from '@/shared/model/session-hydration'

export const Route = createFileRoute('/auth/login')({
  component: LoginPage,
})

function LoginPage() {
  const navigate = useNavigate()
  const router = useRouter()
  const { setAuthState, setFullSession, clearAuthState } = useAuthContext()
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [rememberMe, setRememberMe] = useState(false)
  const { error, setError, loading, execute } = useAsyncAction(getApiErrorMessage)

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()

    await execute(async () => {
      const result = await login(email, password, rememberMe)
      await router.invalidate()

      // Handle based on login result type
      if (result.type === 'device_required') {
        // New/unverified device - needs to go through PendingDevice flow
        // Session is created but no keys were returned
        // Set partial auth state so device-register can access userId
        setAuthState({
          userId: result.userId,
          email: result.email,
          expiresAt: result.expiresAt,
          umk: null,
          identityKeys: null,
        })
        navigate({ to: '/auth/device-register' })
        return
      }

      // Device verified - we have UMK and identity keys
      if (!result.deviceKeys) {
        clearAuthState()
        setError('Device keys not found. Please use account recovery to restore access.')
        return
      }

      // Set full session (auth + device) atomically
      setFullSession(
        buildAuthState(result),
        buildDeviceState({ deviceId: result.deviceId, deviceKeys: result.deviceKeys }),
      )

      navigate({ to: '/dashboard' })
    })
  }

  return (
    <AuthLayout title="Login" description="Enter your credentials to access your account">
      <form onSubmit={handleSubmit} className="space-y-4">
        {error && (
          <ErrorAlert>{error}</ErrorAlert>
        )}

        <EmailField value={email} onChange={setEmail} disabled={loading} />
        <PasswordField value={password} onChange={setPassword} disabled={loading} />

        <div className="flex items-center space-x-2">
          <Checkbox
            id="remember"
            checked={rememberMe}
            onCheckedChange={(checked) => setRememberMe(checked === true)}
            disabled={loading}
          />
          <Label htmlFor="remember" className="text-xs font-sans normal-case tracking-normal">
            Keep me signed in
          </Label>
        </div>

        <Button type="submit" className="w-full" disabled={loading}>
          {loading ? 'Signing in...' : 'Sign In'}
        </Button>

        <p className="text-center text-sm text-muted-foreground">
          Don't have an account?{' '}
          <Link to="/auth/register" className="text-primary hover:underline">
            Register
          </Link>
        </p>

        <p className="text-center text-sm text-muted-foreground">
          <Link to="/auth/recovery" className="text-primary hover:underline">
            Lost access to your device?
          </Link>
        </p>
      </form>
    </AuthLayout>
  )
}
