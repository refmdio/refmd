import { Link, createFileRoute, useNavigate, useRouter } from '@tanstack/react-router'
import { useState } from 'react'
import { Button } from '@/shared/ui/button'
import { Input } from '@/shared/ui/input'
import { Label } from '@/shared/ui/label'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/shared/ui/card'
import { login } from '@/features/auth'
import { ApiRequestError } from '@/shared/api'
import { useAuthContext } from '@/shared/context/AuthContext'
import { loadDsk, loadAndUnwrapDeviceKeys } from '@/shared/lib/crypto'

type LoginSearch = {
  deviceApproved?: boolean
}

export const Route = createFileRoute('/auth/login')({
  component: LoginPage,
  validateSearch: (search: Record<string, unknown>): LoginSearch => ({
    deviceApproved: search.deviceApproved === true || search.deviceApproved === 'true',
  }),
})

function LoginPage() {
  const navigate = useNavigate()
  const router = useRouter()
  const { deviceApproved } = Route.useSearch()
  const { setAuthState, setDeviceState } = useAuthContext()
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [rememberMe, setRememberMe] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError(null)
    setLoading(true)

    try {
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
      setAuthState({
        userId: result.userId,
        email: result.email,
        expiresAt: result.expiresAt,
        umk: result.umk,
        identityKeys: result.identityKeys,
      })

      // Load device keys for PoP authentication
      const dsk = await loadDsk()
      if (dsk) {
        const deviceKeysData = await loadAndUnwrapDeviceKeys(dsk)
        if (deviceKeysData && deviceKeysData.userId === result.userId) {
          setDeviceState({
            deviceId: result.deviceId,
            deviceKeys: {
              ecdhPrivateKey: deviceKeysData.ecdhPrivateKey,
              ecdhPublicKey: deviceKeysData.ecdhPublicKey,
              signingPrivateKey: deviceKeysData.signingPrivateKey,
              signingPublicKey: deviceKeysData.signingPublicKey,
            },
          })
        }
      }

      navigate({ to: '/dashboard' })
    } catch (err) {
      if (err instanceof ApiRequestError) {
        setError(err.message)
      } else {
        setError('An unexpected error occurred')
      }
    } finally {
      setLoading(false)
    }
  }

  return (
    <main className="min-h-screen flex items-center justify-center p-4">
      <Card className="w-full max-w-md">
        <CardHeader className="space-y-1">
          <CardTitle className="text-2xl font-bold">Login</CardTitle>
          <CardDescription>
            Enter your credentials to access your account
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleSubmit} className="space-y-4">
            {deviceApproved && (
              <div className="p-3 text-sm text-green-700 bg-green-100 border border-green-200 rounded dark:text-green-400 dark:bg-green-900/30 dark:border-green-800">
                Device approved successfully. Please log in to complete setup.
              </div>
            )}
            {error && (
              <div className="p-3 text-sm text-destructive bg-destructive/10 border border-destructive/50 rounded">
                {error}
              </div>
            )}

            <div className="space-y-2">
              <Label htmlFor="email">Email</Label>
              <Input
                id="email"
                type="email"
                placeholder="you@example.com"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required
                disabled={loading}
                autoComplete="email"
              />
            </div>

            <div className="space-y-2">
              <Label htmlFor="password">Password</Label>
              <Input
                id="password"
                type="password"
                placeholder="••••••••"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
                disabled={loading}
                autoComplete="current-password"
              />
            </div>

            <div className="flex items-center space-x-2">
              <input
                id="remember"
                type="checkbox"
                checked={rememberMe}
                onChange={(e) => setRememberMe(e.target.checked)}
                disabled={loading}
                className="h-4 w-4 rounded border-input bg-background"
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
          </form>
        </CardContent>
      </Card>
    </main>
  )
}
