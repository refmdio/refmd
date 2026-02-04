/**
 * Device Registration Page
 *
 * Used when a user logs in on a new device that needs to be registered
 * to receive the UMK (User Master Key) from an existing device.
 */

import { createFileRoute, useNavigate } from '@tanstack/react-router'
import { useState, useEffect } from 'react'
import { Button } from '@/shared/ui/button'
import { Input } from '@/shared/ui/input'
import { Label } from '@/shared/ui/label'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/shared/ui/card'
import { useDevice } from '@/features/device'
import { SasVerification } from '@/features/device/ui/SasVerification'

export const Route = createFileRoute('/auth/device-register')({
  component: DeviceRegisterPage,
})

function DeviceRegisterPage() {
  const navigate = useNavigate()
  const { state, startRegistration, reset } = useDevice()

  const [deviceName, setDeviceName] = useState('')
  const [deviceType, setDeviceType] = useState<'browser' | 'desktop' | 'mobile'>('browser')
  const [sasEmojis, setSasEmojis] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [pollInterval, setPollInterval] = useState<ReturnType<typeof setInterval> | null>(null)

  // Detect device type
  useEffect(() => {
    const userAgent = navigator.userAgent.toLowerCase()
    if (/mobile|android|iphone|ipad/.test(userAgent)) {
      setDeviceType('mobile')
    } else if (/electron/.test(userAgent)) {
      setDeviceType('desktop')
    } else {
      setDeviceType('browser')
    }

    // Set default device name
    const browserName = /chrome/.test(userAgent)
      ? 'Chrome'
      : /firefox/.test(userAgent)
        ? 'Firefox'
        : /safari/.test(userAgent)
          ? 'Safari'
          : /edge/.test(userAgent)
            ? 'Edge'
            : 'Browser'
    setDeviceName(`${browserName} on ${navigator.platform}`)
  }, [])

  // Use SAS emojis from state (calculated client-side during registration)
  useEffect(() => {
    if (state.step === 'waiting-for-approval' && state.sasEmojis && !sasEmojis) {
      setSasEmojis(state.sasEmojis)
    }
  }, [state.step, state.sasEmojis, sasEmojis])

  // Cleanup on unmount
  useEffect(() => {
    return () => {
      if (pollInterval) {
        clearInterval(pollInterval)
      }
    }
  }, [pollInterval])

  const handleStartRegistration = async (e: React.FormEvent) => {
    e.preventDefault()
    setError(null)
    setLoading(true)

    try {
      await startRegistration(deviceName, deviceType)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to start registration')
    } finally {
      setLoading(false)
    }
  }

  const handleCancel = () => {
    reset()
    navigate({ to: '/auth/login' })
  }

  // Show registration form
  if (state.step === 'idle' || state.step === 'generating-keys' || state.step === 'creating-pending') {
    return (
      <main className="min-h-screen flex items-center justify-center p-4">
        <Card className="w-full max-w-md">
          <CardHeader className="space-y-1">
            <CardTitle className="text-2xl font-bold">Register Device</CardTitle>
            <CardDescription>
              Register this device to access your encrypted data
            </CardDescription>
          </CardHeader>
          <CardContent>
            <form onSubmit={handleStartRegistration} className="space-y-4">
              {error && (
                <div className="p-3 text-sm text-destructive bg-destructive/10 border border-destructive/50 rounded">
                  {error}
                </div>
              )}

              <div className="space-y-2">
                <Label htmlFor="deviceName">Device Name</Label>
                <Input
                  id="deviceName"
                  type="text"
                  placeholder="My Browser"
                  value={deviceName}
                  onChange={(e) => setDeviceName(e.target.value)}
                  required
                  disabled={loading}
                />
              </div>

              <div className="space-y-2">
                <Label htmlFor="deviceType">Device Type</Label>
                <select
                  id="deviceType"
                  value={deviceType}
                  onChange={(e) => setDeviceType(e.target.value as 'browser' | 'desktop' | 'mobile')}
                  disabled={loading}
                  className="flex h-10 w-full rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
                >
                  <option value="browser">Browser</option>
                  <option value="desktop">Desktop App</option>
                  <option value="mobile">Mobile App</option>
                </select>
              </div>

              <Button type="submit" className="w-full" disabled={loading}>
                {loading ? 'Registering...' : 'Register Device'}
              </Button>

              <Button
                type="button"
                variant="outline"
                className="w-full"
                onClick={handleCancel}
                disabled={loading}
              >
                Cancel
              </Button>
            </form>
          </CardContent>
        </Card>
      </main>
    )
  }

  // Show SAS verification (waiting for approval)
  if (state.step === 'waiting-for-approval') {
    return (
      <main className="min-h-screen flex items-center justify-center p-4">
        <Card className="w-full max-w-md">
          <CardHeader className="space-y-1">
            <CardTitle className="text-2xl font-bold">Waiting for Approval</CardTitle>
            <CardDescription>
              Verify the emojis on your existing device
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-6">
            {sasEmojis ? (
              <SasVerification emojis={sasEmojis} role="new" />
            ) : (
              <div className="flex justify-center py-8">
                <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary" />
              </div>
            )}

            <div className="text-center text-sm text-muted-foreground">
              <p>Open RefMD on your existing device and approve this device.</p>
              <p className="mt-2">The emojis must match exactly.</p>
            </div>

            <Button
              variant="outline"
              className="w-full"
              onClick={handleCancel}
            >
              Cancel
            </Button>
          </CardContent>
        </Card>
      </main>
    )
  }

  // Show approved state
  if (state.step === 'approved') {
    return (
      <main className="min-h-screen flex items-center justify-center p-4">
        <Card className="w-full max-w-md">
          <CardHeader className="space-y-1">
            <CardTitle className="text-2xl font-bold">Device Approved</CardTitle>
            <CardDescription>
              Your device has been registered successfully
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="flex justify-center py-4">
              <div className="w-16 h-16 rounded-full bg-green-100 dark:bg-green-900 flex items-center justify-center">
                <svg
                  className="w-8 h-8 text-green-600 dark:text-green-400"
                  fill="none"
                  stroke="currentColor"
                  viewBox="0 0 24 24"
                >
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth={2}
                    d="M5 13l4 4L19 7"
                  />
                </svg>
              </div>
            </div>

            <Button
              className="w-full"
              onClick={() => navigate({ to: '/dashboard' })}
            >
              Continue to Dashboard
            </Button>
          </CardContent>
        </Card>
      </main>
    )
  }

  // Show error state
  if (state.step === 'error') {
    return (
      <main className="min-h-screen flex items-center justify-center p-4">
        <Card className="w-full max-w-md">
          <CardHeader className="space-y-1">
            <CardTitle className="text-2xl font-bold text-destructive">Registration Failed</CardTitle>
            <CardDescription>
              An error occurred during device registration
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="p-3 text-sm text-destructive bg-destructive/10 border border-destructive/50 rounded">
              {state.error || 'Unknown error'}
            </div>

            <Button
              className="w-full"
              onClick={reset}
            >
              Try Again
            </Button>

            <Button
              variant="outline"
              className="w-full"
              onClick={handleCancel}
            >
              Back to Login
            </Button>
          </CardContent>
        </Card>
      </main>
    )
  }

  return null
}
