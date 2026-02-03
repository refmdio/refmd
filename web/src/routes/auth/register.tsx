import { Link, createFileRoute, useNavigate } from '@tanstack/react-router'
import { useState } from 'react'
import { Button } from '@/shared/ui/button'
import { Input } from '@/shared/ui/input'
import { Label } from '@/shared/ui/label'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/shared/ui/card'
import { register } from '@/features/auth'
import { ApiRequestError } from '@/shared/api'

export const Route = createFileRoute('/auth/register')({
  component: RegisterPage,
})

function RegisterPage() {
  const navigate = useNavigate()
  const [name, setName] = useState('')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)
  const [recoveryMnemonic, setRecoveryMnemonic] = useState<string | null>(null)
  const [mnemonicConfirmed, setMnemonicConfirmed] = useState(false)
  const [showMnemonic, setShowMnemonic] = useState(false)

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError(null)

    if (password !== confirmPassword) {
      setError('Passwords do not match')
      return
    }

    if (password.length < 8) {
      setError('Password must be at least 8 characters')
      return
    }

    setLoading(true)

    try {
      const result = await register(email, password, name)
      setRecoveryMnemonic(result.recoveryMnemonic)
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

  const handleCopyRecoveryKey = async () => {
    if (!recoveryMnemonic) return
    await navigator.clipboard.writeText(recoveryMnemonic)
    setMnemonicConfirmed(true)
  }

  const handleDownloadRecoveryKey = () => {
    if (!recoveryMnemonic) return

    const words = recoveryMnemonic.split(' ')
    const content = [
      'RefMD Recovery Key',
      '==================',
      '',
      'Keep this file in a safe place.',
      'You will need these 24 words to recover your account if you forget your password.',
      '',
      ...words.map((word, i) => `${String(i + 1).padStart(2, ' ')}. ${word}`),
      '',
      'WARNING: If you lose this recovery key and forget your password,',
      'you will permanently lose access to your encrypted data.',
    ].join('\n')

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

  const handleConfirmMnemonic = () => {
    navigate({ to: '/auth/login' })
  }

  // Show recovery mnemonic after successful registration
  if (recoveryMnemonic) {
    const words = recoveryMnemonic.split(' ')

    return (
      <main className="min-h-screen flex items-center justify-center p-4">
        <Card className="w-full max-w-lg">
          <CardHeader className="space-y-1">
            <CardTitle className="text-2xl font-bold">Recovery Key</CardTitle>
            <CardDescription>
              Save this recovery key in a safe place. You will need it to recover your account if
              you forget your password.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
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

            <div className="p-3 text-sm text-destructive bg-destructive/10 border border-destructive/50 rounded">
              <strong>Warning:</strong> If you lose this recovery key and forget your password, you
              will permanently lose access to your encrypted data.
            </div>

            <Button
              onClick={handleConfirmMnemonic}
              className="w-full"
              disabled={!mnemonicConfirmed}
            >
              Continue to Login
            </Button>
          </CardContent>
        </Card>
      </main>
    )
  }

  return (
    <main className="min-h-screen flex items-center justify-center p-4">
      <Card className="w-full max-w-md">
        <CardHeader className="space-y-1">
          <CardTitle className="text-2xl font-bold">Create Account</CardTitle>
          <CardDescription>
            Enter your details to create a new account
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleSubmit} className="space-y-4">
            {error && (
              <div className="p-3 text-sm text-destructive bg-destructive/10 border border-destructive/50 rounded">
                {error}
              </div>
            )}

            <div className="space-y-2">
              <Label htmlFor="name">Name</Label>
              <Input
                id="name"
                type="text"
                placeholder="John Doe"
                value={name}
                onChange={(e) => setName(e.target.value)}
                required
                disabled={loading}
                autoComplete="name"
              />
            </div>

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
                autoComplete="new-password"
              />
            </div>

            <div className="space-y-2">
              <Label htmlFor="confirmPassword">Confirm Password</Label>
              <Input
                id="confirmPassword"
                type="password"
                placeholder="••••••••"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                required
                disabled={loading}
                autoComplete="new-password"
              />
            </div>

            <Button type="submit" className="w-full" disabled={loading}>
              {loading ? 'Creating account...' : 'Create Account'}
            </Button>

            <p className="text-center text-sm text-muted-foreground">
              Already have an account?{' '}
              <Link to="/auth/login" className="text-primary hover:underline">
                Sign in
              </Link>
            </p>
          </form>
        </CardContent>
      </Card>
    </main>
  )
}
