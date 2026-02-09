/**
 * PDK Fallback Password Prompt
 *
 * Shown when DSK (IndexedDB non-exportable key) is unavailable but
 * PDK-wrapped device keys exist in localStorage. The user must re-enter
 * their password to derive PDK and unwrap the device keys.
 */

import { useState } from 'react'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/shared/ui/dialog'
import { Button } from '@/shared/ui/button'
import { Input } from '@/shared/ui/input'
import { Label } from '@/shared/ui/label'
import { Loader2 } from 'lucide-react'

interface PdkFallbackDialogProps {
  open: boolean
  email: string
  onSubmit: (password: string) => Promise<void>
  onCancel: () => void
}

export function PdkFallbackDialog({
  open,
  email,
  onSubmit,
  onCancel,
}: PdkFallbackDialogProps) {
  const [password, setPassword] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError(null)
    setLoading(true)

    try {
      await onSubmit(password)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to restore session')
    } finally {
      setLoading(false)
    }
  }

  return (
    <Dialog open={open} onOpenChange={(isOpen) => !isOpen && onCancel()}>
      <DialogContent className="sm:max-w-md">
        <form onSubmit={handleSubmit}>
          <DialogHeader>
            <DialogTitle>Password Required</DialogTitle>
            <DialogDescription>
              Your device storage key is unavailable. Enter your password to restore access.
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-4 py-4">
            {error && (
              <div className="p-3 text-sm text-destructive bg-destructive/10 border border-destructive/50 rounded">
                {error}
              </div>
            )}

            <div className="space-y-2">
              <Label htmlFor="pdk-email">Email</Label>
              <Input
                id="pdk-email"
                type="email"
                value={email}
                disabled
              />
            </div>

            <div className="space-y-2">
              <Label htmlFor="pdk-password">Password</Label>
              <Input
                id="pdk-password"
                type="password"
                placeholder="Enter your password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
                disabled={loading}
                autoComplete="current-password"
                autoFocus
              />
            </div>
          </div>

          <DialogFooter className="flex-col gap-2 sm:flex-row">
            <Button
              type="button"
              variant="outline"
              onClick={onCancel}
              disabled={loading}
            >
              Cancel
            </Button>
            <Button type="submit" disabled={loading || !password}>
              {loading ? (
                <>
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                  Restoring...
                </>
              ) : (
                'Unlock'
              )}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
