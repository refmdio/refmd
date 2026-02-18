/**
 * Account Section
 *
 * Account management including logout.
 */

import { useState } from 'react'
import { useNavigate } from '@tanstack/react-router'
import { Button } from '@/shared/ui/button'
import { Checkbox } from '@/shared/ui/checkbox'
import { Label } from '@/shared/ui/label'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/shared/ui/dialog'
import { useAuthContext } from '@/shared/context'
import { logout, secureLogout } from '@/features/auth'
import { LogOut } from 'lucide-react'

interface AccountSectionProps {
  onClose: () => void
}

export function AccountSection({ onClose }: AccountSectionProps) {
  const { auth, clearAuthState } = useAuthContext()
  const navigate = useNavigate()
  const [showLogoutDialog, setShowLogoutDialog] = useState(false)
  const [keepCredentials, setKeepCredentials] = useState(true)
  const [isLoggingOut, setIsLoggingOut] = useState(false)

  const handleLogout = async () => {
    setIsLoggingOut(true)
    try {
      if (keepCredentials) {
        await logout()
      } else {
        await secureLogout()
      }
    } catch {
      // Ignore errors
    } finally {
      clearAuthState()
      setShowLogoutDialog(false)
      onClose()
      navigate({ to: '/auth/login' })
    }
  }

  return (
    <div className="p-6 space-y-6">
      <div>
        <h3 className="text-lg font-semibold mb-1">Account</h3>
        <p className="text-sm text-muted-foreground">
          Manage your account settings.
        </p>
      </div>

      {/* User Info */}
      {auth && (
        <section>
          <h4 className="text-sm font-medium mb-3">Profile</h4>
          <div className="p-4 rounded border border-border/60 bg-card space-y-2">
            <div>
              <p className="text-xs text-muted-foreground">Email</p>
              <p className="text-sm font-medium">{auth.email}</p>
            </div>
            <div>
              <p className="text-xs text-muted-foreground">User ID</p>
              <p className="text-sm font-mono text-muted-foreground">{auth.userId}</p>
            </div>
          </div>
        </section>
      )}

      {/* Logout */}
      <section className="pt-4 border-t border-border/60">
        <h4 className="text-sm font-medium mb-3">Session</h4>
        <Button
          variant="destructive"
          onClick={() => setShowLogoutDialog(true)}
          className="w-full sm:w-auto"
        >
          <LogOut className="h-4 w-4 mr-2" />
          Log out
        </Button>
        <p className="text-xs text-muted-foreground mt-2">
          You will be signed out of this device.
        </p>
      </section>

      {/* Logout Confirmation Dialog */}
      <Dialog open={showLogoutDialog} onOpenChange={setShowLogoutDialog}>
        <DialogContent className="max-w-sm">
          <DialogHeader>
            <DialogTitle>Log out</DialogTitle>
            <DialogDescription className="sr-only">
              Logout confirmation dialog
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-4">
            <div className="flex items-start gap-3">
              <Checkbox
                id="keep-credentials"
                checked={keepCredentials}
                onCheckedChange={(checked) => setKeepCredentials(checked === true)}
                disabled={isLoggingOut}
              />
              <div className="space-y-1">
                <Label
                  htmlFor="keep-credentials"
                  className="text-sm font-medium cursor-pointer"
                >
                  Keep credentials on this device
                </Label>
                <p className="text-xs text-muted-foreground">
                  If unchecked, you will need to enter your password next time you log in.
                </p>
              </div>
            </div>
          </div>

          <DialogFooter>
            <Button
              variant="outline"
              onClick={() => setShowLogoutDialog(false)}
              disabled={isLoggingOut}
            >
              Cancel
            </Button>
            <Button
              variant="destructive"
              onClick={handleLogout}
              disabled={isLoggingOut}
            >
              {isLoggingOut ? 'Logging out...' : 'Log out'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}
