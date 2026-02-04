/**
 * Account Section
 *
 * Account management including logout.
 */

import { useNavigate } from '@tanstack/react-router'
import { Button } from '@/shared/ui/button'
import { useAuthContext } from '@/shared/context/AuthContext'
import { logout } from '@/features/auth'
import { LogOut } from 'lucide-react'

interface AccountSectionProps {
  onClose: () => void
}

export function AccountSection({ onClose }: AccountSectionProps) {
  const { auth, clearAuthState } = useAuthContext()
  const navigate = useNavigate()

  const handleLogout = async () => {
    try {
      await logout()
    } catch {
      // Ignore errors
    } finally {
      clearAuthState()
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
          onClick={handleLogout}
          className="w-full sm:w-auto"
        >
          <LogOut className="h-4 w-4 mr-2" />
          Log out
        </Button>
        <p className="text-xs text-muted-foreground mt-2">
          You will be signed out of this device.
        </p>
      </section>
    </div>
  )
}
