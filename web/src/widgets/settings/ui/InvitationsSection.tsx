/**
 * Invitations Section
 *
 * Active invitations list with revoke actions and create button.
 */

import { Button } from '@/shared/ui/button'
import { Spinner } from '@/shared/ui/spinner'
import type { components } from '@/shared/api'

type InvitationDetail = components['schemas']['InvitationListItem']

interface InvitationsSectionProps {
  invitations: InvitationDetail[]
  loading: boolean
  error: Error | null
  actionError: string | null
  onRevoke: (invitationId: string) => Promise<void>
  onCreateClick: () => void
}

export function InvitationsSection({
  invitations,
  loading,
  error,
  actionError,
  onRevoke,
  onCreateClick,
}: InvitationsSectionProps) {
  if (loading) {
    return (
      <div className="flex items-center gap-2 py-4">
        <Spinner size="sm" />
        <span className="text-sm text-muted-foreground">Loading invitations...</span>
      </div>
    )
  }

  if (error) {
    return (
      <p className="text-sm text-destructive">Failed to load invitations: {error.message}</p>
    )
  }

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <h4 className="text-sm font-medium">Invitations ({invitations.length})</h4>
        <Button variant="outline" size="sm" onClick={onCreateClick}>
          Create invite link
        </Button>
      </div>

      {actionError && (
        <p className="text-sm text-destructive">{actionError}</p>
      )}

      {invitations.length === 0 ? (
        <p className="text-sm text-muted-foreground py-2">No active invitations.</p>
      ) : (
        <div className="space-y-2">
          {invitations.map((inv) => {
            const expiresAt = new Date(inv.expires_at)
            const isExpiringSoon = expiresAt.getTime() - Date.now() < 24 * 60 * 60 * 1000

            return (
              <div
                key={inv.invitation_id}
                className="flex items-center justify-between py-2 px-3 rounded border border-border/40 bg-muted/20"
              >
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2">
                    <span className="text-sm truncate">{inv.invited_email}</span>
                    <span className="text-xs font-mono text-muted-foreground">{inv.token_prefix}...</span>
                  </div>
                  <div className="flex items-center gap-3 mt-0.5 text-xs text-muted-foreground">
                    <span className={isExpiringSoon ? 'text-amber-500' : ''}>
                      Expires: {expiresAt.toLocaleDateString()}
                    </span>
                    {inv.role_name && (
                      <span>Role: {inv.role_name}</span>
                    )}
                  </div>
                </div>

                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => onRevoke(inv.invitation_id)}
                  className="text-destructive hover:text-destructive shrink-0 ml-3"
                >
                  Revoke
                </Button>
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}
