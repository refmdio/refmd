/**
 * Members Section
 *
 * Displays workspace members with role management and removal.
 */

import { useState } from 'react'
import { Button } from '@/shared/ui/button'
import { Spinner } from '@/shared/ui/spinner'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '@/shared/ui/dropdown-menu'
import type { components } from '@/shared/api'

type MemberDetail = components['schemas']['MemberDetailResponse']
type RoleDetail = components['schemas']['RoleDetailResponse']

interface MembersSectionProps {
  members: MemberDetail[]
  roles: RoleDetail[]
  currentUserId: string | null
  loading: boolean
  error: Error | null
  actionError: string | null
  canChangeRoles: boolean
  canRemoveMembers: boolean
  onChangeRole: (userId: string, roleId: string) => Promise<void>
  onRemove: (userId: string) => Promise<void>
}

export function MembersSection({
  members,
  roles,
  currentUserId,
  loading,
  error,
  actionError,
  canChangeRoles,
  canRemoveMembers,
  onChangeRole,
  onRemove,
}: MembersSectionProps) {
  const [confirmRemoveId, setConfirmRemoveId] = useState<string | null>(null)

  if (loading) {
    return (
      <div className="flex items-center gap-2 py-4">
        <Spinner size="sm" />
        <span className="text-sm text-muted-foreground">Loading members...</span>
      </div>
    )
  }

  if (error) {
    return (
      <p className="text-sm text-destructive">Failed to load members: {error.message}</p>
    )
  }

  return (
    <div className="space-y-3">
      <h4 className="text-sm font-medium">Members ({members.length})</h4>

      {actionError && (
        <p className="text-sm text-destructive">{actionError}</p>
      )}

      <div className="space-y-2">
        {members.map((member) => {
          const isSelf = member.user_id === currentUserId

          return (
            <div
              key={member.user_id}
              className="flex items-center justify-between py-2 px-3 rounded border border-border/40 bg-muted/20"
            >
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2">
                  <span className="text-sm font-medium truncate">{member.name}</span>
                  {isSelf && (
                    <span className="text-xs text-muted-foreground">(you)</span>
                  )}
                </div>
                <div className="text-xs text-muted-foreground truncate">{member.email}</div>
                <div className="flex items-center gap-2 mt-0.5">
                  <span className="text-xs px-1.5 py-0.5 rounded bg-muted font-medium">
                    {member.base_role}
                  </span>
                  <span className="text-xs text-muted-foreground">{member.role_name}</span>
                </div>
              </div>

              {(canChangeRoles || canRemoveMembers) && (
                <div className="flex items-center gap-2 shrink-0 ml-3">
                  {/* Role change dropdown */}
                  {canChangeRoles && (
                    <DropdownMenu>
                      <DropdownMenuTrigger asChild>
                        <Button variant="ghost" size="sm" disabled={isSelf}>
                          Role
                        </Button>
                      </DropdownMenuTrigger>
                      <DropdownMenuContent align="end">
                        {roles.filter((role) => role.base_role !== 'owner').map((role) => (
                          <DropdownMenuItem
                            key={role.id}
                            onClick={() => onChangeRole(member.user_id, role.id)}
                            disabled={role.id === member.role_id}
                          >
                            {role.name}
                            <span className="ml-2 text-xs text-muted-foreground">({role.base_role})</span>
                          </DropdownMenuItem>
                        ))}
                      </DropdownMenuContent>
                    </DropdownMenu>
                  )}

                  {/* Remove button */}
                  {canRemoveMembers && (
                    confirmRemoveId === member.user_id ? (
                      <div className="flex items-center gap-1">
                        <Button
                          variant="destructive"
                          size="sm"
                          onClick={() => {
                            setConfirmRemoveId(null)
                            onRemove(member.user_id)
                          }}
                        >
                          Confirm
                        </Button>
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => setConfirmRemoveId(null)}
                        >
                          Cancel
                        </Button>
                      </div>
                    ) : (
                      <Button
                        variant="ghost"
                        size="sm"
                        disabled={isSelf}
                        onClick={() => setConfirmRemoveId(member.user_id)}
                        className="text-destructive hover:text-destructive"
                      >
                        Remove
                      </Button>
                    )
                  )}
                </div>
              )}
            </div>
          )
        })}
      </div>
    </div>
  )
}
