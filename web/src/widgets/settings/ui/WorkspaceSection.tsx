/**
 * Workspace Section
 *
 * Workspace settings, members, roles, and invitations management.
 */

import { useState } from 'react'
import { useNavigate } from '@tanstack/react-router'
import { useWorkspaceSection } from '../model/useWorkspaceSection'
import { WorkspaceInfoSection } from './WorkspaceInfoSection'
import { MembersSection } from './MembersSection'
import { RolesSection } from './RolesSection'
import { InvitationsSection } from './InvitationsSection'
import { InviteDialog } from './InviteDialog'
import { CreateWorkspaceDialog } from '@/features/workspace-create'
import { useWorkspaceSelection } from '@/entities/workspace'
import { Button } from '@/shared/ui/button'

interface WorkspaceSectionProps {
  onClose: () => void
}

export function WorkspaceSection({ onClose }: WorkspaceSectionProps) {
  const navigate = useNavigate()
  const { setCurrentWorkspaceId } = useWorkspaceSelection()
  const {
    workspaceId,
    workspaceName,
    currentUserId,
    isOwner,
    permissions,
    members,
    roles,
    invitations,
    actions,
    refresh,
  } = useWorkspaceSection()

  const [inviteDialogOpen, setInviteDialogOpen] = useState(false)
  const [createWorkspaceOpen, setCreateWorkspaceOpen] = useState(false)

  const handleDeleteComplete = () => {
    setCurrentWorkspaceId(null)
    onClose()
    navigate({ to: '/workspace' })
  }

  const handleLeaveComplete = () => {
    setCurrentWorkspaceId(null)
    onClose()
    navigate({ to: '/workspace' })
  }

  if (!workspaceId) {
    return (
      <div className="p-6">
        <p className="text-sm text-muted-foreground">No workspace selected.</p>
      </div>
    )
  }

  return (
    <div className="p-6 space-y-6">
      <div>
        <h3 className="text-lg font-semibold mb-1">Workspace</h3>
        <p className="text-sm text-muted-foreground">
          Manage workspace settings, members, roles, and invitations.
        </p>
      </div>

      <WorkspaceInfoSection
        workspaceName={workspaceName}
        canUpdate={permissions.canUpdateWorkspace}
        canDelete={permissions.canDeleteWorkspace}
        canLeave={!isOwner || (members.data?.members ?? []).filter(m => m.base_role === 'owner').length > 1}
        actionError={actions.workspaceActionError}
        onUpdate={actions.updateWorkspace}
        onDelete={actions.deleteWorkspace}
        onDeleteComplete={handleDeleteComplete}
        onLeave={actions.leaveWorkspace}
        onLeaveComplete={handleLeaveComplete}
      />

      <div className="border-t border-border/40" />

      <MembersSection
        members={members.data?.members ?? []}
        roles={roles.data?.roles ?? []}
        currentUserId={currentUserId}
        loading={members.isLoading}
        error={members.error}
        actionError={actions.changeMemberRoleError || actions.removeMemberError}
        canChangeRoles={permissions.canChangeRoles}
        canRemoveMembers={permissions.canRemoveMembers}
        onChangeRole={actions.changeMemberRole}
        onRemove={actions.removeMember}
      />

      {permissions.canManageRoles && (
        <>
          <div className="border-t border-border/40" />

          <RolesSection
            roles={roles.data?.roles ?? []}
            loading={roles.isLoading}
            error={roles.error}
            actionError={actions.roleActionError}
            isOwner={isOwner}
            onCreateRole={actions.createRole}
            onUpdateRole={actions.updateRole}
            onDeleteRole={actions.deleteRole}
          />
        </>
      )}

      {permissions.canInvite && (
        <>
          <div className="border-t border-border/40" />

          <InvitationsSection
            invitations={invitations.data?.invitations ?? []}
            loading={invitations.isLoading}
            error={invitations.error}
            actionError={actions.revokeInvitationError}
            onRevoke={actions.revokeInvitation}
            onCreateClick={() => setInviteDialogOpen(true)}
          />

          <InviteDialog
            open={inviteDialogOpen}
            onOpenChange={setInviteDialogOpen}
            workspaceId={workspaceId}
            roles={roles.data?.roles ?? []}
            onSuccess={refresh}
          />
        </>
      )}

      <div className="border-t border-border/40" />

      <div>
        <h4 className="text-sm font-medium mb-2">Create workspace</h4>
        <p className="text-sm text-muted-foreground mb-3">
          Create a new workspace to organize documents separately.
        </p>
        <Button variant="outline" size="sm" onClick={() => setCreateWorkspaceOpen(true)}>
          Create workspace
        </Button>
      </div>

      <CreateWorkspaceDialog
        open={createWorkspaceOpen}
        onOpenChange={setCreateWorkspaceOpen}
      />
    </div>
  )
}
