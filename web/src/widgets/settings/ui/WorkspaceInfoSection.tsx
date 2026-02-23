/**
 * Workspace Info Section
 *
 * Workspace name editing and deletion.
 */

import { useState, useEffect } from 'react'
import { Button } from '@/shared/ui/button'
import { Input } from '@/shared/ui/input'

interface WorkspaceInfoSectionProps {
  workspaceName: string | undefined
  canUpdate: boolean
  canDelete: boolean
  canLeave: boolean
  actionError: string | null
  onUpdate: (updates: { name?: string }) => Promise<void>
  onDelete: () => Promise<boolean>
  onDeleteComplete: () => void
  onLeave: () => Promise<boolean>
  onLeaveComplete: () => void
}

export function WorkspaceInfoSection({
  workspaceName,
  canUpdate,
  canDelete,
  canLeave,
  actionError,
  onUpdate,
  onDelete,
  onDeleteComplete,
  onLeave,
  onLeaveComplete,
}: WorkspaceInfoSectionProps) {
  const [editing, setEditing] = useState(false)
  const [name, setName] = useState(workspaceName ?? '')
  const [saving, setSaving] = useState(false)
  const [confirmDelete, setConfirmDelete] = useState(false)
  const [deleting, setDeleting] = useState(false)
  const [deleteError, setDeleteError] = useState<string | null>(null)
  const [confirmLeave, setConfirmLeave] = useState(false)
  const [leaving, setLeaving] = useState(false)
  const [leaveError, setLeaveError] = useState<string | null>(null)

  // Sync local state when the prop changes (e.g. workspace switch while mounted)
  useEffect(() => {
    setName(workspaceName ?? '')
    setEditing(false)
    setSaving(false)
    setConfirmDelete(false)
    setDeleting(false)
    setDeleteError(null)
    setConfirmLeave(false)
    setLeaving(false)
    setLeaveError(null)
  }, [workspaceName])

  const handleSave = async () => {
    if (!name.trim()) return
    setSaving(true)
    try {
      await onUpdate({ name: name.trim() })
      setEditing(false)
    } finally {
      setSaving(false)
    }
  }

  const handleDelete = async () => {
    setDeleting(true)
    setDeleteError(null)
    const success = await onDelete()
    if (success) {
      onDeleteComplete()
    } else {
      setDeleteError('Failed to delete workspace')
      setDeleting(false)
    }
  }

  const handleLeave = async () => {
    setLeaving(true)
    setLeaveError(null)
    const success = await onLeave()
    if (success) {
      onLeaveComplete()
    } else {
      setLeaveError('Failed to leave workspace')
      setLeaving(false)
    }
  }

  return (
    <div className="space-y-3">
      <h4 className="text-sm font-medium">Settings</h4>

      {(actionError || deleteError || leaveError) && (
        <p className="text-sm text-destructive">{actionError || deleteError || leaveError}</p>
      )}

      <div className="py-2 px-3 rounded border border-border/40 bg-muted/20 space-y-3">
        {/* Workspace name */}
        <div className="flex items-center justify-between">
          <div className="flex-1 min-w-0">
            <span className="text-xs text-muted-foreground">Workspace name</span>
            {editing ? (
              <div className="flex items-center gap-2 mt-1">
                <Input
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  className="h-8 text-sm"
                  onKeyDown={(e) => {
                    if (e.key === 'Enter') handleSave()
                    if (e.key === 'Escape') {
                      setEditing(false)
                      setName(workspaceName ?? '')
                    }
                  }}
                  autoFocus
                />
                <Button size="sm" onClick={handleSave} disabled={saving || !name.trim()}>
                  Save
                </Button>
                <Button size="sm" variant="ghost" onClick={() => {
                  setEditing(false)
                  setName(workspaceName ?? '')
                }}>
                  Cancel
                </Button>
              </div>
            ) : (
              <div className="flex items-center gap-2 mt-1">
                <span className="text-sm font-medium">{workspaceName}</span>
                {canUpdate && (
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => {
                      setName(workspaceName ?? '')
                      setEditing(true)
                    }}
                  >
                    Rename
                  </Button>
                )}
              </div>
            )}
          </div>
        </div>

        {/* Leave workspace (non-owners only) */}
        {canLeave && (
          <div className="pt-2 border-t border-border/40">
            {confirmLeave ? (
              <div className="flex items-center gap-2">
                <span className="text-sm text-destructive">Leave this workspace?</span>
                <Button
                  variant="destructive"
                  size="sm"
                  onClick={handleLeave}
                  disabled={leaving}
                >
                  {leaving ? 'Leaving...' : 'Leave'}
                </Button>
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => setConfirmLeave(false)}
                  disabled={leaving}
                >
                  Cancel
                </Button>
              </div>
            ) : (
              <Button
                variant="ghost"
                size="sm"
                onClick={() => setConfirmLeave(true)}
                className="text-destructive hover:text-destructive"
              >
                Leave workspace
              </Button>
            )}
          </div>
        )}

        {/* Delete workspace */}
        {canDelete && (
          <div className="pt-2 border-t border-border/40">
            {confirmDelete ? (
              <div className="flex items-center gap-2">
                <span className="text-sm text-destructive">Delete this workspace permanently?</span>
                <Button
                  variant="destructive"
                  size="sm"
                  onClick={handleDelete}
                  disabled={deleting}
                >
                  {deleting ? 'Deleting...' : 'Delete'}
                </Button>
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => setConfirmDelete(false)}
                  disabled={deleting}
                >
                  Cancel
                </Button>
              </div>
            ) : (
              <Button
                variant="ghost"
                size="sm"
                onClick={() => setConfirmDelete(true)}
                className="text-destructive hover:text-destructive"
              >
                Delete workspace
              </Button>
            )}
          </div>
        )}
      </div>
    </div>
  )
}
