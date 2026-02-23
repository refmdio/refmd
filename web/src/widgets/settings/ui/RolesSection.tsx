/**
 * Roles Section
 *
 * Displays workspace roles with create, rename, default change, delete,
 * and permission override editing.
 */

import { useState, useMemo, useCallback, useEffect } from 'react'
import { Button } from '@/shared/ui/button'
import { Input } from '@/shared/ui/input'
import { Spinner } from '@/shared/ui/spinner'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '@/shared/ui/dropdown-menu'
import type { components } from '@/shared/api'
import {
  ALL_PERMISSIONS,
  PERMISSION_LABELS,
  CEILING,
  isAtOrAbove,
  defaultGrant,
} from '@/entities/workspace'
import type { BaseRole } from '@/entities/workspace'

type RoleDetail = components['schemas']['RoleDetailResponse']

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

interface RolesSectionProps {
  roles: RoleDetail[]
  loading: boolean
  error: Error | null
  actionError: string | null
  isOwner: boolean
  onCreateRole: (name: string, baseRole: string, isDefault: boolean) => Promise<void>
  onUpdateRole: (roleId: string, updates: { name?: string; is_default?: boolean; permission_overrides?: Array<{ permission: string; granted: boolean }> }) => Promise<void>
  onDeleteRole: (roleId: string) => Promise<void>
}

export function RolesSection({
  roles,
  loading,
  error,
  actionError,
  isOwner,
  onCreateRole,
  onUpdateRole,
  onDeleteRole,
}: RolesSectionProps) {
  const [showCreate, setShowCreate] = useState(false)
  const [newRoleName, setNewRoleName] = useState('')
  const [newBaseRole, setNewBaseRole] = useState('editor')
  const [creating, setCreating] = useState(false)
  const [confirmDeleteId, setConfirmDeleteId] = useState<string | null>(null)
  const [editingId, setEditingId] = useState<string | null>(null)
  const [editName, setEditName] = useState('')
  const [permEditingId, setPermEditingId] = useState<string | null>(null)

  if (loading) {
    return (
      <div className="flex items-center gap-2 py-4">
        <Spinner size="sm" />
        <span className="text-sm text-muted-foreground">Loading roles...</span>
      </div>
    )
  }

  if (error) {
    return (
      <p className="text-sm text-destructive">Failed to load roles: {error.message}</p>
    )
  }

  const handleCreate = async () => {
    if (!newRoleName.trim()) return
    setCreating(true)
    try {
      await onCreateRole(newRoleName.trim(), newBaseRole, false)
      setNewRoleName('')
      setNewBaseRole('editor')
      setShowCreate(false)
    } finally {
      setCreating(false)
    }
  }

  const handleRename = async (roleId: string) => {
    if (!editName.trim()) return
    await onUpdateRole(roleId, { name: editName.trim() })
    setEditingId(null)
    setEditName('')
  }

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <h4 className="text-sm font-medium">Roles ({roles.length})</h4>
        <Button variant="outline" size="sm" onClick={() => setShowCreate(!showCreate)}>
          {showCreate ? 'Cancel' : 'Create role'}
        </Button>
      </div>

      {actionError && (
        <p className="text-sm text-destructive">{actionError}</p>
      )}

      {showCreate && (
        <div className="flex items-end gap-2 py-2 px-3 rounded border border-border/40 bg-muted/20">
          <div className="flex-1 space-y-1">
            <span className="text-xs text-muted-foreground">Name</span>
            <Input
              value={newRoleName}
              onChange={(e) => setNewRoleName(e.target.value)}
              placeholder="Custom role name"
              className="h-8 text-sm"
            />
          </div>
          <div className="space-y-1">
            <span className="text-xs text-muted-foreground">Base role</span>
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button variant="outline" size="sm" className="min-w-[80px]">
                  {newBaseRole}
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent>
                {['admin', 'editor', 'viewer'].map((br) => (
                  <DropdownMenuItem key={br} onClick={() => setNewBaseRole(br)}>
                    {br}
                  </DropdownMenuItem>
                ))}
              </DropdownMenuContent>
            </DropdownMenu>
          </div>
          <Button size="sm" onClick={handleCreate} disabled={creating || !newRoleName.trim()}>
            {creating ? <Spinner size="sm" /> : 'Add'}
          </Button>
        </div>
      )}

      <div className="space-y-2">
        {roles.map((role) => {
          const isEditing = editingId === role.id
          const isPermEditing = permEditingId === role.id

          return (
            <div
              key={role.id}
              className="py-2 px-3 rounded border border-border/40 bg-muted/20"
            >
              <div className="flex items-center justify-between">
                <div className="flex-1 min-w-0">
                  {isEditing ? (
                    <div className="flex items-center gap-2">
                      <Input
                        value={editName}
                        onChange={(e) => setEditName(e.target.value)}
                        className="h-7 text-sm w-40"
                        onKeyDown={(e) => {
                          if (e.key === 'Enter') handleRename(role.id)
                          if (e.key === 'Escape') setEditingId(null)
                        }}
                        autoFocus
                      />
                      <Button size="sm" variant="ghost" onClick={() => handleRename(role.id)}>
                        Save
                      </Button>
                      <Button size="sm" variant="ghost" onClick={() => setEditingId(null)}>
                        Cancel
                      </Button>
                    </div>
                  ) : (
                    <div className="flex items-center gap-2">
                      <span className="text-sm font-medium">{role.name}</span>
                      <span className="text-xs px-1.5 py-0.5 rounded bg-muted">
                        {role.base_role}
                      </span>
                      {role.is_default && (
                        <span className="text-xs px-1.5 py-0.5 rounded bg-primary/10 text-primary">
                          default
                        </span>
                      )}
                    </div>
                  )}
                </div>

                {!isEditing && (
                  <div className="flex items-center gap-1 shrink-0 ml-3">
                    {/* Rename */}
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => {
                        setEditingId(role.id)
                        setEditName(role.name)
                      }}
                    >
                      Rename
                    </Button>

                    {/* Edit permissions (not for owner base_role) */}
                    {role.base_role !== 'owner' && (
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => setPermEditingId(isPermEditing ? null : role.id)}
                      >
                        {isPermEditing ? 'Close' : 'Permissions'}
                      </Button>
                    )}

                    {/* Set as default (owner only) */}
                    {isOwner && !role.is_default && (
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => onUpdateRole(role.id, { is_default: true })}
                      >
                        Set default
                      </Button>
                    )}

                    {/* Delete */}
                    {role.base_role !== 'owner' && !role.is_default && (
                      confirmDeleteId === role.id ? (
                        <div className="flex items-center gap-1">
                          <Button
                            variant="destructive"
                            size="sm"
                            onClick={() => {
                              setConfirmDeleteId(null)
                              onDeleteRole(role.id)
                            }}
                          >
                            Confirm
                          </Button>
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => setConfirmDeleteId(null)}
                          >
                            Cancel
                          </Button>
                        </div>
                      ) : (
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => setConfirmDeleteId(role.id)}
                          className="text-destructive hover:text-destructive"
                        >
                          Delete
                        </Button>
                      )
                    )}
                  </div>
                )}
              </div>

              {/* Permission overrides editor */}
              {isPermEditing && (
                <PermissionEditor
                  role={role}
                  onSave={async (overrides) => {
                    await onUpdateRole(role.id, { permission_overrides: overrides })
                    setPermEditingId(null)
                  }}
                  onCancel={() => setPermEditingId(null)}
                />
              )}
            </div>
          )
        })}
      </div>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Permission editor sub-component
// ---------------------------------------------------------------------------

interface PermissionEditorProps {
  role: RoleDetail
  onSave: (overrides: Array<{ permission: string; granted: boolean }>) => Promise<void>
  onCancel: () => void
}

function PermissionEditor({ role, onSave, onCancel }: PermissionEditorProps) {
  const baseRole = role.base_role as BaseRole
  const [saving, setSaving] = useState(false)

  // Build initial permission state from defaults + existing overrides
  const initialState = useMemo(() => {
    const state: Record<string, boolean> = {}
    const overrideMap = new Map(
      (role.permission_overrides ?? []).map((o) => [o.permission, o.granted])
    )
    for (const perm of ALL_PERMISSIONS) {
      const withinCeiling = isAtOrAbove(baseRole, CEILING[perm])
      if (withinCeiling) {
        // If there's a DB override, use it; otherwise use default
        state[perm] = overrideMap.has(perm) ? overrideMap.get(perm)! : defaultGrant(baseRole, perm)
      }
    }
    return state
  }, [role, baseRole])

  const [permState, setPermState] = useState<Record<string, boolean>>(initialState)

  // Re-sync local state when role props change (e.g. after server refresh)
  useEffect(() => {
    setPermState(initialState)
  }, [initialState])

  const toggle = useCallback((perm: string) => {
    setPermState((prev) => ({ ...prev, [perm]: !prev[perm] }))
  }, [])

  // Compute overrides = only diffs from the default grant
  const computeOverrides = useCallback(() => {
    const overrides: Array<{ permission: string; granted: boolean }> = []
    for (const perm of ALL_PERMISSIONS) {
      if (!(perm in permState)) continue
      const def = defaultGrant(baseRole, perm)
      if (permState[perm] !== def) {
        overrides.push({ permission: perm, granted: permState[perm] })
      }
    }
    return overrides
  }, [permState, baseRole])

  const handleSave = async () => {
    setSaving(true)
    try {
      await onSave(computeOverrides())
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="mt-3 pt-3 border-t border-border/30 space-y-2">
      <span className="text-xs font-medium text-muted-foreground">
        Permissions (within {baseRole} ceiling)
      </span>
      <div className="grid grid-cols-2 gap-1">
        {ALL_PERMISSIONS.map((perm) => {
          const withinCeiling = isAtOrAbove(baseRole, CEILING[perm])
          if (!withinCeiling) return null

          const checked = permState[perm] ?? false
          const isDefault = defaultGrant(baseRole, perm)
          const isOverridden = checked !== isDefault

          return (
            <label
              key={perm}
              className="flex items-center gap-2 py-1 px-2 rounded hover:bg-muted/40 cursor-pointer text-sm"
            >
              <input
                type="checkbox"
                checked={checked}
                onChange={() => toggle(perm)}
                className="rounded border-border"
              />
              <span className={isOverridden ? 'font-medium' : ''}>
                {PERMISSION_LABELS[perm]}
              </span>
              {isOverridden && (
                <span className="text-xs text-amber-500">
                  (override)
                </span>
              )}
            </label>
          )
        })}
      </div>
      <div className="flex items-center gap-2 pt-1">
        <Button size="sm" onClick={handleSave} disabled={saving}>
          {saving ? <Spinner size="sm" /> : 'Save permissions'}
        </Button>
        <Button size="sm" variant="ghost" onClick={onCancel}>
          Cancel
        </Button>
      </div>
    </div>
  )
}
