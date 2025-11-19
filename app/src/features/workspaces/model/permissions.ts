import type {
  PermissionOverridePayload,
  WorkspaceRoleResponse,
} from '@/entities/workspace/api'

export type BaseRole = 'viewer' | 'editor' | 'admin'
export type SystemRole = BaseRole | 'owner'
export type InviteRoleValue = `system:${SystemRole}` | `custom:${string}`

export const PERMISSION_GROUPS = [
  {
    title: 'Documents & Folders',
    permissions: [
      { id: 'doc:view', label: 'View documents' },
      { id: 'doc:edit', label: 'Edit documents' },
      { id: 'doc:create', label: 'Create documents' },
      { id: 'doc:archive', label: 'Archive documents' },
      { id: 'doc:delete', label: 'Delete documents' },
      { id: 'doc:move', label: 'Move documents' },
      { id: 'folder:create', label: 'Create folders' },
      { id: 'folder:delete', label: 'Delete folders' },
    ],
  },
  {
    title: 'Files & Attachments',
    permissions: [
      { id: 'file:upload', label: 'Upload files' },
      { id: 'file:delete', label: 'Delete files' },
    ],
  },
  {
    title: 'Sharing & Publishing',
    permissions: [
      { id: 'share:create', label: 'Create share links' },
      { id: 'share:delete', label: 'Delete share links' },
      { id: 'public:publish', label: 'Publish publicly' },
      { id: 'public:unpublish', label: 'Unpublish' },
    ],
  },
  {
    title: 'Members & Workspaces',
    permissions: [
      { id: 'member:view', label: 'View members' },
      { id: 'member:invite', label: 'Invite members' },
      { id: 'member:update_role', label: 'Manage roles' },
      { id: 'member:remove', label: 'Remove members' },
      { id: 'workspace:update_settings', label: 'Update workspace settings' },
      { id: 'workspace:delete', label: 'Delete workspace' },
    ],
  },
  {
    title: 'Integrations',
    permissions: [
      { id: 'plugin:install', label: 'Install plugins' },
      { id: 'plugin:uninstall', label: 'Uninstall plugins' },
      { id: 'plugin:run', label: 'Run plugins' },
      { id: 'git:init', label: 'Initialize Git' },
      { id: 'git:sync', label: 'Sync with Git' },
      { id: 'git:configure', label: 'Configure Git' },
    ],
  },
  {
    title: 'Automation & API',
    permissions: [
      { id: 'shortcut:update', label: 'Manage shortcuts' },
      { id: 'api_token:manage', label: 'Manage API tokens' },
    ],
  },
] as const

export const ALL_PERMISSIONS = PERMISSION_GROUPS.flatMap((group) =>
  group.permissions.map((item) => item.id),
)

const SYSTEM_ROLE_DEFAULTS: Record<SystemRole, string[]> = {
  owner: ALL_PERMISSIONS,
  admin: ALL_PERMISSIONS.filter((perm) => perm !== 'workspace:delete'),
  editor: [
    'doc:view',
    'doc:edit',
    'doc:create',
    'doc:archive',
    'doc:delete',
    'doc:move',
    'folder:create',
    'folder:delete',
    'file:upload',
    'file:delete',
    'share:create',
    'share:delete',
    'public:publish',
    'public:unpublish',
    'plugin:run',
    'plugin:install',
    'plugin:uninstall',
    'git:init',
    'git:sync',
    'git:configure',
    'shortcut:update',
    'api_token:manage',
  ],
  viewer: ['doc:view'],
}

export const DEFAULT_INVITE_ROLE: InviteRoleValue = 'system:editor'

export function buildSystemPermissionSet(role: SystemRole) {
  return new Set(SYSTEM_ROLE_DEFAULTS[role])
}

export function applyOverrides(
  base: Set<string>,
  overrides?: PermissionOverridePayload[] | null,
) {
  if (!overrides || overrides.length === 0) {
    return base
  }
  const next = new Set(base)
  overrides.forEach((override) => {
    if (override.allowed) {
      next.add(override.permission)
    } else {
      next.delete(override.permission)
    }
  })
  return next
}

export function roleToPermissionSet(role: WorkspaceRoleResponse) {
  const base = buildSystemPermissionSet(role.base_role as BaseRole)
  return applyOverrides(base, role.overrides)
}

export function computeOverrides(baseRole: BaseRole, selected: Set<string>) {
  const baseSet = buildSystemPermissionSet(baseRole)
  const overrides: PermissionOverridePayload[] = []
  ALL_PERMISSIONS.forEach((perm) => {
    const inBase = baseSet.has(perm)
    const isSelected = selected.has(perm)
    if (inBase !== isSelected) {
      overrides.push({ permission: perm, allowed: isSelected })
    }
  })
  return overrides
}
