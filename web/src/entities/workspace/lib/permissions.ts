/**
 * Shared permission resolution utilities
 *
 * Mirrors the server-side permission model from
 * crates/domain/src/workspace/permission.rs
 */

import type { components } from '@/shared/api'

type RoleDetail = components['schemas']['RoleDetailResponse']

// ---------------------------------------------------------------------------
// Permission catalog
// ---------------------------------------------------------------------------

export const ALL_PERMISSIONS = [
  'document:read',
  'document:write',
  'document:delete',
  'document:archive',
  'workspace:update',
  'workspace:delete',
  'member:list',
  'member:invite',
  'member:change_role',
  'member:remove',
  'role:manage',
] as const

export type Permission = (typeof ALL_PERMISSIONS)[number]

export const PERMISSION_LABELS: Record<Permission, string> = {
  'document:read': 'Read documents',
  'document:write': 'Write documents',
  'document:delete': 'Delete documents',
  'document:archive': 'Archive documents',
  'workspace:update': 'Update workspace',
  'workspace:delete': 'Delete workspace',
  'member:list': 'List members',
  'member:invite': 'Invite members',
  'member:change_role': 'Change member roles',
  'member:remove': 'Remove members',
  'role:manage': 'Manage roles',
}

// ---------------------------------------------------------------------------
// Base roles & privilege levels
// ---------------------------------------------------------------------------

export type BaseRole = 'owner' | 'admin' | 'editor' | 'viewer'

export const PRIVILEGE_LEVEL: Record<BaseRole, number> = {
  viewer: 0,
  editor: 1,
  admin: 2,
  owner: 3,
}

// ---------------------------------------------------------------------------
// Ceiling map — the least-privileged base_role that can ever hold this perm
// ---------------------------------------------------------------------------

export const CEILING: Record<Permission, BaseRole> = {
  'document:read': 'viewer',
  'document:write': 'editor',
  'document:delete': 'admin',
  'document:archive': 'editor',
  'workspace:update': 'admin',
  'workspace:delete': 'owner',
  'member:list': 'viewer',
  'member:invite': 'admin',
  'member:change_role': 'admin',
  'member:remove': 'admin',
  'role:manage': 'admin',
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Whether `role` is at or above `ceilingRole` in privilege */
export function isAtOrAbove(role: BaseRole, ceilingRole: BaseRole): boolean {
  return PRIVILEGE_LEVEL[role] >= PRIVILEGE_LEVEL[ceilingRole]
}

/** Default grant for a (base_role, permission) pair -- no DB override */
export function defaultGrant(baseRole: BaseRole, perm: Permission): boolean {
  switch (perm) {
    case 'document:read':
    case 'member:list':
      return true
    case 'document:write':
    case 'document:archive':
      return ['owner', 'admin', 'editor'].includes(baseRole)
    case 'document:delete':
    case 'workspace:update':
    case 'member:invite':
    case 'member:change_role':
    case 'member:remove':
    case 'role:manage':
      return ['owner', 'admin'].includes(baseRole)
    case 'workspace:delete':
      return baseRole === 'owner'
    default:
      return false
  }
}

// ---------------------------------------------------------------------------
// Effective permission check (matches server algorithm)
// ---------------------------------------------------------------------------

/**
 * Check whether a role effectively has a given permission.
 *
 * Algorithm (must match server):
 * 1. Owner base_role -> always true
 * 2. Ceiling check: if base_role < ceiling for this permission -> false
 *    (regardless of overrides — an editor can never get admin-only perms)
 * 3. Check override: if an explicit override exists, use it
 * 4. Fall back to default grant for the base_role
 */
export function checkEffectivePermission(
  roles: RoleDetail[],
  roleId: string,
  permission: string,
): boolean {
  const role = roles.find(r => r.id === roleId)
  if (!role) return false

  const baseRole = role.base_role as BaseRole
  const perm = permission as Permission

  // 1. Reject unknown permissions before owner fast-path (fail-closed)
  if (!ALL_PERMISSIONS.includes(perm)) return false

  // 2. Owner always has all known permissions
  if (baseRole === 'owner') return true

  // 3. Ceiling check: if base_role is below the ceiling, deny regardless of overrides
  const ceiling = CEILING[perm]
  if (ceiling && !isAtOrAbove(baseRole, ceiling)) return false

  // 4. Check for explicit override
  const override_ = role.permission_overrides?.find(o => o.permission === permission)
  if (override_ !== undefined) return override_.granted

  // 5. Default grant
  return defaultGrant(baseRole, perm)
}
