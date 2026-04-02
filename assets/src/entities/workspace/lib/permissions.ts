export const ALL_PERMISSIONS = [
  "document:read",
  "document:write",
  "document:delete",
  "document:archive",
  "workspace:update",
  "workspace:admin",
  "workspace:delete",
  "member:list",
  "member:invite",
  "member:change_role",
  "member:remove",
  "role:manage",
] as const;
type Permission = (typeof ALL_PERMISSIONS)[number];
export type BaseRole = "owner" | "admin" | "editor" | "viewer";
export const PERMISSION_LABELS: Record<Permission, string> = {
  "document:read": "Read documents",
  "document:write": "Write documents",
  "document:delete": "Delete documents",
  "document:archive": "Archive documents",
  "workspace:update": "Update workspace",
  "workspace:admin": "Admin workspace",
  "workspace:delete": "Delete workspace",
  "member:list": "List members",
  "member:invite": "Invite members",
  "member:change_role": "Change member roles",
  "member:remove": "Remove members",
  "role:manage": "Manage roles",
};
export const PRIVILEGE_LEVEL: Record<BaseRole, number> = {
  viewer: 0,
  editor: 1,
  admin: 2,
  owner: 3,
};
const SINCE_VERSION: Record<Permission, number> = {
  "document:read": 1,
  "document:write": 1,
  "document:delete": 1,
  "document:archive": 1,
  "workspace:update": 1,
  "workspace:admin": 1,
  "workspace:delete": 1,
  "member:list": 1,
  "member:invite": 1,
  "member:change_role": 1,
  "member:remove": 1,
  "role:manage": 1,
};
export const CEILING: Record<Permission, BaseRole> = {
  "document:read": "viewer",
  "document:write": "editor",
  "document:delete": "admin",
  "document:archive": "editor",
  "workspace:update": "admin",
  "workspace:admin": "admin",
  "workspace:delete": "owner",
  "member:list": "viewer",
  "member:invite": "admin",
  "member:change_role": "admin",
  "member:remove": "admin",
  "role:manage": "admin",
};
export function isAtOrAbove(role: BaseRole, ceilingRole: BaseRole): boolean {
  return PRIVILEGE_LEVEL[role] >= PRIVILEGE_LEVEL[ceilingRole];
}
function defaultGrant(baseRole: BaseRole, perm: Permission): boolean {
  switch (perm) {
    case "document:read":
    case "member:list":
      return true;
    case "document:write":
    case "document:archive":
      return (["owner", "admin", "editor"] as string[]).includes(baseRole);
    case "document:delete":
    case "workspace:update":
    case "workspace:admin":
    case "member:invite":
    case "member:change_role":
    case "member:remove":
    case "role:manage":
      return (["owner", "admin"] as string[]).includes(baseRole);
    case "workspace:delete":
      return baseRole === "owner";
    default:
      return false;
  }
}
export function checkEffectivePermission(
  roles: Array<{
    id: string;
    base_role: string;
    catalog_version?: number | null;
    permissions?: Array<{
      permission: string;
      granted: boolean;
    }>;
  }>,
  roleId: string,
  permission: string,
): boolean {
  const role = roles.find((r) => r.id === roleId);
  if (!role) return false;
  const baseRole = role.base_role as BaseRole;
  const perm = permission as Permission;
  if (!(ALL_PERMISSIONS as readonly string[]).includes(perm)) return false;
  if (baseRole === "owner") return true;
  const ceiling = CEILING[perm];
  if (ceiling && !isAtOrAbove(baseRole, ceiling)) return false;
  const override = role.permissions?.find((o) => o.permission === permission);
  if (override !== undefined) return override.granted;
  if (role.catalog_version != null && SINCE_VERSION[perm] > role.catalog_version) {
    return false;
  }
  return defaultGrant(baseRole, perm);
}
