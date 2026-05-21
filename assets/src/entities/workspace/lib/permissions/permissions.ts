export const ALL_PERMISSIONS = [
  "document:read",
  "document:write",
  "document:manage_share",
  "document:delete",
  "document:archive",
  "workspace:update",
  "workspace:features",
  "workspace:admin",
  "workspace:delete",
  "member:list",
  "member:invite",
  "guest:invite",
  "member:change_role",
  "member:remove",
  "role:manage",
] as const;
type Permission = (typeof ALL_PERMISSIONS)[number];
export type BaseRole = "owner" | "admin" | "editor" | "viewer" | "guest";
export const PERMISSION_LABELS: Record<Permission, string> = {
  "document:read": "Read documents",
  "document:write": "Write documents",
  "document:manage_share": "Manage shares",
  "document:delete": "Delete documents",
  "document:archive": "Archive documents",
  "workspace:update": "Update workspace",
  "workspace:features": "Manage workspace features",
  "workspace:admin": "Admin workspace",
  "workspace:delete": "Delete workspace",
  "member:list": "List members",
  "member:invite": "Invite members",
  "guest:invite": "Invite guests",
  "member:change_role": "Change member roles",
  "member:remove": "Remove members",
  "role:manage": "Manage roles",
};
export const PRIVILEGE_LEVEL: Record<BaseRole, number> = {
  viewer: 0,
  guest: 0,
  editor: 1,
  admin: 2,
  owner: 3,
};
const SINCE_VERSION: Record<Permission, number> = {
  "document:read": 1,
  "document:write": 1,
  "document:manage_share": 1,
  "document:delete": 1,
  "document:archive": 1,
  "workspace:update": 1,
  "workspace:features": 1,
  "workspace:admin": 1,
  "workspace:delete": 1,
  "member:list": 1,
  "member:invite": 1,
  "guest:invite": 1,
  "member:change_role": 1,
  "member:remove": 1,
  "role:manage": 1,
};
export const CEILING: Record<Permission, BaseRole> = {
  "document:read": "viewer",
  "document:write": "editor",
  "document:manage_share": "editor",
  "document:delete": "admin",
  "document:archive": "editor",
  "workspace:update": "admin",
  "workspace:features": "admin",
  "workspace:admin": "admin",
  "workspace:delete": "owner",
  "member:list": "viewer",
  "member:invite": "admin",
  "guest:invite": "admin",
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
      return true;
    case "member:list":
      return baseRole !== "guest";
    case "document:write":
    case "document:manage_share":
    case "document:archive":
      return perm === "document:manage_share"
        ? (["owner", "admin", "editor"] as string[]).includes(baseRole)
        : (["owner", "admin", "editor", "guest"] as string[]).includes(baseRole);
    case "document:delete":
    case "workspace:update":
    case "workspace:features":
    case "workspace:admin":
    case "member:invite":
    case "guest:invite":
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
  if (
    baseRole === "guest" &&
    !["document:read", "document:write", "document:archive"].includes(perm)
  ) {
    return false;
  }
  const ceiling = CEILING[perm];
  if (baseRole !== "guest" && ceiling && !isAtOrAbove(baseRole, ceiling)) return false;
  const override = role.permissions?.find((o) => o.permission === permission);
  if (override !== undefined) return override.granted;
  if (role.catalog_version != null && SINCE_VERSION[perm] > role.catalog_version) {
    return false;
  }
  return defaultGrant(baseRole, perm);
}
