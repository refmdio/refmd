import type { components } from "@/shared/api";
type PermissionOverride = components["schemas"]["PermissionOverride"];
export type PermissionOverrideMap = Record<string, boolean | null>;
export function buildRolePermissions(overrides: PermissionOverrideMap): PermissionOverride[] {
  const permissions: PermissionOverride[] = [];
  for (const [key, value] of Object.entries(overrides)) {
    if (value !== null) {
      permissions.push({ permission: key, granted: value });
    }
  }
  return permissions;
}
export function togglePermissionOverride(
  current: PermissionOverrideMap,
  permissionKey: string,
): PermissionOverrideMap {
  const currentValue = current[permissionKey];
  if (currentValue === undefined || currentValue === null) {
    return { ...current, [permissionKey]: true };
  }
  if (currentValue === true) {
    return { ...current, [permissionKey]: false };
  }
  const next = { ...current };
  delete next[permissionKey];
  return next;
}
export function getPermissionOverrideState(
  overrides: PermissionOverrideMap,
  permissionKey: string,
): "default" | "granted" | "denied" {
  const value = overrides[permissionKey];
  if (value === true) return "granted";
  if (value === false) return "denied";
  return "default";
}
