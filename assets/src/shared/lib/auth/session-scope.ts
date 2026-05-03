export const SHARE_SESSION_SCOPE_HEADER = "X-Refmd-Session-Scope";

type PreferredSessionScope = "share" | null;

let preferredSessionScope: PreferredSessionScope = null;

export function getPreferredSessionScope(): PreferredSessionScope {
  return preferredSessionScope;
}

export function setPreferredSessionScope(scope: PreferredSessionScope): void {
  preferredSessionScope = scope;
}
