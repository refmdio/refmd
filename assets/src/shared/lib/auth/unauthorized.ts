export type AuthSessionScope = "user" | "share";

export class AuthUnauthorizedError extends Error {
  readonly scope: AuthSessionScope;

  constructor(scope: AuthSessionScope, message = "session unauthorized") {
    super(message);
    this.name = "AuthUnauthorizedError";
    this.scope = scope;
  }
}

let onUnauthorized: ((scope: AuthSessionScope) => void) | null = null;

export function setAuthUnauthorizedHandler(
  handler: ((scope: AuthSessionScope) => void) | null,
): void {
  onUnauthorized = handler;
}

export function notifyAuthUnauthorized(scope: AuthSessionScope): void {
  onUnauthorized?.(scope);
}

export function isAuthUnauthorizedError(error: unknown): error is AuthUnauthorizedError {
  return error instanceof AuthUnauthorizedError;
}
