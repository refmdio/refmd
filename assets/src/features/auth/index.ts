export { default as PasswordReentryDialog } from "./password-reentry-dialog";
export { register } from "./lib/register";
export type { RegisterResult } from "./lib/register";
export { login } from "./lib/login";
export type { LoginResult } from "./lib/login";
export { restoreSession } from "./lib/session";
export type { SessionRestoreResult, SessionRestoreError } from "./lib/session";
export {
  persistWrappedDeviceKeys,
  persistWrappedUmk,
  persistDeviceId,
  getPersistedDeviceId,
  hasPdkData,
  persistSessionPdk,
  restoreSessionPdk,
  clearSessionData,
  clearAllPersistedKeys,
} from "./lib/key-persistence";
