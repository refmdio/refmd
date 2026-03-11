export { default as PasswordReentryDialog } from "./password-reentry-dialog";
export { register } from "./lib/register";
export type { RegisterResult } from "./lib/register";
export { login } from "./lib/login";
export type { LoginResult } from "./lib/login";
export { restoreSession } from "./lib/session";
export type { SessionRestoreResult } from "./lib/session";
export {
  persistKeys,
  persistDeviceKeysOnly,
  persistUmkForLogin,
  persistDeviceId,
  getPersistedDeviceId,
  restoreKeysFromDsk,
  restoreKeysFromPdk,
  restoreDeviceKeysFromDsk,
  restoreDeviceKeysFromPdk,
  restoreUmkFromSession,
  hasPdkData,
  clearSessionUmk,
  persistSessionPdk,
  restoreSessionPdk,
  clearSessionData,
  clearAllPersistedKeys,
} from "./lib/key-persistence";
export type { PersistKeysParams, RestoredKeys } from "./lib/key-persistence";
