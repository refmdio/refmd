import {
  handleClearTransientKeys,
  handleGetDeviceId,
  handleGetPublicKeys,
  handleInit,
  handleInitFromPassword,
  handleIsReady,
  handleLock,
  handleSetDsk,
  handleSetInitialized,
  handleSetUserContext,
} from "../lifecycle";
import type { RequestHandlerTable } from "./shared";

export const lifecycleRequestHandlers = {
  "clear-transient-keys": () => handleClearTransientKeys(),
  "get-device-id": (state) => handleGetDeviceId(state),
  "get-public-keys": (state) => handleGetPublicKeys(state),
  init: (state, payload) => handleInit(state, payload),
  "init-from-password": (state, payload) => handleInitFromPassword(state, payload),
  "is-ready": (state) => handleIsReady(state),
  lock: (state) => handleLock(state),
  "set-dsk": (state, payload) => handleSetDsk(state, payload),
  "set-initialized": (state) => handleSetInitialized(state),
  "set-user-context": (state, payload) => handleSetUserContext(state, payload),
} satisfies RequestHandlerTable;
