import { clearRegisteredDocumentAccess, registerSharedDocumentAccess } from "./access";
import { getDocumentState } from "./store";
import { resetDocumentState } from "./lifecycle";

export function activateSharedDocumentRoute(
  stateKey: string,
  access: Parameters<typeof registerSharedDocumentAccess>[1],
): void {
  const existingState = getDocumentState(stateKey);
  if (existingState && existingState.refCount <= 0) {
    resetDocumentState(stateKey, { flushCache: false });
  }

  registerSharedDocumentAccess(stateKey, access);
}

export function disposeSharedDocumentRoute(stateKey: string): void {
  clearRegisteredDocumentAccess(stateKey);
}
