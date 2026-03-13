import { createSignal } from "solid-js";

export const WORKSPACE_STORAGE_KEY = "refmd_workspace_id";

function loadWorkspaceId(): string | null {
  try {
    return localStorage.getItem(WORKSPACE_STORAGE_KEY);
  } catch {
    return null;
  }
}

const [currentWorkspaceId, _setCurrentWorkspaceId] = createSignal<string | null>(
  loadWorkspaceId(),
);

export function setCurrentWorkspaceId(id: string | null) {
  _setCurrentWorkspaceId(id);
  try {
    if (id) {
      localStorage.setItem(WORKSPACE_STORAGE_KEY, id);
    } else {
      localStorage.removeItem(WORKSPACE_STORAGE_KEY);
    }
  } catch {
    // Ignore storage errors
  }
}

export { currentWorkspaceId };
