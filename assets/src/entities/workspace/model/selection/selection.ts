import { createSignal } from "solid-js";

const WORKSPACE_STORAGE_KEY = "refmd_workspace_id";

function storedWorkspaceId(): string | null {
  return globalThis.localStorage?.getItem(WORKSPACE_STORAGE_KEY) ?? null;
}

const [currentWorkspaceId, setCurrentWorkspaceIdSignal] = createSignal<string | null>(
  storedWorkspaceId(),
);

function setCurrentWorkspaceId(workspaceId: string | null): void {
  if (workspaceId) {
    globalThis.localStorage?.setItem(WORKSPACE_STORAGE_KEY, workspaceId);
  } else {
    globalThis.localStorage?.removeItem(WORKSPACE_STORAGE_KEY);
  }
  setCurrentWorkspaceIdSignal(workspaceId);
}

export { currentWorkspaceId, setCurrentWorkspaceId };
